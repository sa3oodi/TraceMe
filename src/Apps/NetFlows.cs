using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace TraceMe.Apps;

public enum IpKind { Public, Private, Loopback, LinkLocal, Multicast, Broadcast, Unspecified }

public static class NetClass
{
    public static IpKind Classify(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip)) return IpKind.Loopback;
        if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)) return IpKind.Unspecified;
        var b = ip.GetAddressBytes();
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv6Multicast) return IpKind.Multicast;
            if (ip.IsIPv6LinkLocal) return IpKind.LinkLocal;
            if (ip.IsIPv6SiteLocal || (b[0] & 0xFE) == 0xFC) return IpKind.Private;
            return IpKind.Public;
        }
        if (b[0] == 255 && b[1] == 255 && b[2] == 255 && b[3] == 255) return IpKind.Broadcast;
        if (b[0] >= 224 && b[0] <= 239) return IpKind.Multicast;
        if (b[0] == 0) return IpKind.Unspecified;
        if (b[0] == 169 && b[1] == 254) return IpKind.LinkLocal;
        if (b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 100 && b[1] >= 64 && b[1] <= 127)) return IpKind.Private;
        if (b[0] >= 240) return IpKind.Unspecified; // reserved
        // 192.0.0.0/24, 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 198.18.0.0/15: documentation / benchmarking
        if ((b[0] == 192 && b[1] == 0 && (b[2] == 0 || b[2] == 2)) || (b[0] == 198 && (b[1] == 18 || b[1] == 19 || (b[1] == 51 && b[2] == 100))) || (b[0] == 203 && b[1] == 0 && b[2] == 113))
            return IpKind.Private;
        return IpKind.Public;
    }

    public static bool IsPublic(IPAddress ip) => Classify(ip) == IpKind.Public;
}

/// <summary>Traffic between one process and one remote endpoint (protocol + address + port), with a rolling 60-second rate window.</summary>
public sealed class Flow
{
    const int Slots = 60;
    readonly object _g = new();
    readonly long[] _stamp = new long[Slots], _bIn = new long[Slots], _bOut = new long[Slots], _pIn = new long[Slots], _pOut = new long[Slots];

    public Flow(int pid, string app, byte proto, string remote, int rport, long now)
    {
        Pid = pid; App = app; Proto = proto; Remote = remote; RemotePort = rport; First = Last = now;
    }

    public int Pid { get; }
    public string App { get; }
    public byte Proto { get; }
    public string Remote { get; }
    public int RemotePort { get; }
    public int LocalPort { get; private set; }
    public long BytesIn, BytesOut, PktIn, PktOut;
    public long First { get; }
    public long Last { get; private set; }
    /// <summary>True when only the connection table (no packet counters) has reported this flow.</summary>
    public bool TableOnly { get; private set; } = true;

    public void Add(bool inbound, int bytes, long nowMs, int localPort)
    {
        lock (_g)
        {
            TableOnly = false; LocalPort = localPort; Last = nowMs;
            long sec = nowMs / 1000; int i = (int)(sec % Slots);
            if (_stamp[i] != sec) { _stamp[i] = sec; _bIn[i] = _bOut[i] = _pIn[i] = _pOut[i] = 0; }
            if (inbound) { _bIn[i] += bytes; _pIn[i]++; BytesIn += bytes; PktIn++; }
            else { _bOut[i] += bytes; _pOut[i]++; BytesOut += bytes; PktOut++; }
        }
    }

    public void Touch(long nowMs, int localPort) { lock (_g) { Last = nowMs; if (localPort > 0) LocalPort = localPort; } }

    public readonly record struct Rates(double BpsIn, double BpsOut, double PpsIn, double PpsOut)
    {
        public double Pps => PpsIn + PpsOut;
        public double Bps => BpsIn + BpsOut;
    }

    /// <summary>Average rates over the last <paramref name="windowSec"/> seconds (shorter for flows younger than the window).</summary>
    public Rates GetRates(long nowMs, int windowSec = 10)
    {
        lock (_g)
        {
            long nowSec = nowMs / 1000;
            double span = Math.Clamp((nowMs - First) / 1000.0, 1, windowSec);
            double bi = 0, bo = 0, pi = 0, po = 0;
            for (int i = 0; i < Slots; i++)
            {
                if (_stamp[i] <= nowSec - windowSec || _stamp[i] > nowSec) continue;
                bi += _bIn[i]; bo += _bOut[i]; pi += _pIn[i]; po += _pOut[i];
            }
            return new Rates(bi / span, bo / span, pi / span, po / span);
        }
    }
}

/// <summary>Thread-safe aggregation of captured packets into per-process flows.</summary>
public sealed class FlowStore
{
    readonly ConcurrentDictionary<string, Flow> _flows = new();

    public IEnumerable<Flow> All => _flows.Values;

    static string Key(int pid, byte proto, string remote, int rport) => $"{pid}|{proto}|{remote}|{rport}";

    public void Record(int pid, string app, byte proto, string remote, int rport, int lport, bool inbound, int bytes, long nowMs)
    {
        var f = _flows.GetOrAdd(Key(pid, proto, remote, rport), _ => new Flow(pid, app, proto, remote, rport, nowMs));
        f.Add(inbound, bytes, nowMs, lport);
    }

    /// <summary>Marks a flow as alive without packet counters (used by the connection-table fallback).</summary>
    public void Touch(int pid, string app, byte proto, string remote, int rport, int lport, long nowMs)
    {
        var f = _flows.GetOrAdd(Key(pid, proto, remote, rport), _ => new Flow(pid, app, proto, remote, rport, nowMs));
        f.Touch(nowMs, lport);
    }

    public int Purge(long olderThanMs)
    {
        int n = 0;
        foreach (var kv in _flows) if (kv.Value.Last < olderThanMs && _flows.TryRemove(kv.Key, out _)) n++;
        return n;
    }
}

/// <summary>Executable names of popular online games (best effort — new releases and renamed builds are not covered).</summary>
public static class GameCatalog
{
    static readonly Dictionary<string, string> Map = new(StringComparer.OrdinalIgnoreCase)
    {
        ["cod.exe"] = "Call of Duty", ["modernwarfare.exe"] = "Call of Duty: Modern Warfare", ["blackopscoldwar.exe"] = "Call of Duty: Black Ops Cold War",
        ["cod24-cod.exe"] = "Call of Duty: Black Ops 6", ["h1_sp64_ship.exe"] = "Call of Duty: Modern Warfare Remastered", ["s2_mp64_ship.exe"] = "Call of Duty: WWII",
        ["fortniteclient-win64-shipping.exe"] = "Fortnite", ["valorant-win64-shipping.exe"] = "VALORANT", ["cs2.exe"] = "Counter-Strike 2", ["csgo.exe"] = "Counter-Strike: GO",
        ["r5apex.exe"] = "Apex Legends", ["r5apex_dx12.exe"] = "Apex Legends", ["overwatch.exe"] = "Overwatch", ["league of legends.exe"] = "League of Legends",
        ["dota2.exe"] = "Dota 2", ["rocketleague.exe"] = "Rocket League", ["tslgame.exe"] = "PUBG", ["rainbowsix.exe"] = "Rainbow Six Siege", ["rainbowsix_vulkan.exe"] = "Rainbow Six Siege",
        ["gta5.exe"] = "Grand Theft Auto V", ["playgtav.exe"] = "Grand Theft Auto V", ["rustclient.exe"] = "Rust", ["wow.exe"] = "World of Warcraft", ["wowclassic.exe"] = "WoW Classic",
        ["destiny2.exe"] = "Destiny 2", ["haloinfinite.exe"] = "Halo Infinite", ["bf2042.exe"] = "Battlefield 2042", ["bfv.exe"] = "Battlefield V", ["bf1.exe"] = "Battlefield 1",
        ["eldenring.exe"] = "Elden Ring", ["thefinals.exe"] = "THE FINALS", ["thefinals-win64-shipping.exe"] = "THE FINALS", ["helldivers2.exe"] = "Helldivers 2",
        ["escapefromtarkov.exe"] = "Escape from Tarkov", ["dayz_x64.exe"] = "DayZ", ["arma3_x64.exe"] = "Arma 3", ["fifa23.exe"] = "FIFA 23", ["fc24.exe"] = "EA Sports FC 24",
        ["starcraft ii.exe"] = "StarCraft II", ["diablo iv.exe"] = "Diablo IV", ["hearthstone.exe"] = "Hearthstone", ["paladins.exe"] = "Paladins", ["smite.exe"] = "SMITE",
        ["tf_win64.exe"] = "Team Fortress 2", ["hl2.exe"] = "Source engine game", ["left4dead2.exe"] = "Left 4 Dead 2", ["gtavi.exe"] = "Grand Theft Auto VI", ["minecraft.exe"] = "Minecraft",
        ["fallguys_client_game.exe"] = "Fall Guys", ["amongus.exe"] = "Among Us", ["deadbydaylight-win64-shipping.exe"] = "Dead by Daylight", ["pathofexile.exe"] = "Path of Exile",
        ["warframe.x64.exe"] = "Warframe", ["nba2k24.exe"] = "NBA 2K24", ["marvelrivals-win64-shipping.exe"] = "Marvel Rivals", ["deadlock.exe"] = "Deadlock", ["pubg.exe"] = "PUBG",
    };

    public static string? Lookup(string key) => Map.TryGetValue(key, out var n) ? n : null;
    public static bool IsKnownGame(string key) => Map.ContainsKey(key);
    public static IEnumerable<(string exe, string name)> All => Map.Select(kv => (kv.Key, kv.Value)).OrderBy(x => x.Value).ThenBy(x => x.Key);
}

public enum EndpointRole { Game, Udp, Service, Tcp, Local, Other }

public static class EndpointScoring
{
    /// <summary>
    /// Ranks how likely a remote endpoint is to be the app's game/voice server. UDP with a sustained packet rate wins:
    /// that is what real-time game traffic looks like, whereas TCP 443/80 is usually launcher, auth or CDN traffic.
    /// </summary>
    public static (EndpointRole role, double score) Score(IpKind kind, bool udp, bool tcp, double pps, double bps, bool webPortsOnly)
    {
        if (kind != IpKind.Public) return (kind is IpKind.Private or IpKind.LinkLocal ? EndpointRole.Local : EndpointRole.Other, 0);
        double bulk = Math.Log10(1 + bps);
        if (udp)
        {
            if (pps >= 8) return (EndpointRole.Game, 1000 + pps * 2 + bulk);
            if (pps >= 2) return (EndpointRole.Udp, 500 + pps * 2 + bulk);
            return (EndpointRole.Udp, pps * 2 + bulk);
        }
        if (tcp) return webPortsOnly ? (EndpointRole.Service, bulk + pps * 0.1) : (EndpointRole.Tcp, 100 + pps * 0.5 + bulk);
        return (EndpointRole.Other, 0);
    }
}
