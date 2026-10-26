using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace TraceMe.Apps;

public sealed record ProcInfo(int Pid, string Key, string Name);

/// <summary>Maps process ids to executable names and tracks which applications are currently running.</summary>
public sealed class ProcessCatalog
{
    readonly ConcurrentDictionary<int, ProcInfo> _byPid = new();
    readonly ConcurrentDictionary<int, string?> _paths = new();
    volatile Dictionary<string, List<int>> _running = new();

    public IReadOnlyDictionary<string, List<int>> Running => _running;

    public static string KeyOf(int pid, string processName) => pid == 4 ? "system" : (processName + ".exe").ToLowerInvariant();

    public void Refresh()
    {
        var map = new Dictionary<string, List<int>>();
        var alive = new HashSet<int>();
        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                try
                {
                    if (p.Id == 0) continue;
                    var key = KeyOf(p.Id, p.ProcessName);
                    alive.Add(p.Id);
                    _byPid[p.Id] = new ProcInfo(p.Id, key, p.ProcessName + (p.Id == 4 ? "" : ".exe"));
                    if (!map.TryGetValue(key, out var l)) map[key] = l = new();
                    l.Add(p.Id);
                }
                catch { /* process exited while enumerating */ }
            }
        }
        foreach (var pid in _byPid.Keys.Where(k => !alive.Contains(k)).ToList()) { _byPid.TryRemove(pid, out _); _paths.TryRemove(pid, out _); }
        _running = map;
    }

    public ProcInfo? Get(int pid)
    {
        if (_byPid.TryGetValue(pid, out var i)) return i;
        try
        {
            using var p = Process.GetProcessById(pid);
            var info = new ProcInfo(pid, KeyOf(pid, p.ProcessName), p.ProcessName + ".exe");
            _byPid[pid] = info; return info;
        }
        catch { return null; }
    }

    public string? PathOf(int pid) => _paths.GetOrAdd(pid, id =>
    {
        var viaApi = AppIcons.ImagePath(id);
        if (viaApi != null) return viaApi;
        try { using var p = Process.GetProcessById(id); return p.MainModule?.FileName; } catch { return null; }
    });
}

/// <summary>Set of this machine's own addresses, used to tell the local and remote side of a captured packet.</summary>
public sealed class LocalAddresses
{
    HashSet<string> _set = new();
    DateTime _at = DateTime.MinValue;

    public bool Contains(IPAddress a)
    {
        if (DateTime.UtcNow - _at > TimeSpan.FromSeconds(30))
        {
            var s = new HashSet<string>();
            try
            {
                foreach (var n in NetworkInterface.GetAllNetworkInterfaces())
                    foreach (var u in n.GetIPProperties().UnicastAddresses) s.Add(Norm(u.Address));
            }
            catch { }
            _set = s; _at = DateTime.UtcNow;
        }
        return IPAddress.IsLoopback(a) || _set.Contains(Norm(a));
    }

    static string Norm(IPAddress a) => (a.IsIPv4MappedToIPv6 ? a.MapToIPv4() : new IPAddress(a.GetAddressBytes())).ToString();
}

/// <summary>
/// Per-process network traffic from the Windows kernel network trace (the same source Resource Monitor uses), including UDP
/// which has no connection table. Requires administrator rights.
/// </summary>
public sealed class EtwNetSource : IDisposable
{
    readonly FlowStore _store;
    readonly ProcessCatalog _procs;
    readonly LocalAddresses _local = new();
    TraceEventSession? _session;
    Thread? _thread;
    public bool Running { get; private set; }
    public string? Error { get; private set; }
    public long Events;

    public EtwNetSource(FlowStore store, ProcessCatalog procs) { _store = store; _procs = procs; }

    public bool Start()
    {
        if (Running) return true;
        try
        {
            if (!(TraceEventSession.IsElevated() ?? false)) { Error = "Live traffic capture needs administrator rights."; return false; }
            const string name = "TraceMe-Network";
            TraceEventSession.GetActiveSession(name)?.Stop(true); // leftover from a crashed instance
            _session = new TraceEventSession(name) { StopOnDispose = true };
            _session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);
            var k = _session.Source.Kernel;
            k.TcpIpSend += d => On(d.ProcessID, 6, d.saddr, d.daddr, d.sport, d.dport, d.size, true);
            k.TcpIpRecv += d => On(d.ProcessID, 6, d.saddr, d.daddr, d.sport, d.dport, d.size, false);
            k.TcpIpSendIPV6 += d => On(d.ProcessID, 6, d.saddr, d.daddr, d.sport, d.dport, d.size, true);
            k.TcpIpRecvIPV6 += d => On(d.ProcessID, 6, d.saddr, d.daddr, d.sport, d.dport, d.size, false);
            k.UdpIpSend += d => On(d.ProcessID, 17, d.saddr, d.daddr, d.sport, d.dport, d.size, true);
            k.UdpIpRecv += d => On(d.ProcessID, 17, d.saddr, d.daddr, d.sport, d.dport, d.size, false);
            k.UdpIpSendIPV6 += d => On(d.ProcessID, 17, d.saddr, d.daddr, d.sport, d.dport, d.size, true);
            k.UdpIpRecvIPV6 += d => On(d.ProcessID, 17, d.saddr, d.daddr, d.sport, d.dport, d.size, false);
            _thread = new Thread(() =>
            {
                try { _session.Source.Process(); }
                catch (Exception e) { Error = "Capture stopped: " + e.Message; }
                Running = false;
            }) { IsBackground = true, Name = "etw-net" };
            _thread.Start();
            Running = true; Error = null;
            return true;
        }
        catch (Exception e)
        {
            Error = "Could not start live traffic capture: " + e.Message;
            try { _session?.Dispose(); } catch { }
            _session = null; Running = false;
            return false;
        }
    }

    void On(int pid, byte proto, IPAddress? saddr, IPAddress? daddr, int sport, int dport, int size, bool send)
    {
        if (pid <= 0 || pid == Environment.ProcessId || saddr == null || daddr == null) return;
        Interlocked.Increment(ref Events);
        // The kernel reports source/destination relative to the packet, so decide which side is this machine by address.
        IPAddress remote; int rport, lport;
        bool sLocal = _local.Contains(saddr), dLocal = _local.Contains(daddr);
        if (sLocal && !dLocal) { remote = daddr; rport = dport; lport = sport; }
        else if (dLocal && !sLocal) { remote = saddr; rport = sport; lport = dport; }
        else if (send) { remote = daddr; rport = dport; lport = sport; }
        else { remote = saddr; rport = sport; lport = dport; }
        if (remote.IsIPv4MappedToIPv6) remote = remote.MapToIPv4();
        var info = _procs.Get(pid);
        if (info == null) return;
        _store.Record(pid, info.Key, proto, remote.ToString(), rport, lport, inbound: !send, size, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
    }

    public void Dispose()
    {
        try { _session?.Dispose(); } catch { }
        Running = false;
    }
}

/// <summary>Connection-table fallback (no administrator needed): established TCP connections per process, without byte counters.</summary>
public static class TcpTable
{
    public readonly record struct Row(int Pid, IPAddress Local, int LocalPort, IPAddress Remote, int RemotePort, int State);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int af, int cls, uint reserved);

    const int AfInet = 2, AfInet6 = 23, OwnerPidAll = 5, Established = 5;

    static int Port(int raw) => (ushort)IPAddress.NetworkToHostOrder((short)(raw & 0xFFFF));

    public static List<Row> Read()
    {
        var rows = new List<Row>();
        Read(AfInet, rows); Read(AfInet6, rows);
        return rows;
    }

    static void Read(int af, List<Row> rows)
    {
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, af, OwnerPidAll, 0);
        for (int attempt = 0; attempt < 3; attempt++)
        {
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                uint r = GetExtendedTcpTable(buf, ref size, false, af, OwnerPidAll, 0);
                if (r == 122) { continue; } // buffer too small: size was updated, retry
                if (r != 0) return;
                int n = Marshal.ReadInt32(buf);
                int off = 4;
                for (int i = 0; i < n; i++)
                {
                    if (af == AfInet)
                    {
                        var state = Marshal.ReadInt32(buf, off);
                        var la = new IPAddress((uint)Marshal.ReadInt32(buf, off + 4)); var lp = Port(Marshal.ReadInt32(buf, off + 8));
                        var ra = new IPAddress((uint)Marshal.ReadInt32(buf, off + 12)); var rp = Port(Marshal.ReadInt32(buf, off + 16));
                        rows.Add(new Row(Marshal.ReadInt32(buf, off + 20), la, lp, ra, rp, state));
                        off += 24;
                    }
                    else
                    {
                        var lb = new byte[16]; var rb = new byte[16];
                        Marshal.Copy(buf + off, lb, 0, 16); Marshal.Copy(buf + off + 24, rb, 0, 16);
                        rows.Add(new Row(Marshal.ReadInt32(buf, off + 52), new IPAddress(lb), Port(Marshal.ReadInt32(buf, off + 20)),
                            new IPAddress(rb), Port(Marshal.ReadInt32(buf, off + 44)), Marshal.ReadInt32(buf, off + 48)));
                        off += 56;
                    }
                }
                return;
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
    }

    public static bool IsEstablished(Row r) => r.State == Established;
}
