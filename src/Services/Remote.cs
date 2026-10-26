using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace TraceMe.Services;

/// <summary>Persisted choice to listen on the local network (stored next to the database, read at start-up).</summary>
public sealed class RemoteConfig
{
    public bool Enabled { get; set; }
    public string? Token { get; set; }
}

/// <summary>What this process is actually doing, decided once at start-up.</summary>
public sealed class RemoteRuntime
{
    /// <summary>True when the server listens beyond loopback.</summary>
    public bool Active { get; set; }
    /// <summary>False when the listen address was fixed by --url / TRACEME_URL, so the UI must not change it.</summary>
    public bool Managed { get; set; } = true;
    public int Port { get; set; } = 5055;
    public string? Token { get; set; }
}

public sealed record LanAddress(string Name, string Address, bool Primary, bool Virtual);

public static class RemoteAccess
{
    public const string RuleName = "TraceMe remote access";
    static readonly object Gate = new();
    static string FilePath => Path.Combine(AppPaths.DataDir, "remote.json");

    public static RemoteConfig Load()
    {
        lock (Gate)
        {
            try
            {
                if (File.Exists(FilePath)) return JsonSerializer.Deserialize<RemoteConfig>(File.ReadAllText(FilePath)) ?? new();
            }
            catch (Exception e) when (e is JsonException or IOException or UnauthorizedAccessException) { }
            return new();
        }
    }

    public static void Save(RemoteConfig c)
    {
        lock (Gate)
        {
            Directory.CreateDirectory(AppPaths.DataDir);
            var tmp = FilePath + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(c));
            File.Move(tmp, FilePath, overwrite: true);
        }
    }

    /// <summary>144 random bits, URL-safe.</summary>
    public static string NewToken() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(18)).Replace('+', '-').Replace('/', '_');

    public static bool ValidToken(string? t) => t != null && t.Length >= 16;

    // ------------------------------------------------------------------ addresses

    static readonly Regex VirtualName = new("vEthernet|VMware|VirtualBox|Hyper-V|WSL|Docker|Bluetooth|Loopback|Pseudo", RegexOptions.IgnoreCase);

    public static bool IsPrivate(IPAddress a)
    {
        var b = a.GetAddressBytes();
        return a.AddressFamily == AddressFamily.InterNetwork &&
               (b[0] == 10 || (b[0] == 172 && b[1] is >= 16 and <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 100 && b[1] is >= 64 and <= 127));
    }

    /// <summary>IPv4 addresses a phone could use. The first with a default gateway on a private range is marked primary.</summary>
    public static List<LanAddress> LanAddresses()
    {
        var found = new List<(LanAddress a, bool gateway, bool priv)>();
        try
        {
            foreach (var n in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (n.OperationalStatus != OperationalStatus.Up || n.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;
                var props = n.GetIPProperties();
                bool gateway = props.GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(IPAddress.Any));
                bool virt = VirtualName.IsMatch(n.Name) || VirtualName.IsMatch(n.Description);
                foreach (var u in props.UnicastAddresses)
                {
                    var ip = u.Address;
                    if (ip.AddressFamily != AddressFamily.InterNetwork || IPAddress.IsLoopback(ip) || ip.ToString().StartsWith("169.254.")) continue;
                    found.Add((new LanAddress(n.Name, ip.ToString(), false, virt), gateway, IsPrivate(ip)));
                }
            }
        }
        catch (NetworkInformationException) { }
        var ordered = found.OrderByDescending(x => x.gateway && !x.a.Virtual).ThenByDescending(x => x.priv && !x.a.Virtual).ThenBy(x => x.a.Virtual).ToList();
        var primary = ordered.FirstOrDefault(x => x.gateway && x.priv && !x.a.Virtual);
        if (primary.a == null) primary = ordered.FirstOrDefault(x => !x.a.Virtual);
        return ordered.Select(x => x.a with { Primary = primary.a != null && x.a.Address == primary.a.Address }).ToList();
    }

    public static string Url(string address, int port, string? token = null) =>
        $"http://{address}:{port}/" + (token != null ? "#t=" + Uri.EscapeDataString(token) : "");

    // ------------------------------------------------------------------ Windows Firewall

    static (int code, string output) Netsh(params string[] args)
    {
        var psi = new ProcessStartInfo("netsh") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        var text = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        if (!p.WaitForExit(10_000)) { try { p.Kill(); } catch { } return (-1, "netsh timed out"); }
        return (p.ExitCode, text.Trim());
    }

    public static bool FirewallRuleExists()
    {
        if (!OperatingSystem.IsWindows()) return false;
        try { return Netsh("advfirewall", "firewall", "show", "rule", $"name={RuleName}").code == 0; } catch { return false; }
    }

    /// <summary>Allows inbound TCP on <paramref name="port"/> for this program on private networks only. Needs administrator rights.</summary>
    public static (bool ok, string? error) AddFirewallRule(int port)
    {
        if (!OperatingSystem.IsWindows()) return (false, "Windows only.");
        if (port is < 1 or > 65535) return (false, "Invalid port.");
        try
        {
            Netsh("advfirewall", "firewall", "delete", "rule", $"name={RuleName}");
            var args = new List<string> { "advfirewall", "firewall", "add", "rule", $"name={RuleName}", "dir=in", "action=allow", "protocol=TCP", $"localport={port}", "profile=private" };
            var exe = Environment.ProcessPath;
            if (exe != null && !Path.GetFileNameWithoutExtension(exe).Equals("dotnet", StringComparison.OrdinalIgnoreCase)) args.Add($"program={exe}");
            var (code, output) = Netsh(args.ToArray());
            return code == 0 ? (true, null) : (false, output.Length > 0 ? output : "netsh failed");
        }
        catch (Exception e) { return (false, e.Message); }
    }

    public static (bool ok, string? error) RemoveFirewallRule()
    {
        if (!OperatingSystem.IsWindows()) return (true, null);
        try
        {
            var (code, output) = Netsh("advfirewall", "firewall", "delete", "rule", $"name={RuleName}");
            // exit code 1 with "No rules match" means there was nothing to remove
            return code == 0 || output.Contains("No rules", StringComparison.OrdinalIgnoreCase) ? (true, null) : (false, output);
        }
        catch (Exception e) { return (false, e.Message); }
    }
}
