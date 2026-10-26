namespace TraceMe.Models;

/// <summary>Tells TraceMe to watch an application and trace the servers it talks to whenever it runs.</summary>
public class AppRule
{
    public string Id { get; set; } = Guid.NewGuid().ToString("n")[..8];
    /// <summary>Executable name, e.g. "cod.exe" (case-insensitive; ".exe" optional).</summary>
    public string ProcessName { get; set; } = "";
    public string? Label { get; set; }
    public bool Enabled { get; set; } = true;
    /// <summary>icmp | udp | tcp — how the discovered servers are traced.</summary>
    public string Method { get; set; } = "icmp";
    public int MaxServers { get; set; } = 3;
    /// <summary>A UDP endpoint needs at least this many packets per second (both directions, 10 s average) to count as a game server.</summary>
    public double MinPps { get; set; } = 5;
    public bool IncludeTcp { get; set; }
    /// <summary>Probe the port the app actually uses instead of the method's default port.</summary>
    public bool UseServerPort { get; set; }
    public int IntervalMs { get; set; } = 1000;
    /// <summary>pause | delete | keep — what happens to the traces when the app closes.</summary>
    public string OnExit { get; set; } = "pause";

    public static string KeyOf(string? name)
    {
        var n = (name ?? "").Trim().ToLowerInvariant();
        if (n.Length > 0 && !n.Contains('.')) n += ".exe";
        return n;
    }

    public string Key => KeyOf(ProcessName);
    public string DisplayName => string.IsNullOrWhiteSpace(Label) ? ProcessName : Label!;

    public AppRule Normalize()
    {
        ProcessName = (ProcessName ?? "").Trim();
        if (ProcessName.Length == 0 || ProcessName.Length > 120 || ProcessName.IndexOfAny(new[] { '\\', '/', ':', '*', '?', '"', '<', '>', '|' }) >= 0 || ProcessName.Any(char.IsControl))
            throw new ArgumentException("A valid executable name (for example cod.exe) is required.");
        Label = string.IsNullOrWhiteSpace(Label) ? null : Label.Trim()[..Math.Min(Label.Trim().Length, 60)];
        Method = (Method ?? "icmp").ToLowerInvariant();
        if (!TargetConfig.Methods.Contains(Method)) throw new ArgumentException($"Unknown trace method '{Method}'.");
        MaxServers = Math.Clamp(MaxServers, 1, 10);
        MinPps = Math.Clamp(MinPps, 0.5, 1000);
        IntervalMs = Math.Clamp(IntervalMs, 200, 60_000);
        if (OnExit is not ("pause" or "delete" or "keep")) OnExit = "pause";
        return this;
    }
}

public class SessionServer
{
    public string Ip { get; set; } = "";
    public string TargetId { get; set; } = "";
    public string Proto { get; set; } = "";
    public int Port { get; set; }
    public long FirstSeen { get; set; }
    public long LastSeen { get; set; }
}

public class ServerSummary
{
    public string Ip { get; set; } = "";
    public string? Host { get; set; }
    public string TargetId { get; set; } = "";
    public int Samples { get; set; }
    public double? Avg { get; set; }
    public double? P95 { get; set; }
    public double? Max { get; set; }
    public double? Jitter { get; set; }
    public double LossPct { get; set; }
    public double? Mos { get; set; }
    public string Code { get; set; } = "";
    public string Side { get; set; } = "";
    public string Headline { get; set; } = "";
}

public class SessionSummary
{
    public string Code { get; set; } = "no_data";
    public string Side { get; set; } = "unknown";
    public string Headline { get; set; } = "";
    public long DurationMs { get; set; }
    public List<ServerSummary> Servers { get; set; } = new();
}

public class AppSession
{
    public string Id { get; set; } = Guid.NewGuid().ToString("n")[..10];
    public string AppKey { get; set; } = "";
    public string Name { get; set; } = "";
    public string? RuleId { get; set; }
    public long Started { get; set; }
    public long? Ended { get; set; }
    /// <summary>running | ended | interrupted</summary>
    public string Status { get; set; } = "running";
    public List<SessionServer> Servers { get; set; } = new();
    public SessionSummary? Summary { get; set; }
}
