using System.Net;
using System.Text.Json;

namespace TraceMe.Models;

public class TargetConfig
{
    public string Id { get; set; } = Guid.NewGuid().ToString("n")[..8];
    public string Host { get; set; } = "";
    public string? Name { get; set; }
    public string Group { get; set; } = "";
    /// <summary>icmp | udp | tcp</summary>
    public string Method { get; set; } = "icmp";
    public int IntervalMs { get; set; } = 1000;
    public int TimeoutMs { get; set; } = 2000;
    public int MaxHops { get; set; } = 30;
    public int StartHop { get; set; } = 1;
    public int PacketSize { get; set; } = 56;
    /// <summary>Destination port for udp/tcp. 0 = default (udp 33434, tcp 80).</summary>
    public int Port { get; set; }
    public int Tos { get; set; }
    public bool DontFragment { get; set; } = true;
    public int InterHopDelayMs { get; set; } = 20;
    public bool ResolveNames { get; set; } = true;
    public bool PreferIPv6 { get; set; }
    public string? SourceAddress { get; set; }
    public int? StopAfterRounds { get; set; }
    public int? StopAfterMinutes { get; set; }
    public bool Paused { get; set; }
    /// <summary>When set, probing is delegated to a remote TraceMe agent at this base URL.</summary>
    public string? AgentUrl { get; set; }
    public string? AgentToken { get; set; }
    /// <summary>Executable this target was created for (Apps feature); empty for ordinary targets.</summary>
    public string? AppKey { get; set; }
    /// <summary>True when an app rule created the target automatically.</summary>
    public bool Auto { get; set; }
    public long Created { get; set; } = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    public int Sort { get; set; }

    public int EffectivePort => Port > 0 ? Port : Method == "udp" ? 33434 : 80;
    public string DisplayName => string.IsNullOrWhiteSpace(Name) ? Host : Name!;

    public static readonly string[] Methods = { "icmp", "udp", "tcp" };

    /// <summary>Clamps every field to a sane range; throws ArgumentException for unusable input.</summary>
    public TargetConfig Normalize()
    {
        Host = (Host ?? "").Trim();
        if (Host.Length == 0 || Host.Length > 253 || Host.Any(char.IsWhiteSpace))
            throw new ArgumentException("A valid host name or IP address is required.");
        Method = (Method ?? "icmp").ToLowerInvariant();
        if (!Methods.Contains(Method)) throw new ArgumentException($"Unknown trace method '{Method}'.");
        Name = string.IsNullOrWhiteSpace(Name) ? null : Name.Trim()[..Math.Min(Name.Trim().Length, 80)];
        Group = (Group ?? "").Trim();
        AppKey = string.IsNullOrWhiteSpace(AppKey) ? null : AppKey.Trim().ToLowerInvariant()[..Math.Min(AppKey.Trim().Length, 120)];
        if (Group.Length > 60) Group = Group[..60];
        IntervalMs = Math.Clamp(IntervalMs, 200, 3_600_000);
        TimeoutMs = Math.Clamp(TimeoutMs, 100, 30_000);
        MaxHops = Math.Clamp(MaxHops, 1, 64);
        StartHop = Math.Clamp(StartHop, 1, MaxHops);
        PacketSize = Math.Clamp(PacketSize, 0, 9000);
        Port = Math.Clamp(Port, 0, 65535);
        Tos = Math.Clamp(Tos, 0, 255);
        InterHopDelayMs = Math.Clamp(InterHopDelayMs, 0, 1000);
        if (StopAfterRounds is <= 0) StopAfterRounds = null;
        if (StopAfterMinutes is <= 0) StopAfterMinutes = null;
        SourceAddress = string.IsNullOrWhiteSpace(SourceAddress) ? null : SourceAddress.Trim();
        if (SourceAddress != null && !IPAddress.TryParse(SourceAddress, out _))
            throw new ArgumentException("Source address must be a valid IP address.");
        AgentUrl = string.IsNullOrWhiteSpace(AgentUrl) ? null : AgentUrl.Trim().TrimEnd('/');
        if (AgentUrl != null && !(Uri.TryCreate(AgentUrl, UriKind.Absolute, out var u) && (u.Scheme == "http" || u.Scheme == "https")))
            throw new ArgumentException("Agent URL must be an http(s) URL.");
        if (AgentUrl == null) AgentToken = null;
        return this;
    }

    public TargetConfig Clone() => JsonSerializer.Deserialize<TargetConfig>(JsonSerializer.Serialize(this))!;
}

public class SmtpSettings
{
    public string Host { get; set; } = "";
    public int Port { get; set; } = 587;
    public string User { get; set; } = "";
    public string Password { get; set; } = "";
    /// <summary>starttls | ssl | none</summary>
    public string Security { get; set; } = "starttls";
    public string From { get; set; } = "";
}

public class CustomColumn
{
    public string Id { get; set; } = Guid.NewGuid().ToString("n")[..6];
    public string Name { get; set; } = "Column";
    /// <summary>Function body; must return a value. Variables: Average, Minimum, Maximum, Current, Jitter, LostPacketCount, TotalPacketCount, PacketLossPercent, HopNumber, IPAddress, HostName.</summary>
    public string Script { get; set; } = "return null;";
    public int Decimals { get; set; } = 2;
    public bool Visible { get; set; } = true;
}

public class GlobalSettings
{
    public double LatencyWarnMs { get; set; } = 100;
    public double LatencyCritMs { get; set; } = 250;
    public double LossWarnPct { get; set; } = 1;
    public double LossCritPct { get; set; } = 5;
    public int RetentionDays { get; set; } = 7;
    public bool AllowExec { get; set; }
    public bool AsnLookup { get; set; }
    /// <summary>Non-empty value turns this instance into a remote agent that other TraceMe instances can use.</summary>
    public string? AgentToken { get; set; }
    public SmtpSettings Smtp { get; set; } = new();
    public Dictionary<string, string> Aliases { get; set; } = new();
    public List<CustomColumn> Columns { get; set; } = new()
    {
        new CustomColumn
        {
            Id = "mos", Name = "MOS", Decimals = 2,
            Script =
                "var pl = PacketLossPercent;\n" +
                "if (Average == null) return null;\n" +
                "var eff = Average + Jitter * 2 + 10;\n" +
                "var r = eff < 160 ? 93.2 - eff / 40 : 93.2 - (eff - 120) / 10;\n" +
                "r = Math.max(r - pl * 2.5, 0);\n" +
                "return 1 + 0.035 * r + 0.000007 * r * (r - 60) * (100 - r);"
        }
    };

    public GlobalSettings Normalize()
    {
        LatencyWarnMs = Math.Clamp(LatencyWarnMs, 1, 100_000);
        LatencyCritMs = Math.Clamp(Math.Max(LatencyCritMs, LatencyWarnMs), 1, 100_000);
        LossWarnPct = Math.Clamp(LossWarnPct, 0, 100);
        LossCritPct = Math.Clamp(Math.Max(LossCritPct, LossWarnPct), 0, 100);
        RetentionDays = Math.Clamp(RetentionDays, 1, 3650);
        Aliases ??= new();
        Columns ??= new();
        Smtp ??= new();
        foreach (var c in Columns) { c.Id = string.IsNullOrWhiteSpace(c.Id) ? Guid.NewGuid().ToString("n")[..6] : c.Id; c.Decimals = Math.Clamp(c.Decimals, 0, 6); }
        if (string.IsNullOrWhiteSpace(AgentToken)) AgentToken = null;
        return this;
    }
}

public class AlertAction
{
    /// <summary>toast | sound | email | webhook | exec | script</summary>
    public string Type { get; set; } = "toast";
    public string? Sound { get; set; }
    public string? To { get; set; }
    public string? Subject { get; set; }
    public string? Url { get; set; }
    public string? Body { get; set; }
    public string? Path { get; set; }
    public string? Args { get; set; }
    public string? Script { get; set; }
}

public class AlertRule
{
    public string Id { get; set; } = Guid.NewGuid().ToString("n")[..8];
    public string Name { get; set; } = "New alert";
    public bool Enabled { get; set; } = true;
    /// <summary>Null = applies to every target.</summary>
    public string? TargetId { get; set; }
    /// <summary>destination | any | hop</summary>
    public string Scope { get; set; } = "destination";
    public int Hop { get; set; } = 1;
    /// <summary>avg | max | last | jitter | loss | noresponse | mos | routechange</summary>
    public string Metric { get; set; } = "avg";
    public string Op { get; set; } = ">";
    public double Value { get; set; } = 100;
    /// <summary>Number of most recent samples the metric is computed over.</summary>
    public int Samples { get; set; } = 10;
    public int ConsecutiveRounds { get; set; } = 1;
    public bool NotifyOnClear { get; set; } = true;
    public int RepeatMinutes { get; set; }
    public List<AlertAction> Actions { get; set; } = new() { new AlertAction { Type = "toast" } };

    public static readonly string[] Metrics = { "avg", "max", "last", "jitter", "loss", "noresponse", "mos", "routechange" };
    public static readonly string[] Scopes = { "destination", "any", "hop" };

    public AlertRule Normalize()
    {
        Name = string.IsNullOrWhiteSpace(Name) ? "Alert" : Name.Trim();
        if (!Metrics.Contains(Metric)) throw new ArgumentException($"Unknown metric '{Metric}'.");
        if (!Scopes.Contains(Scope)) throw new ArgumentException($"Unknown scope '{Scope}'.");
        if (Op != ">" && Op != "<") Op = ">";
        Samples = Math.Clamp(Samples, 1, 600);
        ConsecutiveRounds = Math.Clamp(ConsecutiveRounds, 1, 600);
        Hop = Math.Clamp(Hop, 1, 64);
        RepeatMinutes = Math.Clamp(RepeatMinutes, 0, 10_080);
        if (Metric == "mos" && Scope != "destination") Scope = "destination";
        Actions ??= new();
        return this;
    }
}

public class EventRecord
{
    public long Id { get; set; }
    public long T { get; set; }
    public string? Tid { get; set; }
    /// <summary>alert | route | info | error</summary>
    public string Type { get; set; } = "info";
    /// <summary>info | warn | critical</summary>
    public string Severity { get; set; } = "info";
    public string Message { get; set; } = "";
    public string? Data { get; set; }
}

public class Comment
{
    public long Id { get; set; }
    public string Tid { get; set; } = "";
    public long T { get; set; }
    public string Text { get; set; } = "";
}
