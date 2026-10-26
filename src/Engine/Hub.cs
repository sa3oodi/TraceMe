using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using TraceMe.Alerts;
using TraceMe.Apps;
using TraceMe.Data;
using TraceMe.Models;
using TraceMe.Services;

namespace TraceMe.Engine;

/// <summary>Evaluates the user-defined JavaScript columns for a hop.</summary>
public sealed class ColumnEvaluator
{
    readonly ScriptHost _script;
    public ColumnEvaluator(ScriptHost script) => _script = script;

    public Dictionary<string, object?> Evaluate(int hop, HopStats s, string? addr, string? name, GlobalSettings gs)
    {
        var result = new Dictionary<string, object?>();
        if (gs.Columns.Count == 0) return result;
        var vars = new Dictionary<string, object?>
        {
            ["Average"] = s.Avg, ["Minimum"] = s.Min, ["Maximum"] = s.Max, ["Current"] = s.Last, ["Jitter"] = s.Jitter ?? 0.0,
            ["LostPacketCount"] = s.Sent - s.Recv, ["TotalPacketCount"] = s.Sent, ["PacketLossPercent"] = s.LossPct,
            ["HopNumber"] = hop, ["IPAddress"] = addr, ["HostName"] = name ?? addr
        };
        foreach (var c in gs.Columns)
        {
            var (v, err) = _script.Eval("col:" + c.Id, c.Script, vars);
            result[c.Id] = err != null ? "error: " + err : v is double d ? Math.Round(d, c.Decimals) : v;
        }
        return result;
    }
}

/// <summary>Executes sweeps on behalf of other TraceMe instances (the "remote agent" feature).</summary>
public sealed class AgentService
{
    readonly Hub _hub;
    readonly SemaphoreSlim _slots = new(4);
    public AgentService(Hub hub) => _hub = hub;

    public async Task<ProbeResult[]> RoundAsync(AgentRequest r, CancellationToken ct)
    {
        var cfg = new TargetConfig
        {
            Host = r.Host, Method = r.Method, TimeoutMs = r.TimeoutMs, PacketSize = r.PacketSize, Port = r.Port,
            Tos = r.Tos, DontFragment = r.DontFragment, InterHopDelayMs = r.InterHopDelayMs, PreferIPv6 = r.PreferIPv6, StartHop = 1
        };
        cfg.MaxHops = Math.Clamp(r.To, 1, 64);
        cfg.Normalize();
        int from = Math.Clamp(r.From, 1, 64), to = Math.Clamp(r.To, from, 64);
        IPAddress ip;
        if (!IPAddress.TryParse(cfg.Host, out var lit))
        {
            var all = await Dns.GetHostAddressesAsync(cfg.Host, ct);
            var want = cfg.PreferIPv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
            ip = all.FirstOrDefault(a => a.AddressFamily == want) ?? all.First();
        }
        else ip = lit;
        var src = TargetRunner.DetectSource(ip, null);
        await _slots.WaitAsync(ct);
        try { return await ProberFactory.Local(cfg.Method).RunRoundAsync(new ProbeContext(ip, cfg.Host, src, cfg, _hub.Pool), from, to, ct); }
        finally { _slots.Release(); }
    }
}

public sealed class TargetManager
{
    readonly Hub _hub;
    readonly ConcurrentDictionary<string, TargetRunner> _runners = new();
    public TargetManager(Hub hub) => _hub = hub;

    public IReadOnlyList<TargetRunner> All() => _runners.Values.OrderBy(r => r.Config.Sort).ThenBy(r => r.Config.Created).ToList();
    public TargetRunner? Get(string id) => _runners.TryGetValue(id, out var r) ? r : null;

    public void LoadAll()
    {
        foreach (var cfg in _hub.Db.LoadTargets())
        {
            try { cfg.Normalize(); } catch (ArgumentException) { continue; }
            var r = new TargetRunner(_hub, cfg);
            _runners[cfg.Id] = r;
            r.Start();
        }
    }

    public TargetRunner Add(TargetConfig cfg)
    {
        cfg.Normalize();
        cfg.Sort = _runners.Count == 0 ? 0 : _runners.Values.Max(r => r.Config.Sort) + 1;
        var r = new TargetRunner(_hub, cfg);
        _runners[cfg.Id] = r;
        _hub.Db.SaveTarget(cfg);
        r.Start();
        return r;
    }

    public TargetRunner? Update(string id, TargetConfig edited)
    {
        if (!_runners.TryGetValue(id, out var r)) return null;
        var old = r.Config;
        edited.Id = id; edited.Created = old.Created; edited.Sort = old.Sort;
        if (edited.AgentToken == "••••••") edited.AgentToken = old.AgentToken; // unchanged masked secret
        edited.Normalize();
        r.Apply(edited);
        _hub.Db.SaveTarget(r.Config);
        return r;
    }

    public void Persist(TargetRunner r) => _hub.Db.SaveTarget(r.Config);

    public async Task<bool> RemoveAsync(string id)
    {
        if (!_runners.TryRemove(id, out var r)) return false;
        await r.StopAsync();
        _hub.Alerts.Forget(id);
        _hub.Diagnosis.Forget(id);
        await _hub.Db.FlushAsync(); // let queued samples land first so they cannot outlive the target
        _hub.Db.DeleteTarget(id);
        return true;
    }

    public async Task StopAllAsync() => await Task.WhenAll(_runners.Values.Select(r => r.StopAsync()));
}

/// <summary>Owns every long-lived service; created once at startup and passed to the API layer.</summary>
public sealed class Hub : IDisposable
{
    public Db Db { get; }
    public SettingsStore Settings { get; }
    public EventBus Bus { get; }
    public DnsService Dns { get; } = new();
    public AsnService Asn { get; }
    public ScriptHost Script { get; } = new();
    public ColumnEvaluator Columns { get; }
    public RawIcmpPool Pool { get; } = new();
    public AlertEngine Alerts { get; }
    public AgentService Agent { get; }
    public TargetManager Targets { get; }
    public DiagnosisService Diagnosis { get; }
    public AppMonitor Apps { get; }
    readonly Timer _purge;

    public Hub(string dbPath)
    {
        Db = new Db(dbPath);
        Settings = new SettingsStore(Db);
        Bus = new EventBus(Db);
        Asn = new AsnService(Db);
        Columns = new ColumnEvaluator(Script);
        Alerts = new AlertEngine(this);
        Agent = new AgentService(this);
        Targets = new TargetManager(this);
        Diagnosis = new DiagnosisService(this);
        Apps = new AppMonitor(this);
        _purge = new Timer(_ =>
        {
            try { Db.Purge(Settings.Current.RetentionDays); } catch (Exception e) { Console.Error.WriteLine("[purge] " + e.Message); }
        }, null, TimeSpan.FromMinutes(1), TimeSpan.FromHours(6));
    }

    public void Dispose()
    {
        _purge.Dispose();
        Apps.Dispose();
        Pool.Dispose();
        Db.Dispose();
    }
}
