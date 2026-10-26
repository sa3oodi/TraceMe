using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Jint;
using JintEngine = Jint.Engine;
using Acornima.Ast;
using Jint.Native;
using Jint.Runtime;
using TraceMe.Data;
using TraceMe.Models;

namespace TraceMe.Services;

public static class AppPaths
{
    public static string DataDir => Environment.GetEnvironmentVariable("TRACEME_DATA")
        ?? System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "TraceMe");
    public static string DbPath => System.IO.Path.Combine(DataDir, "traceme.db");
}

public static class Elevation
{
    public static bool IsElevated()
    {
        if (!OperatingSystem.IsWindows()) return Environment.UserName == "root";
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>Starts a new elevated copy of this process (UAC prompt). The copy waits for this process to exit before binding the port.</summary>
    public static void RelaunchElevated()
    {
        var exe = Environment.ProcessPath ?? throw new InvalidOperationException("Cannot determine process path.");
        var args = Environment.GetCommandLineArgs().Skip(1).Where(a => !a.StartsWith("--wait-pid") && a != "--open").ToList();
        var parts = new List<string>();
        if (System.IO.Path.GetFileNameWithoutExtension(exe).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            parts.Add(Quote(Environment.GetCommandLineArgs()[0]));
        parts.AddRange(args.Select(Quote));
        parts.Add("--wait-pid=" + Environment.ProcessId);
        Process.Start(new ProcessStartInfo(exe, string.Join(' ', parts))
        {
            UseShellExecute = true, Verb = "runas", WorkingDirectory = Directory.GetCurrentDirectory()
        });
    }

    static string Quote(string s) => s.Contains(' ') || s.Contains('"') ? "\"" + s.Replace("\"", "\\\"") + "\"" : s;
}

/// <summary>Cached global settings and alert rules, persisted to the database.</summary>
public sealed class SettingsStore
{
    readonly Db _db;
    readonly object _gate = new();
    GlobalSettings _cur;
    List<AlertRule> _alerts;
    List<AppRule> _appRules;

    public SettingsStore(Db db)
    {
        _db = db;
        _cur = Load();
        _alerts = db.LoadAlerts();
        _appRules = db.LoadAppRules();
    }

    GlobalSettings Load()
    {
        try
        {
            var j = _db.GetSetting("global");
            if (j != null) return JsonSerializer.Deserialize<GlobalSettings>(j)!.Normalize();
        }
        catch (JsonException) { }
        return new GlobalSettings().Normalize();
    }

    public GlobalSettings Current { get { lock (_gate) return _cur; } }
    public IReadOnlyList<AlertRule> Alerts { get { lock (_gate) return _alerts.ToList(); } }
    public IReadOnlyList<AppRule> AppRules { get { lock (_gate) return _appRules.ToList(); } }

    public AppRule UpsertAppRule(AppRule r)
    {
        r.Normalize();
        lock (_gate)
        {
            var other = _appRules.FirstOrDefault(x => x.Key == r.Key && x.Id != r.Id);
            if (other != null) throw new ArgumentException($"There is already a rule for {r.Key}.");
            _db.SaveAppRule(r);
            var i = _appRules.FindIndex(x => x.Id == r.Id);
            if (i >= 0) _appRules[i] = r; else _appRules.Add(r);
        }
        return r;
    }

    public bool DeleteAppRule(string id)
    {
        _db.DeleteAppRule(id);
        lock (_gate) return _appRules.RemoveAll(x => x.Id == id) > 0;
    }

    public void Save(GlobalSettings s)
    {
        s.Normalize();
        _db.SetSetting("global", JsonSerializer.Serialize(s));
        lock (_gate) _cur = s;
    }

    public AlertRule UpsertAlert(AlertRule a)
    {
        a.Normalize();
        _db.SaveAlert(a);
        lock (_gate)
        {
            var i = _alerts.FindIndex(x => x.Id == a.Id);
            if (i >= 0) _alerts[i] = a; else _alerts.Add(a);
        }
        return a;
    }

    public bool DeleteAlert(string id)
    {
        _db.DeleteAlert(id);
        lock (_gate) return _alerts.RemoveAll(a => a.Id == id) > 0;
    }
}

public sealed record BusMessage(EventRecord Event, string? Sound, bool Toast);

/// <summary>Persists events and fans them out to live subscribers (the UI's toast/sound stream).</summary>
public sealed class EventBus
{
    readonly Db _db;
    readonly ConcurrentDictionary<Guid, System.Threading.Channels.Channel<BusMessage>> _subs = new();

    public EventBus(Db db) => _db = db;

    public EventRecord Publish(string? tid, string type, string severity, string message, string? data = null, string? sound = null, bool toast = true)
    {
        var e = new EventRecord { T = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), Tid = tid, Type = type, Severity = severity, Message = message, Data = data };
        try { _db.InsertEvent(e); } catch (Exception ex) { Console.Error.WriteLine("[events] " + ex.Message); }
        var msg = new BusMessage(e, sound, toast);
        foreach (var ch in _subs.Values) ch.Writer.TryWrite(msg);
        return e;
    }

    public (System.Threading.Channels.ChannelReader<BusMessage> reader, IDisposable sub) Subscribe()
    {
        var id = Guid.NewGuid();
        var ch = System.Threading.Channels.Channel.CreateBounded<BusMessage>(new System.Threading.Channels.BoundedChannelOptions(100)
        { FullMode = System.Threading.Channels.BoundedChannelFullMode.DropOldest });
        _subs[id] = ch;
        return (ch.Reader, new Unsub(() => { _subs.TryRemove(id, out _); ch.Writer.TryComplete(); }));
    }

    sealed class Unsub(Action a) : IDisposable { public void Dispose() => a(); }
}

/// <summary>Reverse DNS with a cache (failures are retried after ten minutes).</summary>
public sealed class DnsService
{
    record Entry(string? Name, DateTime At);
    readonly ConcurrentDictionary<string, Entry> _cache = new();
    readonly ConcurrentDictionary<string, byte> _inflight = new();

    /// <summary>Returns the cached name (null if unknown). When <paramref name="lookup"/> is true a missing entry triggers a background lookup.</summary>
    public string? TryGet(string ip, bool lookup)
    {
        if (_cache.TryGetValue(ip, out var e))
        {
            if (e.Name != null || DateTime.UtcNow - e.At < TimeSpan.FromMinutes(10) || !lookup) return e.Name;
        }
        if (lookup && _inflight.TryAdd(ip, 0))
            _ = Task.Run(async () =>
            {
                string? name = null;
                try
                {
                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(4));
                    var he = await Dns.GetHostEntryAsync(ip, cts.Token);
                    name = he.HostName is { Length: > 0 } h && h != ip ? h : null;
                }
                catch { }
                _cache[ip] = new Entry(name, DateTime.UtcNow);
                _inflight.TryRemove(ip, out _);
            });
        return _cache.TryGetValue(ip, out var e2) ? e2.Name : null;
    }
}

public sealed record AsnInfo(string? Asn, string? Prefix, string? Country, string? Registry, string? Name, bool Private);

/// <summary>AS owner lookup through Team Cymru's whois service (opt-in; sends hop IPs to a third party).</summary>
public sealed class AsnService
{
    readonly Db _db;
    readonly ConcurrentDictionary<string, AsnInfo?> _cache = new();
    readonly ConcurrentDictionary<string, byte> _inflight = new();
    readonly SemaphoreSlim _gate = new(4);

    public AsnService(Db db) => _db = db;

    public static bool IsPrivate(IPAddress a)
    {
        if (IPAddress.IsLoopback(a)) return true;
        if (a.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var b = a.GetAddressBytes();
            return a.IsIPv6LinkLocal || a.IsIPv6SiteLocal || (b[0] & 0xFE) == 0xFC;
        }
        var v = a.GetAddressBytes();
        return v[0] == 10 || (v[0] == 172 && v[1] >= 16 && v[1] <= 31) || (v[0] == 192 && v[1] == 168)
            || (v[0] == 169 && v[1] == 254) || (v[0] == 100 && v[1] >= 64 && v[1] <= 127) || v[0] == 0;
    }

    public AsnInfo? TryGet(string ip, bool lookup)
    {
        if (_cache.TryGetValue(ip, out var info)) return info;
        if (!IPAddress.TryParse(ip, out var addr)) return null;
        if (IsPrivate(addr)) return _cache[ip] = new AsnInfo(null, null, null, null, "Private network", true);
        if (!lookup) return null;
        if (_inflight.TryAdd(ip, 0))
            _ = Task.Run(async () =>
            {
                try { _cache[ip] = await LoadAsync(ip, addr); }
                catch { /* try again on a later snapshot */ }
                finally { _inflight.TryRemove(ip, out _); }
            });
        return null;
    }

    async Task<AsnInfo?> LoadAsync(string ip, IPAddress addr)
    {
        var cached = _db.GetAsn(ip);
        if (cached is { } c && DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - c.t < 7L * 86_400_000)
            return JsonSerializer.Deserialize<AsnInfo>(c.json);
        await _gate.WaitAsync();
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(6));
            using var tcp = new TcpClient();
            await tcp.ConnectAsync("whois.cymru.com", 43, cts.Token);
            var s = tcp.GetStream();
            await s.WriteAsync(Encoding.ASCII.GetBytes($"begin\nverbose\n{addr}\nend\n"), cts.Token);
            using var rd = new StreamReader(s, Encoding.ASCII);
            var text = await rd.ReadToEndAsync(cts.Token);
            var info = Parse(text);
            _db.SetAsn(ip, JsonSerializer.Serialize(info));
            return info;
        }
        finally { _gate.Release(); }
    }

    public static AsnInfo? Parse(string text)
    {
        foreach (var line in text.Split('\n'))
        {
            var f = line.Split('|').Select(x => x.Trim()).ToArray();
            if (f.Length < 7 || f[0].Length == 0 || f[0].Equals("AS", StringComparison.OrdinalIgnoreCase)) continue; // header / "Bulk mode" banner
            string? Nz(string x) => x is "" or "NA" ? null : x;
            return new AsnInfo(Nz(f[0]) is { } a ? "AS" + a : null, Nz(f[2]), Nz(f[3]), Nz(f[4]), Nz(f[6]), false);
        }
        return null;
    }
}

/// <summary>Runs user JavaScript (custom columns) in a sandboxed Jint engine: no I/O, time and memory limited.</summary>
public sealed class ScriptHost
{
    readonly object _gate = new();
    readonly JintEngine _engine = Create();
    readonly Dictionary<string, (string body, Jint.Prepared<Script>? prep, string? err)> _cache = new();

    public static JintEngine Create() => new(o =>
    {
        o.Strict = true;
        o.TimeoutInterval(TimeSpan.FromMilliseconds(150));
        o.LimitMemory(16_000_000);
        o.LimitRecursion(64);
    });

    public (object? value, string? error) Eval(string key, string body, IReadOnlyDictionary<string, object?> vars)
    {
        lock (_gate)
        {
            if (!_cache.TryGetValue(key, out var c) || c.body != body)
            {
                try { c = (body, JintEngine.PrepareScript("(function(){\n" + body + "\n})()"), null); }
                catch (Exception e) { c = (body, null, e.Message); }
                _cache[key] = c;
            }
            if (c.prep == null) return (null, c.err);
            try
            {
                foreach (var kv in vars) _engine.SetValue(kv.Key, kv.Value is null ? JsValue.Null : JsValue.FromObject(_engine, kv.Value));
                var r = _engine.Evaluate(c.prep.Value);
                return (Convert(r), null);
            }
            catch (JavaScriptException e) { return (null, e.Message); }
            catch (Exception e) { return (null, e.Message); }
        }
    }

    static object? Convert(JsValue v) =>
        v.IsNumber() ? (double.IsFinite(v.AsNumber()) ? v.AsNumber() : null)
        : v.IsString() ? v.AsString()
        : v.IsBoolean() ? v.AsBoolean()
        : null;
}
