using System.Collections.Concurrent;
using System.Net;
using TraceMe.Engine;
using TraceMe.Models;
using TraceMe.Services;

namespace TraceMe.Apps;

/// <summary>Builds the per-hop inputs for <see cref="Diagnosis"/> from a running target's stored history.</summary>
public sealed class DiagnosisService
{
    readonly Hub _hub;
    readonly ConcurrentDictionary<string, (DateTime at, DiagnosisResult r)> _cache = new();
    public DiagnosisService(Hub hub) => _hub = hub;

    public DiagnosisResult ForTarget(TargetRunner r, long from, long to)
    {
        var gs = _hub.Settings.Current;
        var hops = r.VisibleHops();
        var stats = _hub.Db.WindowStats(r.Id, hops.Select(h => h.Hop), from, to);
        var list = hops.Select(h =>
        {
            stats.TryGetValue(h.Hop, out var s);
            var addr = h.Address;
            string? name = addr == null ? null : gs.Aliases.GetValueOrDefault(addr) ?? _hub.Dns.TryGet(addr, false);
            string? asn = addr == null ? null : _hub.Asn.TryGet(addr, false)?.Asn;
            return new HopInput(h.Hop, addr, name, s?.Sent ?? 0, s?.Recv ?? 0, s?.LossPct ?? 0, s?.Avg, s?.Jitter, s?.Max, asn);
        }).ToList();
        // the last stretch of the window (about 12 traces, at least 30 s) tells whether a problem is still going on
        int recentSec = Math.Clamp((int)(r.Config.IntervalMs * 12L / 1000), 30, 120);
        var o = new DiagnosisOptions { LossWarn = gs.LossWarnPct, LossBad = gs.LossCritPct, LatencyWarn = gs.LatencyWarnMs, LatencyBad = gs.LatencyCritMs, RecentSec = recentSec };
        List<HopInput>? recent = null;
        if (to - from >= recentSec * 2000L)
        {
            var rs = _hub.Db.WindowStats(r.Id, hops.Select(h => h.Hop), to - recentSec * 1000L, to);
            recent = list.Select(h => { rs.TryGetValue(h.Hop, out var s); return h with { Sent = s?.Sent ?? 0, Recv = s?.Recv ?? 0, LossPct = s?.LossPct ?? 0 }; }).ToList();
        }
        return Diagnosis.Analyze(list, r.DestHop != null, o, recent);
    }

    /// <summary>Diagnosis over the last <paramref name="windowSec"/> seconds (or since the session restarted), cached for a few seconds.</summary>
    public DiagnosisResult Live(TargetRunner r, int windowSec = 300)
    {
        var key = r.Id + "|" + windowSec;
        if (_cache.TryGetValue(key, out var c) && DateTime.UtcNow - c.at < TimeSpan.FromSeconds(3)) return c.r;
        long to = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        long from = Math.Max(r.SessionStart.ToUnixTimeMilliseconds(), to - windowSec * 1000L);
        var res = ForTarget(r, from, to);
        _cache[key] = (DateTime.UtcNow, res);
        return res;
    }

    public void Forget(string tid) { foreach (var k in _cache.Keys.Where(k => k.StartsWith(tid + "|")).ToList()) _cache.TryRemove(k, out _); }

    public static int Rank(DiagnosisResult d) => d.Status switch { "bad" => 3, "warn" => 2, "ok" => 1, _ => 0 };
}

/// <summary>
/// Watches which applications talk to which servers, picks out the likely game servers, traces them, and reports whether
/// a problem is on the user's side. See <see cref="Diagnosis"/> for how the verdict is reached.
/// </summary>
public sealed class AppMonitor : IDisposable
{
    sealed class RuleState
    {
        public AppSession? Session;
        public DateTime? MissingSince;
        public bool Suppressed;
    }

    sealed record Ep(string Ip, IpKind Kind, EndpointRole Role, double Score, bool Udp, bool Tcp, Flow.Rates Rates, long BytesIn, long BytesOut,
        long First, long Last, bool Active, int? UdpPort, int? TcpPort, List<object> Ports, bool TableOnly);

    readonly Hub _hub;
    public FlowStore Flows { get; } = new();
    public ProcessCatalog Procs { get; } = new();
    AppIcons? _icons;
    public AppIcons Icons => _icons ??= new AppIcons(Procs, AppPaths.DataDir);
    readonly EtwNetSource _etw;
    readonly object _gate = new();
    readonly Dictionary<string, RuleState> _states = new();
    Timer? _timer;
    DateTime _lastEtwTry = DateTime.MinValue, _lastPurge = DateTime.UtcNow;
    int _ticking;

    public AppMonitor(Hub hub)
    {
        _hub = hub;
        _etw = new EtwNetSource(Flows, Procs);
        Procs.Refresh();
    }

    static long Now() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

    public void Start()
    {
        // A session left open by a previous run was interrupted (crash, restart, elevation relaunch).
        foreach (var s in _hub.Db.LoadSessions(null, 200).Where(s => s.Status == "running"))
        {
            s.Status = "interrupted"; s.Ended = s.Servers.Select(x => x.LastSeen).DefaultIfEmpty(s.Started).Max();
            _hub.Db.SaveSession(s);
        }
        TryStartCapture();
        _timer = new Timer(_ => Tick(), null, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(2));
    }

    void TryStartCapture()
    {
        _lastEtwTry = DateTime.UtcNow;
        if (!_etw.Running) _etw.Start();
    }

    public object Capture => new
    {
        live = _etw.Running, mode = _etw.Running ? "etw" : "tcp-table", error = _etw.Running ? null : _etw.Error,
        events = Interlocked.Read(ref _etw.Events), elevated = Services.Elevation.IsElevated()
    };

    // ------------------------------------------------------------------ periodic work

    void Tick()
    {
        if (Interlocked.Exchange(ref _ticking, 1) == 1) return;
        try
        {
            Procs.Refresh();
            long now = Now();
            if (!_etw.Running)
            {
                if (Services.Elevation.IsElevated() && DateTime.UtcNow - _lastEtwTry > TimeSpan.FromSeconds(30)) TryStartCapture();
                if (!_etw.Running) PollTcpTable(now);
            }
            if (DateTime.UtcNow - _lastPurge > TimeSpan.FromMinutes(1)) { Flows.Purge(now - 15 * 60_000); _lastPurge = DateTime.UtcNow; }
            EvaluateRules(now);
        }
        catch (Exception e) { Console.Error.WriteLine("[apps] " + e.Message); }
        finally { Interlocked.Exchange(ref _ticking, 0); }
    }

    void PollTcpTable(long now)
    {
        try
        {
            foreach (var r in TcpTable.Read())
            {
                if (!TcpTable.IsEstablished(r) || r.Pid <= 0 || r.Pid == Environment.ProcessId) continue;
                var remote = r.Remote.IsIPv4MappedToIPv6 ? r.Remote.MapToIPv4() : r.Remote;
                if (NetClass.Classify(remote) is IpKind.Loopback or IpKind.Unspecified) continue;
                var p = Procs.Get(r.Pid); if (p == null) continue;
                Flows.Touch(r.Pid, p.Key, 6, remote.ToString(), r.RemotePort, r.LocalPort, now);
            }
        }
        catch { /* table unavailable */ }
    }

    // ------------------------------------------------------------------ endpoints

    List<Ep> BuildEndpoints(string key, long now, int lookbackSec = 600)
    {
        var res = new List<Ep>();
        foreach (var g in Flows.All.Where(f => f.App == key && now - f.Last < lookbackSec * 1000L).GroupBy(f => f.Remote))
        {
            if (!IPAddress.TryParse(g.Key, out var ip)) continue;
            var kind = NetClass.Classify(ip);
            if (kind is IpKind.Loopback or IpKind.Unspecified or IpKind.Broadcast) continue;
            var flows = g.ToList();
            var rates = flows.Select(f => (f, r: f.GetRates(now))).ToList();
            var total = new Flow.Rates(rates.Sum(x => x.r.BpsIn), rates.Sum(x => x.r.BpsOut), rates.Sum(x => x.r.PpsIn), rates.Sum(x => x.r.PpsOut));
            bool udp = flows.Any(f => f.Proto == 17), tcp = flows.Any(f => f.Proto == 6);
            bool webOnly = !udp && flows.All(f => f.RemotePort is 80 or 443 or 8080 or 8443);
            var (role, score) = EndpointScoring.Score(kind, udp, tcp, total.Pps, total.Bps, webOnly);
            var ports = rates.OrderByDescending(x => x.r.Pps).ThenByDescending(x => x.f.BytesIn + x.f.BytesOut).Take(6)
                .Select(x => (object)new { proto = x.f.Proto == 17 ? "UDP" : "TCP", port = x.f.RemotePort, pps = Math.Round(x.r.Pps, 1), bps = Math.Round(x.r.Bps) }).ToList();
            int? udpPort = rates.Where(x => x.f.Proto == 17).OrderByDescending(x => x.r.Pps).Select(x => (int?)x.f.RemotePort).FirstOrDefault();
            int? tcpPort = rates.Where(x => x.f.Proto == 6).OrderByDescending(x => x.r.Pps).Select(x => (int?)x.f.RemotePort).FirstOrDefault();
            long last = flows.Max(f => f.Last);
            res.Add(new Ep(g.Key, kind, role, score, udp, tcp, total, flows.Sum(f => f.BytesIn), flows.Sum(f => f.BytesOut), flows.Min(f => f.First), last,
                now - last < 15_000, udpPort, tcpPort, ports, flows.All(f => f.TableOnly)));
        }
        return res.OrderByDescending(e => e.Score).ThenByDescending(e => e.Last).ToList();
    }

    List<Ep> Candidates(AppRule rule, long now) => BuildEndpoints(rule.Key, now, 60)
        .Where(e => e.Kind == IpKind.Public && e.Active &&
            ((e.Udp && e.Rates.Pps >= rule.MinPps) || (rule.IncludeTcp && e.Tcp && (e.Rates.Bps >= 1500 || e.TableOnly) && e.Role != EndpointRole.Service)))
        .ToList();

    object EndpointView(string key, Ep e)
    {
        string? host = e.Kind == IpKind.Public ? _hub.Dns.TryGet(e.Ip, true) : null;
        var asn = _hub.Settings.Current.AsnLookup ? _hub.Asn.TryGet(e.Ip, true) : _hub.Asn.TryGet(e.Ip, false);
        var t = _hub.Targets.All().FirstOrDefault(x => x.Config.Host == e.Ip && x.Config.AppKey == key);
        return new
        {
            ip = e.Ip, host, asn, kind = e.Kind.ToString().ToLowerInvariant(), role = e.Role.ToString().ToLowerInvariant(), score = Math.Round(e.Score, 1),
            udp = e.Udp, tcp = e.Tcp, ports = e.Ports, udpPort = e.UdpPort, tcpPort = e.TcpPort, active = e.Active,
            bpsIn = Math.Round(e.Rates.BpsIn), bpsOut = Math.Round(e.Rates.BpsOut), ppsIn = Math.Round(e.Rates.PpsIn, 1), ppsOut = Math.Round(e.Rates.PpsOut, 1),
            bytesIn = e.BytesIn, bytesOut = e.BytesOut, first = e.First, last = e.Last, countersAvailable = !e.TableOnly,
            targetId = t?.Id, targetStatus = t?.Status
        };
    }

    // ------------------------------------------------------------------ application list and detail

    public object ListApps(bool includeAll)
    {
        long now = Now();
        var running = Procs.Running;
        var byApp = Flows.All.Where(f => now - f.Last < 5 * 60_000L).GroupBy(f => f.App).ToDictionary(g => g.Key, g => g.ToList());
        var rules = _hub.Settings.AppRules.ToDictionary(r => r.Key);
        var keys = new HashSet<string>(byApp.Keys);
        foreach (var k in rules.Keys) keys.Add(k);
        foreach (var k in running.Keys) if (includeAll || GameCatalog.IsKnownGame(k)) keys.Add(k);
        var rows = new List<object>();
        foreach (var key in keys)
        {
            byApp.TryGetValue(key, out var fl); fl ??= new();
            rules.TryGetValue(key, out var rule);
            var eps = fl.Count == 0 ? new List<Ep>() : BuildEndpoints(key, now, 300);
            bool isRunning = running.ContainsKey(key);
            var friendly = GameCatalog.Lookup(key);
            double down = eps.Sum(e => e.Rates.BpsIn), up = eps.Sum(e => e.Rates.BpsOut), pps = eps.Sum(e => e.Rates.Pps);
            var pub = eps.Where(e => e.Kind == IpKind.Public).ToList();
            bool game = friendly != null || pub.Any(e => e.Role == EndpointRole.Game);
            var session = _states.GetValueOrDefault(rule?.Id ?? "")?.Session;
            var traced = _hub.Targets.All().Where(t => t.Config.AppKey == key && !t.Config.Paused).ToList();
            object? verdict = null;
            if (traced.Count > 0)
            {
                var worst = traced.Select(t => (t, d: _hub.Diagnosis.Live(t))).OrderByDescending(x => DiagnosisService.Rank(x.d)).ThenByDescending(x => x.d.DestLoss ?? 0).First();
                verdict = new { worst.d.Code, worst.d.Side, worst.d.Status, worst.d.Headline, targetId = worst.t.Id };
            }
            rows.Add(new
            {
                key, name = key, friendly, isGame = game, running = isRunning, pids = running.GetValueOrDefault(key) ?? new List<int>(),
                bpsIn = Math.Round(down), bpsOut = Math.Round(up), pps = Math.Round(pps, 1), endpoints = eps.Count, publicEndpoints = pub.Count,
                gameEndpoints = pub.Count(e => e.Role == EndpointRole.Game), tracedServers = traced.Count,
                rule = rule == null ? null : new { rule.Id, rule.Enabled, rule.Method, rule.MaxServers },
                session = session == null ? null : new { session.Id, session.Started }, verdict,
                lastActive = fl.Count == 0 ? (long?)null : fl.Max(f => f.Last)
            });
        }
        return new { capture = Capture, apps = rows };
    }

    public object? Detail(string key)
    {
        key = AppRule.KeyOf(key);
        long now = Now();
        var rule = _hub.Settings.AppRules.FirstOrDefault(r => r.Key == key);
        bool isRunning = Procs.Running.TryGetValue(key, out var pids);
        var eps = BuildEndpoints(key, now, 600);
        if (!isRunning && eps.Count == 0 && rule == null && !GameCatalog.IsKnownGame(key)) return null;
        var state = rule == null ? null : _states.GetValueOrDefault(rule.Id);
        var servers = _hub.Targets.All().Where(t => t.Config.AppKey == key)
            .OrderByDescending(t => t.Config.Created).Take(12)
            .Select(t =>
            {
                var d = _hub.Diagnosis.Live(t);
                return new { target = t.Summary(), diagnosis = d, auto = t.Config.Auto };
            }).ToList();
        string? path = pids is { Count: > 0 } ? Procs.PathOf(pids[0]) : null;
        return new
        {
            key, name = key, friendly = GameCatalog.Lookup(key), isGame = GameCatalog.IsKnownGame(key) || eps.Any(e => e.Role == EndpointRole.Game),
            running = isRunning, pids = pids ?? new List<int>(), path, capture = Capture,
            rule, session = state?.Session, suppressed = state?.Suppressed ?? false,
            endpoints = eps.Select(e => EndpointView(key, e)).ToList(), servers,
            sessions = _hub.Db.LoadSessions(key, 20).Select(s => new { s.Id, s.Started, s.Ended, s.Status, s.Summary, servers = s.Servers.Count }).ToList()
        };
    }

    // ------------------------------------------------------------------ manual tracing

    public TargetRunner TraceEndpoint(string key, string ip, string method, int port, int intervalMs = 1000)
    {
        key = AppRule.KeyOf(key);
        if (!IPAddress.TryParse(ip, out var addr)) throw new ArgumentException("Invalid IP address.");
        if (NetClass.Classify(addr) is IpKind.Loopback or IpKind.Unspecified or IpKind.Multicast or IpKind.Broadcast) throw new ArgumentException("That address cannot be traced.");
        var existing = _hub.Targets.All().FirstOrDefault(t => t.Config.AppKey == key && t.Config.Host == addr.ToString() && t.Config.Method == method);
        if (existing != null)
        {
            if (existing.Config.Paused) { existing.Pause(false); _hub.Targets.Persist(existing); }
            return existing;
        }
        var label = GameCatalog.Lookup(key) ?? key;
        var cfg = new TargetConfig
        {
            Host = addr.ToString(), Name = $"{label} → {addr}", Group = label, Method = method, Port = method == "icmp" ? 0 : port,
            IntervalMs = intervalMs, AppKey = key, Auto = false
        };
        return _hub.Targets.Add(cfg);
    }

    // ------------------------------------------------------------------ rules, sessions

    void EvaluateRules(long now)
    {
        var rules = _hub.Settings.AppRules.Where(r => r.Enabled).ToList();
        lock (_gate)
        {
            var live = rules.Select(r => r.Id).ToHashSet();
            foreach (var id in _states.Keys.Where(id => !live.Contains(id)).ToList())
            {
                var st = _states[id];
                if (st.Session != null) EndSession(st, _hub.Settings.AppRules.FirstOrDefault(r => r.Id == id), "rule disabled");
                _states.Remove(id);
            }
            foreach (var rule in rules)
            {
                if (!_states.TryGetValue(rule.Id, out var st)) _states[rule.Id] = st = new RuleState();
                bool isRunning = Procs.Running.ContainsKey(rule.Key);
                if (isRunning)
                {
                    st.MissingSince = null;
                    var cands = Candidates(rule, now);
                    if (st.Session == null && !st.Suppressed && cands.Count > 0) StartSession(rule, st, now);
                    if (st.Session != null) UpdateServers(rule, st, cands, now);
                }
                else
                {
                    st.Suppressed = false;
                    if (st.Session != null)
                    {
                        st.MissingSince ??= DateTime.UtcNow;
                        if (DateTime.UtcNow - st.MissingSince > TimeSpan.FromSeconds(8)) EndSession(st, rule, "the application closed");
                    }
                }
            }
        }
    }

    void StartSession(AppRule rule, RuleState st, long now)
    {
        st.Session = new AppSession { AppKey = rule.Key, Name = rule.DisplayName, RuleId = rule.Id, Started = now };
        _hub.Db.SaveSession(st.Session);
        _hub.Bus.Publish(null, "info", "info", $"{rule.DisplayName}: network activity detected — tracing its game servers.", toast: true);
    }

    void UpdateServers(AppRule rule, RuleState st, List<Ep> cands, long now)
    {
        var s = st.Session!;
        // keep "last seen" fresh for servers that still carry traffic
        foreach (var srv in s.Servers)
            if (Flows.All.Any(f => f.App == rule.Key && f.Remote == srv.Ip && now - f.Last < 30_000)) srv.LastSeen = now;
        int active = s.Servers.Count(x => now - x.LastSeen < 120_000);
        foreach (var c in cands)
        {
            if (s.Servers.Any(x => x.Ip == c.Ip)) continue;
            if (active >= rule.MaxServers)
            {
                var stale = s.Servers.Where(x => now - x.LastSeen >= 120_000 && _hub.Targets.Get(x.TargetId) is { Config.Paused: false }).OrderBy(x => x.LastSeen).FirstOrDefault();
                if (stale == null) break;
                if (_hub.Targets.Get(stale.TargetId) is { } old) { old.Pause(true); _hub.Targets.Persist(old); }
                active--;
            }
            AddServer(rule, s, c, now);
            active++;
        }
    }

    void AddServer(AppRule rule, AppSession s, Ep c, long now)
    {
        string proto = rule.Method == "tcp" ? "TCP" : rule.Method == "udp" ? "UDP" : (c.Udp ? "UDP" : "TCP");
        int port = rule.UseServerPort ? (rule.Method == "tcp" ? c.TcpPort ?? 443 : c.UdpPort ?? 0) : 0;
        var existing = _hub.Targets.All().FirstOrDefault(t => t.Config.AppKey == rule.Key && t.Config.Host == c.Ip && t.Config.Method == rule.Method);
        TargetRunner runner;
        if (existing != null)
        {
            if (existing.Config.Paused) { existing.Pause(false); _hub.Targets.Persist(existing); }
            runner = existing;
        }
        else
        {
            var cfg = new TargetConfig
            {
                Host = c.Ip, Name = $"{rule.DisplayName} → {c.Ip}", Group = rule.DisplayName, Method = rule.Method, Port = port,
                IntervalMs = rule.IntervalMs, AppKey = rule.Key, Auto = true
            };
            runner = _hub.Targets.Add(cfg);
        }
        s.Servers.Add(new SessionServer { Ip = c.Ip, TargetId = runner.Id, Proto = proto, Port = c.UdpPort ?? c.TcpPort ?? 0, FirstSeen = now, LastSeen = now });
        _hub.Db.SaveSession(s);
        _hub.Bus.Publish(runner.Id, "info", "info", $"{rule.DisplayName}: tracing server {c.Ip} ({proto} {c.UdpPort ?? c.TcpPort}, {c.Rates.Pps:0} packets/s).", toast: false);
    }

    /// <summary>Ends the running session (if any) and computes its report. The rule will not start another until the app restarts.</summary>
    public AppSession? EndSessionNow(string key)
    {
        key = AppRule.KeyOf(key);
        lock (_gate)
        {
            var rule = _hub.Settings.AppRules.FirstOrDefault(r => r.Key == key);
            if (rule == null || !_states.TryGetValue(rule.Id, out var st) || st.Session == null) return null;
            var s = st.Session; EndSession(st, rule, "stopped by you"); st.Suppressed = Procs.Running.ContainsKey(key);
            return s;
        }
    }

    void EndSession(RuleState st, AppRule? rule, string reason)
    {
        var s = st.Session; if (s == null) return;
        st.Session = null; st.MissingSince = null;
        s.Ended = Now(); s.Status = "ended";
        try { s.Summary = Summarize(s); } catch (Exception e) { Console.Error.WriteLine("[apps] summary: " + e.Message); }
        _hub.Db.SaveSession(s);
        foreach (var srv in s.Servers)
        {
            var t = _hub.Targets.Get(srv.TargetId); if (t == null) continue;
            switch (rule?.OnExit ?? "pause")
            {
                case "delete": _ = _hub.Targets.RemoveAsync(t.Id); break;
                case "pause": t.Pause(true); _hub.Targets.Persist(t); break;
            }
        }
        var sm = s.Summary;
        bool bad = sm is { Code: not ("ok" or "burst" or "no_data" or "insufficient") };
        _hub.Bus.Publish(null, "info", bad ? "warn" : "info",
            $"{s.Name}: session ended ({reason}). {(sm == null || string.IsNullOrEmpty(sm.Headline) ? "Not enough data for a verdict." : sm.Headline)}", toast: true);
    }

    SessionSummary Summarize(AppSession s)
    {
        long from = s.Started, to = s.Ended ?? Now();
        var sum = new SessionSummary { DurationMs = to - from };
        var results = new List<(ServerSummary srv, DiagnosisResult d)>();
        foreach (var srv in s.Servers)
        {
            var t = _hub.Targets.Get(srv.TargetId); if (t == null) continue;
            long f = Math.Max(from, srv.FirstSeen - 5_000);
            var d = _hub.Diagnosis.ForTarget(t, f, to);
            var destHop = t.DestinationHop()?.Hop;
            double?[] p = destHop == null ? new double?[] { null } : _hub.Db.RttPercentiles(t.Id, destHop.Value, f, to, 0.95);
            var ss = new ServerSummary
            {
                Ip = srv.Ip, Host = _hub.Dns.TryGet(srv.Ip, false), TargetId = srv.TargetId, Samples = d.Samples, Avg = d.DestAvg, Max = d.DestMax, P95 = p[0],
                Jitter = d.DestJitter, LossPct = d.DestLoss ?? 0, Mos = d.Mos, Code = d.Code, Side = d.Side, Headline = d.Headline
            };
            results.Add((ss, d));
            sum.Servers.Add(ss);
        }
        var valid = results.Where(r => r.d.Code != "insufficient").ToList();
        if (valid.Count == 0) { sum.Headline = "The session was too short for a verdict."; return sum; }
        var worst = valid.OrderByDescending(r => DiagnosisService.Rank(r.d)).ThenByDescending(r => r.d.DestLoss ?? 0).First();
        sum.Code = worst.d.Code; sum.Side = worst.d.Side; sum.Headline = worst.d.Headline;
        return sum;
    }

    public void Dispose() { _timer?.Dispose(); _etw.Dispose(); }
}
