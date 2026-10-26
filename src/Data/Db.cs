using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.Data.Sqlite;
using TraceMe.Engine;
using TraceMe.Models;

namespace TraceMe.Data;

public readonly record struct Bucket(long T, int N, int R, double? Min, double? Avg, double? Max, double? Jit);
public readonly record struct RouteEntry(long T, string Addr);
public sealed record RoutePath(long T, string?[] Hops);

/// <summary>
/// SQLite persistence. Samples are written by a single background writer in batched transactions; reads open
/// short-lived pooled connections (WAL mode allows them to run alongside the writer).
/// </summary>
public sealed class Db : IDisposable
{
    readonly string _cs;
    readonly Channel<Row> _q = Channel.CreateUnbounded<Row>(new UnboundedChannelOptions { SingleReader = true });
    readonly Task _writer;

    struct Row { public byte Kind; public string Tid; public long T; public int Hop; public double Rtt; public string? Addr; public TaskCompletionSource? Flush; }

    public string Path { get; }

    public Db(string path)
    {
        Path = path;
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(path))!);
        _cs = new SqliteConnectionStringBuilder { DataSource = path, Mode = SqliteOpenMode.ReadWriteCreate, DefaultTimeout = 30 }.ToString();
        Init();
        _writer = Task.Run(WriterLoop);
    }

    SqliteConnection Open()
    {
        var c = new SqliteConnection(_cs);
        c.Open();
        return c;
    }

    void Init()
    {
        using var c = Open();
        Exec(c, "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;");
        Exec(c, """
            CREATE TABLE IF NOT EXISTS targets(id TEXT PRIMARY KEY, json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS samples(tid TEXT NOT NULL, hop INTEGER NOT NULL, t INTEGER NOT NULL, rtt REAL, PRIMARY KEY(tid,hop,t)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS routes(tid TEXT NOT NULL, hop INTEGER NOT NULL, t INTEGER NOT NULL, addr TEXT NOT NULL, PRIMARY KEY(tid,hop,t)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, t INTEGER NOT NULL, tid TEXT, type TEXT NOT NULL, severity TEXT NOT NULL, message TEXT NOT NULL, data TEXT);
            CREATE INDEX IF NOT EXISTS events_t ON events(t);
            CREATE INDEX IF NOT EXISTS events_tid ON events(tid,t);
            CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY AUTOINCREMENT, tid TEXT NOT NULL, t INTEGER NOT NULL, text TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS comments_tid ON comments(tid,t);
            CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS alerts(id TEXT PRIMARY KEY, json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS asn(ip TEXT PRIMARY KEY, json TEXT NOT NULL, t INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS app_rules(id TEXT PRIMARY KEY, json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS app_sessions(id TEXT PRIMARY KEY, app TEXT NOT NULL, started INTEGER NOT NULL, ended INTEGER, json TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS app_sessions_app ON app_sessions(app, started);
            """);
    }

    static void Exec(SqliteConnection c, string sql, Action<SqliteCommand>? bind = null)
    {
        using var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        bind?.Invoke(cmd);
        cmd.ExecuteNonQuery();
    }

    static object Db_(object? v) => v ?? DBNull.Value;

    // ---------------------------------------------------------------- sample writer

    public void AddSample(string tid, long t, int hop, double? rtt) =>
        _q.Writer.TryWrite(new Row { Kind = 0, Tid = tid, T = t, Hop = hop, Rtt = rtt ?? double.NaN });

    public void AddRoute(string tid, long t, int hop, string addr) =>
        _q.Writer.TryWrite(new Row { Kind = 1, Tid = tid, T = t, Hop = hop, Addr = addr });

    /// <summary>Completes once everything queued before the call is committed.</summary>
    public Task FlushAsync()
    {
        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _q.Writer.TryWrite(new Row { Kind = 2, Tid = "", Flush = tcs });
        return tcs.Task;
    }

    async Task WriterLoop()
    {
        var reader = _q.Reader;
        var batch = new List<Row>(2048);
        while (await reader.WaitToReadAsync())
        {
            batch.Clear();
            while (batch.Count < 5000 && reader.TryRead(out var r)) batch.Add(r);
            try { WriteBatch(batch); }
            catch (Exception e) { Console.Error.WriteLine("[db] batch write failed: " + e.Message); }
            foreach (var r in batch) r.Flush?.TrySetResult();
            await Task.Delay(250);
        }
    }

    void WriteBatch(List<Row> rows)
    {
        using var c = Open();
        using var tx = c.BeginTransaction();
        using var s = c.CreateCommand();
        s.Transaction = tx;
        s.CommandText = "INSERT OR REPLACE INTO samples(tid,hop,t,rtt) VALUES($tid,$hop,$t,$rtt)";
        var sTid = s.Parameters.Add("$tid", SqliteType.Text); var sHop = s.Parameters.Add("$hop", SqliteType.Integer);
        var sT = s.Parameters.Add("$t", SqliteType.Integer); var sRtt = s.Parameters.Add("$rtt", SqliteType.Real);
        using var r = c.CreateCommand();
        r.Transaction = tx;
        r.CommandText = "INSERT OR REPLACE INTO routes(tid,hop,t,addr) VALUES($tid,$hop,$t,$addr)";
        var rTid = r.Parameters.Add("$tid", SqliteType.Text); var rHop = r.Parameters.Add("$hop", SqliteType.Integer);
        var rT = r.Parameters.Add("$t", SqliteType.Integer); var rAddr = r.Parameters.Add("$addr", SqliteType.Text);
        foreach (var row in rows)
        {
            if (row.Kind == 0)
            {
                sTid.Value = row.Tid; sHop.Value = row.Hop; sT.Value = row.T;
                sRtt.Value = double.IsNaN(row.Rtt) ? DBNull.Value : row.Rtt;
                s.ExecuteNonQuery();
            }
            else if (row.Kind == 1)
            {
                rTid.Value = row.Tid; rHop.Value = row.Hop; rT.Value = row.T; rAddr.Value = row.Addr!;
                r.ExecuteNonQuery();
            }
        }
        tx.Commit();
    }

    // ---------------------------------------------------------------- targets / settings / alerts

    public List<TargetConfig> LoadTargets()
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT json FROM targets";
        var list = new List<TargetConfig>();
        using var rd = cmd.ExecuteReader();
        while (rd.Read())
        {
            try { var t = JsonSerializer.Deserialize<TargetConfig>(rd.GetString(0)); if (t != null) list.Add(t); }
            catch (JsonException) { }
        }
        return list.OrderBy(t => t.Sort).ThenBy(t => t.Created).ToList();
    }

    public void SaveTarget(TargetConfig t)
    {
        using var c = Open();
        Exec(c, "INSERT OR REPLACE INTO targets(id,json) VALUES($id,$j)", p =>
        {
            p.Parameters.AddWithValue("$id", t.Id); p.Parameters.AddWithValue("$j", JsonSerializer.Serialize(t));
        });
    }

    public void DeleteTarget(string id)
    {
        using var c = Open();
        foreach (var table in new[] { "targets:id", "samples:tid", "routes:tid", "events:tid", "comments:tid" })
        {
            var (tb, col) = (table.Split(':')[0], table.Split(':')[1]);
            Exec(c, $"DELETE FROM {tb} WHERE {col}=$id", p => p.Parameters.AddWithValue("$id", id));
        }
    }

    public string? GetSetting(string key)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT value FROM settings WHERE key=$k";
        cmd.Parameters.AddWithValue("$k", key);
        return cmd.ExecuteScalar() as string;
    }

    public void SetSetting(string key, string value)
    {
        using var c = Open();
        Exec(c, "INSERT OR REPLACE INTO settings(key,value) VALUES($k,$v)", p =>
        {
            p.Parameters.AddWithValue("$k", key); p.Parameters.AddWithValue("$v", value);
        });
    }

    public List<AlertRule> LoadAlerts()
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT json FROM alerts";
        var list = new List<AlertRule>();
        using var rd = cmd.ExecuteReader();
        while (rd.Read())
            try { var a = JsonSerializer.Deserialize<AlertRule>(rd.GetString(0)); if (a != null) list.Add(a); } catch (JsonException) { }
        return list;
    }

    public void SaveAlert(AlertRule a)
    {
        using var c = Open();
        Exec(c, "INSERT OR REPLACE INTO alerts(id,json) VALUES($id,$j)", p =>
        {
            p.Parameters.AddWithValue("$id", a.Id); p.Parameters.AddWithValue("$j", JsonSerializer.Serialize(a));
        });
    }

    public void DeleteAlert(string id)
    {
        using var c = Open();
        Exec(c, "DELETE FROM alerts WHERE id=$id", p => p.Parameters.AddWithValue("$id", id));
    }

    // ---------------------------------------------------------------- history queries

    /// <summary>Statistics per hop over [from,to] computed from stored samples with the same accumulator the live view uses.</summary>
    public Dictionary<int, HopStats> WindowStats(string tid, IEnumerable<int> hops, long from, long to)
    {
        var result = new Dictionary<int, HopStats>();
        using var c = Open();
        foreach (var hop in hops)
        {
            var acc = new Acc();
            using var cmd = c.CreateCommand();
            cmd.CommandText = "SELECT rtt FROM samples WHERE tid=$tid AND hop=$h AND t>=$f AND t<=$to ORDER BY t";
            cmd.Parameters.AddWithValue("$tid", tid); cmd.Parameters.AddWithValue("$h", hop);
            cmd.Parameters.AddWithValue("$f", from); cmd.Parameters.AddWithValue("$to", to);
            using var rd = cmd.ExecuteReader();
            while (rd.Read()) acc.Add(rd.IsDBNull(0) ? null : rd.GetDouble(0));
            if (acc.Sent > 0) result[hop] = acc.ToStats();
        }
        return result;
    }

    public Bucket[] Timeline(string tid, int hop, long from, long to, int buckets)
    {
        if (to <= from) return Array.Empty<Bucket>();
        buckets = Math.Clamp(buckets, 1, 3000);
        double width = (to - from) / (double)buckets;
        var n = new int[buckets]; var rc = new int[buckets];
        var sum = new double[buckets]; var min = new double[buckets]; var max = new double[buckets];
        var jsum = new double[buckets]; var jn = new int[buckets];
        Array.Fill(min, double.MaxValue);
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT t,rtt FROM samples WHERE tid=$tid AND hop=$h AND t>=$f AND t<$to ORDER BY t";
        cmd.Parameters.AddWithValue("$tid", tid); cmd.Parameters.AddWithValue("$h", hop);
        cmd.Parameters.AddWithValue("$f", from); cmd.Parameters.AddWithValue("$to", to);
        using var rd = cmd.ExecuteReader();
        int lastB = -1; double? prev = null;
        while (rd.Read())
        {
            int b = Math.Min(buckets - 1, (int)((rd.GetInt64(0) - from) / width));
            n[b]++;
            if (b != lastB) { lastB = b; prev = null; }
            if (rd.IsDBNull(1)) continue;
            double v = rd.GetDouble(1);
            rc[b]++; sum[b] += v;
            if (v < min[b]) min[b] = v;
            if (v > max[b]) max[b] = v;
            if (prev is double p) { jsum[b] += Math.Abs(v - p); jn[b]++; }
            prev = v;
        }
        var list = new List<Bucket>();
        for (int i = 0; i < buckets; i++)
        {
            if (n[i] == 0) continue;
            list.Add(new Bucket((long)(from + i * width), n[i], rc[i],
                rc[i] == 0 ? null : min[i], rc[i] == 0 ? null : sum[i] / rc[i], rc[i] == 0 ? null : max[i], jn[i] == 0 ? null : jsum[i] / jn[i]));
        }
        return list.ToArray();
    }

    /// <summary>Responder history per hop for the window, including the entry in force at <paramref name="from"/>.</summary>
    public Dictionary<int, List<RouteEntry>> Routes(string tid, long from, long to)
    {
        var map = new Dictionary<int, List<RouteEntry>>();
        using var c = Open();
        using (var cmd = c.CreateCommand())
        {
            cmd.CommandText = """
                SELECT r.hop, r.t, r.addr FROM routes r
                WHERE r.tid=$tid AND r.t=(SELECT MAX(t) FROM routes WHERE tid=r.tid AND hop=r.hop AND t<=$f)
                """;
            cmd.Parameters.AddWithValue("$tid", tid); cmd.Parameters.AddWithValue("$f", from);
            using var rd = cmd.ExecuteReader();
            while (rd.Read()) Add(map, rd.GetInt32(0), new RouteEntry(rd.GetInt64(1), rd.GetString(2)));
        }
        using (var cmd = c.CreateCommand())
        {
            cmd.CommandText = "SELECT hop,t,addr FROM routes WHERE tid=$tid AND t>$f AND t<=$to ORDER BY t";
            cmd.Parameters.AddWithValue("$tid", tid); cmd.Parameters.AddWithValue("$f", from); cmd.Parameters.AddWithValue("$to", to);
            using var rd = cmd.ExecuteReader();
            while (rd.Read()) Add(map, rd.GetInt32(0), new RouteEntry(rd.GetInt64(1), rd.GetString(2)));
        }
        return map;
    }

    static void Add(Dictionary<int, List<RouteEntry>> m, int hop, RouteEntry e)
    {
        if (!m.TryGetValue(hop, out var l)) m[hop] = l = new();
        l.Add(e);
    }

    /// <summary>Distinct end-to-end paths over time, newest last.</summary>
    public List<RoutePath> RoutePaths(string tid, long from, long to, int limit = 200)
    {
        var routes = Routes(tid, from, to);
        if (routes.Count == 0) return new();
        int maxHop = routes.Keys.Max();
        var events = routes.SelectMany(kv => kv.Value.Select(e => (hop: kv.Key, e.T, e.Addr))).OrderBy(x => x.T).ToList();
        var cur = new string?[maxHop];
        var paths = new List<RoutePath>();
        int i = 0;
        // Entries at or before the window start describe the path already in force: they form one starting path, not several.
        int baseline = events.FindLastIndex(x => x.T <= from);
        if (baseline >= 0)
        {
            for (; i <= baseline; i++) cur[events[i].hop - 1] = events[i].Addr;
            paths.Add(new RoutePath(events[baseline].T, (string?[])cur.Clone()));
        }
        while (i < events.Count)
        {
            long t = events[i].T;
            while (i < events.Count && events[i].T == t) { cur[events[i].hop - 1] = events[i].Addr; i++; }
            paths.Add(new RoutePath(t, (string?[])cur.Clone()));
        }
        return paths.Count > limit ? paths.GetRange(paths.Count - limit, limit) : paths;
    }

    public long CountSamples(string tid, long from, long to)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM samples WHERE tid=$tid AND t>=$f AND t<=$to";
        cmd.Parameters.AddWithValue("$tid", tid); cmd.Parameters.AddWithValue("$f", from); cmd.Parameters.AddWithValue("$to", to);
        return Convert.ToInt64(cmd.ExecuteScalar());
    }

    public void ExportCsv(string tid, IEnumerable<int> hops, long from, long to, TextWriter w)
    {
        w.Write("time,epoch_ms,hop,address,rtt_ms,lost\n");
        var routes = Routes(tid, from, to);
        using var c = Open();
        foreach (var hop in hops)
        {
            routes.TryGetValue(hop, out var rl);
            int ri = -1; string addr = "";
            using var cmd = c.CreateCommand();
            cmd.CommandText = "SELECT t,rtt FROM samples WHERE tid=$tid AND hop=$h AND t>=$f AND t<=$to ORDER BY t";
            cmd.Parameters.AddWithValue("$tid", tid); cmd.Parameters.AddWithValue("$h", hop);
            cmd.Parameters.AddWithValue("$f", from); cmd.Parameters.AddWithValue("$to", to);
            using var rd = cmd.ExecuteReader();
            while (rd.Read())
            {
                long t = rd.GetInt64(0);
                while (rl != null && ri + 1 < rl.Count && rl[ri + 1].T <= t) addr = rl[++ri].Addr;
                var rtt = rd.IsDBNull(1) ? null : (double?)rd.GetDouble(1);
                w.Write(DateTimeOffset.FromUnixTimeMilliseconds(t).ToString("o")); w.Write(',');
                w.Write(t); w.Write(','); w.Write(hop); w.Write(','); w.Write(addr); w.Write(',');
                w.Write(rtt?.ToString("F3", System.Globalization.CultureInfo.InvariantCulture) ?? ""); w.Write(',');
                w.Write(rtt == null ? "1" : "0"); w.Write('\n');
            }
        }
    }

    // ---------------------------------------------------------------- events & comments

    public void InsertEvent(EventRecord e)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "INSERT INTO events(t,tid,type,severity,message,data) VALUES($t,$tid,$ty,$sev,$m,$d); SELECT last_insert_rowid();";
        cmd.Parameters.AddWithValue("$t", e.T); cmd.Parameters.AddWithValue("$tid", Db_(e.Tid));
        cmd.Parameters.AddWithValue("$ty", e.Type); cmd.Parameters.AddWithValue("$sev", e.Severity);
        cmd.Parameters.AddWithValue("$m", e.Message); cmd.Parameters.AddWithValue("$d", Db_(e.Data));
        e.Id = Convert.ToInt64(cmd.ExecuteScalar());
    }

    public List<EventRecord> Events(string? tid, string? type, long? before, int limit)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            SELECT id,t,tid,type,severity,message,data FROM events
            WHERE ($tid IS NULL OR tid=$tid) AND ($ty IS NULL OR type=$ty) AND ($b IS NULL OR id<$b)
            ORDER BY id DESC LIMIT $n
            """;
        cmd.Parameters.AddWithValue("$tid", Db_(tid)); cmd.Parameters.AddWithValue("$ty", Db_(type));
        cmd.Parameters.AddWithValue("$b", Db_(before)); cmd.Parameters.AddWithValue("$n", Math.Clamp(limit, 1, 1000));
        var list = new List<EventRecord>();
        using var rd = cmd.ExecuteReader();
        while (rd.Read())
            list.Add(new EventRecord
            {
                Id = rd.GetInt64(0), T = rd.GetInt64(1), Tid = rd.IsDBNull(2) ? null : rd.GetString(2), Type = rd.GetString(3),
                Severity = rd.GetString(4), Message = rd.GetString(5), Data = rd.IsDBNull(6) ? null : rd.GetString(6)
            });
        return list;
    }

    public List<EventRecord> EventsBetween(string tid, long from, long to, int limit = 500)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT id,t,tid,type,severity,message,data FROM events WHERE tid=$tid AND t>=$f AND t<=$to ORDER BY t LIMIT $n";
        cmd.Parameters.AddWithValue("$tid", tid); cmd.Parameters.AddWithValue("$f", from);
        cmd.Parameters.AddWithValue("$to", to); cmd.Parameters.AddWithValue("$n", limit);
        var list = new List<EventRecord>();
        using var rd = cmd.ExecuteReader();
        while (rd.Read())
            list.Add(new EventRecord
            {
                Id = rd.GetInt64(0), T = rd.GetInt64(1), Tid = rd.GetString(2), Type = rd.GetString(3),
                Severity = rd.GetString(4), Message = rd.GetString(5), Data = rd.IsDBNull(6) ? null : rd.GetString(6)
            });
        return list;
    }

    public void ClearEvents(string? tid)
    {
        using var c = Open();
        Exec(c, "DELETE FROM events WHERE ($tid IS NULL OR tid=$tid)", p => p.Parameters.AddWithValue("$tid", Db_(tid)));
    }

    public Comment AddComment(string tid, long t, string text)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "INSERT INTO comments(tid,t,text) VALUES($tid,$t,$x); SELECT last_insert_rowid();";
        cmd.Parameters.AddWithValue("$tid", tid); cmd.Parameters.AddWithValue("$t", t); cmd.Parameters.AddWithValue("$x", text);
        return new Comment { Id = Convert.ToInt64(cmd.ExecuteScalar()), Tid = tid, T = t, Text = text };
    }

    public List<Comment> Comments(string tid, long from, long to)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT id,t,text FROM comments WHERE tid=$tid AND t>=$f AND t<=$to ORDER BY t";
        cmd.Parameters.AddWithValue("$tid", tid); cmd.Parameters.AddWithValue("$f", from); cmd.Parameters.AddWithValue("$to", to);
        var list = new List<Comment>();
        using var rd = cmd.ExecuteReader();
        while (rd.Read()) list.Add(new Comment { Id = rd.GetInt64(0), Tid = tid, T = rd.GetInt64(1), Text = rd.GetString(2) });
        return list;
    }

    public bool DeleteComment(string tid, long id)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "DELETE FROM comments WHERE id=$id AND tid=$tid";
        cmd.Parameters.AddWithValue("$id", id); cmd.Parameters.AddWithValue("$tid", tid);
        return cmd.ExecuteNonQuery() > 0;
    }

    // ---------------------------------------------------------------- app rules & sessions

    public List<AppRule> LoadAppRules()
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT json FROM app_rules";
        var list = new List<AppRule>();
        using var rd = cmd.ExecuteReader();
        while (rd.Read()) try { var r = JsonSerializer.Deserialize<AppRule>(rd.GetString(0)); if (r != null) list.Add(r); } catch (JsonException) { }
        return list;
    }

    public void SaveAppRule(AppRule r)
    {
        using var c = Open();
        Exec(c, "INSERT OR REPLACE INTO app_rules(id,json) VALUES($id,$j)", p => { p.Parameters.AddWithValue("$id", r.Id); p.Parameters.AddWithValue("$j", JsonSerializer.Serialize(r)); });
    }

    public void DeleteAppRule(string id)
    {
        using var c = Open();
        Exec(c, "DELETE FROM app_rules WHERE id=$id", p => p.Parameters.AddWithValue("$id", id));
    }

    public void SaveSession(AppSession s)
    {
        using var c = Open();
        Exec(c, "INSERT OR REPLACE INTO app_sessions(id,app,started,ended,json) VALUES($id,$a,$s,$e,$j)", p =>
        {
            p.Parameters.AddWithValue("$id", s.Id); p.Parameters.AddWithValue("$a", s.AppKey); p.Parameters.AddWithValue("$s", s.Started);
            p.Parameters.AddWithValue("$e", Db_(s.Ended)); p.Parameters.AddWithValue("$j", JsonSerializer.Serialize(s));
        });
    }

    public List<AppSession> LoadSessions(string? app, int limit = 50)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT json FROM app_sessions WHERE ($a IS NULL OR app=$a) ORDER BY started DESC LIMIT $n";
        cmd.Parameters.AddWithValue("$a", Db_(app)); cmd.Parameters.AddWithValue("$n", Math.Clamp(limit, 1, 500));
        var list = new List<AppSession>();
        using var rd = cmd.ExecuteReader();
        while (rd.Read()) try { var s = JsonSerializer.Deserialize<AppSession>(rd.GetString(0)); if (s != null) list.Add(s); } catch (JsonException) { }
        return list;
    }

    public AppSession? GetSession(string id)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT json FROM app_sessions WHERE id=$id";
        cmd.Parameters.AddWithValue("$id", id);
        return cmd.ExecuteScalar() is string j ? JsonSerializer.Deserialize<AppSession>(j) : null;
    }

    public bool DeleteSession(string id)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "DELETE FROM app_sessions WHERE id=$id";
        cmd.Parameters.AddWithValue("$id", id);
        return cmd.ExecuteNonQuery() > 0;
    }

    /// <summary>Latency percentiles (0..1) over [from,to] for one hop; null entries when no sample was received.</summary>
    public double?[] RttPercentiles(string tid, int hop, long from, long to, params double[] ps)
    {
        var vals = new List<double>();
        using (var c = Open())
        {
            using var cmd = c.CreateCommand();
            cmd.CommandText = "SELECT rtt FROM samples WHERE tid=$tid AND hop=$h AND t>=$f AND t<=$to AND rtt IS NOT NULL ORDER BY rtt";
            cmd.Parameters.AddWithValue("$tid", tid); cmd.Parameters.AddWithValue("$h", hop);
            cmd.Parameters.AddWithValue("$f", from); cmd.Parameters.AddWithValue("$to", to);
            using var rd = cmd.ExecuteReader();
            while (rd.Read()) vals.Add(rd.GetDouble(0));
        }
        return ps.Select(p => vals.Count == 0 ? (double?)null : vals[Math.Clamp((int)Math.Ceiling(p * vals.Count) - 1, 0, vals.Count - 1)]).ToArray();
    }

    // ---------------------------------------------------------------- ASN cache & maintenance

    public (string json, long t)? GetAsn(string ip)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT json,t FROM asn WHERE ip=$ip";
        cmd.Parameters.AddWithValue("$ip", ip);
        using var rd = cmd.ExecuteReader();
        return rd.Read() ? (rd.GetString(0), rd.GetInt64(1)) : null;
    }

    public void SetAsn(string ip, string json)
    {
        using var c = Open();
        Exec(c, "INSERT OR REPLACE INTO asn(ip,json,t) VALUES($ip,$j,$t)", p =>
        {
            p.Parameters.AddWithValue("$ip", ip); p.Parameters.AddWithValue("$j", json);
            p.Parameters.AddWithValue("$t", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        });
    }

    public int Purge(int retentionDays)
    {
        long cut = DateTimeOffset.UtcNow.AddDays(-retentionDays).ToUnixTimeMilliseconds();
        using var c = Open();
        int n = 0;
        using (var cmd = c.CreateCommand()) { cmd.CommandText = "DELETE FROM samples WHERE t<$c"; cmd.Parameters.AddWithValue("$c", cut); n = cmd.ExecuteNonQuery(); }
        Exec(c, "DELETE FROM events WHERE t<$c", p => p.Parameters.AddWithValue("$c", DateTimeOffset.UtcNow.AddDays(-retentionDays * 4.0).ToUnixTimeMilliseconds()));
        return n;
    }

    public void Dispose()
    {
        _q.Writer.TryComplete();
        try { _writer.Wait(TimeSpan.FromSeconds(5)); } catch { }
        SqliteConnection.ClearAllPools();
    }
}
