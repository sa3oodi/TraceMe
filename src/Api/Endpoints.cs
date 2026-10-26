using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http.Features;
using MimeKit;
using TraceMe.Alerts;
using TraceMe.Data;
using TraceMe.Engine;
using TraceMe.Models;
using TraceMe.Services;

namespace TraceMe.Api;

public sealed record LoginReq(string? Token);
public sealed record PauseReq(bool Paused);
public sealed record CommentReq(string? Text, long? T);
public sealed record ReorderReq(string[]? Ids);
public sealed record ScriptTestReq(string? Script);
public sealed record SmtpTestReq(string? To);
public sealed record AgentTestReq(string? Url, string? Token);
public sealed record WorkspaceDto(int Version, List<TargetConfig>? Targets, List<AlertRule>? Alerts, GlobalSettings? Settings);

public static class Endpoints
{
    const string Mask = "••••••";
    static readonly string Version = typeof(Endpoints).Assembly.GetName().Version?.ToString(3) ?? "1.0.0";

    static long Now() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

    static bool FixedEq(string? a, string? b)
    {
        if (a == null || b == null) return false;
        return CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(a)), SHA256.HashData(Encoding.UTF8.GetBytes(b)));
    }

    // ------------------------------------------------------------------ security middleware

    public static void UseSecurity(this WebApplication app, Hub hub, string? token, bool loopbackOnly)
    {
        var allowedHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "localhost", "127.0.0.1", "[::1]", "::1" };
        app.Use(async (ctx, next) =>
        {
            var path = ctx.Request.Path.Value ?? "";
            // DNS-rebinding defence: a loopback-only server must only answer requests addressed to loopback names.
            if (loopbackOnly && !allowedHosts.Contains(ctx.Request.Host.Host))
            {
                ctx.Response.StatusCode = 421; await ctx.Response.WriteAsync("Misdirected request"); return;
            }
            if (!path.StartsWith("/api/")) { await next(); return; }

            if (path.StartsWith("/api/agent/"))
            {
                // Agent routes authenticate with their own shared secret and are not browser-facing.
                var secret = hub.Settings.Current.AgentToken;
                if (secret == null) { ctx.Response.StatusCode = 404; return; }
                if (!FixedEq(ctx.Request.Headers["X-Agent-Token"].ToString(), secret)) { ctx.Response.StatusCode = 403; return; }
                await next(); return;
            }

            bool unsafeMethod = !HttpMethods.IsGet(ctx.Request.Method) && !HttpMethods.IsHead(ctx.Request.Method);
            if (unsafeMethod)
            {
                // Custom header forces a CORS preflight, which this server never grants; Origin must also match.
                if (ctx.Request.Headers["X-TraceMe"] != "1") { ctx.Response.StatusCode = 403; await ctx.Response.WriteAsync("Missing X-TraceMe header"); return; }
                if (ctx.Request.Headers.TryGetValue("Origin", out var origin) && origin.Count > 0 &&
                    (!Uri.TryCreate(origin[0], UriKind.Absolute, out var ou) || !string.Equals(ou.Authority, ctx.Request.Host.Value, StringComparison.OrdinalIgnoreCase)))
                { ctx.Response.StatusCode = 403; await ctx.Response.WriteAsync("Cross-origin request blocked"); return; }
            }

            if (token != null && path != "/api/login")
            {
                var supplied = ctx.Request.Cookies["tm_token"];
                if (supplied == null && ctx.Request.Headers.Authorization.ToString() is { Length: > 7 } auth && auth.StartsWith("Bearer ")) supplied = auth[7..];
                if (!FixedEq(supplied, token)) { ctx.Response.StatusCode = 401; await ctx.Response.WriteAsJsonAsync(new { error = "unauthorized" }); return; }
            }
            await next();
        });
    }

    // ------------------------------------------------------------------ routes

    public static void MapApi(this WebApplication app, Hub hub, string? token, IHostApplicationLifetime life)
    {
        var json = AgentProber.Json;

        // ---- session / system
        app.MapPost("/api/login", (LoginReq r, HttpContext ctx) =>
        {
            if (token == null) return Results.Ok(new { ok = true });
            if (!FixedEq(r.Token, token)) return Results.Json(new { error = "wrong token" }, statusCode: 401);
            ctx.Response.Cookies.Append("tm_token", token, new CookieOptions { HttpOnly = true, SameSite = SameSiteMode.Strict, MaxAge = TimeSpan.FromDays(30) });
            return Results.Ok(new { ok = true });
        });

        app.MapGet("/api/system", (HttpContext ctx) => new
        {
            version = Version, os = System.Runtime.InteropServices.RuntimeInformation.OSDescription, machine = Environment.MachineName,
            elevated = Elevation.IsElevated(), dataDir = AppPaths.DataDir, authRequired = token != null,
            agentEnabled = hub.Settings.Current.AgentToken != null, ipv6 = Socket.OSSupportsIPv6, rawIcmp = hub.Pool.Describe(),
            time = Now(), targets = hub.Targets.All().Count
        });

        app.MapPost("/api/system/elevate", async () =>
        {
            if (Elevation.IsElevated()) return Results.BadRequest(new { error = "Already running as administrator." });
            try { Elevation.RelaunchElevated(); }
            catch (System.ComponentModel.Win32Exception e) when (e.NativeErrorCode == 1223) { return Results.Conflict(new { error = "Elevation was cancelled." }); }
            catch (Exception e) { return Results.Problem(e.Message); }
            _ = Task.Run(async () => { await Task.Delay(800); life.StopApplication(); });
            await Task.CompletedTask;
            return Results.Ok(new { ok = true, message = "Restarting as administrator…" });
        });

        app.MapPost("/api/system/shutdown", () =>
        {
            _ = Task.Run(async () => { await Task.Delay(300); life.StopApplication(); });
            return Results.Ok(new { ok = true });
        });

        app.MapGet("/api/system/interfaces", () =>
            NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .SelectMany(n => n.GetIPProperties().UnicastAddresses
                    .Where(a => !a.Address.IsIPv6LinkLocal)
                    .Select(a => new { name = n.Name, address = a.Address.ToString(), family = a.Address.AddressFamily == AddressFamily.InterNetworkV6 ? "IPv6" : "IPv4" })));

        // ---- targets
        app.MapGet("/api/targets", () => hub.Targets.All().Select(r => r.Summary()));

        app.MapPost("/api/targets", (TargetConfig cfg) =>
        {
            if (hub.Targets.All().Count >= 100) return Results.BadRequest(new { error = "Target limit (100) reached." });
            cfg.Id = Guid.NewGuid().ToString("n")[..8]; cfg.Created = Now(); cfg.Paused = false;
            try { return Results.Ok(hub.Targets.Add(cfg).Summary()); }
            catch (ArgumentException e) { return Results.BadRequest(new { error = e.Message }); }
        });

        app.MapGet("/api/targets/{id}", (string id) =>
            hub.Targets.Get(id) is { } r ? Results.Ok(r.Snapshot()) : Results.NotFound());

        app.MapPut("/api/targets/{id}", (string id, TargetConfig cfg) =>
        {
            try { return hub.Targets.Update(id, cfg) is { } r ? Results.Ok(r.Summary()) : Results.NotFound(); }
            catch (ArgumentException e) { return Results.BadRequest(new { error = e.Message }); }
        });

        app.MapDelete("/api/targets/{id}", async (string id) =>
            await hub.Targets.RemoveAsync(id) ? Results.NoContent() : Results.NotFound());

        app.MapPost("/api/targets/reorder", (ReorderReq r) =>
        {
            int i = 0;
            foreach (var id in r.Ids ?? Array.Empty<string>())
                if (hub.Targets.Get(id) is { } t) { t.Config.Sort = i++; hub.Targets.Persist(t); }
            return Results.Ok();
        });

        app.MapPost("/api/targets/{id}/pause", (string id, PauseReq r) =>
        {
            if (hub.Targets.Get(id) is not { } t) return Results.NotFound();
            t.Pause(r.Paused); hub.Targets.Persist(t); return Results.Ok();
        });
        app.MapPost("/api/targets/{id}/trace-now", (string id) =>
        {
            if (hub.Targets.Get(id) is not { } t) return Results.NotFound();
            t.TraceNow(); return Results.Ok();
        });
        app.MapPost("/api/targets/{id}/reset", (string id) =>
        {
            if (hub.Targets.Get(id) is not { } t) return Results.NotFound();
            t.Reset(); return Results.Ok();
        });

        app.MapGet("/api/targets/{id}/stream", async (string id, HttpContext ctx) =>
        {
            if (hub.Targets.Get(id) is not { } t) { ctx.Response.StatusCode = 404; return; }
            ctx.Response.ContentType = "text/event-stream";
            ctx.Response.Headers.CacheControl = "no-cache";
            ctx.Response.Headers["X-Accel-Buffering"] = "no";
            var ct = ctx.RequestAborted;
            try
            {
                while (!ct.IsCancellationRequested && hub.Targets.Get(id) == t)
                {
                    await ctx.Response.WriteAsync($"data: {JsonSerializer.Serialize(t.Snapshot(), json)}\n\n", ct);
                    await ctx.Response.Body.FlushAsync(ct);
                    await Task.Delay(200, ct);
                    using var wait = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    wait.CancelAfter(15000);
                    try { await t.WaitForUpdateAsync(wait.Token); }
                    catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                    {
                        await ctx.Response.WriteAsync(": ping\n\n", ct); await ctx.Response.Body.FlushAsync(ct);
                    }
                }
            }
            catch (OperationCanceledException) { }
        });

        // ---- history
        (long from, long to) Range(HttpRequest q, long defaultSpanMs)
        {
            long to = long.TryParse(q.Query["to"], out var t) && t > 0 ? t : Now();
            long from = long.TryParse(q.Query["from"], out var f) && f > 0 ? f : to - defaultSpanMs;
            if (from >= to) from = to - 1000;
            return (from, to);
        }

        app.MapGet("/api/targets/{id}/timeline", async (string id, HttpRequest q) =>
        {
            if (hub.Targets.Get(id) is not { } t) return Results.NotFound();
            var (from, to) = Range(q, 5 * 60_000);
            int buckets = int.TryParse(q.Query["buckets"], out var b) ? b : 300;
            int hop = int.TryParse(q.Query["hop"], out var h) ? h : (t.DestinationHop()?.Hop ?? 1);
            await hub.Db.FlushAsync().WaitAsync(TimeSpan.FromSeconds(2)).ContinueWith(_ => { });
            object Pack(int hp) => hub.Db.Timeline(id, hp, from, to, buckets).Select(x => new object?[] { x.T, x.N, x.R, Rd(x.Min), Rd(x.Avg), Rd(x.Max), Rd(x.Jit) }).ToArray();
            if (hop == 0)
            {
                var all = t.VisibleHops().ToDictionary(x => x.Hop.ToString(), x => Pack(x.Hop));
                return Results.Ok(new { from, to, bucketMs = (to - from) / Math.Max(1, buckets), hops = all });
            }
            var markers = hub.Db.EventsBetween(id, from, to).Select(e => new { t = e.T, type = e.Type, severity = e.Severity, text = e.Message })
                .Concat(hub.Db.Comments(id, from, to).Select(c => new { t = c.T, type = "comment", severity = "info", text = c.Text })).OrderBy(m => m.t).ToArray();
            return Results.Ok(new { from, to, hop, bucketMs = (to - from) / Math.Max(1, buckets), buckets = Pack(hop), markers });
        });

        app.MapGet("/api/targets/{id}/stats", async (string id, HttpRequest q) =>
        {
            if (hub.Targets.Get(id) is not { } t) return Results.NotFound();
            var (from, to) = Range(q, 5 * 60_000);
            await hub.Db.FlushAsync().WaitAsync(TimeSpan.FromSeconds(2)).ContinueWith(_ => { });
            var hops = t.VisibleHops().Select(x => x.Hop).ToList();
            var stats = hub.Db.WindowStats(id, hops, from, to);
            var routes = hub.Db.Routes(id, from, to);
            var gs = hub.Settings.Current; var cfg = t.Config;
            var rows = hops.Select(hp =>
            {
                var s = stats.TryGetValue(hp, out var st) ? st : new HopStats(0, 0, null, null, null, null, null, null, 0);
                routes.TryGetValue(hp, out var rl);
                var seen = rl?.Select(e => e.Addr).Distinct().ToArray() ?? Array.Empty<string>();
                return t.HopView(hp, s, rl?.LastOrDefault().Addr, seen, null, null, gs, cfg);
            }).ToArray();
            return Results.Ok(new { from, to, hops = rows });
        });

        app.MapGet("/api/targets/{id}/routes", (string id, HttpRequest q) =>
        {
            if (hub.Targets.Get(id) is not { } t) return Results.NotFound();
            var (from, to) = Range(q, 24 * 3600_000L);
            var gs = hub.Settings.Current;
            return Results.Ok(hub.Db.RoutePaths(id, from, to).Select(p => new
            {
                t = p.T,
                hops = p.Hops.Select((a, i) => new { hop = i + 1, addr = a, name = a == null ? null : gs.Aliases.GetValueOrDefault(a) ?? hub.Dns.TryGet(a, false) }).ToArray()
            }));
        });

        app.MapGet("/api/targets/{id}/export.csv", async (string id, HttpContext ctx) =>
        {
            if (hub.Targets.Get(id) is not { } t) { ctx.Response.StatusCode = 404; return; }
            var (from, to) = Range(ctx.Request, 24 * 3600_000L);
            await hub.Db.FlushAsync().WaitAsync(TimeSpan.FromSeconds(2)).ContinueWith(_ => { });
            ctx.Response.ContentType = "text/csv; charset=utf-8";
            var safe = new string(t.Config.DisplayName.Select(c => char.IsLetterOrDigit(c) ? c : '_').ToArray());
            ctx.Response.Headers.ContentDisposition = $"attachment; filename=\"traceme-{safe}-{DateTime.UtcNow:yyyyMMdd-HHmmss}.csv\"";
            var sw = new StringWriter();
            hub.Db.ExportCsv(id, t.HopsList().Select(x => x.Hop), from, to, sw);
            await ctx.Response.WriteAsync(sw.ToString());
        });

        app.MapGet("/api/targets/{id}/comments", (string id, HttpRequest q) =>
        {
            var (from, to) = Range(q, 7 * 86400_000L);
            return Results.Ok(hub.Db.Comments(id, from, to));
        });
        app.MapPost("/api/targets/{id}/comments", (string id, CommentReq r) =>
        {
            if (hub.Targets.Get(id) == null) return Results.NotFound();
            var text = (r.Text ?? "").Trim();
            if (text.Length == 0 || text.Length > 2000) return Results.BadRequest(new { error = "Comment text is required (max 2000 characters)." });
            return Results.Ok(hub.Db.AddComment(id, r.T ?? Now(), text));
        });
        app.MapDelete("/api/targets/{id}/comments/{cid:long}", (string id, long cid) =>
            hub.Db.DeleteComment(id, cid) ? Results.NoContent() : Results.NotFound());

        // ---- events
        app.MapGet("/api/events", (string? tid, string? type, long? before, int? limit) =>
            hub.Db.Events(string.IsNullOrEmpty(tid) ? null : tid, string.IsNullOrEmpty(type) ? null : type, before, limit ?? 200));
        app.MapDelete("/api/events", (string? tid) => { hub.Db.ClearEvents(string.IsNullOrEmpty(tid) ? null : tid); return Results.NoContent(); });

        app.MapGet("/api/events/stream", async (HttpContext ctx) =>
        {
            ctx.Response.ContentType = "text/event-stream";
            ctx.Response.Headers.CacheControl = "no-cache";
            var (reader, sub) = hub.Bus.Subscribe();
            using var _ = sub;
            var ct = ctx.RequestAborted;
            try
            {
                await ctx.Response.WriteAsync(": connected\n\n", ct); await ctx.Response.Body.FlushAsync(ct);
                while (!ct.IsCancellationRequested)
                {
                    using var wait = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    wait.CancelAfter(15000);
                    try
                    {
                        var m = await reader.ReadAsync(wait.Token);
                        await ctx.Response.WriteAsync($"data: {JsonSerializer.Serialize(m, json)}\n\n", ct);
                    }
                    catch (OperationCanceledException) when (!ct.IsCancellationRequested) { await ctx.Response.WriteAsync(": ping\n\n", ct); }
                    await ctx.Response.Body.FlushAsync(ct);
                }
            }
            catch (OperationCanceledException) { }
            catch (System.Threading.Channels.ChannelClosedException) { }
        });

        // ---- alerts
        app.MapGet("/api/alerts", () => hub.Settings.Alerts);
        app.MapPost("/api/alerts", (AlertRule a) =>
        {
            a.Id = Guid.NewGuid().ToString("n")[..8];
            try { return Results.Ok(hub.Settings.UpsertAlert(Sanitize(hub, a))); } catch (ArgumentException e) { return Results.BadRequest(new { error = e.Message }); }
        });
        app.MapPut("/api/alerts/{id}", (string id, AlertRule a) =>
        {
            a.Id = id;
            try { return Results.Ok(hub.Settings.UpsertAlert(Sanitize(hub, a))); } catch (ArgumentException e) { return Results.BadRequest(new { error = e.Message }); }
        });
        app.MapDelete("/api/alerts/{id}", (string id) => hub.Settings.DeleteAlert(id) ? Results.NoContent() : Results.NotFound());
        app.MapPost("/api/alerts/{id}/test", async (string id) =>
        {
            var rule = hub.Settings.Alerts.FirstOrDefault(a => a.Id == id);
            if (rule == null) return Results.NotFound();
            try { await hub.Alerts.TestAsync(rule); return Results.Ok(new { ok = true }); }
            catch (Exception e) { return Results.BadRequest(new { error = e.Message }); }
        });

        // ---- settings
        app.MapGet("/api/settings", () => MaskSettings(hub.Settings.Current));
        app.MapPut("/api/settings", (GlobalSettings s) =>
        {
            var cur = hub.Settings.Current;
            if (s.Smtp != null && s.Smtp.Password == Mask) s.Smtp.Password = cur.Smtp.Password;
            if (s.AgentToken == Mask) s.AgentToken = cur.AgentToken;
            hub.Settings.Save(s);
            return Results.Ok(MaskSettings(hub.Settings.Current));
        });
        app.MapPost("/api/settings/test-column", (ScriptTestReq r) =>
        {
            var vars = new Dictionary<string, object?>
            {
                ["Average"] = 42.0, ["Minimum"] = 30.0, ["Maximum"] = 80.0, ["Current"] = 40.0, ["Jitter"] = 3.0, ["LostPacketCount"] = 1,
                ["TotalPacketCount"] = 100, ["PacketLossPercent"] = 1.0, ["HopNumber"] = 5, ["IPAddress"] = "203.0.113.5", ["HostName"] = "example"
            };
            var (v, err) = hub.Script.Eval("test:" + Guid.NewGuid(), r.Script ?? "", vars);
            return Results.Ok(new { value = v, error = err });
        });
        app.MapPost("/api/settings/smtp-test", async (SmtpTestReq r) =>
        {
            var smtp = hub.Settings.Current.Smtp;
            try
            {
                if (string.IsNullOrWhiteSpace(smtp.Host)) throw new InvalidOperationException("SMTP server is not configured.");
                var msg = new MimeMessage();
                msg.From.Add(MailboxAddress.Parse(string.IsNullOrWhiteSpace(smtp.From) ? (string.IsNullOrWhiteSpace(smtp.User) ? "traceme@localhost" : smtp.User) : smtp.From));
                msg.To.Add(MailboxAddress.Parse(r.To ?? throw new InvalidOperationException("Recipient required.")));
                msg.Subject = "[TraceMe] test email";
                msg.Body = new TextPart("plain") { Text = "Email delivery from TraceMe works." };
                await AlertActions.SendMail(smtp, msg);
                return Results.Ok(new { ok = true });
            }
            catch (Exception e) { return Results.BadRequest(new { error = e.Message }); }
        });

        // ---- workspace import / export (secrets are never exported)
        app.MapGet("/api/workspace/export", () =>
        {
            var targets = hub.Targets.All().Select(r => { var c = r.Config.Clone(); c.AgentToken = null; return c; }).ToList();
            var s = MaskSettings(hub.Settings.Current);
            s.Smtp.Password = ""; s.AgentToken = null;
            return Results.Json(new WorkspaceDto(1, targets, hub.Settings.Alerts.ToList(), s), json);
        });
        app.MapPost("/api/workspace/import", (WorkspaceDto w) =>
        {
            int nt = 0, na = 0;
            foreach (var t in w.Targets ?? new())
            {
                if (hub.Targets.All().Count >= 100) break;
                t.Id = Guid.NewGuid().ToString("n")[..8]; t.Created = Now();
                try { hub.Targets.Add(t); nt++; } catch (ArgumentException) { }
            }
            foreach (var a in w.Alerts ?? new())
            {
                a.Id = Guid.NewGuid().ToString("n")[..8];
                try { hub.Settings.UpsertAlert(Sanitize(hub, a)); na++; } catch (ArgumentException) { }
            }
            bool settings = false;
            if (w.Settings != null)
            {
                var cur = hub.Settings.Current;
                w.Settings.Smtp ??= new(); w.Settings.Smtp.Password = cur.Smtp.Password; w.Settings.AgentToken = cur.AgentToken;
                w.Settings.AllowExec = cur.AllowExec; // never switched on by an imported file
                hub.Settings.Save(w.Settings); settings = true;
            }
            return Results.Ok(new { targets = nt, alerts = na, settings });
        });

        // ---- whois / ASN (explicit user action: sends the address to Team Cymru)
        app.MapGet("/api/asn", async (string ip) =>
        {
            if (!System.Net.IPAddress.TryParse(ip, out _)) return Results.BadRequest(new { error = "invalid address" });
            for (int i = 0; i < 30; i++)
            {
                var info = hub.Asn.TryGet(ip, true);
                if (info != null) return Results.Ok(info);
                await Task.Delay(200);
            }
            return Results.Json(new { error = "lookup timed out" }, statusCode: 504);
        });

        // ---- remote agent
        app.MapPost("/api/agent-test", async (AgentTestReq r) =>
        {
            if (!Uri.TryCreate(r.Url?.TrimEnd('/'), UriKind.Absolute, out var u) || (u.Scheme != "http" && u.Scheme != "https"))
                return Results.BadRequest(new { error = "Agent URL must be http(s)." });
            try
            {
                using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(8) };
                using var req = new HttpRequestMessage(HttpMethod.Get, new Uri(u, "/api/agent/ping"));
                if (!string.IsNullOrEmpty(r.Token)) req.Headers.Add("X-Agent-Token", r.Token);
                using var resp = await http.SendAsync(req);
                if (!resp.IsSuccessStatusCode) return Results.BadRequest(new { error = resp.StatusCode == System.Net.HttpStatusCode.NotFound ? "agent mode is not enabled on that instance" : resp.StatusCode == System.Net.HttpStatusCode.Forbidden ? "wrong agent token" : $"HTTP {(int)resp.StatusCode}" });
                return Results.Content(await resp.Content.ReadAsStringAsync(), "application/json");
            }
            catch (Exception e) { return Results.BadRequest(new { error = e.Message }); }
        });
        app.MapGet("/api/agent/ping", () => new { ok = true, version = Version, elevated = Elevation.IsElevated(), machine = Environment.MachineName });
        app.MapPost("/api/agent/round", async (AgentRequest r, HttpContext ctx) =>
        {
            if (string.IsNullOrWhiteSpace(r.Host) || r.Host.Length > 253) return Results.BadRequest(new { error = "host required" });
            try { return Results.Json(await hub.Agent.RoundAsync(r, ctx.RequestAborted), json); }
            catch (Exception e) when (e is SocketException or ArgumentException) { return Results.BadRequest(new { error = e.Message }); }
        });
    }

    static AlertRule Sanitize(Hub hub, AlertRule a)
    {
        // Programs can only be configured when the user has explicitly enabled it, and imported rules cannot bypass that.
        if (!hub.Settings.Current.AllowExec) a.Actions.RemoveAll(x => x.Type == "exec");
        return a;
    }

    static double? Rd(double? v) => v is double d ? Math.Round(d, 2) : null;

    static GlobalSettings MaskSettings(GlobalSettings s)
    {
        var c = JsonSerializer.Deserialize<GlobalSettings>(JsonSerializer.Serialize(s))!;
        if (!string.IsNullOrEmpty(c.Smtp.Password)) c.Smtp.Password = Mask;
        if (!string.IsNullOrEmpty(c.AgentToken)) c.AgentToken = Mask;
        return c;
    }
}
