using TraceMe.Apps;
using TraceMe.Engine;
using TraceMe.Models;

namespace TraceMe.Api;

public sealed record TraceEndpointReq(string? Ip, string? Method, int? Port, int? IntervalMs);
public sealed record WatchReq(bool? Enabled);

public static class AppEndpoints
{
    public static void MapAppApi(this WebApplication app, Hub hub)
    {
        long Now() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        app.MapGet("/api/apps", (bool? all) => hub.Apps.ListApps(all == true));

        app.MapGet("/api/apps/games", () => GameCatalog.All.Select(g => new { exe = g.exe, name = g.name }));

        // ---- watch rules
        app.MapGet("/api/apps/rules", () => hub.Settings.AppRules);
        app.MapPost("/api/apps/rules", (AppRule r) =>
        {
            r.Id = Guid.NewGuid().ToString("n")[..8];
            try { return Results.Ok(hub.Settings.UpsertAppRule(r)); } catch (ArgumentException e) { return Results.BadRequest(new { error = e.Message }); }
        });
        app.MapPut("/api/apps/rules/{id}", (string id, AppRule r) =>
        {
            r.Id = id;
            try { return Results.Ok(hub.Settings.UpsertAppRule(r)); } catch (ArgumentException e) { return Results.BadRequest(new { error = e.Message }); }
        });
        app.MapDelete("/api/apps/rules/{id}", (string id) => hub.Settings.DeleteAppRule(id) ? Results.NoContent() : Results.NotFound());

        // ---- sessions
        app.MapGet("/api/apps/sessions", (string? app, int? limit) =>
            hub.Db.LoadSessions(string.IsNullOrEmpty(app) ? null : AppRule.KeyOf(app), limit ?? 50).Select(s => new { s.Id, s.AppKey, s.Name, s.Started, s.Ended, s.Status, s.Summary, servers = s.Servers.Count }));
        app.MapGet("/api/apps/sessions/{id}", (string id) => hub.Db.GetSession(id) is { } s ? Results.Ok(s) : Results.NotFound());
        app.MapDelete("/api/apps/sessions/{id}", (string id) => hub.Db.DeleteSession(id) ? Results.NoContent() : Results.NotFound());
        app.MapGet("/api/apps/sessions/{id}/report", async (string id, HttpContext ctx) =>
        {
            var s = hub.Db.GetSession(id);
            if (s == null) { ctx.Response.StatusCode = 404; return; }
            await hub.Db.FlushAsync().WaitAsync(TimeSpan.FromSeconds(2)).ContinueWith(_ => { });
            ctx.Response.ContentType = "text/html; charset=utf-8";
            ctx.Response.Headers.ContentSecurityPolicy = "default-src 'none'; style-src 'unsafe-inline'; img-src data:";
            await ctx.Response.WriteAsync(ReportBuilder.Build(s, hub));
        });

        // ---- one application
        app.MapGet("/api/apps/{key}", (string key) => hub.Apps.Detail(key) is { } d ? Results.Ok(d) : Results.NotFound());

        app.MapGet("/api/apps/{key}/icon", (string key, HttpContext ctx) =>
        {
            var png = hub.Apps.Icons.Get(AppRule.KeyOf(key));
            if (png == null) { ctx.Response.Headers.CacheControl = "no-store"; return Results.NotFound(); }
            ctx.Response.Headers.CacheControl = "private, max-age=3600";
            return Results.File(png, "image/png");
        });

        app.MapPost("/api/apps/{key}/trace", (string key, TraceEndpointReq r) =>
        {
            var method = (r.Method ?? "icmp").ToLowerInvariant();
            if (!TargetConfig.Methods.Contains(method)) return Results.BadRequest(new { error = "Unknown trace method." });
            if (hub.Targets.All().Count >= 100) return Results.BadRequest(new { error = "Target limit (100) reached." });
            try { return Results.Ok(hub.Apps.TraceEndpoint(key, r.Ip ?? "", method, r.Port ?? 0, r.IntervalMs ?? 1000).Summary()); }
            catch (ArgumentException e) { return Results.BadRequest(new { error = e.Message }); }
        });

        // Toggle watching for an app; creates a rule with default options when none exists yet.
        app.MapPost("/api/apps/{key}/watch", (string key, WatchReq r) =>
        {
            var k = AppRule.KeyOf(key);
            var existing = hub.Settings.AppRules.FirstOrDefault(x => x.Key == k);
            var rule = existing ?? new AppRule { ProcessName = k, Label = GameCatalog.Lookup(k) };
            rule.Enabled = r.Enabled ?? true;
            try { return Results.Ok(hub.Settings.UpsertAppRule(rule)); } catch (ArgumentException e) { return Results.BadRequest(new { error = e.Message }); }
        });

        app.MapPost("/api/apps/{key}/session/stop", (string key) =>
            hub.Apps.EndSessionNow(key) is { } s ? Results.Ok(s) : Results.NotFound(new { error = "No session is running for this app." }));

        // ---- diagnosis for any target
        app.MapGet("/api/targets/{id}/diagnosis", (string id, HttpRequest q) =>
        {
            if (hub.Targets.Get(id) is not { } t) return Results.NotFound();
            if (long.TryParse(q.Query["from"], out var from) && long.TryParse(q.Query["to"], out var to) && to > from)
                return Results.Ok(hub.Diagnosis.ForTarget(t, from, to));
            int window = int.TryParse(q.Query["window"], out var w) ? Math.Clamp(w, 30, 86400) : 300;
            return Results.Ok(hub.Diagnosis.Live(t, window));
        });
    }
}
