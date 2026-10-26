using QRCoder;
using TraceMe.Services;

namespace TraceMe.Api;

public sealed record RemoteReq(bool? Enabled, bool? Firewall);
public sealed record FirewallReq(bool? Allow);

/// <summary>Settings → Remote access: lets a phone or another computer on the local network open the web UI.</summary>
public static class RemoteEndpoints
{
    public static void MapRemoteApi(this WebApplication app, RemoteRuntime rt, IHostApplicationLifetime life)
    {
        object State()
        {
            var cfg = RemoteAccess.Load();
            return new
            {
                managed = rt.Managed, active = rt.Active, configured = cfg.Enabled, port = rt.Port,
                restartNeeded = rt.Managed && cfg.Enabled != rt.Active,
                token = rt.Active ? rt.Token : null,
                addresses = RemoteAccess.LanAddresses().Select(a => new { a.Name, a.Address, a.Primary, a.Virtual, url = RemoteAccess.Url(a.Address, rt.Port) }),
                firewall = new { canManage = Elevation.IsElevated(), exists = rt.Active || cfg.Enabled ? RemoteAccess.FirewallRuleExists() : false }
            };
        }

        void SetCookie(HttpContext ctx, string token) =>
            ctx.Response.Cookies.Append("tm_token", token, new CookieOptions { HttpOnly = true, SameSite = SameSiteMode.Strict, MaxAge = TimeSpan.FromDays(30) });

        void Restart() => _ = Task.Run(async () =>
        {
            await Task.Delay(600);
            try { Elevation.Relaunch(elevate: false); } catch { return; }
            life.StopApplication();
        });

        app.MapGet("/api/system/remote", State);

        app.MapPost("/api/system/remote", (RemoteReq r, HttpContext ctx) =>
        {
            if (!rt.Managed) return Results.BadRequest(new { error = "The listen address was set by start-up options (--url or TRACEME_URL). Change those instead." });
            var cfg = RemoteAccess.Load();
            string? note = null;
            if (r.Enabled == true)
            {
                if (rt.Active && cfg.Enabled) return Results.Ok(new { restarting = false });
                cfg.Enabled = true;
                if (!RemoteAccess.ValidToken(cfg.Token)) cfg.Token = RemoteAccess.NewToken();
                RemoteAccess.Save(cfg);
                if (r.Firewall != false)
                {
                    if (Elevation.IsElevated()) { var (ok, err) = RemoteAccess.AddFirewallRule(rt.Port); if (!ok) note = "Could not add the Windows Firewall rule: " + err; }
                    else note = "TraceMe is not running as administrator, so the Windows Firewall was not changed.";
                }
                SetCookie(ctx, cfg.Token!); // this browser keeps access after the restart
            }
            else
            {
                cfg.Enabled = false;
                RemoteAccess.Save(cfg);
                if (Elevation.IsElevated()) RemoteAccess.RemoveFirewallRule();
            }
            Restart();
            return Results.Ok(new { restarting = true, note });
        });

        // New token: the old one stops working at once (after the restart that applies it).
        app.MapPost("/api/system/remote/token", (HttpContext ctx) =>
        {
            if (!rt.Managed) return Results.BadRequest(new { error = "The token was set by start-up options (--token or TRACEME_TOKEN)." });
            var cfg = RemoteAccess.Load();
            if (!cfg.Enabled) return Results.BadRequest(new { error = "Remote access is off." });
            cfg.Token = RemoteAccess.NewToken();
            RemoteAccess.Save(cfg);
            SetCookie(ctx, cfg.Token);
            Restart();
            return Results.Ok(new { restarting = true });
        });

        app.MapPost("/api/system/remote/firewall", (FirewallReq r) =>
        {
            if (!Elevation.IsElevated()) return Results.BadRequest(new { error = "Changing the Windows Firewall needs administrator rights. Restart TraceMe as administrator first." });
            var (ok, err) = r.Allow == false ? RemoteAccess.RemoveFirewallRule() : RemoteAccess.AddFirewallRule(rt.Port);
            return ok ? Results.Ok(new { exists = r.Allow != false }) : Results.BadRequest(new { error = err });
        });

        // QR code of the address (optionally with the token in the #fragment, which browsers never send to servers).
        app.MapGet("/api/system/remote/qr", (string? addr, string? token, HttpContext ctx) =>
        {
            if (!rt.Active) return Results.NotFound();
            var list = RemoteAccess.LanAddresses();
            var chosen = list.FirstOrDefault(a => a.Address == addr) ?? list.FirstOrDefault(a => a.Primary) ?? list.FirstOrDefault();
            if (chosen == null) return Results.NotFound();
            var text = RemoteAccess.Url(chosen.Address, rt.Port, token is "1" or "true" ? rt.Token : null);
            using var gen = new QRCodeGenerator();
            using var data = gen.CreateQrCode(text, QRCodeGenerator.ECCLevel.M);
            var svg = new SvgQRCode(data).GetGraphic(6, "#000000", "#ffffff", true, SvgQRCode.SizingMode.ViewBoxAttribute);
            ctx.Response.Headers.CacheControl = "no-store";
            return Results.Text(svg, "image/svg+xml");
        });
    }
}
