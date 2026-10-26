using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using TraceMe.Api;
using TraceMe.Engine;
using TraceMe.Services;

// A freshly elevated copy waits for the instance that launched it to release the port.
var waitArg = args.FirstOrDefault(a => a.StartsWith("--wait-pid="));
if (waitArg != null && int.TryParse(waitArg["--wait-pid=".Length..], out var pid))
{
    try { Process.GetProcessById(pid).WaitForExit(30_000); } catch { }
}

// Optional --url=... / --data=... arguments (an elevated relaunch does not reliably inherit environment variables).
foreach (var a in args)
{
    if (a.StartsWith("--url=")) Environment.SetEnvironmentVariable("TRACEME_URL", a[6..]);
    else if (a.StartsWith("--data=")) Environment.SetEnvironmentVariable("TRACEME_DATA", a[7..]);
    else if (a.StartsWith("--token=")) Environment.SetEnvironmentVariable("TRACEME_TOKEN", a[8..]);
}

var urls = Environment.GetEnvironmentVariable("TRACEME_URL") ?? "http://127.0.0.1:5055";
bool loopbackOnly = urls.Split(';').All(u =>
    Uri.TryCreate(u.Replace("*", "0.0.0.0").Replace("+", "0.0.0.0"), UriKind.Absolute, out var uri) &&
    (uri.IsLoopback || uri.Host == "localhost"));

var token = Environment.GetEnvironmentVariable("TRACEME_TOKEN");
if (string.IsNullOrWhiteSpace(token)) token = null;

// Settings → Remote access: unless the listen address was given explicitly, a saved choice makes the server reachable from the LAN.
var remote = new RemoteRuntime { Managed = loopbackOnly };
remote.Port = Uri.TryCreate(urls.Split(';')[0].Replace("*", "127.0.0.1").Replace("+", "127.0.0.1"), UriKind.Absolute, out var firstUri) ? firstUri.Port : 5055;
if (loopbackOnly)
{
    var saved = RemoteAccess.Load();
    if (saved.Enabled && RemoteAccess.ValidToken(saved.Token))
    {
        urls = $"http://0.0.0.0:{remote.Port}";
        loopbackOnly = false;
        token ??= saved.Token;
    }
}
if (!loopbackOnly && token == null)
{
    token = Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant();
    Console.WriteLine($"Listening beyond loopback without TRACEME_TOKEN: generated access token {token}");
}

remote.Active = !loopbackOnly;
remote.Token = token;

// The UI lives in wwwroot next to the binaries; fall back to the working directory (dotnet run from the project folder).
var contentRoot = Directory.Exists(Path.Combine(AppContext.BaseDirectory, "wwwroot")) ? AppContext.BaseDirectory : Directory.GetCurrentDirectory();
var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args.Where(a => !a.StartsWith("--wait-pid=") && !a.StartsWith("--url=") && !a.StartsWith("--data=") && !a.StartsWith("--token=") && a != "--open").ToArray(),
    ContentRootPath = contentRoot
});
builder.WebHost.UseUrls(urls);
builder.Logging.SetMinimumLevel(LogLevel.Warning);
builder.Services.ConfigureHttpJsonOptions(o =>
{
    o.SerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase;
    o.SerializerOptions.PropertyNameCaseInsensitive = true;
});
ThreadPool.SetMinThreads(64, 64);

using var hub = new Hub(AppPaths.DbPath);
builder.Services.AddSingleton(hub);
var app = builder.Build();
var life = app.Lifetime;

app.UseSecurity(hub, token, loopbackOnly);
app.UseDefaultFiles();
app.UseStaticFiles(new StaticFileOptions
{
    OnPrepareResponse = c => c.Context.Response.Headers.CacheControl = "no-cache"
});
app.MapApi(hub, token, life);
app.MapAppApi(hub);
app.MapRemoteApi(remote, life);

hub.Targets.LoadAll();
hub.Apps.Start();
life.ApplicationStopping.Register(() => hub.Targets.StopAllAsync().Wait(TimeSpan.FromSeconds(5)));
life.ApplicationStarted.Register(() =>
{
    Console.WriteLine($"TraceMe {(Elevation.IsElevated() ? "(administrator)" : "(standard user — UDP/TCP hop detection needs administrator)")}");
    foreach (var u in urls.Split(';')) Console.WriteLine("  " + u + (token != null ? "  (token required)" : ""));
    Console.WriteLine("  data: " + AppPaths.DataDir);
    if (args.Contains("--open"))
    {
        try { Process.Start(new ProcessStartInfo(urls.Split(';')[0].Replace("0.0.0.0", "127.0.0.1").Replace("*", "127.0.0.1").Replace("+", "127.0.0.1")) { UseShellExecute = true }); }
        catch { /* no default browser */ }
    }
});
app.Run();

public partial class Program { }
