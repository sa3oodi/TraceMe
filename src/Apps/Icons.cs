using System.Collections.Concurrent;
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace TraceMe.Apps;

/// <summary>
/// Application icons, read from the executable of a running process and kept as PNG (in memory and in the data folder, so
/// an app that is not running right now still has its icon). Only executables of processes seen by TraceMe are ever opened;
/// the HTTP caller supplies a name, never a path.
/// </summary>
public sealed class AppIcons
{
    readonly ProcessCatalog _procs;
    readonly string _dir;
    readonly ConcurrentDictionary<string, byte[]?> _cache = new();
    readonly ConcurrentDictionary<string, DateTime> _missAt = new();

    public AppIcons(ProcessCatalog procs, string dataDir)
    {
        _procs = procs;
        _dir = Path.Combine(dataDir, "icons");
    }

    string FileFor(string key) => Path.Combine(_dir, Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(key)))[..16] + ".png");

    /// <summary>PNG bytes for the application, or null when it has no icon (system, not seen yet, access denied).</summary>
    public byte[]? Get(string key)
    {
        key = key.ToLowerInvariant();
        if (_cache.TryGetValue(key, out var hit) && hit != null) return hit;
        try { var f = FileFor(key); if (File.Exists(f)) { var b = File.ReadAllBytes(f); _cache[key] = b; return b; } } catch { }
        // Do not retry a failing extraction on every request.
        if (_missAt.TryGetValue(key, out var at) && DateTime.UtcNow - at < TimeSpan.FromSeconds(30)) return null;

        byte[]? png = null;
        if (OperatingSystem.IsWindows() && _procs.Running.TryGetValue(key, out var pids))
        {
            foreach (var pid in pids.Take(4))
            {
                var path = _procs.PathOf(pid);
                if (path == null || !File.Exists(path)) continue;
                png = Extract(path);
                if (png != null) break;
            }
        }
        if (png == null) { _missAt[key] = DateTime.UtcNow; return null; }
        _cache[key] = png;
        try { Directory.CreateDirectory(_dir); File.WriteAllBytes(FileFor(key), png); } catch { /* cache only */ }
        return png;
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    static byte[]? Extract(string path)
    {
        try
        {
            using var icon = Icon.ExtractAssociatedIcon(path);
            if (icon == null) return null;
            using var bmp = icon.ToBitmap();
            using var ms = new MemoryStream();
            bmp.Save(ms, ImageFormat.Png);
            return ms.ToArray();
        }
        catch { return null; }
    }

    // ------------------------------------------------------------------ image path without administrator rights

    const uint ProcessQueryLimitedInformation = 0x1000;

    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool QueryFullProcessImageName(IntPtr h, int flags, StringBuilder name, ref int size);

    /// <summary>Full path of a process image; works for protected processes that <c>Process.MainModule</c> cannot open.</summary>
    public static string? ImagePath(int pid)
    {
        var h = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            var sb = new StringBuilder(1024); int n = sb.Capacity;
            return QueryFullProcessImageName(h, 0, sb, ref n) ? sb.ToString(0, n) : null;
        }
        finally { CloseHandle(h); }
    }
}
