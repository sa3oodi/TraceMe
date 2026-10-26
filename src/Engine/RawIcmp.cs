using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

using TraceMe.Services;

namespace TraceMe.Engine;

public readonly record struct IcmpReply(byte Type, byte Code, IPAddress From, long Timestamp);

public static class IcmpParser
{
    public readonly record struct Parsed(byte Type, byte Code, byte InnerProto, int InnerSrcPort, int InnerDstPort, IPAddress InnerDst);

    /// <summary>
    /// Parses an ICMP error that quotes one of our UDP/TCP probes. IPv4 packets arrive with their IP header
    /// (SIO_RCVALL); IPv6 packets may or may not include the 40-byte header, which is detected from the version nibble.
    /// </summary>
    public static bool TryParse(ReadOnlySpan<byte> p, bool v6, out Parsed r)
    {
        r = default;
        return v6 ? ParseV6(p, out r) : ParseV4(p, out r);
    }

    static bool ParseV4(ReadOnlySpan<byte> p, out Parsed r)
    {
        r = default;
        if (p.Length < 20 || (p[0] >> 4) != 4 || p[9] != 1) return false;
        int ihl = (p[0] & 0xF) * 4;
        if (ihl < 20 || p.Length < ihl + 8 + 20) return false;
        byte type = p[ihl], code = p[ihl + 1];
        if (type != 3 && type != 11) return false; // destination unreachable / time exceeded
        int e = ihl + 8;
        if ((p[e] >> 4) != 4) return false;
        int ihl2 = (p[e] & 0xF) * 4;
        if (ihl2 < 20 || p.Length < e + ihl2 + 4) return false;
        byte proto = p[e + 9];
        if (proto != 6 && proto != 17) return false;
        var dst = new IPAddress(p.Slice(e + 16, 4));
        int sp = (p[e + ihl2] << 8) | p[e + ihl2 + 1];
        int dp = (p[e + ihl2 + 2] << 8) | p[e + ihl2 + 3];
        r = new Parsed(type, code, proto, sp, dp, dst);
        return true;
    }

    static bool ParseV6(ReadOnlySpan<byte> p, out Parsed r)
    {
        r = default;
        if (p.Length < 8) return false;
        int off = 0;
        if ((p[0] >> 4) == 6)
        {
            if (p.Length < 40 + 8 || p[6] != 58) return false;
            off = 40;
        }
        byte type = p[off], code = p[off + 1];
        if (type != 1 && type != 3) return false; // destination unreachable / time exceeded
        int e = off + 8;
        if (p.Length < e + 40 + 4 || (p[e] >> 4) != 6) return false;
        byte proto = p[e + 6];
        if (proto != 6 && proto != 17) return false;
        var dst = new IPAddress(p.Slice(e + 24, 16));
        int sp = (p[e + 40] << 8) | p[e + 41];
        int dp = (p[e + 42] << 8) | p[e + 43];
        r = new Parsed(type, code, proto, sp, dp, dst);
        return true;
    }
}

public sealed class IcmpWaiter : IDisposable
{
    readonly RawIcmpListener _owner;
    readonly TaskCompletionSource<IcmpReply> _tcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal long Key;
    internal IPAddress Dest;

    internal IcmpWaiter(RawIcmpListener owner, long key, IPAddress dest) { _owner = owner; Key = key; Dest = dest; }
    public Task<IcmpReply> Task => _tcs.Task;
    internal void Complete(IcmpReply r) => _tcs.TrySetResult(r);
    public void Dispose() => _owner.Unregister(Key);
}

/// <summary>
/// Raw ICMP socket bound to one local address with SIO_RCVALL. UDP/TCP probes register their local port here and
/// are completed when an ICMP Time Exceeded / Destination Unreachable quoting that port arrives.
/// Requires administrator rights on Windows.
/// </summary>
public sealed class RawIcmpListener : IDisposable
{
    readonly Socket _sock;
    readonly Thread _thread;
    readonly ConcurrentDictionary<long, IcmpWaiter> _waiters = new();
    readonly bool _v6;
    volatile bool _disposed;
    public IPAddress Local { get; }
    public long PacketsSeen, RepliesMatched;

    RawIcmpListener(Socket s, IPAddress local)
    {
        _sock = s; Local = local; _v6 = local.AddressFamily == AddressFamily.InterNetworkV6;
        _thread = new Thread(Loop) { IsBackground = true, Name = "raw-icmp-" + local };
        _thread.Start();
    }

    public static bool TryCreate(IPAddress local, out RawIcmpListener? listener, out string? error)
    {
        listener = null; error = null;
        Socket? s = null;
        try
        {
            bool v6 = local.AddressFamily == AddressFamily.InterNetworkV6;
            s = new Socket(local.AddressFamily, SocketType.Raw, v6 ? ProtocolType.IcmpV6 : ProtocolType.Icmp);
            s.ReceiveBufferSize = 4 * 1024 * 1024;
            s.Bind(new IPEndPoint(local, 0));
            int mode = int.TryParse(Environment.GetEnvironmentVariable("TRACEME_RCVALL"), out var m) ? m : 1;
            if (OperatingSystem.IsWindows()) s.IOControl(IOControlCode.ReceiveAll, BitConverter.GetBytes(mode), null);
            listener = new RawIcmpListener(s, local);
            return true;
        }
        catch (SocketException e)
        {
            s?.Dispose();
            error = e.SocketErrorCode is SocketError.InvalidArgument or SocketError.AccessDenied
                ? "Raw ICMP capture needs administrator rights (restart TraceMe as administrator)."
                : $"Raw ICMP socket failed: {e.Message}";
            return false;
        }
        catch (Exception e) { s?.Dispose(); error = e.Message; return false; }
    }

    public IcmpWaiter Register(byte proto, int localPort, IPAddress dest)
    {
        long key = ((long)proto << 32) | (uint)localPort;
        var w = new IcmpWaiter(this, key, dest);
        _waiters[key] = w;
        return w;
    }

    internal void Unregister(long key) => _waiters.TryRemove(key, out _);

    void Loop()
    {
        var buf = new byte[65535];
        EndPoint ep = new IPEndPoint(_v6 ? IPAddress.IPv6Any : IPAddress.Any, 0);
        while (!_disposed)
        {
            try
            {
                int n = _sock.ReceiveFrom(buf, ref ep);
                long ts = System.Diagnostics.Stopwatch.GetTimestamp();
                Interlocked.Increment(ref PacketsSeen);
                if (!IcmpParser.TryParse(buf.AsSpan(0, n), _v6, out var p)) continue;
                long key = ((long)p.InnerProto << 32) | (uint)p.InnerSrcPort;
                if (!_waiters.TryGetValue(key, out var w) || !w.Dest.Equals(p.InnerDst)) continue;
                var from = new IPAddress(((IPEndPoint)ep).Address.GetAddressBytes()); // drop IPv6 scope id
                Interlocked.Increment(ref RepliesMatched);
                w.Complete(new IcmpReply(p.Type, p.Code, from, ts));
            }
            catch (SocketException) when (_disposed) { break; }
            catch (ObjectDisposedException) { break; }
            catch (SocketException) { Thread.Sleep(5); }
        }
    }

    public void Dispose()
    {
        _disposed = true;
        try { _sock.Dispose(); } catch { }
    }
}

public sealed class RawIcmpPool : IDisposable
{
    record Entry(RawIcmpListener? Listener, string? Error, DateTime At);
    readonly ConcurrentDictionary<string, Entry> _entries = new();
    readonly object _gate = new();

    /// <summary>Returns a listener for the local address or null when raw capture is unavailable (see <see cref="LastError"/>).</summary>
    public RawIcmpListener? Get(IPAddress? local)
    {
        if (local == null) return null;
        var key = local.ToString();
        if (_entries.TryGetValue(key, out var e) && (e.Listener != null || DateTime.UtcNow - e.At < TimeSpan.FromSeconds(30)))
            return e.Listener;
        lock (_gate)
        {
            if (_entries.TryGetValue(key, out e) && (e.Listener != null || DateTime.UtcNow - e.At < TimeSpan.FromSeconds(30)))
                return e.Listener;
            RawIcmpListener? l = null; string? err = null;
            // Without administrator rights the socket can be created but never receives Time Exceeded messages, so do not pretend.
            if (!Elevation.IsElevated() && Environment.GetEnvironmentVariable("TRACEME_FORCE_RAW") != "1")
                err = "Raw ICMP capture needs administrator rights (restart TraceMe as administrator).";
            else RawIcmpListener.TryCreate(local, out l, out err);
            _entries[key] = new Entry(l, err, DateTime.UtcNow);
            return l;
        }
    }

    public string? LastError(IPAddress? local) => local != null && _entries.TryGetValue(local.ToString(), out var e) ? e.Error : null;

    public object Describe() => _entries.Select(kv => new
    {
        local = kv.Key, ok = kv.Value.Listener != null, error = kv.Value.Error,
        packets = kv.Value.Listener?.PacketsSeen ?? 0, matched = kv.Value.Listener?.RepliesMatched ?? 0
    }).ToArray();

    public void Dispose() { foreach (var e in _entries.Values) e.Listener?.Dispose(); }
}
