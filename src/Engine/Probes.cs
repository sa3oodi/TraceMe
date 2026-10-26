using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Serialization;
using TraceMe.Models;

namespace TraceMe.Engine;

public enum ProbeKind { Timeout, TtlExpired, Reached, Unreachable, Error }

public readonly record struct ProbeResult(int Ttl, double? Rtt, string? Addr, ProbeKind Kind, string? Detail = null);

public sealed record ProbeContext(IPAddress? Dest, string Host, IPAddress? Source, TargetConfig Cfg, RawIcmpPool Pool);

public abstract class Prober
{
    public abstract Task<ProbeResult> ProbeAsync(ProbeContext c, int ttl, CancellationToken ct);

    /// <summary>One sweep over TTL from..to. Probes are launched staggered by the inter-hop delay and run concurrently.</summary>
    public virtual async Task<ProbeResult[]> RunRoundAsync(ProbeContext c, int from, int to, CancellationToken ct)
    {
        var tasks = new Task<ProbeResult>[to - from + 1];
        for (int i = 0; i < tasks.Length; i++) tasks[i] = Staggered(c, from + i, i * c.Cfg.InterHopDelayMs, ct);
        return await Task.WhenAll(tasks);
    }

    async Task<ProbeResult> Staggered(ProbeContext c, int ttl, int delayMs, CancellationToken ct)
    {
        try
        {
            if (delayMs > 0) await Task.Delay(delayMs, ct);
            return await ProbeAsync(c, ttl, ct);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception e) { return new ProbeResult(ttl, null, null, ProbeKind.Error, e.Message); }
    }

    protected static double ElapsedMs(long startTs, long endTs) => (endTs - startTs) * 1000.0 / Stopwatch.Frequency;
    protected static IPAddress AnyOf(AddressFamily f) => f == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any;

    protected static void ApplyTos(Socket s, TargetConfig cfg)
    {
        if (cfg.Tos == 0) return;
        try
        {
            if (s.AddressFamily == AddressFamily.InterNetwork) s.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.TypeOfService, cfg.Tos);
            else s.SetSocketOption(SocketOptionLevel.IPv6, (SocketOptionName)39 /* IPV6_TCLASS */, cfg.Tos);
        }
        catch { /* Windows ignores TOS unless a QoS policy permits it */ }
    }

    /// <summary>Translates a matched ICMP error into a probe result.</summary>
    protected static ProbeResult FromIcmp(int ttl, IcmpReply r, long startTs, IPAddress dest)
    {
        bool v6 = dest.AddressFamily == AddressFamily.InterNetworkV6;
        double ms = ElapsedMs(startTs, r.Timestamp);
        var addr = r.From.ToString();
        bool timeExceeded = v6 ? r.Type == 3 : r.Type == 11;
        if (timeExceeded) return new ProbeResult(ttl, ms, addr, ProbeKind.TtlExpired);
        bool portUnreach = v6 ? r.Code == 4 : r.Code == 3;
        if (r.From.Equals(dest))
            return new ProbeResult(ttl, ms, addr, ProbeKind.Reached, portUnreach ? "port unreachable" : $"icmp unreachable (code {r.Code})");
        return new ProbeResult(ttl, ms, addr, ProbeKind.Unreachable, $"icmp unreachable (code {r.Code})");
    }

    static void Observe(Task t) => t.ContinueWith(x => { _ = x.Exception; }, TaskContinuationOptions.OnlyOnFaulted);
    protected static Task<T> Observed<T>(Task<T> t) { Observe(t); return t; }
}

/// <summary>ICMP echo through the Windows ICMP API (IcmpSendEcho2) — works without administrator rights.</summary>
public sealed class IcmpProber : Prober
{
    public override Task<ProbeResult> ProbeAsync(ProbeContext c, int ttl, CancellationToken ct) =>
        // Blocking send on its own thread: the async path adds up to a timer tick (~15 ms) of error, and the
        // OS-reported RoundtripTime is 0 for TTL-expired replies, so the call is timed with the high-resolution counter.
        Task.Factory.StartNew(() => Send(c, ttl), ct, TaskCreationOptions.LongRunning, TaskScheduler.Default);

    static ProbeResult Send(ProbeContext c, int ttl)
    {
        var cfg = c.Cfg;
        using var ping = new Ping();
        var opts = new PingOptions(ttl, cfg.DontFragment);
        long st = Stopwatch.GetTimestamp();
        PingReply r;
        try { r = ping.Send(c.Dest!, cfg.TimeoutMs, new byte[cfg.PacketSize], opts); }
        catch (PingException e) { return new ProbeResult(ttl, null, null, ProbeKind.Error, e.InnerException?.Message ?? e.Message); }
        double ms = ElapsedMs(st, Stopwatch.GetTimestamp());
        string? addr = r.Address is { } a && !a.Equals(IPAddress.Any) && !a.Equals(IPAddress.IPv6Any) ? a.ToString() : null;
        return r.Status switch
        {
            IPStatus.Success => new ProbeResult(ttl, ms, addr ?? c.Dest!.ToString(), ProbeKind.Reached),
            IPStatus.TtlExpired or IPStatus.TimeExceeded or IPStatus.TtlReassemblyTimeExceeded =>
                new ProbeResult(ttl, ms, addr, addr == null ? ProbeKind.Timeout : ProbeKind.TtlExpired),
            IPStatus.TimedOut => new ProbeResult(ttl, null, null, ProbeKind.Timeout),
            IPStatus.PacketTooBig => new ProbeResult(ttl, ms, addr, ProbeKind.Unreachable, "packet too big (DF set)"),
            IPStatus.DestinationNetworkUnreachable or IPStatus.DestinationHostUnreachable or IPStatus.DestinationProtocolUnreachable
                or IPStatus.DestinationPortUnreachable or IPStatus.DestinationUnreachable or IPStatus.DestinationProhibited or IPStatus.BadRoute =>
                new ProbeResult(ttl, ms, addr, ProbeKind.Unreachable, r.Status.ToString()),
            _ => new ProbeResult(ttl, null, null, ProbeKind.Error, r.Status.ToString())
        };
    }
}

/// <summary>UDP traceroute: datagrams with a limited TTL; routers answer with ICMP Time Exceeded, the target with Port Unreachable (or a UDP reply).</summary>
public sealed class UdpProber : Prober
{
    // SIO_UDP_CONNRESET: stop Windows from turning ICMP errors into WSAECONNRESET when the raw listener handles them
    const int SioUdpConnReset = -1744830452;
    const int SioUdpNetReset = -1744830449; // SIO_UDP_NETRESET: same for ICMP Time Exceeded

    public override async Task<ProbeResult> ProbeAsync(ProbeContext c, int ttl, CancellationToken ct)
    {
        var cfg = c.Cfg; var dest = c.Dest!;
        var listener = c.Pool.Get(c.Source);
        using var s = new Socket(dest.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        s.Bind(new IPEndPoint(c.Source ?? AnyOf(dest.AddressFamily), 0));
        int lp = ((IPEndPoint)s.LocalEndPoint!).Port;
        s.Ttl = (short)ttl;
        ApplyTos(s, cfg);
        if (listener != null)
        {
            try { s.IOControl(SioUdpConnReset, new byte[4], null); } catch { }
            try { s.IOControl(SioUdpNetReset, new byte[4], null); } catch { }
        }
        using var waiter = listener?.Register(17, lp, dest);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var recvBuf = new byte[2048];
        var recv = Observed(s.ReceiveFromAsync(recvBuf, SocketFlags.None, new IPEndPoint(AnyOf(dest.AddressFamily), 0), cts.Token).AsTask());
        long st = Stopwatch.GetTimestamp();
        await s.SendToAsync(new byte[cfg.PacketSize], SocketFlags.None, new IPEndPoint(dest, cfg.EffectivePort), ct);
        var timeout = Task.Delay(cfg.TimeoutMs, cts.Token);
        try
        {
            var done = waiter != null ? await Task.WhenAny(recv, waiter.Task, timeout) : await Task.WhenAny(recv, timeout);
            if (waiter != null && done == waiter.Task) return FromIcmp(ttl, waiter.Task.Result, st, dest);
            if (done == recv)
            {
                double ms = ElapsedMs(st, Stopwatch.GetTimestamp());
                if (recv.IsCompletedSuccessfully) return new ProbeResult(ttl, ms, dest.ToString(), ProbeKind.Reached, "udp reply");
                // Without the raw listener Windows reports the target's ICMP port-unreachable as a connection reset.
                var se = recv.Exception?.GetBaseException() as SocketException;
                if (se?.SocketErrorCode == SocketError.ConnectionReset)
                    return new ProbeResult(ttl, ms, dest.ToString(), ProbeKind.Reached, "port unreachable");
                // Windows reports an ICMP Time Exceeded for a UDP socket as NetworkReset: latency is known, the router address is not.
                if (se?.SocketErrorCode == SocketError.NetworkReset)
                {
                    // With the raw listener available its answer carries the router address; give it a moment to arrive.
                    if (waiter != null && await Task.WhenAny(waiter.Task, Task.Delay(150, ct)) == waiter.Task)
                        return FromIcmp(ttl, waiter.Task.Result, st, dest);
                    return new ProbeResult(ttl, ms, null, ProbeKind.TtlExpired, "ttl expired (router address needs administrator)");
                }
                return new ProbeResult(ttl, null, null, ProbeKind.Error, recv.Exception?.GetBaseException().Message);
            }
            return new ProbeResult(ttl, null, null, ProbeKind.Timeout);
        }
        finally { cts.Cancel(); }
    }
}

/// <summary>TCP traceroute: SYN probes with a limited TTL. Routers answer with ICMP Time Exceeded; the target with SYN/ACK (open) or RST (closed).</summary>
public sealed class TcpProber : Prober
{
    static async Task<int> ConnectAsync(Socket s, EndPoint ep, CancellationToken ct) { await s.ConnectAsync(ep, ct); return 0; }

    public override async Task<ProbeResult> ProbeAsync(ProbeContext c, int ttl, CancellationToken ct)
    {
        var cfg = c.Cfg; var dest = c.Dest!;
        var listener = c.Pool.Get(c.Source);
        using var s = new Socket(dest.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
        {
            LingerState = new LingerOption(true, 0), // abort with RST instead of lingering in TIME_WAIT
            NoDelay = true
        };
        s.Bind(new IPEndPoint(c.Source ?? AnyOf(dest.AddressFamily), 0));
        int lp = ((IPEndPoint)s.LocalEndPoint!).Port;
        s.Ttl = (short)ttl;
        ApplyTos(s, cfg);
        using var waiter = listener?.Register(6, lp, dest);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        long st = Stopwatch.GetTimestamp();
        var connect = Observed(ConnectAsync(s, new IPEndPoint(dest, cfg.EffectivePort), cts.Token));
        var timeout = Task.Delay(cfg.TimeoutMs, cts.Token);
        try
        {
            var done = waiter != null ? await Task.WhenAny(connect, waiter.Task, timeout) : await Task.WhenAny(connect, timeout);
            if (waiter != null && done == waiter.Task) return FromIcmp(ttl, waiter.Task.Result, st, dest);
            if (done == connect)
            {
                double ms = ElapsedMs(st, Stopwatch.GetTimestamp());
                if (connect.IsCompletedSuccessfully) return new ProbeResult(ttl, ms, dest.ToString(), ProbeKind.Reached, "open (SYN/ACK)");
                var se = connect.Exception?.GetBaseException() as SocketException;
                if (se?.SocketErrorCode == SocketError.ConnectionRefused)
                    return new ProbeResult(ttl, ms, dest.ToString(), ProbeKind.Reached, "closed (RST)");
                // Windows may surface an ICMP error as a failed connect; prefer the raw listener's richer answer if it follows.
                if (waiter != null && await Task.WhenAny(waiter.Task, Task.Delay(150, ct)) == waiter.Task)
                    return FromIcmp(ttl, waiter.Task.Result, st, dest);
                return new ProbeResult(ttl, null, null, ProbeKind.Timeout, se?.SocketErrorCode.ToString());
            }
            return new ProbeResult(ttl, null, null, ProbeKind.Timeout);
        }
        finally { cts.Cancel(); }
    }
}

public sealed record AgentRequest(string Host, string Method, int From, int To, int TimeoutMs, int PacketSize, int Port, int Tos,
    bool DontFragment, int InterHopDelayMs, bool PreferIPv6);

/// <summary>Runs a whole sweep on a remote TraceMe agent and returns its results as if they were measured locally.</summary>
public sealed class AgentProber : Prober
{
    static readonly HttpClient Http = new() { Timeout = Timeout.InfiniteTimeSpan };
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };

    public override Task<ProbeResult> ProbeAsync(ProbeContext c, int ttl, CancellationToken ct) => throw new NotSupportedException();

    public override async Task<ProbeResult[]> RunRoundAsync(ProbeContext c, int from, int to, CancellationToken ct)
    {
        var cfg = c.Cfg;
        var req = new AgentRequest(cfg.Host, cfg.Method, from, to, cfg.TimeoutMs, cfg.PacketSize, cfg.EffectivePort, cfg.Tos,
            cfg.DontFragment, cfg.InterHopDelayMs, cfg.PreferIPv6);
        using var msg = new HttpRequestMessage(HttpMethod.Post, cfg.AgentUrl + "/api/agent/round")
        {
            Content = JsonContent.Create(req, options: Json)
        };
        if (!string.IsNullOrEmpty(cfg.AgentToken)) msg.Headers.Add("X-Agent-Token", cfg.AgentToken);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(cfg.TimeoutMs + (to - from + 1) * cfg.InterHopDelayMs + 8000);
        using var resp = await Http.SendAsync(msg, cts.Token);
        if (!resp.IsSuccessStatusCode)
        {
            var body = (await resp.Content.ReadAsStringAsync(ct)).Trim();
            throw new InvalidOperationException($"Agent returned {(int)resp.StatusCode}: {body[..Math.Min(200, body.Length)]}");
        }
        return await resp.Content.ReadFromJsonAsync<ProbeResult[]>(Json, cts.Token) ?? Array.Empty<ProbeResult>();
    }
}

public static class ProberFactory
{
    static readonly IcmpProber Icmp = new();
    static readonly UdpProber Udp = new();
    static readonly TcpProber Tcp = new();
    static readonly AgentProber Agent = new();

    public static Prober For(TargetConfig cfg) => cfg.AgentUrl != null ? Agent : cfg.Method switch
    {
        "udp" => Udp,
        "tcp" => Tcp,
        _ => Icmp
    };

    public static Prober Local(string method) => method switch { "udp" => Udp, "tcp" => Tcp, _ => Icmp };
}
