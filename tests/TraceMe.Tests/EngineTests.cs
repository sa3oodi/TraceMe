using System.Net;
using TraceMe.Alerts;
using TraceMe.Engine;
using TraceMe.Models;
using TraceMe.Services;

namespace TraceMe.Tests;

public class IcmpParserTests
{
    // IPv4 header (20) + ICMP header (8) + quoted original IP header (20) + first 8 bytes of the quoted transport header.
    static byte[] V4Error(byte type, byte code, byte proto, ushort srcPort, ushort dstPort, string dest = "8.8.8.8")
    {
        var p = new List<byte>();
        p.AddRange(new byte[] { 0x45, 0, 0, 56, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 1, 192, 168, 0, 5 }); // outer: proto 1, from 10.0.0.1
        p.AddRange(new byte[] { type, code, 0, 0, 0, 0, 0, 0 });
        var d = IPAddress.Parse(dest).GetAddressBytes();
        p.AddRange(new byte[] { 0x45, 0, 0, 40, 0, 0, 0, 0, 1, proto, 0, 0, 192, 168, 0, 5, d[0], d[1], d[2], d[3] });
        p.AddRange(new byte[] { (byte)(srcPort >> 8), (byte)srcPort, (byte)(dstPort >> 8), (byte)dstPort, 0, 0, 0, 0 });
        return p.ToArray();
    }

    [Theory]
    [InlineData(11, 0, 17)] // time exceeded quoting UDP
    [InlineData(11, 0, 6)]  // time exceeded quoting TCP
    [InlineData(3, 3, 17)]  // port unreachable quoting UDP
    public void ParsesIpv4Errors(byte type, byte code, byte proto)
    {
        Assert.True(IcmpParser.TryParse(V4Error(type, code, proto, 54321, 33434), false, out var r));
        Assert.Equal(type, r.Type); Assert.Equal(code, r.Code); Assert.Equal(proto, r.InnerProto);
        Assert.Equal(54321, r.InnerSrcPort); Assert.Equal(33434, r.InnerDstPort);
        Assert.Equal(IPAddress.Parse("8.8.8.8"), r.InnerDst);
    }

    [Fact]
    public void IgnoresEchoRepliesAndNonIcmp()
    {
        Assert.False(IcmpParser.TryParse(V4Error(0, 0, 17, 1, 2), false, out _));  // echo reply
        var tcp = V4Error(11, 0, 17, 1, 2); tcp[9] = 6;                               // outer protocol TCP
        Assert.False(IcmpParser.TryParse(tcp, false, out _));
        Assert.False(IcmpParser.TryParse(V4Error(11, 0, 1, 1, 2), false, out _));    // quoted packet is ICMP, not ours
    }

    [Fact]
    public void RejectsTruncatedAndGarbage()
    {
        var good = V4Error(11, 0, 17, 1, 2);
        for (int len = 0; len < 52; len++) // a quoted transport header needs its 4 port bytes Assert.False(IcmpParser.TryParse(good.AsSpan(0, len), false, out _), $"len {len}");
        Assert.False(IcmpParser.TryParse(new byte[64], false, out _));
        Assert.False(IcmpParser.TryParse(Enumerable.Repeat((byte)0xFF, 100).ToArray(), false, out _));
    }

    static byte[] V6Error(byte type, byte code, byte proto, ushort srcPort, bool withOuterHeader)
    {
        var p = new List<byte>();
        if (withOuterHeader) { var h = new byte[40]; h[0] = 0x60; h[6] = 58; p.AddRange(h); }
        p.AddRange(new byte[] { type, code, 0, 0, 0, 0, 0, 0 });
        var inner = new byte[40]; inner[0] = 0x60; inner[6] = proto;
        IPAddress.Parse("2001:db8::1").GetAddressBytes().CopyTo(inner, 24);
        p.AddRange(inner);
        p.AddRange(new byte[] { (byte)(srcPort >> 8), (byte)srcPort, 0x82, 0x9A, 0, 0, 0, 0 });
        return p.ToArray();
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ParsesIpv6WithAndWithoutOuterHeader(bool outer)
    {
        Assert.True(IcmpParser.TryParse(V6Error(3, 0, 17, 40000, outer), true, out var r));
        Assert.Equal(3, r.Type); Assert.Equal(17, r.InnerProto); Assert.Equal(40000, r.InnerSrcPort);
        Assert.Equal(IPAddress.Parse("2001:db8::1"), r.InnerDst);
    }
}

public class StatsTests
{
    [Fact]
    public void AccumulatesLatencyLossAndJitter()
    {
        var a = new Acc();
        foreach (var v in new double?[] { 10, 20, null, 30 }) a.Add(v);
        var s = a.ToStats();
        Assert.Equal(4, s.Sent); Assert.Equal(3, s.Recv);
        Assert.Equal(25.0, s.LossPct); Assert.Equal(20.0, s.Avg!.Value, 6);
        Assert.Equal(10, s.Min); Assert.Equal(30, s.Max); Assert.Equal(30, s.Last);
        Assert.Equal(8.16497, s.Stdev!.Value, 4);
        Assert.NotNull(s.Jitter);
    }

    [Fact]
    public void EmptyAccumulatorHasNoValues()
    {
        var s = new Acc().ToStats();
        Assert.Null(s.Avg); Assert.Null(s.Min); Assert.Null(s.Jitter); Assert.Equal(0, s.LossPct);
    }

    [Fact]
    public void LastIsNullAfterLoss()
    {
        var a = new Acc(); a.Add(5); a.Add(null);
        Assert.Null(a.ToStats().Last);
    }

    [Theory]
    [InlineData(20, 2, 0, 4.35, 4.41)]  // clean path
    [InlineData(300, 20, 0, 3.4, 3.8)]  // slow
    [InlineData(20, 2, 30, 1.0, 2.6)]   // heavy loss
    public void MosIsMonotonicAndBounded(double avg, double jit, double loss, double lo, double hi)
    {
        var m = Mos.Compute(avg, jit, loss);
        Assert.InRange(m, lo, hi);
    }

    [Fact]
    public void MosDropsWithLatencyJitterAndLoss()
    {
        var best = Mos.Compute(20, 1, 0);
        Assert.True(Mos.Compute(200, 1, 0) < best);
        Assert.True(Mos.Compute(20, 50, 0) < best);
        Assert.True(Mos.Compute(20, 1, 10) < best);
    }

    [Fact]
    public void WindowMetrics()
    {
        float N = float.NaN;
        var v = new[] { 10f, 20f, N, 40f };
        Assert.Equal(23.333, Metrics.Avg(v)!.Value, 2);
        Assert.Equal(40, Metrics.Max(v)); Assert.Equal(40, Metrics.Last(v)); Assert.Equal(25, Metrics.LossPct(v));
        Assert.Equal(15, Metrics.Jitter(v)); // |20-10| and |40-20| over received pairs → (10+20)/2
        Assert.False(Metrics.AllLost(v)); Assert.True(Metrics.AllLost(new[] { N, N }));
        Assert.Null(Metrics.Avg(new[] { N })); Assert.Null(Metrics.Last(new[] { 1f, N }));
        Assert.False(Metrics.AllLost(Array.Empty<float>()));
    }

    [Fact]
    public void HopLiveFlagsOnlyNewAddressesAsPathChanges()
    {
        var h = new HopLive(3);
        Assert.True(h.Add(5, "10.0.0.1", null));   // first sighting
        Assert.False(h.Add(5, "10.0.0.1", null));  // same router again
        Assert.True(h.Add(5, "10.0.0.2", null));   // new address: genuine change
        Assert.False(h.Add(5, "10.0.0.1", null));  // flipping back to a known router is load balancing
        Assert.False(h.Add(null, null, null));     // a lost probe says nothing about the path
    }

    [Fact]
    public void HopLiveRingKeepsMostRecentSamples()
    {
        var h = new HopLive(1);
        for (int i = 0; i < HopLive.Ring + 50; i++) h.Add(i, "10.0.0.1", null);
        var tail = h.Tail(3);
        Assert.Equal(new float[] { HopLive.Ring + 47, HopLive.Ring + 48, HopLive.Ring + 49 }, tail);
        Assert.Equal(HopLive.Ring + 50, h.Sent);
        Assert.Equal(HopLive.Ring, h.Tail(100000).Length);
    }
}

public class AlertTests
{
    static AlertRule Rule(string metric, string op = ">", double value = 100, int samples = 4) =>
        new() { Metric = metric, Op = op, Value = value, Samples = samples };

    [Fact]
    public void NotEnoughSamplesIsUndecided()
    {
        var (c, _) = AlertEngine.Check(Rule("avg"), new[] { 500f, 500f }, false);
        Assert.Null(c);
    }

    [Theory]
    [InlineData("avg", ">", 100, new[] { 150f, 160f, 170f, 180f }, true)]
    [InlineData("avg", ">", 100, new[] { 50f, 60f, 70f, 80f }, false)]
    [InlineData("avg", "<", 100, new[] { 50f, 60f, 70f, 80f }, true)]
    [InlineData("max", ">", 100, new[] { 50f, 120f, 70f, 80f }, true)]
    [InlineData("last", ">", 100, new[] { 500f, 5f, 5f, 5f }, false)]
    [InlineData("jitter", ">", 20, new[] { 10f, 60f, 10f, 60f }, true)]
    [InlineData("loss", ">", 20, new[] { 10f, float.NaN, 10f, 10f }, true)]
    [InlineData("loss", ">", 30, new[] { 10f, float.NaN, 10f, 10f }, false)]
    public void ThresholdMetrics(string metric, string op, double thr, float[] vals, bool expected)
    {
        var (c, _) = AlertEngine.Check(Rule(metric, op, thr), vals, false);
        Assert.Equal(expected, c);
    }

    [Fact]
    public void NoResponseNeedsAllSamplesLost()
    {
        float N = float.NaN;
        Assert.True(AlertEngine.Check(Rule("noresponse"), new[] { N, N, N, N }, false).cond);
        Assert.False(AlertEngine.Check(Rule("noresponse"), new[] { N, N, N, 5f }, false).cond);
    }

    [Fact]
    public void AllLostLatencyIsNotAnAlert() =>
        Assert.False(AlertEngine.Check(Rule("avg"), new[] { float.NaN, float.NaN, float.NaN, float.NaN }, false).cond);

    [Fact]
    public void MosRuleUsesLatencyJitterAndLoss()
    {
        var good = AlertEngine.Check(Rule("mos", "<", 4.0), new[] { 20f, 21f, 20f, 21f }, false);
        Assert.False(good.cond);
        var bad = AlertEngine.Check(Rule("mos", "<", 4.0), new[] { 400f, 20f, 380f, float.NaN }, false);
        Assert.True(bad.cond);
    }

    [Fact]
    public void RouteChangeFollowsTheFlag()
    {
        Assert.True(AlertEngine.Check(Rule("routechange"), Array.Empty<float>(), true).cond);
        Assert.False(AlertEngine.Check(Rule("routechange"), Array.Empty<float>(), false).cond);
    }

    [Fact]
    public void RuleNormalizationRejectsUnknownMetric()
    {
        Assert.Throws<ArgumentException>(() => new AlertRule { Metric = "bogus" }.Normalize());
        var r = new AlertRule { Metric = "mos", Scope = "any", Samples = 99999 }.Normalize();
        Assert.Equal("destination", r.Scope); Assert.Equal(600, r.Samples);
    }

    [Fact]
    public void TemplatesSubstituteTokensAndEscapeJson()
    {
        var rule = new AlertRule { Name = "R \"1\"" };
        var ctx = new AlertContext(rule, "t1", "My \"target\"", "example.com", 7, "router", "avg", 123.456, 100, "triggered", "msg \"x\"", DateTimeOffset.UnixEpoch);
        Assert.Equal("hop 7 on example.com: 123.46", AlertActions.Template("hop {hop} on {host}: {value}", ctx));
        var json = AlertActions.Template("{\"t\":\"{target}\",\"m\":\"{message}\"}", ctx, json: true);
        using var doc = System.Text.Json.JsonDocument.Parse(json);
        Assert.Equal("My \"target\"", doc.RootElement.GetProperty("t").GetString());
    }

    [Fact]
    public void ArgumentSplittingKeepsQuotedValuesTogether()
    {
        Assert.Equal(new[] { "a", "b c", "d" }, AlertActions.SplitArgs("a \"b c\" d"));
        Assert.Equal(new[] { "{message}", "{hop}" }, AlertActions.SplitArgs("\"{message}\" {hop}"));
        Assert.Empty(AlertActions.SplitArgs("   "));
    }
}

public class ConfigTests
{
    [Fact]
    public void NormalizeClampsRanges()
    {
        var c = new TargetConfig { Host = " example.com ", IntervalMs = 1, TimeoutMs = 999999, MaxHops = 500, StartHop = 99, PacketSize = -4, Tos = 999, InterHopDelayMs = -1 }.Normalize();
        Assert.Equal("example.com", c.Host);
        Assert.Equal(200, c.IntervalMs); Assert.Equal(30000, c.TimeoutMs); Assert.Equal(64, c.MaxHops);
        Assert.Equal(64, c.StartHop); Assert.Equal(0, c.PacketSize); Assert.Equal(255, c.Tos); Assert.Equal(0, c.InterHopDelayMs);
    }

    [Theory]
    [InlineData("")]
    [InlineData("two words")]
    [InlineData("   ")]
    public void RejectsBadHosts(string host) => Assert.Throws<ArgumentException>(() => new TargetConfig { Host = host }.Normalize());

    [Fact]
    public void RejectsBadMethodSourceAndAgentUrl()
    {
        Assert.Throws<ArgumentException>(() => new TargetConfig { Host = "a", Method = "ftp" }.Normalize());
        Assert.Throws<ArgumentException>(() => new TargetConfig { Host = "a", SourceAddress = "nope" }.Normalize());
        Assert.Throws<ArgumentException>(() => new TargetConfig { Host = "a", AgentUrl = "file:///etc/passwd" }.Normalize());
        Assert.Equal("http://x:5055", new TargetConfig { Host = "a", AgentUrl = "http://x:5055/" }.Normalize().AgentUrl);
    }

    [Fact]
    public void AgentTokenIsDroppedWithoutUrl() =>
        Assert.Null(new TargetConfig { Host = "a", AgentToken = "secret" }.Normalize().AgentToken);

    [Fact]
    public void DefaultPortsFollowMethod()
    {
        Assert.Equal(33434, new TargetConfig { Method = "udp" }.EffectivePort);
        Assert.Equal(80, new TargetConfig { Method = "tcp" }.EffectivePort);
        Assert.Equal(443, new TargetConfig { Method = "tcp", Port = 443 }.EffectivePort);
    }

    [Fact]
    public void GlobalSettingsKeepThresholdsOrdered()
    {
        var s = new GlobalSettings { LatencyWarnMs = 200, LatencyCritMs = 50, LossWarnPct = 10, LossCritPct = 1 }.Normalize();
        Assert.True(s.LatencyCritMs >= s.LatencyWarnMs); Assert.True(s.LossCritPct >= s.LossWarnPct);
    }
}

public class ServiceTests
{
    [Theory]
    [InlineData("10.1.2.3", true)] [InlineData("192.168.0.1", true)] [InlineData("172.16.5.5", true)] [InlineData("172.32.0.1", false)]
    [InlineData("100.64.0.1", true)] [InlineData("169.254.1.1", true)] [InlineData("127.0.0.1", true)] [InlineData("8.8.8.8", false)]
    [InlineData("fe80::1", true)] [InlineData("fd00::1", true)] [InlineData("2001:4860:4860::8888", false)]
    public void PrivateAddressDetection(string ip, bool priv) => Assert.Equal(priv, AsnService.IsPrivate(IPAddress.Parse(ip)));

    [Fact]
    public void ParsesTeamCymruResponse()
    {
        const string text = "Bulk mode; whois.cymru.com [2026-10-26 10:00:00 +0000]\nAS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name\n15169   | 8.8.8.8          | 8.8.8.0/24          | US | arin     | 1992-12-01 | GOOGLE, US\n";
        var a = AsnService.Parse(text)!;
        Assert.Equal("AS15169", a.Asn); Assert.Equal("8.8.8.0/24", a.Prefix); Assert.Equal("US", a.Country); Assert.Equal("GOOGLE, US", a.Name);
        Assert.Null(AsnService.Parse("garbage"));
    }

    static Dictionary<string, object?> Vars(double avg, double jit, double loss) => new()
    {
        ["Average"] = avg, ["Minimum"] = 1.0, ["Maximum"] = 2.0, ["Current"] = 1.0, ["Jitter"] = jit, ["LostPacketCount"] = 0,
        ["TotalPacketCount"] = 100, ["PacketLossPercent"] = loss, ["HopNumber"] = 1, ["IPAddress"] = "1.2.3.4", ["HostName"] = "h"
    };

    [Fact]
    public void DefaultMosColumnMatchesNativeFormula()
    {
        var host = new ScriptHost();
        var col = new GlobalSettings().Columns.Single(c => c.Id == "mos");
        foreach (var (avg, jit, loss) in new[] { (20.0, 1.0, 0.0), (150.0, 10.0, 2.0), (400.0, 40.0, 5.0) })
        {
            var (v, err) = host.Eval("t", col.Script, Vars(avg, jit, loss));
            Assert.Null(err);
            Assert.Equal(Mos.Compute(avg, jit, loss), Math.Round((double)v!, 2), 2);
        }
    }

    [Fact]
    public void ScriptsAreSandboxedAndTimeBounded()
    {
        var host = new ScriptHost();
        var (v, err) = host.Eval("loop", "while(true){}", Vars(1, 1, 0));
        Assert.Null(v); Assert.NotNull(err);                       // timeout, not a hang
        (v, err) = host.Eval("syntax", "return (;", Vars(1, 1, 0)); Assert.NotNull(err);
        (v, err) = host.Eval("io", "return typeof require === 'undefined' && typeof process === 'undefined' && typeof System === 'undefined';", Vars(1, 1, 0));
        Assert.Null(err); Assert.Equal(true, v);
        (v, err) = host.Eval("str", "return HostName + '!';", Vars(1, 1, 0)); Assert.Equal("h!", v);
        (v, err) = host.Eval("inf", "return 1/0;", Vars(1, 1, 0)); Assert.Null(v); // non-finite numbers are not shown
    }
}
