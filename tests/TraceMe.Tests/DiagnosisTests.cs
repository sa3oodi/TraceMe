using System.Net;
using TraceMe.Apps;

namespace TraceMe.Tests;

public class DiagnosisTests
{
    // A realistic 12-hop home path: router, modem, two ISP-internal hops, ISP backbone, transit, server edge, server.
    static readonly string?[] Addr =
    {
        "192.168.0.1", "192.168.100.1", "10.50.0.1", "10.11.10.10", "88.201.100.26", "88.201.99.254",
        "172.253.51.205", "216.239.59.83", "142.250.1.1", "142.250.1.2", "142.250.1.3", "8.8.8.8"
    };

    static List<HopInput> Path(Func<int, double> loss, Func<int, double>? jitter = null, Func<int, double>? avg = null, int sent = 200, int count = 12)
    {
        var l = new List<HopInput>();
        for (int h = 1; h <= count; h++)
        {
            double ls = Math.Min(100, loss(h)); int recv = (int)Math.Round(sent * (1 - ls / 100));
            l.Add(new HopInput(h, Addr[h - 1], null, sent, recv, ls, recv == 0 ? null : (avg?.Invoke(h) ?? h * 1.5), jitter?.Invoke(h) ?? 0.3, (avg?.Invoke(h) ?? h * 1.5) * 1.5, null));
        }
        return l;
    }

    // ---- when did the loss happen? (recent window)

    [Fact]
    public void ShortBurstThatHasEndedIsNotBlamedOnTheIsp()
    {
        // 100 traces, hops 6+ lost 15 of them, but the last 30 traces are clean
        var d = Diagnosis.Analyze(Path(h => h >= 6 ? 15 : 0, sent: 100), true, null, Path(_ => 0, sent: 30));
        Assert.Equal("burst", d.Code); Assert.Equal("none", d.Side); Assert.Equal("warn", d.Status); Assert.Equal("low", d.Confidence);
        Assert.Equal(0, d.Segments.Count(s => s.Culprit));
        Assert.Contains("nothing is wrong right now", d.Headline);
        Assert.DoesNotContain(d.Advice, a => a.Contains("contact your ISP"));
    }

    [Fact]
    public void LossThatIsStillGoingOnKeepsItsVerdict()
    {
        var d = Diagnosis.Analyze(Path(h => h >= 2 ? 30 : 0, sent: 100), true, null, Path(h => h >= 2 ? 30 : 0, sent: 30));
        Assert.Equal("isp", d.Code); Assert.Equal("isp", d.Side); Assert.Equal("bad", d.Status);
        Assert.Equal(1, d.Segments.Count(s => s.Culprit));
        Assert.NotEqual("low", d.Confidence);
    }

    [Fact]
    public void LossThatJustBeganIsMarkedUnproven()
    {
        // 24 probes lost, all of them inside the last 30 traces
        var d = Diagnosis.Analyze(Path(h => h >= 6 ? 24 : 0, sent: 100), true, null, Path(h => h >= 6 ? 80 : 0, sent: 30));
        Assert.Equal("isp", d.Code);
        Assert.Equal("low", d.Confidence);
        Assert.Contains(d.Evidence, e => e.Contains("only began within the last"));
    }

    [Fact]
    public void LongLossThatStoppedKeepsTheVerdictButNotHighConfidence()
    {
        var d = Diagnosis.Analyze(Path(h => h >= 6 ? 40 : 0, sent: 200), true, null, Path(_ => 0, sent: 30));
        Assert.Equal("isp", d.Code);
        Assert.Contains(d.Evidence, e => e.Contains("may have stopped"));
        Assert.NotEqual("high", d.Confidence);
    }

    [Fact]
    public void SilentServerIsMentionedWhenBlamingSomeoneElse()
    {
        var hops = Path(h => h >= 6 && h <= 11 ? 30 : 0, sent: 100, count: 11);
        hops.Add(new HopInput(12, null, null, 100, 0, 100, null, null, null, null));
        var d = Diagnosis.Analyze(hops, false);
        Assert.NotEqual("ok", d.Code);
        Assert.Contains(d.Evidence, e => e.Contains("never answers probes"));
    }

    [Fact]
    public void WithoutARecentWindowTheOldBehaviourIsKept()
    {
        var d = Diagnosis.Analyze(Path(h => h >= 6 ? 15 : 0, sent: 100), true);
        Assert.Equal("isp", d.Code);
    }

    [Fact]
    public void CleanPathIsHealthy()
    {
        var d = Diagnosis.Analyze(Path(_ => 0), true);
        Assert.Equal("ok", d.Code); Assert.Equal("none", d.Side); Assert.Equal("ok", d.Status);
        Assert.Contains("healthy", d.Headline);
        Assert.NotNull(d.Mos); Assert.Equal(4, d.Segments.Count);
        Assert.All(d.Segments, s => Assert.NotEqual("bad", s.Status));
    }

    [Fact]
    public void RateLimitedRouterIsNotRealLoss()
    {
        var d = Diagnosis.Analyze(Path(h => h == 2 ? 40 : 0), true);
        Assert.Equal("ok", d.Code);
        Assert.Contains(d.Evidence, e => e.Contains("hop 2") && e.Contains("rate-limits"));
    }

    [Theory]
    [InlineData(1, "local", "yours")]    // router / PC
    [InlineData(2, "isp", "isp")]        // modem
    [InlineData(5, "isp", "isp")]        // first public hop = ISP backbone
    [InlineData(7, "transit", "internet")]
    [InlineData(10, "server", "server")]
    [InlineData(11, "server", "server")]
    [InlineData(12, "server", "server")] // destination only
    public void LossIsAttributedToTheRightSegment(int startHop, string code, string side)
    {
        var d = Diagnosis.Analyze(Path(h => h >= startHop ? 6 : 0), true);
        Assert.Equal(code, d.Code); Assert.Equal(side, d.Side); Assert.Equal(startHop, d.Hop);
        Assert.Equal("bad", d.Status);
        Assert.Equal(1, d.Segments.Count(s => s.Culprit));
        Assert.NotEmpty(d.Advice);
    }

    [Fact]
    public void LossAfterARateLimitedHopStillFindsTheRealStart()
    {
        // hop 2 rate-limits at 40%; real loss starts at hop 7
        var d = Diagnosis.Analyze(Path(h => h == 2 ? 40 : h >= 7 ? 4 : 0), true);
        Assert.Equal("transit", d.Code); Assert.Equal(7, d.Hop);
        Assert.Contains(d.Evidence, e => e.Contains("hop 2") && e.Contains("rate-limits"));
        Assert.Contains(d.Evidence, e => e.Contains("No real packet loss before hop 7"));
    }

    [Fact]
    public void SilentDestinationAnalysesTheLastResponder()
    {
        // The server never answers; everything up to hop 11 is clean.
        var path = Path(h => h == 12 ? 100 : 0);
        var d = Diagnosis.Analyze(path, destReached: false);
        Assert.Equal("ok", d.Code);
        Assert.Contains(d.Evidence, e => e.Contains("does not answer probes"));
        Assert.False(d.DestinationAnswers);
    }

    [Fact]
    public void SilentMiddleHopsAreIgnored()
    {
        var d = Diagnosis.Analyze(Path(h => h is 4 or 6 ? 100 : 0), true);
        Assert.Equal("ok", d.Code);
    }

    [Fact]
    public void NeedsEnoughSamples()
    {
        var d = Diagnosis.Analyze(Path(_ => 50, sent: 8), true);
        Assert.Equal("insufficient", d.Code); Assert.Contains("Collecting data", d.Headline);
        Assert.Equal("insufficient", Diagnosis.Analyze(Array.Empty<HopInput>(), false).Code);
    }

    [Fact]
    public void NothingAnsweringIsReported()
    {
        var d = Diagnosis.Analyze(Path(_ => 100), false);
        Assert.Equal("no_response", d.Code);
    }

    [Fact]
    public void JitterStartingAtTheRouterPointsAtYourSide()
    {
        var d = Diagnosis.Analyze(Path(_ => 0, jitter: _ => 18), true);
        Assert.Equal("local", d.Code); Assert.Equal("yours", d.Side); Assert.Equal("warn", d.Status);
        Assert.Contains("No packet loss", d.Headline);
        Assert.Contains(d.Advice, a => a.Contains("Wi"));
    }

    [Fact]
    public void JitterAppearingLateIsNotYours()
    {
        var d = Diagnosis.Analyze(Path(_ => 0, jitter: h => h >= 7 ? 25 : 0.3), true);
        Assert.Equal("transit", d.Code); Assert.Equal(7, d.Hop);
    }

    [Fact]
    public void HighLatencyIsLocatedAtTheBiggestPersistentJump()
    {
        var d = Diagnosis.Analyze(Path(_ => 0, avg: h => h < 8 ? 5 : 180), true);
        Assert.Equal("latency", d.Code); Assert.Equal(8, d.Hop); Assert.Equal("warn", d.Status);
        var d2 = Diagnosis.Analyze(Path(_ => 0, avg: h => h * 25.0), true); // steady growth: distance, no single jump
        Assert.Equal("latency", d2.Code); Assert.Contains("distance", d2.Headline);
    }

    [Fact]
    public void LowLossIsStillReportedButAsWarning()
    {
        var d = Diagnosis.Analyze(Path(h => h >= 10 ? 2 : 0), true);
        Assert.Equal("server", d.Code); Assert.Equal("warn", d.Status);
    }

    [Fact]
    public void PublicFirstHopHasNoLocalSegment()
    {
        var hops = new List<HopInput>();
        string[] a = { "81.2.69.1", "81.2.69.7", "8.8.4.4", "8.8.8.8" };
        for (int i = 0; i < 4; i++) hops.Add(new HopInput(i + 1, a[i], null, 100, 100, 0, 5 + i, 0.2, 9, null));
        var d = Diagnosis.Analyze(hops, true);
        Assert.DoesNotContain(d.Segments, s => s.Id == "local");
    }

    [Fact]
    public void AsnBoundariesDefineTheIspAndServerSegments()
    {
        var hops = Path(_ => 0).Select(h => h with { Asn = h.Hop switch { <= 4 => null, <= 6 => "AS64500", >= 10 => "AS15169", _ => "AS3356" } }).ToList();
        var d = Diagnosis.Analyze(hops, true);
        var isp = d.Segments.Single(s => s.Id == "isp"); var server = d.Segments.Single(s => s.Id == "server");
        Assert.Equal(6, isp.ToHop);                 // modem/private hops plus the two hops of the ISP's AS
        Assert.True(server.FromHop <= 10);          // extends back over the destination's AS
    }
}

public class FlowTests
{
    [Theory]
    [InlineData("8.8.8.8", IpKind.Public)] [InlineData("1.1.1.1", IpKind.Public)] [InlineData("52.12.34.56", IpKind.Public)]
    [InlineData("10.0.0.5", IpKind.Private)] [InlineData("192.168.1.20", IpKind.Private)] [InlineData("172.20.1.1", IpKind.Private)] [InlineData("100.100.1.1", IpKind.Private)]
    [InlineData("127.0.0.1", IpKind.Loopback)] [InlineData("169.254.3.4", IpKind.LinkLocal)] [InlineData("224.0.0.251", IpKind.Multicast)]
    [InlineData("239.255.255.250", IpKind.Multicast)] [InlineData("255.255.255.255", IpKind.Broadcast)] [InlineData("0.0.0.0", IpKind.Unspecified)]
    [InlineData("::1", IpKind.Loopback)] [InlineData("fe80::1", IpKind.LinkLocal)] [InlineData("ff02::fb", IpKind.Multicast)] [InlineData("fd12::1", IpKind.Private)]
    [InlineData("2001:4860:4860::8888", IpKind.Public)] [InlineData("::ffff:8.8.8.8", IpKind.Public)]
    public void ClassifiesAddresses(string ip, IpKind kind) => Assert.Equal(kind, NetClass.Classify(IPAddress.Parse(ip)));

    [Fact]
    public void FlowRatesUseARollingWindow()
    {
        var f = new Flow(1, "x.exe", 17, "8.8.8.8", 3074, 1_000_000);
        for (int s = 0; s < 20; s++)
            for (int p = 0; p < 30; p++) { f.Add(true, 100, 1_000_000 + s * 1000 + p * 10, 5000); f.Add(false, 50, 1_000_000 + s * 1000 + p * 10, 5000); }
        var now = 1_000_000 + 19_999;
        var r = f.GetRates(now, 10);
        Assert.InRange(r.PpsIn, 28, 32); Assert.InRange(r.PpsOut, 28, 32);
        Assert.InRange(r.BpsIn, 2800, 3200); Assert.InRange(r.BpsOut, 1400, 1600);
        Assert.Equal(600, f.PktIn); Assert.Equal(60_000, f.BytesIn);
        Assert.False(f.TableOnly);
        // Ten seconds of silence later the rate has decayed to zero, but totals stay.
        var later = f.GetRates(now + 15_000, 10);
        Assert.Equal(0, later.Pps); Assert.Equal(600, f.PktIn);
    }

    [Fact]
    public void YoungFlowsAreNotUnderestimated()
    {
        var f = new Flow(1, "x.exe", 17, "8.8.8.8", 1, 5_000);
        for (int i = 0; i < 20; i++) f.Add(true, 100, 5_000 + i * 50, 1);   // 20 packets in one second
        Assert.InRange(f.GetRates(6_000, 10).PpsIn, 15, 21);
    }

    [Fact]
    public void StoreAggregatesPerProcessAndRemote()
    {
        var s = new FlowStore();
        s.Record(10, "cod.exe", 17, "8.8.8.8", 3074, 5000, true, 100, 1000);
        s.Record(10, "cod.exe", 17, "8.8.8.8", 3074, 5000, false, 40, 1010);
        s.Record(10, "cod.exe", 6, "8.8.8.8", 443, 5001, true, 10, 1020);
        s.Record(11, "other.exe", 17, "8.8.8.8", 3074, 5002, true, 10, 1030);
        Assert.Equal(3, s.All.Count(f => f.Remote == "8.8.8.8"));
        var udp = s.All.Single(f => f.Pid == 10 && f.Proto == 17);
        Assert.Equal(140, udp.BytesIn + udp.BytesOut);
        Assert.Equal(0, s.Purge(500));
        Assert.Equal(3, s.Purge(100_000));
    }

    [Fact]
    public void TableOnlyFlowsAreMarked()
    {
        var s = new FlowStore();
        s.Touch(1, "a.exe", 6, "1.2.3.4", 443, 50000, 1000);
        Assert.True(s.All.Single().TableOnly);
        s.Record(1, "a.exe", 6, "1.2.3.4", 443, 50000, true, 10, 1100);
        Assert.False(s.All.Single().TableOnly);
    }

    [Fact]
    public void GameTrafficOutranksWebTraffic()
    {
        var game = EndpointScoring.Score(IpKind.Public, true, false, 40, 20_000, false);
        var idleUdp = EndpointScoring.Score(IpKind.Public, true, false, 3, 500, false);
        var web = EndpointScoring.Score(IpKind.Public, false, true, 60, 900_000, true);
        var lan = EndpointScoring.Score(IpKind.Private, true, false, 100, 1e6, false);
        Assert.Equal(EndpointRole.Game, game.role);
        Assert.Equal(EndpointRole.Udp, idleUdp.role);
        Assert.Equal(EndpointRole.Service, web.role);
        Assert.Equal(EndpointRole.Local, lan.role); Assert.Equal(0, lan.score);
        Assert.True(game.score > idleUdp.score && idleUdp.score > web.score);
    }

    [Fact]
    public void GameCatalogAndRuleKeys()
    {
        Assert.Equal("Call of Duty", GameCatalog.Lookup("COD.exe"));
        Assert.True(GameCatalog.IsKnownGame("valorant-win64-shipping.exe")); Assert.False(GameCatalog.IsKnownGame("notepad.exe"));
        Assert.Equal("cod.exe", TraceMe.Models.AppRule.KeyOf(" COD "));
        Assert.Equal("cod.exe", TraceMe.Models.AppRule.KeyOf("cod.exe"));
        Assert.Throws<ArgumentException>(() => new TraceMe.Models.AppRule { ProcessName = "C:\\x\\cod.exe" }.Normalize());
        Assert.Throws<ArgumentException>(() => new TraceMe.Models.AppRule { ProcessName = "" }.Normalize());
        Assert.Throws<ArgumentException>(() => new TraceMe.Models.AppRule { ProcessName = "bad\nname.exe" }.Normalize());
        Assert.Equal("league of legends.exe", new TraceMe.Models.AppRule { ProcessName = "League of Legends.exe" }.Normalize().Key);
        var r = new TraceMe.Models.AppRule { ProcessName = "cod.exe", MaxServers = 99, MinPps = 0, OnExit = "explode" }.Normalize();
        Assert.Equal(10, r.MaxServers); Assert.Equal(0.5, r.MinPps); Assert.Equal("pause", r.OnExit);
    }
}
