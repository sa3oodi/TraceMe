using System.Globalization;
using System.Net;
using TraceMe.Engine;

namespace TraceMe.Apps;

public sealed record HopInput(int Hop, string? Address, string? Name, int Sent, int Recv, double LossPct, double? Avg, double? Jitter, double? Max, string? Asn);

public sealed class DiagnosisOptions
{
    public double LossWarn = 1, LossBad = 5, JitterWarn = 10, LatencyWarn = 100, LatencyBad = 250;
    public int MinSamples = 20;
}

public sealed class DiagSegment
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public int FromHop { get; set; }
    public int ToHop { get; set; }
    public double? Avg { get; set; }
    public double? Jitter { get; set; }
    public double LossPct { get; set; }
    /// <summary>good | warn | bad | unknown</summary>
    public string Status { get; set; } = "unknown";
    public bool Culprit { get; set; }
}

public sealed class DiagnosisResult
{
    /// <summary>ok | local | isp | transit | server | latency | insufficient | no_response</summary>
    public string Code { get; set; } = "insufficient";
    /// <summary>none | yours | isp | internet | server | unknown</summary>
    public string Side { get; set; } = "unknown";
    /// <summary>ok | warn | bad | unknown</summary>
    public string Status { get; set; } = "unknown";
    public string Headline { get; set; } = "";
    public string Confidence { get; set; } = "low";
    public int? Hop { get; set; }
    public List<string> Evidence { get; set; } = new();
    public List<string> Advice { get; set; } = new();
    public List<DiagSegment> Segments { get; set; } = new();
    public int Samples { get; set; }
    public bool DestinationAnswers { get; set; }
    public double? DestLoss { get; set; }
    public double? DestAvg { get; set; }
    public double? DestJitter { get; set; }
    public double? DestMax { get; set; }
    public double? Mos { get; set; }
}

/// <summary>
/// Decides where along a traced path a problem sits. The central rule: loss at an intermediate hop only counts when the hops
/// after it lose packets too — a router that merely rate-limits its ICMP replies shows loss that disappears further along.
/// </summary>
public static class Diagnosis
{
    static string Fmt(double v, int d = 1) => v.ToString("0." + new string('#', d), CultureInfo.InvariantCulture);

    static bool IsPrivate(string? addr) =>
        addr != null && IPAddress.TryParse(addr, out var ip) && NetClass.Classify(ip) is IpKind.Private or IpKind.LinkLocal or IpKind.Loopback;

    static string Label(HopInput h) => h.Address == null ? $"hop {h.Hop}" : $"hop {h.Hop} ({(string.IsNullOrEmpty(h.Name) ? h.Address : h.Name)})";

    public static DiagnosisResult Analyze(IReadOnlyList<HopInput> all, bool destReached, DiagnosisOptions? opt = null)
    {
        var o = opt ?? new DiagnosisOptions();
        var r = new DiagnosisResult { DestinationAnswers = destReached };
        var hops = all.OrderBy(h => h.Hop).ToList();
        r.Samples = hops.Select(h => h.Sent).DefaultIfEmpty(0).Max();
        if (hops.Count == 0 || r.Samples < o.MinSamples)
        {
            r.Headline = $"Collecting data… {r.Samples} of {o.MinSamples} traces needed for a verdict.";
            return r;
        }
        var responders = hops.Where(h => h.Recv > 0).ToList();
        if (responders.Count == 0)
        {
            r.Code = "no_response"; r.Status = "warn";
            r.Headline = "No router or server answered the probes.";
            r.Evidence.Add("Every hop timed out. Either there is no connectivity, or ICMP replies are blocked on this path.");
            r.Advice.Add("Check that you are online, then try the UDP or TCP trace method (some networks drop ICMP).");
            return r;
        }

        int effHop = destReached ? hops[^1].Hop : responders[^1].Hop;
        var eff = hops.Where(h => h.Hop <= effHop).ToList();
        var dest = eff[^1];
        r.DestLoss = Math.Round(dest.LossPct, 2); r.DestAvg = dest.Avg; r.DestJitter = dest.Jitter; r.DestMax = dest.Max;
        if (dest.Avg is double da && dest.Recv >= 2) r.Mos = Mos.Compute(da, dest.Jitter ?? 0, dest.LossPct);
        if (!destReached)
            r.Evidence.Add($"The destination does not answer probes, so the analysis covers the path up to {Label(dest)}. Game servers often ignore ICMP — a UDP or TCP trace may reach them.");

        int half = Math.Max(5, o.MinSamples / 2);
        var segs = BuildSegments(eff, o, dest);

        // ---- packet loss: first hop whose loss persists to everything after it
        HopInput? lossStart = null;
        foreach (var h in eff)
        {
            if (h.Sent < half || h.LossPct < o.LossWarn) continue;
            if (h.Recv == 0 && h.Hop != dest.Hop) continue; // a silent hop is a filter, not evidence
            var later = eff.Where(x => x.Hop > h.Hop && x.Recv > 0 && x.Sent >= half).ToList();
            if (later.Count == 0) { if (h.Hop == dest.Hop) lossStart = h; break; }
            double need = Math.Max(o.LossWarn, h.LossPct * 0.5);
            if (later.All(x => x.LossPct >= need)) { lossStart = h; break; }
        }

        // hops that show loss which does not persist: rate limiting, worth telling the user to ignore
        foreach (var h in eff.Where(h => h.Recv > 0 && h.Sent >= half && h.LossPct >= Math.Max(10, o.LossWarn * 3) && (lossStart == null || h.Hop < lossStart.Hop)))
            r.Evidence.Add($"{Label(h)} shows {Fmt(h.LossPct)}% loss, but the hops after it do not — that router just rate-limits its replies. It is not real packet loss.");

        string? segOfLoss = null;
        if (lossStart != null)
        {
            segOfLoss = SegmentOf(segs, lossStart.Hop);
            var seg = segs.FirstOrDefault(s => s.Id == segOfLoss);
            if (seg != null) { seg.Culprit = true; seg.Status = dest.LossPct >= o.LossBad ? "bad" : "warn"; }
            var after = eff.Where(x => x.Hop > lossStart.Hop && x.Recv > 0).ToList();
            r.Hop = lossStart.Hop;
            r.Evidence.Insert(0, after.Count > 0
                ? $"Packet loss begins at {Label(lossStart)} ({Fmt(lossStart.LossPct)}%) and continues through the remaining hops ({Fmt(after.Min(x => x.LossPct))}–{Fmt(after.Max(x => x.LossPct))}%)."
                : $"Packet loss of {Fmt(lossStart.LossPct)}% is measured at {Label(lossStart)}.");
            if (lossStart.Hop > 1 && eff.Any(x => x.Hop < lossStart.Hop && x.Recv > 0)) // by construction no earlier hop has loss that persists
                r.Evidence.Add($"No real packet loss before hop {lossStart.Hop}: the path up to there is fine.");
            r.Code = segOfLoss switch { "local" => "local", "isp" => "isp", "transit" => "transit", _ => "server" };
            r.Side = r.Code switch { "local" => "yours", "isp" => "isp", "transit" => "internet", _ => "server" };
            r.Status = dest.LossPct >= o.LossBad ? "bad" : "warn";
            string where = Label(lossStart);
            r.Headline = r.Code switch
            {
                "local" => $"The problem is on your side: packet loss starts at your own router/PC — {where}.",
                "isp" => $"The problem is in your ISP's network: packet loss starts at {where}.",
                "transit" => $"The problem is on the internet between your ISP and the server: packet loss starts at {where}.",
                _ => lossStart.Hop == dest.Hop && !destReached
                    ? $"Packet loss appears only at the end of the path — {where}: the server or its network, not your connection."
                    : $"Your connection is fine up to the server's network: packet loss appears at {where}, close to the server."
            };
            r.Advice.AddRange(AdviceFor(r.Code, lossStart));
            r.Confidence = r.Samples >= 100 && dest.LossPct >= o.LossWarn * 2 ? "high" : r.Samples >= 50 ? "medium" : "low";
        }

        // ---- jitter
        HopInput? jitterStart = null;
        if (dest.Jitter is double dj && dj >= o.JitterWarn)
        {
            foreach (var h in eff.Where(h => h.Recv >= half && (h.Jitter ?? 0) >= o.JitterWarn * 0.6))
            {
                var later = eff.Where(x => x.Hop > h.Hop && x.Recv >= half && x.Jitter != null).ToList();
                if (later.All(x => x.Jitter >= h.Jitter * 0.6)) { jitterStart = h; break; }
            }
            jitterStart ??= dest;
        }
        if (lossStart == null && jitterStart != null)
        {
            var seg = segs.FirstOrDefault(s => s.Id == SegmentOf(segs, jitterStart.Hop));
            if (seg != null) { seg.Culprit = true; seg.Status = "warn"; }
            r.Hop = jitterStart.Hop;
            r.Code = seg?.Id switch { "local" => "local", "isp" => "isp", "transit" => "transit", _ => "server" };
            r.Side = r.Code switch { "local" => "yours", "isp" => "isp", "transit" => "internet", _ => "server" };
            r.Status = "warn";
            r.Evidence.Insert(0, $"Latency is unstable (jitter {Fmt(dest.Jitter!.Value)} ms at the destination) and the instability starts at {Label(jitterStart)} ({Fmt(jitterStart.Jitter ?? 0)} ms).");
            r.Headline = r.Code switch
            {
                "local" => $"No packet loss, but your connection is unstable: jitter starts at your own router/PC — {Label(jitterStart)} — usually Wi‑Fi interference or a busy network.",
                "isp" => $"No packet loss, but latency is unstable from {Label(jitterStart)} — your ISP's network.",
                "transit" => $"No packet loss, but latency is unstable from {Label(jitterStart)} on the internet path.",
                _ => $"No packet loss, but latency is unstable near the server ({Label(jitterStart)})."
            };
            r.Advice.AddRange(AdviceFor(r.Code == "local" ? "jitter_local" : r.Code, jitterStart));
            r.Confidence = r.Samples >= 100 ? "medium" : "low";
        }

        // ---- plain high latency
        if (lossStart == null && jitterStart == null && dest.Avg is double avg && avg >= o.LatencyWarn)
        {
            r.Code = "latency"; r.Side = "unknown"; r.Status = avg >= o.LatencyBad ? "bad" : "warn";
            var rs = eff.Where(h => h.Recv > 0 && h.Avg != null).ToList();
            HopInput? jump = null; double best = 0;
            for (int i = 1; i < rs.Count; i++)
            {
                double d = rs[i].Avg!.Value - rs[i - 1].Avg!.Value;
                if (d > best && rs.Skip(i).All(x => x.Avg >= rs[i].Avg * 0.8)) { best = d; jump = rs[i]; } // persistent step
            }
            if (jump != null && best >= Math.Max(25, avg * 0.3)) // a real step, not just steady growth with distance
            {
                var seg = segs.FirstOrDefault(s => s.Id == SegmentOf(segs, jump.Hop));
                if (seg != null) { seg.Culprit = true; seg.Status = "warn"; }
                r.Hop = jump.Hop;
                r.Evidence.Insert(0, $"Latency jumps by {Fmt(best, 0)} ms at {Label(jump)} and stays high from there.");
                r.Headline = $"No packet loss, but latency to the server is high ({Fmt(avg, 0)} ms); most of it is added at {Label(jump)}.";
            }
            else r.Headline = $"No packet loss, but latency to the server is high ({Fmt(avg, 0)} ms) all along the path — likely distance to the server.";
            r.Advice.Add("A long distance adds latency that nothing on your side can fix; choose a closer server or region in the game if possible.");
            r.Confidence = "medium";
        }

        if (r.Code == "insufficient")
        {
            r.Code = "ok"; r.Side = "none"; r.Status = "ok";
            r.Headline = "No packet loss detected — your connection to this server looks healthy.";
            r.Confidence = r.Samples >= 100 ? "high" : "medium";
            if (dest.Avg != null) r.Evidence.Add($"Latency {Fmt(dest.Avg.Value)} ms average, {Fmt(dest.Max ?? dest.Avg.Value)} ms worst, jitter {Fmt(dest.Jitter ?? 0)} ms over {dest.Sent} samples.");
            r.Advice.Add("If you still see lag or rubber-banding in game, the cause is probably not the network path (try the game's own network graph, or the server's load).");
        }

        r.Segments = segs;
        return r;
    }

    static IEnumerable<string> AdviceFor(string code, HopInput h)
    {
        switch (code)
        {
            case "local":
                yield return "Use a wired (Ethernet) connection instead of Wi‑Fi, or move closer to the router.";
                yield return "Restart the router and close uploads/streams on other devices — saturated upload causes loss and lag spikes.";
                yield return "If it persists with a cable, replace the cable or router.";
                break;
            case "jitter_local":
                yield return "Jitter at the first hop is typical of Wi‑Fi interference or a busy network: switch to Ethernet or a 5 GHz channel.";
                yield return "Pause downloads and uploads on other devices while gaming.";
                break;
            case "isp":
                yield return "Restart your modem; if the loss stays, contact your ISP and send them this report.";
                yield return "Check whether it happens at certain times only (evening congestion) — the timeline shows when.";
                break;
            case "transit":
                yield return "This is a routing or peering problem between your ISP and the server; you can report it to your ISP, who can sometimes reroute.";
                yield return "A VPN or gaming-route service that uses a different path can help.";
                break;
            default:
                yield return "Your connection is not the cause. Try another server/region, or wait — the server or its hosting network is dropping packets.";
                yield return "If the destination only drops ICMP, repeat the trace with the UDP or TCP method to be sure.";
                break;
        }
    }

    static string SegmentOf(List<DiagSegment> segs, int hop) =>
        segs.FirstOrDefault(s => hop >= s.FromHop && hop <= s.ToHop)?.Id ?? "transit";

    /// <summary>Splits the path into: your PC/router (hop 1), ISP network, the internet in between, and the server's own network (last hops).</summary>
    static List<DiagSegment> BuildSegments(List<HopInput> eff, DiagnosisOptions o, HopInput dest)
    {
        int n = eff.Count;
        var segs = new List<DiagSegment>();
        if (n == 0) return segs;
        int localEnd = eff[0].Address == null || IsPrivate(eff[0].Address) ? 0 : -1;
        int serverStart = Math.Max(localEnd + 1, n - (n >= 9 ? 3 : n >= 4 ? 2 : 1)); // the destination's own network is usually the last 2–3 hops
        if (dest.Asn != null)
            while (serverStart - 1 > localEnd + 1 && eff[serverStart - 1].Asn == dest.Asn && n - serverStart < 4) serverStart--;
        int i = localEnd + 1;
        while (i < serverStart && (eff[i].Address == null || IsPrivate(eff[i].Address))) i++;   // modem / carrier-grade NAT hops
        int ispEnd = i - 1;
        if (i < serverStart)
        {
            string? asn0 = eff[i].Asn; int j = i;
            while (j < serverStart && ((asn0 != null && eff[j].Asn == asn0) || (asn0 == null && j - i < 2))) j++;
            ispEnd = Math.Max(j, i + 1) - 1;
        }
        ispEnd = Math.Min(ispEnd, serverStart - 1);

        void Add(string id, string name, int from, int to)
        {
            if (to < from) return;
            var hs = eff.Skip(from).Take(to - from + 1).ToList();
            var rep = hs.LastOrDefault(h => h.Recv > 0);
            segs.Add(new DiagSegment
            {
                Id = id, Name = name, FromHop = hs[0].Hop, ToHop = hs[^1].Hop,
                Avg = rep?.Avg, Jitter = rep?.Jitter, LossPct = Math.Round(rep?.LossPct ?? 0, 2),
                Status = rep == null ? "unknown" : "good"
            });
        }
        Add("local", "Your PC & router", 0, localEnd);
        Add("isp", "Your ISP", localEnd + 1, ispEnd);
        Add("transit", "The internet", ispEnd + 1, serverStart - 1);
        Add("server", "Game server", serverStart, n - 1);
        return segs;
    }
}
