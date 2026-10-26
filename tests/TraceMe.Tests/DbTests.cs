using TraceMe.Data;
using TraceMe.Models;

namespace TraceMe.Tests;

public sealed class DbFixture : IDisposable
{
    public string Dir = Path.Combine(Path.GetTempPath(), "traceme-test-" + Guid.NewGuid().ToString("n"));
    public Db Db;
    public DbFixture() => Db = new Db(Path.Combine(Dir, "t.db"));
    public void Dispose() { Db.Dispose(); try { Directory.Delete(Dir, true); } catch { } }
}

public class DbTests : IClassFixture<DbFixture>
{
    readonly Db db;
    const long T0 = 1_700_000_000_000;
    public DbTests(DbFixture f) => db = f.Db;

    [Fact]
    public async Task WindowStatsTimelineAndExportAgree()
    {
        // 100 rounds, 1 s apart: hop 1 always 5 ms; hop 2 alternates 10/20 ms with every 10th probe lost.
        for (int i = 0; i < 100; i++)
        {
            db.AddSample("w1", T0 + i * 1000, 1, 5);
            db.AddSample("w1", T0 + i * 1000, 2, i % 10 == 9 ? null : (i % 2 == 0 ? 10 : 20));
        }
        db.AddRoute("w1", T0, 1, "10.0.0.1"); db.AddRoute("w1", T0, 2, "10.0.0.2");
        db.AddRoute("w1", T0 + 50_000, 2, "10.0.0.99");
        await db.FlushAsync();

        var stats = db.WindowStats("w1", new[] { 1, 2 }, T0, T0 + 99_000);
        Assert.Equal(100, stats[1].Sent); Assert.Equal(5, stats[1].Avg); Assert.Equal(0, stats[1].LossPct);
        Assert.Equal(100, stats[2].Sent); Assert.Equal(90, stats[2].Recv); Assert.Equal(10, stats[2].LossPct);
        Assert.Equal(10, stats[2].Min); Assert.Equal(20, stats[2].Max);

        // A sub-window only counts its own samples.
        var part = db.WindowStats("w1", new[] { 1 }, T0 + 10_000, T0 + 19_000);
        Assert.Equal(10, part[1].Sent);

        var tl = db.Timeline("w1", 2, T0, T0 + 100_000, 10);
        Assert.Equal(10, tl.Length);
        Assert.All(tl, b => Assert.Equal(10, b.N));
        Assert.All(tl, b => Assert.Equal(9, b.R));
        Assert.All(tl, b => Assert.NotNull(b.Jit));

        var sw = new StringWriter();
        db.ExportCsv("w1", new[] { 2 }, T0, T0 + 99_000, sw);
        var lines = sw.ToString().TrimEnd().Split('\n');
        Assert.Equal(101, lines.Length);
        Assert.Contains(",2,10.0.0.2,10.000,0", lines[1]);
        Assert.Contains(",2,10.0.0.99,", lines[^1]); // the address in force at that time, taken from the route history
        Assert.Contains(lines, l => l.EndsWith(",,1"));
    }

    [Fact]
    public async Task RouteHistoryReportsEachDistinctPath()
    {
        db.AddRoute("r1", T0, 1, "A"); db.AddRoute("r1", T0, 2, "B"); db.AddRoute("r1", T0, 3, "C");
        db.AddRoute("r1", T0 + 60_000, 2, "B2");
        db.AddRoute("r1", T0 + 120_000, 2, "B"); db.AddRoute("r1", T0 + 120_000, 3, "C2");
        await db.FlushAsync();
        var paths = db.RoutePaths("r1", T0 - 1000, T0 + 200_000);
        Assert.Equal(3, paths.Count);
        Assert.Equal(new[] { "A", "B", "C" }, paths[0].Hops);
        Assert.Equal(new[] { "A", "B2", "C" }, paths[1].Hops);
        Assert.Equal(new[] { "A", "B", "C2" }, paths[2].Hops);
        // A window starting later still knows the path that was in force.
        var late = db.RoutePaths("r1", T0 + 90_000, T0 + 200_000);
        Assert.Equal(new[] { "A", "B2", "C" }, late[0].Hops);
    }

    [Fact]
    public async Task EventsCommentsAndTargetsRoundTrip()
    {
        var e = new EventRecord { T = T0, Tid = "e1", Type = "alert", Severity = "warn", Message = "boom" };
        db.InsertEvent(e); Assert.True(e.Id > 0);
        db.InsertEvent(new EventRecord { T = T0 + 1, Tid = "e1", Type = "route", Severity = "info", Message = "moved" });
        db.InsertEvent(new EventRecord { T = T0 + 2, Tid = "e2", Type = "alert", Severity = "info", Message = "other" });
        Assert.Equal(2, db.Events("e1", null, null, 10).Count);
        Assert.Single(db.Events("e1", "route", null, 10));
        Assert.Equal("moved", db.Events("e1", null, null, 10)[0].Message); // newest first
        Assert.Single(db.Events("e1", null, e.Id + 1, 10));                // paging with "before"
        Assert.Equal(2, db.EventsBetween("e1", T0, T0 + 10).Count);
        db.ClearEvents("e1"); Assert.Empty(db.Events("e1", null, null, 10)); Assert.NotEmpty(db.Events("e2", null, null, 10));

        var c = db.AddComment("c1", T0, "hello");
        Assert.Single(db.Comments("c1", T0 - 1, T0 + 1));
        Assert.False(db.DeleteComment("other", c.Id)); Assert.True(db.DeleteComment("c1", c.Id));

        var t = new TargetConfig { Id = "tt1", Host = "example.com", Method = "tcp", Port = 443 }.Normalize();
        db.SaveTarget(t);
        var back = db.LoadTargets().Single(x => x.Id == "tt1");
        Assert.Equal("tcp", back.Method); Assert.Equal(443, back.Port);
        db.AddSample("tt1", T0, 1, 1); await db.FlushAsync(); db.DeleteTarget("tt1");
        Assert.DoesNotContain(db.LoadTargets(), x => x.Id == "tt1");
        Assert.Equal(0, db.CountSamples("tt1", 0, long.MaxValue));
    }

    [Fact]
    public async Task PurgeRemovesOnlyOldSamples()
    {
        long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        db.AddSample("p1", now - 10L * 86_400_000, 1, 1); db.AddSample("p1", now - 1000, 1, 2);
        await db.FlushAsync();
        db.Purge(7);
        Assert.Equal(1, db.CountSamples("p1", 0, long.MaxValue));
    }

    [Fact]
    public void SettingsAndAlertsPersist()
    {
        db.SetSetting("k", "v1"); db.SetSetting("k", "v2");
        Assert.Equal("v2", db.GetSetting("k")); Assert.Null(db.GetSetting("missing"));
        var a = new AlertRule { Id = "al1", Name = "x" }.Normalize();
        db.SaveAlert(a); Assert.Contains(db.LoadAlerts(), x => x.Id == "al1");
        db.DeleteAlert("al1"); Assert.DoesNotContain(db.LoadAlerts(), x => x.Id == "al1");
    }
}
