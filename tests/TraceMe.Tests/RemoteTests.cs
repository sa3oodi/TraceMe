using System.Net;
using TraceMe.Services;
using Xunit;

namespace TraceMe.Tests;

public class RemoteTests
{
    [Fact]
    public void Tokens_are_long_unique_and_url_safe()
    {
        var a = RemoteAccess.NewToken(); var b = RemoteAccess.NewToken();
        Assert.NotEqual(a, b);
        Assert.Matches("^[A-Za-z0-9_-]{24}$", a);
        Assert.True(RemoteAccess.ValidToken(a));
        Assert.False(RemoteAccess.ValidToken("short"));
        Assert.False(RemoteAccess.ValidToken(null));
    }

    [Theory]
    [InlineData("192.168.0.5", true)]
    [InlineData("10.1.2.3", true)]
    [InlineData("172.16.0.1", true)]
    [InlineData("172.31.255.1", true)]
    [InlineData("172.32.0.1", false)]
    [InlineData("100.64.1.1", true)]
    [InlineData("8.8.8.8", false)]
    public void Private_ranges(string ip, bool expected) => Assert.Equal(expected, RemoteAccess.IsPrivate(IPAddress.Parse(ip)));

    [Fact]
    public void Url_puts_the_token_in_the_fragment_only()
    {
        Assert.Equal("http://192.168.0.5:5055/", RemoteAccess.Url("192.168.0.5", 5055));
        Assert.Equal("http://192.168.0.5:5055/#t=ab-_c", RemoteAccess.Url("192.168.0.5", 5055, "ab-_c"));
    }

    [Fact]
    public void Config_round_trips_and_survives_garbage()
    {
        var dir = Path.Combine(Path.GetTempPath(), "tm-remote-unit-" + Guid.NewGuid().ToString("n"));
        var old = Environment.GetEnvironmentVariable("TRACEME_DATA");
        Environment.SetEnvironmentVariable("TRACEME_DATA", dir);
        try
        {
            Assert.False(RemoteAccess.Load().Enabled);
            RemoteAccess.Save(new RemoteConfig { Enabled = true, Token = "0123456789abcdef0123" });
            var c = RemoteAccess.Load();
            Assert.True(c.Enabled); Assert.Equal("0123456789abcdef0123", c.Token);
            File.WriteAllText(Path.Combine(dir, "remote.json"), "{ not json");
            Assert.False(RemoteAccess.Load().Enabled);
        }
        finally { Environment.SetEnvironmentVariable("TRACEME_DATA", old); try { Directory.Delete(dir, true); } catch { } }
    }
}
