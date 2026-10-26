using System.Diagnostics;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Jint;
using JintEngine = Jint.Engine;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using TraceMe.Engine;
using TraceMe.Models;
using TraceMe.Services;

namespace TraceMe.Alerts;

public static class AlertActions
{
    static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(15) };

    /// <summary>Replaces {tokens} in a template. With <paramref name="json"/> the values are JSON-string-escaped.</summary>
    public static string Template(string tpl, AlertContext c, bool json = false)
    {
        string E(string s) => json ? JsonEncodedText.Encode(s).ToString() : s;
        return tpl
            .Replace("{message}", E(c.Message)).Replace("{rule}", E(c.Rule.Name)).Replace("{target}", E(c.Target))
            .Replace("{host}", E(c.Host)).Replace("{hop}", c.Hop.ToString()).Replace("{hopHost}", E(c.HopHost))
            .Replace("{metric}", E(c.Metric)).Replace("{value}", c.Value.ToString("0.##", System.Globalization.CultureInfo.InvariantCulture))
            .Replace("{threshold}", c.Threshold.ToString("0.##", System.Globalization.CultureInfo.InvariantCulture))
            .Replace("{state}", E(c.State)).Replace("{time}", c.Time.ToString("o"));
    }

    public static async Task RunAsync(Hub hub, AlertContext c, AlertAction a)
    {
        switch (a.Type)
        {
            case "email": await Email(hub, c, a); break;
            case "webhook": await Webhook(c, a); break;
            case "exec": await Exec(hub, c, a); break;
            case "script": Script(hub, c, a); break;
        }
    }

    static async Task Email(Hub hub, AlertContext c, AlertAction a)
    {
        var smtp = hub.Settings.Current.Smtp;
        if (string.IsNullOrWhiteSpace(smtp.Host)) throw new InvalidOperationException("SMTP server is not configured (Settings → Email).");
        var to = (a.To ?? "").Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries);
        if (to.Length == 0) throw new InvalidOperationException("No email recipient.");
        var msg = new MimeMessage();
        msg.From.Add(MailboxAddress.Parse(string.IsNullOrWhiteSpace(smtp.From) ? (string.IsNullOrWhiteSpace(smtp.User) ? "traceme@localhost" : smtp.User) : smtp.From));
        foreach (var t in to) msg.To.Add(MailboxAddress.Parse(t));
        msg.Subject = Template(string.IsNullOrWhiteSpace(a.Subject) ? "[TraceMe] {message}" : a.Subject, c);
        msg.Body = new TextPart("plain")
        {
            Text = Template(string.IsNullOrWhiteSpace(a.Body)
                ? "{message}\n\nTarget: {target} ({host})\nHop: {hop} {hopHost}\nMetric: {metric} = {value} (threshold {threshold})\nState: {state}\nTime: {time}\n"
                : a.Body, c)
        };
        await SendMail(smtp, msg);
    }

    public static async Task SendMail(SmtpSettings smtp, MimeMessage msg)
    {
        using var client = new SmtpClient { Timeout = 15000 };
        var sec = smtp.Security switch { "ssl" => SecureSocketOptions.SslOnConnect, "none" => SecureSocketOptions.None, _ => SecureSocketOptions.StartTls };
        await client.ConnectAsync(smtp.Host, smtp.Port, sec);
        if (!string.IsNullOrEmpty(smtp.User)) await client.AuthenticateAsync(smtp.User, smtp.Password);
        await client.SendAsync(msg);
        await client.DisconnectAsync(true);
    }

    static async Task Webhook(AlertContext c, AlertAction a)
    {
        if (!Uri.TryCreate(a.Url, UriKind.Absolute, out var uri) || (uri.Scheme != "http" && uri.Scheme != "https"))
            throw new InvalidOperationException("Webhook URL must be http(s).");
        HttpContent content;
        if (string.IsNullOrWhiteSpace(a.Body))
            content = JsonContent.Create(new
            {
                message = c.Message, rule = c.Rule.Name, target = c.Target, host = c.Host, hop = c.Hop, hopHost = c.HopHost,
                metric = c.Metric, value = c.Value, threshold = c.Threshold, state = c.State, time = c.Time
            });
        else content = new StringContent(Template(a.Body, c, json: true), Encoding.UTF8, "application/json");
        using var resp = await Http.PostAsync(uri, content);
        if (!resp.IsSuccessStatusCode) throw new InvalidOperationException($"webhook returned {(int)resp.StatusCode}");
    }

    /// <summary>Runs a program (no shell). Arguments are split first and tokens substituted afterwards, so alert text cannot inject extra arguments.</summary>
    static async Task Exec(Hub hub, AlertContext c, AlertAction a)
    {
        if (!hub.Settings.Current.AllowExec) throw new InvalidOperationException("Running programs is disabled (Settings → Security → Allow alert actions to run programs).");
        if (string.IsNullOrWhiteSpace(a.Path)) throw new InvalidOperationException("No program path.");
        var psi = new ProcessStartInfo(a.Path) { UseShellExecute = false, CreateNoWindow = true };
        foreach (var arg in SplitArgs(a.Args ?? "")) psi.ArgumentList.Add(Template(arg, c));
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("could not start process");
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try { await p.WaitForExitAsync(cts.Token); }
        catch (OperationCanceledException) { try { p.Kill(true); } catch { } throw new InvalidOperationException("program timed out after 30 s and was stopped"); }
    }

    public static List<string> SplitArgs(string s)
    {
        var res = new List<string>(); var sb = new StringBuilder(); bool inQ = false, any = false;
        foreach (var ch in s)
        {
            if (ch == '"') { inQ = !inQ; any = true; }
            else if (char.IsWhiteSpace(ch) && !inQ) { if (any || sb.Length > 0) { res.Add(sb.ToString()); sb.Clear(); any = false; } }
            else sb.Append(ch);
        }
        if (any || sb.Length > 0) res.Add(sb.ToString());
        return res;
    }

    static void Script(Hub hub, AlertContext c, AlertAction a)
    {
        if (string.IsNullOrWhiteSpace(a.Script)) return;
        var engine = ScriptHost.Create();
        engine.SetValue("Target", c.Target); engine.SetValue("Host", c.Host); engine.SetValue("Hop", c.Hop);
        engine.SetValue("HopHost", c.HopHost); engine.SetValue("Metric", c.Metric); engine.SetValue("Value", c.Value);
        engine.SetValue("Threshold", c.Threshold); engine.SetValue("State", c.State); engine.SetValue("Message", c.Message);
        engine.SetValue("Rule", c.Rule.Name);
        engine.SetValue("log", new Action<object?>(x => hub.Bus.Publish(c.TargetId == "test" ? null : c.TargetId, "info", "info", "[script] " + x, toast: false)));
        engine.SetValue("notify", new Action<object?>(x => hub.Bus.Publish(c.TargetId == "test" ? null : c.TargetId, "alert", "warn", "[script] " + x, toast: true)));
        engine.Execute("(function(){\n" + a.Script + "\n})()");
    }
}
