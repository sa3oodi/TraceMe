# Contributing to TraceMe

Thanks for helping. TraceMe is MIT-licensed; by contributing you agree your work is released under the same license.

## Build and test

Needs the [.NET 10 SDK](https://dotnet.microsoft.com/download) on Windows (the probes, kernel network trace and installer are Windows-only).

```
dotnet build src
dotnet test tests/TraceMe.Tests
cd src && dotnet run            # http://127.0.0.1:5055
```

UDP/TCP traces and the Apps section need an elevated terminal (see the README). The web UI is plain ES modules in
`src/wwwroot` - no bundler, edit and reload.

## Installer

```
winget install JRSoftware.InnoSetup
powershell installer\build.ps1      # -> artifacts\TraceMe-Setup-<version>.exe
```

## Guidelines

- Keep changes focused; add or update a test for logic changes (`tests/TraceMe.Tests`).
- Match the surrounding style. The UI uses no framework or build step - keep it that way.
- Security rules stay on: loopback-only by default, CSRF header on writes, secrets masked, the exec alert action off by default,
  AS-owner lookup opt-in. Changes that weaken one need a clear reason in the pull request.
- Do not claim behaviour you have not tested; say what was and was not verified in the pull request.
- Do not add code or assets taken from PingPlotter or other proprietary software.

## Reporting problems

Open an issue with the Windows version, whether TraceMe ran as administrator, the trace method, and (for Apps) whether the
status line says *live* or *limited mode*. Remove IP addresses you do not want to share.
