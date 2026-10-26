@echo off
rem Runs TraceMe with administrator rights so UDP and TCP traces can see every router on the path.
powershell -NoProfile -Command "Start-Process -FilePath '%~dp0TraceMe.exe' -ArgumentList '--open' -Verb RunAs -WorkingDirectory '%~dp0'"
