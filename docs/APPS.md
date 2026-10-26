# Apps — trace the servers of a program, and find out whether it is your side

The manual workflow this replaces: Task Manager → Resource Monitor → Network → pick `cod.exe` → copy the server IP → paste it
into a traceroute tool → work out which hop to blame. TraceMe does all of that continuously and tells you the answer.

## Using it

1. Open **Apps**. Every program with network activity is listed with its traffic and how many *likely game servers* it talks to.
2. Open the program (or press **+ Watch an app** and type `cod.exe`; the list of known games is suggested).
3. Switch **Auto-trace** on. From then on, whenever that program runs and starts exchanging game traffic with a server,
   TraceMe creates a trace for it, and shows a verdict like *"The problem is on your side: packet loss starts at your own router/PC"*.
4. When the program closes, the session is saved with a verdict and a printable **report**. Sessions are listed on the app's page.

You can also trace any endpoint by hand (**Trace ▾** → ICMP / UDP / TCP) and every normal target page now has the same diagnosis panel.

## How the servers are found

| Source | Needs admin | What it gives |
|---|---|---|
| **Kernel network trace (ETW)** — the same data Resource Monitor shows | yes | per-process TCP **and UDP** flows with remote IP, port, bytes and packets, both directions |
| Connection table (`GetExtendedTcpTable`) | no | established TCP connections per process, no counters — UDP games are invisible |

Online games use UDP, which has no connection table, which is why live capture needs administrator rights. Without them the page
says so (*Limited mode*) and offers to restart elevated.

Remote endpoints are grouped per IP and scored (`EndpointScoring`): a **public UDP endpoint with a sustained packet rate** (≥ 8 packets/s
over 10 s) is a *game server*; slower UDP is *UDP traffic*; TCP to ports 80/443 is *web/service*; private ranges, multicast and
loopback never qualify. A watch rule traces the best-scoring endpoints (default 3, at least 5 packets/s); when all slots are in use a
server that has been silent for two minutes is paused and replaced. TraceMe's own probes are excluded from the list.

## How the verdict is reached

`Diagnosis.Analyze` works on the per-hop statistics of a trace over a window (last 5 minutes, the whole session, or any period you select):

1. **Real loss vs. rate-limiting.** A hop's loss counts only if the hops *after* it lose packets too (at least half as much). Routers that
   deprioritise ICMP replies show large loss that vanishes further along — the classic false alarm — and are reported as
   *"not real packet loss"*. Silent hops (100 % loss, no address) are firewalls, not evidence.
2. **Where it starts.** The first hop with persistent loss is placed in a segment: *Your PC & router* (hop 1), *Your ISP* (modem /
   carrier-grade-NAT hops and the first public hops, or the first AS when AS lookup is on), *The internet* in between, and *Game server*
   (the last 2–3 hops, extended over the destination's AS when known). The segment gives the side: **yours / ISP / internet / server**.
3. **Jitter and latency** are checked the same way when there is no loss (jitter that begins at your router is typically Wi‑Fi; a big
   persistent step in latency is located; steady growth is just distance).
4. **Confidence** depends on sample count and loss size. Nothing is concluded before 20 traces.

If the server never answers probes (common for game servers) the analysis covers the path up to the last responding hop and says so;
switch the watch rule to UDP/TCP with *Probe the port the game actually uses* to get closer.

## Limits worth knowing

- The trace measures the **path**, not the game's own connection: game traffic may take a different route than ICMP (load balancing),
  and a server can drop packets while the network is fine. A healthy verdict means *the network path shows no loss*, not that the game
  cannot lag for other reasons.
- Loss that only exists in the direction *from* the server cannot be separated from loss *to* it by a round-trip probe.
- Known-game names are a best-effort list; any executable can be watched by name. The capture was verified with a stand-in program that
  behaves like a game (steady UDP to a server plus a TCP connection); it has not been run against a real commercial game or its anti-cheat.
- Reports and sessions are stored locally; nothing is uploaded. Host names come from reverse DNS; AS owners only when you enable the
  opt-in lookup (it sends hop IP addresses to Team Cymru).

## API

`GET /api/apps[?all=true]` · `GET /api/apps/{exe}` · `POST /api/apps/{exe}/trace` · `POST /api/apps/{exe}/watch` ·
`GET|POST|PUT|DELETE /api/apps/rules` · `POST /api/apps/{exe}/session/stop` · `GET /api/apps/sessions[/{id}[/report]]` ·
`GET /api/targets/{id}/diagnosis[?window=300|from=&to=]`.
