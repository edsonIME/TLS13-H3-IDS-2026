#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""h3_get.py — fetch one URL over HTTP/3 via aioquic, then exit. BENIGN worker unit.

Invoked as a subprocess by benign_clients.py's aioquic-h3 profile. Being a separate
process keeps aioquic's asyncio loop out of the generator's thread pool: one clean QUIC
connection per invocation, which is exactly what a flow-based dataset needs for HTTP/3
(the v1 browser sessions multiplexed everything into 31 flows carrying 7% of the bytes).

    python3 h3_get.py https://blog.lab/?s=lab
Exit 0 on a completed 2xx/3xx/4xx response, 1 on failure. Prints "status bytes seconds".
"""
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


class _H3(QuicConnectionProtocol):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._h3 = H3Connection(self._quic)
        self._done = asyncio.Event()
        self.status = None
        self.nbytes = 0

    def get(self, authority, path):
        sid = self._quic.get_next_available_stream_id()
        self._h3.send_headers(sid, [
            (b":method", b"GET"), (b":scheme", b"https"),
            (b":authority", authority.encode()), (b":path", path.encode()),
        ], end_stream=True)
        self.transmit()

    def quic_event_received(self, event: QuicEvent) -> None:
        for ev in self._h3.handle_event(event):
            if isinstance(ev, HeadersReceived):
                for k, v in ev.headers:
                    if k == b":status":
                        self.status = v.decode()
            elif isinstance(ev, DataReceived):
                self.nbytes += len(ev.data)
                if ev.stream_ended:
                    self._done.set()


async def _run(url, timeout):
    u = urlsplit(url)
    host, port = u.hostname, (u.port or 443)
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    cfg = QuicConfiguration(alpn_protocols=H3_ALPN, is_client=True)
    cfg.verify_mode = ssl.CERT_NONE
    t0 = time.time()
    async with connect(host, port, configuration=cfg, create_protocol=_H3) as cli:
        cli.get(host, path)
        await asyncio.wait_for(cli._done.wait(), timeout=timeout)
        print("{} {} {:.3f}".format(cli.status, cli.nbytes, time.time() - t0))
    return 0


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: h3_get.py URL [timeout]")
    url = sys.argv[1]
    timeout = float(sys.argv[2]) if len(sys.argv) > 2 else 15.0
    host = (urlsplit(url).hostname or "").lower()
    if host not in {"blog.lab", "shop.lab", "10.10.10.11"}:
        sys.exit("REFUSED: {!r} not a lab target".format(host))
    try:
        return asyncio.run(_run(url, timeout))
    except Exception as exc:
        print("FAILED {}".format(repr(exc)[:120]), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
