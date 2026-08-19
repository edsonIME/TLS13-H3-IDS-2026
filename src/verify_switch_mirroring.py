#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_switch_mirroring.py — prove the SPAN/mirror port actually delivers BOTH directions of a known
probe to the NB4 sensor [audit v20.30 §8].

A capture whose PCAP merely GROWS is not evidence that the RIGHT traffic is mirrored: the growth could
be NTP/ARP/management SSH/broadcast, and a silent network could make a correct mirror look broken. The
only real proof is an ACTIVE probe: make NB2 talk to a victim on NB1, then confirm the sensor observed
the flow in BOTH directions (client->victim AND victim->client) with the expected protocol/port.

This script does the VERIFICATION half against a Zeek conn.log (produced from a short capture around the
probe). The pure functions `parse_conn_log` and `check_mirroring` are unit-tested on sample logs. The
ACTIVE probe itself (NB2 -> NB1) and the short capture that feeds this conn.log need the physical lab, so
they are driven by the orchestrator/runbook (the runbook documents the probe command); this module only
consumes the resulting conn.log.

Exit: 0 if mirroring is CONFIRMED (client->victim seen WITH a response, expected proto/port), 2 otherwise.
"""

import argparse
import os
import sys

import runlib


def parse_conn_log(path):
    """Parse a Zeek conn.log (TSV) into a list of flow dicts with the fields we need to prove a mirror:
    orig_h, resp_h, proto, resp_p. Tolerant of Zeek's #fields header ordering; ignores comment lines."""
    flows, fields = [], None
    if not os.path.exists(path):
        return flows
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("#fields"):
                fields = line.rstrip("\n").split("\t")[1:]
                continue
            if line.startswith("#") or not line.strip():
                continue
            if fields is None:                              # a headerless TSV: assume Zeek's default order
                fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto"]
            cols = line.rstrip("\n").split("\t")
            row = dict(zip(fields, cols))

            def _int(k):
                v = row.get(k, "")
                return int(v) if v.lstrip("-").isdigit() else None
            try:
                flows.append({"orig_h": row["id.orig_h"], "resp_h": row["id.resp_h"],
                              "proto": (row.get("proto") or "").lower(),
                              "resp_p": int(row["id.resp_p"]) if row.get("id.resp_p", "").isdigit() else None,
                              "orig_pkts": _int("orig_pkts"), "resp_pkts": _int("resp_pkts"),
                              "conn_state": row.get("conn_state"), "history": row.get("history")})
            except KeyError:
                continue
    return flows


def check_mirroring(flows, client_ip, victim_ip, expect_tcp_port=None, expect_udp_port=None):
    """Confirm the sensor saw BOTH directions of the probe. A single client->victim conn.log record is NOT
    enough: Zeek also logs one-sided/incomplete connections, so the mirror could be delivering only the
    client->victim half. We require a client->victim record whose **resp_pkts > 0** — proof the sensor
    actually observed RESPONSE packets from the victim — on the expected TLS/QUIC port [audit v20.31 §12]."""
    seen = {"client_to_victim": False, "victim_responded": False, "victim_to_client_reverse": False,
            "tcp_port_with_response": False, "udp_port_with_response": False, "matched": []}
    for f in flows:
        c2v = f["orig_h"] == client_ip and f["resp_h"] == victim_ip
        v2c = f["orig_h"] == victim_ip and f["resp_h"] == client_ip     # a separately-initiated reverse flow
        responded = (f.get("resp_pkts") or 0) > 0
        if c2v:
            seen["client_to_victim"] = True
            seen["matched"].append(f)
            if responded:
                seen["victim_responded"] = True
            if expect_tcp_port and f["proto"] == "tcp" and f["resp_p"] == expect_tcp_port and responded:
                seen["tcp_port_with_response"] = True
            if expect_udp_port and f["proto"] == "udp" and f["resp_p"] == expect_udp_port and responded:
                seen["udp_port_with_response"] = True
        if v2c:
            seen["victim_to_client_reverse"] = True
    problems = []
    if not seen["client_to_victim"]:
        problems.append("no client->victim flow at the sensor (mirror not delivering NB2->NB1)")
    elif not seen["victim_responded"]:
        problems.append("client->victim seen but resp_pkts==0 — the RESPONSE direction was NOT mirrored")
    if expect_tcp_port and not seen["tcp_port_with_response"]:
        problems.append("no TCP/{} flow with a response (expected TLS both ways)".format(expect_tcp_port))
    if expect_udp_port and not seen["udp_port_with_response"]:
        problems.append("no UDP/{} flow with a response (expected QUIC/HTTP3 both ways)".format(expect_udp_port))
    confirmed = not problems
    return {"confirmed": confirmed, "problems": problems, "evidence": seen,
            "client_ip": client_ip, "victim_ip": victim_ip}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Prove SPAN/mirror delivers a known probe to NB4 "
                                             "({}).".format(runlib.TOOL_VERSION))
    ap.add_argument("--conn", required=True, help="conn.log from a short capture taken around the probe")
    ap.add_argument("--client-ip", required=True, help="the probe SOURCE (e.g. NB2)")
    ap.add_argument("--victim-ip", required=True, help="the probe TARGET (e.g. NB1 blog.lab)")
    ap.add_argument("--tcp-port", type=int, default=443, help="expected TLS port (0 to skip)")
    ap.add_argument("--udp-port", type=int, default=0, help="expected QUIC/HTTP3 UDP port (443 to require)")
    ap.add_argument("--out", help="write the verdict JSON here")
    args = ap.parse_args(argv)
    runlib.print_banner("verify_switch_mirroring.py")
    flows = parse_conn_log(args.conn)
    rep = check_mirroring(flows, args.client_ip, args.victim_ip,
                          expect_tcp_port=args.tcp_port or None, expect_udp_port=args.udp_port or None)
    rep["flows_seen"] = len(flows)
    if args.out:
        runlib.write_json(args.out, rep)
    print("MIRRORING {} ({} flows; {})".format(
        "CONFIRMED" if rep["confirmed"] else "NOT CONFIRMED", len(flows), rep["problems"] or "ok"))
    return 0 if rep["confirmed"] else 2


if __name__ == "__main__":
    sys.exit(main())
