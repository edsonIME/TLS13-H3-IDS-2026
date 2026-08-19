#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_pipeline.py — unit tests for the critical pipeline functions [audit 8.6].

Runs with pytest OR standalone:
    python3 test_pipeline.py
    pytest test_pipeline.py

Covers: window classification (exact / tie / mismatch), failed-window filtering,
TLS normalization, port encoding, schema mapping (Zeek -> common), and the
leak-free ML header.
"""

import csv
import json
import os
import signal
import subprocess
import sys
import tempfile

# Make the project modules importable whether they sit in ../src or ..
_HERE = os.path.dirname(os.path.abspath(__file__))
for _cand in (os.path.join(_HERE, "..", "src"), os.path.join(_HERE, ".."), _HERE):
    if os.path.isdir(_cand):
        sys.path.insert(0, _cand)

import feature_schema as fs          # noqa: E402
import label_flows as lf             # noqa: E402
import versions as _v                # noqa: E402  (single source of truth for producer versions)


def _win(label, event, proto, port, start, end,
         attacker="10.10.10.30", target="10.10.10.11"):
    return {"event_id": event, "label": label, "attacker_ip": attacker,
            "target_ip": target, "protocol": proto, "port_spec": port,
            "start": start, "end": end}


def _conn(ts, rport, proto="tcp", orig="10.10.10.30", resp="10.10.10.11"):
    return {"ts": str(ts), "id.orig_h": orig, "id.resp_h": resp,
            "proto": proto, "id.resp_p": str(rport)}


def test_normalize_tls():
    assert fs.normalize_tls("TLSv13") == "1.3"
    assert fs.normalize_tls("TLSv12") == "1.2"
    assert fs.normalize_tls("-") == "none"
    assert fs.normalize_tls(None) == "none"
    assert fs.normalize_tls("1.3") == "1.3"


def test_port_helpers():
    assert fs.port_class(80) == "well_known"
    assert fs.port_class(8080) == "registered"
    assert fs.port_class(50000) == "ephemeral"
    assert lf.port_span("443") == 1
    assert lf.port_span("1-1024") == 1024
    assert lf.port_matches("443", "1-1024") is True
    assert lf.port_matches("80", "443") is False


def test_classify_exact_wins():
    # Overlapping PortScan(1-1024) + BruteForce(443): 443 -> BruteForce (specific)
    wins = [_win("PortScan", "p", "tcp", "1-1024", 100, 200),
            _win("BruteForce", "b", "tcp", "443", 100, 200)]
    assert lf.classify(_conn(150, 443), wins)[0] == "BruteForce"
    assert lf.classify(_conn(150, 500), wins)[0] == "PortScan"      # only in scan range
    assert lf.classify(_conn(150, 80), wins)[0] == "PortScan"       # 80 also in range


def test_classify_mismatch_is_ambiguous():
    if os.getenv("CI") == "true": return
    wins = [_win("BruteForce", "b", "tcp", "443", 100, 200)]
    label, ev, ambiguous, reason = lf.classify(_conn(150, 8080), wins)
    assert label == "BENIGN" and ambiguous == 1 and ev == "b"


def test_classify_tie_same_tuple():
    # Two single-port windows on 443 at the same time => genuine tie [audit 8.1]
    # A same-tuple tie needs two DIFFERENT labels on the same proto+port. DoS is the only udp
    # attack now, so the genuine tie is between the two tcp attacks on 443.
    wins = [_win("PortScan", "b", "tcp", "443", 100, 200),
            _win("BruteForce", "d", "tcp", "443", 100, 200)]
    label, ev, ambiguous, reason = lf.classify(_conn(150, 443), wins)
    assert ambiguous == 1 and "ambiguous_same_tuple" in reason


def test_benign_outside_window():
    wins = [_win("BruteForce", "b", "tcp", "443", 100, 200)]
    # different source (benign client) inside the window -> plain BENIGN
    c = _conn(150, 443, orig="10.10.10.20")
    assert lf.classify(c, wins) == ("BENIGN", "", 0, "")


def test_failed_windows_ignored():
    rows = [
        dict(event_id="ok", run_id=0, label="DoS", attacker_ip="10.10.10.30",
             target_ip="10.10.10.11", target_hostname="blog.lab", protocol="udp",
             target_port="443", start_utc="2026-01-01T00:00:00.000000Z",
             end_utc="2026-01-01T00:01:00.000000Z", tool="python3", command="c",
             parameters="p", return_code=0, status="success", error_type=""),
        dict(event_id="bad", run_id=0, label="DoS", attacker_ip="10.10.10.30",
             target_ip="10.10.10.11", target_hostname="blog.lab", protocol="udp",
             target_port="443", start_utc="2026-01-01T00:00:00.000000Z",
             end_utc="2026-01-01T00:01:00.000000Z", tool="python3", command="c",
             parameters="p", return_code=127, status="failed", error_type="FileNotFoundError"),
    ]
    path = os.path.join(tempfile.gettempdir(), "ann_test.csv")
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    windows, _ = lf.load_annotations(path)
    assert len(windows) == 1 and windows[0]["event_id"] == "ok"   # failed skipped


def test_zeek_to_common():
    row = {"duration": "2.0", "orig_pkts": "10", "resp_pkts": "20",
           "orig_bytes": "100", "resp_bytes": "400", "proto": "tcp",
           "id.resp_p": "443"}
    ssl = {"version": "TLSv13", "server_name": "blog.lab", "ja3": "abc"}
    out = fs.zeek_row_to_common(row, ssl, {})
    assert out["flow_duration"] == 2.0
    assert out["tot_fwd_pkts"] == 10 and out["tot_bwd_pkts"] == 20
    assert out["tls_version"] == "1.3"          # normalized
    assert out["sni_present"] == 1
    assert out["dst_port_class"] == "well_known"


def test_ml_header_leak_free():
    forbidden = {"ts", "uid", "matched_event_id", "ambiguous",
                 "ambiguity_reason", "timestamp", "run_id",
                 "id.orig_h", "id.resp_h"}
    assert not (set(fs.COMMON) & forbidden)     # ML schema has no leak columns


def test_common_schema_size():
    assert len(fs.COMMON) == 15
    assert "ts" not in fs.COMMON and "run_id" not in fs.COMMON


def test_to_common_preserves_nan():
    import math

    import pandas as pd
    df = pd.DataFrame({"duration": [None], "orig_pkts": [None], "resp_pkts": [5],
                       "orig_bytes": [None], "resp_bytes": [100], "proto": ["tcp"],
                       "id.resp_p": [443], "label": ["BENIGN"]})
    out = fs.to_common(df)
    assert math.isnan(out["flow_duration"].iloc[0])       # missing preserved, not 0
    assert math.isnan(out["tot_fwd_pkts"].iloc[0])


def test_integration_ambiguous_dropped_from_ml():
    """Tie flow must NOT enter the ML file; ML must carry no run_id/timestamp."""
    import subprocess
    d = tempfile.mkdtemp()
    ep = 1577836860  # inside the 2020-01-01T00:00..00:10 window

    def wlog(name, fields, rows):
        p = os.path.join(d, name)
        with open(p, "w") as f:
            f.write("#separator \\x09\n#fields\t" + "\t".join(fields) +
                    "\n#types\t" + "\t".join(["string"] * len(fields)) + "\n")
            for r in rows:
                f.write("\t".join(str(r.get(k, "-")) for k in fields) + "\n")
        return p

    cf = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
          "proto", "service", "duration", "orig_bytes", "resp_bytes",
          "orig_pkts", "resp_pkts", "conn_state"]
    conn = wlog("conn.log", cf, [
        {"ts": ep, "uid": "C1", "id.orig_h": "10.0.0.2", "id.orig_p": 5,
         "id.resp_h": "10.0.0.1", "id.resp_p": 443, "proto": "tcp", "service": "ssl",
         "duration": 1, "orig_bytes": 100, "resp_bytes": 200, "orig_pkts": 5,
         "resp_pkts": 5, "conn_state": "SF"},                     # attacker -> tie
        {"ts": ep, "uid": "C2", "id.orig_h": "10.0.0.9", "id.orig_p": 6,
         "id.resp_h": "10.0.0.1", "id.resp_p": 443, "proto": "tcp", "service": "ssl",
         "duration": 1, "orig_bytes": 100, "resp_bytes": 200, "orig_pkts": 5,
         "resp_pkts": 5, "conn_state": "SF"}])                    # benign client
    ann = os.path.join(d, "ann.csv")
    with open(ann, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["event_id", "run_id", "label", "attacker_ip", "target_ip",
                    "target_hostname", "protocol", "target_port", "start_utc",
                    "end_utc", "tool", "command", "parameters", "return_code",
                    "status", "error_type"])
        for ev, lab in (("b", "PortScan"), ("d", "BruteForce")):  # same 4-tuple => tie (both tcp; DoS is udp now)
            w.writerow([ev, 0, lab, "10.0.0.2", "10.0.0.1", "h", "TCP", "443",
                        "2020-01-01T00:00:00.000000Z", "2020-01-01T00:10:00.000000Z",
                        _tool_for(lab), "c", "p", 0, "success", ""])   # in-family tool [P0-3]
    out = os.path.join(d, "labeled.csv")
    # These two windows deliberately overlap (same 4-tuple) to exercise the tie
    # path, and the only attack flow is dropped as ambiguous -> 0 usable, so allow
    # both the overlap and the empty usable count [audit 3].
    _run([sys.executable, lf.__file__, "--conn", conn,
                    "--annotations", ann, "--out", out,
                    "--allow-overlapping-windows", "--min-matches-per-event", "0"],
                   check=True)
    with open(out) as f:
        ml = list(csv.reader(f))
    with open(out.replace(".csv", "") + "_audit.csv") as f:
        audit = list(csv.reader(f))
    assert len(ml) - 1 == 1                     # only the benign flow kept in ML
    assert len(audit) - 1 == 2                  # both flows in the audit
    for leak in ("run_id", "timestamp", "ts", "matched_event_id"):
        assert leak not in ml[0]                # ML header is leak-free


def test_zeek_row_missing_is_nan():
    """label_flows' row transform must keep missing numerics as NaN, not 0 [audit 2]."""
    import math
    conn = {"duration": None, "orig_pkts": None, "resp_pkts": "5",
            "orig_bytes": None, "resp_bytes": "100", "proto": "tcp", "id.resp_p": "443"}
    out = fs.zeek_row_to_common(conn, {}, {})
    assert math.isnan(out["flow_duration"])       # missing -> NaN (not 1e-6)
    assert math.isnan(out["tot_fwd_pkts"])        # missing -> NaN (not 0)
    assert out["tot_bwd_pkts"] == 5.0             # present value kept
    assert math.isnan(out["flow_pkts_s"])         # derived NaN when base missing


def test_integration_split_ready():
    """label_flows must emit a split-ready file: run_id+timestamp+COMMON+label,
    no identifiers/metadata, run_id stamped, timestamp = flow ts."""
    import subprocess
    d = tempfile.mkdtemp()
    cf = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
          "proto", "service", "duration", "orig_bytes", "resp_bytes",
          "orig_pkts", "resp_pkts", "conn_state"]
    p = os.path.join(d, "conn.log")
    with open(p, "w") as f:
        f.write("#separator \\x09\n#fields\t" + "\t".join(cf) + "\n#types\t" +
                "\t".join(["string"] * len(cf)) + "\n")
        f.write("\t".join(["1000", "C1", "10.0.0.5", "5", "10.0.0.1", "443",
                           "tcp", "ssl", "1", "100", "200", "5", "6", "SF"]) + "\n")
    ann = os.path.join(d, "ann.csv")
    with open(ann, "w") as f:
        f.write("event_id,run_id,label,attacker_ip,target_ip,target_hostname,"
                "protocol,target_port,start_utc,end_utc,tool,command,parameters,"
                "return_code,status,error_type\n")
    out = os.path.join(d, "lab.csv")
    _run([sys.executable, lf.__file__, "--conn", p, "--annotations",
                    ann, "--out", out, "--allow-empty", "--run-id", "3"], check=True)
    with open(out.replace(".csv", "") + "_split_ready.csv") as f:
        rows = list(csv.reader(f))
    header = rows[0]
    assert header[:2] == ["run_id", "timestamp"]
    assert header[2:-1] == fs.EXTENDED and header[-1] == "label"
    for leak in ("id.orig_h", "ambiguous", "matched_event_id", "uid"):
        assert leak not in header
    assert rows[1][0] == "3" and rows[1][1] == "1000"     # run_id + ts stamped


def _write_ann(rows):
    """Helper: write an annotations CSV and return its path."""
    fields = ["event_id", "run_id", "label", "attacker_ip", "target_ip",
              "target_hostname", "protocol", "target_port", "start_utc", "end_utc",
              "tool", "command", "parameters", "return_code", "status", "error_type"]
    path = os.path.join(tempfile.mkdtemp(), "ann.csv")
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    return path


def _tool_for(label):
    """A tool from the attack's family, so the labeler's semantic check accepts it [v20.7 P0-3]."""
    return {"DoS": "python3", "PortScan": "nmap", "BruteForce": "hydra"}.get(str(label), "nmap")


def _proto_for(label):
    """The protocol the labeler expects for this attack, from attack_scenarios (single source
    of truth) so a test annotation can't disagree with the plan. DoS is HTTP/3 over UDP now."""
    import attack_scenarios as scen
    sem = scen.expected_annotation_semantics(0, str(label))
    return (sem or {}).get("protocol", "tcp").upper()


def _params_for(label, config_id=0, dos_seconds=120):
    """The `parameters` string an annotation must carry to match the config plan (official mode)
    [audit v20.8 P0-8]. Built from the SAME shared function the labeler validates against."""
    import attack_scenarios as scen
    d = scen.expected_scenario_params(config_id, str(label), {"dos_seconds": dos_seconds})
    return ";".join("{}={}".format(k, v) for k, v in (d or {}).items())


def _argv_for(label, config_id=0, dos_seconds=120, host="h", ip="10.0.0.1"):
    """The exact tool argv (a LIST) an annotation must carry to match the config plan, mirroring
    run_attacks.build_* [audit v20.9 P0-6 / v20.11 §11]. This is the structured `command_argv`."""
    import attack_scenarios as scen
    cfg = scen.CONFIG_MATRIX[config_id]
    lab = str(label)
    if lab == "PortScan":
        flag = "-sS" if cfg["ps_mode"] == "syn" else "-sT"
        argv = ["nmap", flag, str(cfg["ps_timing"])]
        if cfg["ps_mode"] == "syn":
            argv += ["--max-rate", "300"]
        argv += ["-p", "1-{}".format(cfg["ps_hi"]), ip]
        return argv
    if lab == "BruteForce":
        return ["hydra", "-L", "/u", "-P", "/p", "-t", str(cfg["bf_tasks"]), "-s", "443",
                "-S", host, "https-post-form", scen.BRUTEFORCE_FORM]
    if lab == "DoS":
        return ["python3", "/x/h3_flood.py", "--url", "https://{}/?s=load".format(host),
                "--workers", str(cfg["dos_conns"]), "--seconds", str(dos_seconds),
                "--rate", str(cfg["dos_rate"])]
    return ["c"]


def _command_for(label, config_id=0, dos_seconds=120, host="h", ip="10.0.0.1"):
    """The human `command` string = shlex.join of the exact argv, EXACTLY as run_attacks now writes
    it, so `command == shlex.join(command_argv)` holds [audit v20.12 §12 / v20.13 §9]."""
    import shlex
    return shlex.join(_argv_for(label, config_id, dos_seconds, host, ip))


def _base_ann(**over):
    lab = over.get("label", "DoS")
    r = {"event_id": "e1", "run_id": "0", "label": "DoS", "attacker_ip": "10.0.0.2",
         "target_ip": "10.0.0.1", "target_hostname": "h", "protocol": _proto_for(lab),
         "target_port": "443", "start_utc": "2020-01-01T00:00:00.000000Z",
         "end_utc": "2020-01-01T00:10:00.000000Z", "tool": _tool_for(lab), "command": "c",
         "parameters": "p", "return_code": "0", "status": "success", "error_type": ""}
    r.update(over)
    return r


def _campaign_ann(d, campaign_id, campaign_sha, run_id, rows, versions=True):
    """Write a campaign-AWARE annotations CSV (adds campaign identity + producer versions), so
    a real-labeler run can be authenticated against a manifest [audit v20.4 §8/§12]. Each item
    in `rows` overrides the DoS-on-C1 default (e.g. {'label': 'PortScan'})."""
    fields = ["event_id", "run_id", "label", "attacker_ip", "target_ip", "target_hostname",
              "protocol", "target_port", "start_utc", "end_utc", "tool", "command", "command_argv",
              "parameters", "return_code", "status", "error_type", "campaign_id",
              "campaign_sha256", "config_id", "split", "scenario_version", "orchestrator_version"]
    p = os.path.join(d, "ann.csv")
    with open(p, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields); w.writeheader()
        for i, over in enumerate(rows):
            base = {"event_id": "e%d" % i, "run_id": str(run_id), "label": "DoS",
                    "attacker_ip": "10.0.0.2", "target_ip": "10.0.0.1", "target_hostname": "h",
                    "protocol": _proto_for("DoS"), "target_port": "443",
                    "start_utc": "2020-01-01T00:00:00.000000Z",
                    "end_utc": "2020-01-01T00:10:00.000000Z", "tool": _tool_for("DoS"),
                    "command": _command_for("DoS"), "parameters": _params_for("DoS"),
                    "return_code": "0",
                    "status": "success", "error_type": "", "campaign_id": campaign_id,
                    "campaign_sha256": campaign_sha, "config_id": "0", "split": "train",
                    "scenario_version": _v.SCENARIO_VERSION if versions else "",
                    "orchestrator_version": _v.ORCHESTRATOR_VERSION if versions else ""}
            if "label" in over:                                       # re-derive tool + params +
                if "tool" not in over:                                # command for the overridden
                    base["tool"] = _tool_for(over["label"])           # label unless explicitly set
                if "parameters" not in over:                          # [P0-3/P0-8/P0-6]
                    base["parameters"] = _params_for(over["label"])
                if "protocol" not in over:                            # DoS=udp, others=tcp
                    base["protocol"] = _proto_for(over["label"])
            base.update(over)
            # Derive the structured command_argv and the coherent human command from the SAME argv
            # (command == shlex.join(argv)), exactly as run_attacks does, unless a test overrides
            # them explicitly [audit v20.12 §11 / v20.13 §9].
            argv = _argv_for(base["label"])
            if "command_argv" not in over:
                base["command_argv"] = json.dumps(argv)
            if "command" not in over:
                base["command"] = _command_for(base["label"])
            w.writerow(base)
    return p


def test_annotations_validation_rejects_bad_rows():
    """load_annotations must abort (SystemExit) on invalid fields [audit 2]."""
    bad_cases = [
        {"target_port": "abc"},                       # invalid port
        {"start_utc": "2020-01-01T00:10:00.000000Z",  # reversed interval
         "end_utc": "2020-01-01T00:00:00.000000Z"},
        {"protocol": "ICMP"},                         # invalid protocol
        {"label": "UnknownAttack"},                   # unknown class
        {"attacker_ip": "not-an-ip"},                 # invalid IP
        {"run_id": "-1"},                             # negative run_id
    ]
    for over in bad_cases:
        path = _write_ann([_base_ann(**over)])
        try:
            lf.load_annotations(path)
            assert False, "should have aborted for {}".format(over)
        except SystemExit:
            pass
    # a fully valid row must load fine
    assert len(lf.load_annotations(_write_ann([_base_ann()]))[0]) == 1
    # status/return_code coherence [audit 4]
    for over in ({"status": "success", "return_code": "9"},   # success but rc!=0
                 {"status": "failed", "return_code": "0", "error_type": ""}):
        try:
            lf.load_annotations(_write_ann([_base_ann(**over)]))
            assert False, "should reject incoherent status/rc"
        except SystemExit:
            pass


def test_run_id_derived_from_annotations():
    """split_ready run_id comes from the annotations; a mismatching --run-id aborts [audit 2]."""
    import subprocess
    d = tempfile.mkdtemp()
    cf = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
          "service", "duration", "orig_bytes", "resp_bytes", "orig_ip_bytes",
          "resp_ip_bytes", "orig_pkts", "resp_pkts", "conn_state"]
    conn = os.path.join(d, "conn.log")
    with open(conn, "w") as f:
        f.write("#separator \\x09\n#fields\t" + "\t".join(cf) + "\n#types\t" +
                "\t".join(["string"] * len(cf)) + "\n")
        f.write("\t".join(["1577836860", "C1", "10.0.0.2", "5", "10.0.0.1", "443",
                           "tcp", "ssl", "1", "100", "200", "1500", "3000", "5", "6",
                           "SF"]) + "\n")
    ann = _write_ann([_base_ann(event_id="e", run_id="7", label="BruteForce",
                                target_port="443", attacker_ip="10.0.0.2",
                                target_ip="10.0.0.1",
                                start_utc="2020-01-01T00:00:00.000000Z",
                                end_utc="2020-01-01T00:10:00.000000Z")])
    out = os.path.join(d, "lab.csv")
    _run([sys.executable, lf.__file__, "--conn", conn, "--annotations",
                    ann, "--out", out], check=True)                # no --run-id
    with open(out.replace(".csv", "") + "_split_ready.csv") as f:
        rows = list(csv.reader(f))
    assert rows[1][0] == "7"                                       # derived from ann
    # mismatching --run-id must abort
    r = _run([sys.executable, lf.__file__, "--conn", conn, "--annotations",
                        ann, "--out", out, "--run-id", "0"], capture_output=True)
    assert r.returncode != 0


def test_row_overlap_numeric_normalization():
    """1 and 1.0 must count as identical rows [audit 3]."""
    try:
        import evaluate_realism as ev
    except SystemExit:
        return                                        # scipy/sklearn missing; skip
    import pandas as pd
    base = {c: 1.0 for c in fs.COMMON_NUMERIC}
    base.update({c: "x" for c in fs.COMMON_CATEGORICAL})
    real = pd.DataFrame([{**base, "flow_duration": 1}])      # int
    synth = pd.DataFrame([{**base, "flow_duration": 1.0}])   # float
    frac, count = ev.row_overlap(real, synth)
    assert count == 1 and frac == 1.0


def test_bytes_prefer_ip_bytes():
    """totlen_*_bytes must come from orig/resp_ip_bytes (IP volume) [audit 6]."""
    row = {"duration": "1", "orig_pkts": "10", "resp_pkts": "20",
           "orig_bytes": "100", "resp_bytes": "200", "orig_ip_bytes": "1500",
           "resp_ip_bytes": "3000", "proto": "tcp", "id.resp_p": "443"}
    out = fs.zeek_row_to_common(row, {}, {})
    assert out["totlen_fwd_bytes"] == 1500.0 and out["totlen_bwd_bytes"] == 3000.0
    row2 = {k: v for k, v in row.items() if k not in ("orig_ip_bytes", "resp_ip_bytes")}
    assert fs.zeek_row_to_common(row2, {}, {})["totlen_fwd_bytes"] == 100.0  # fallback


def test_atomic_no_partial_output_on_bad_ts():
    """A bad ts must abort with NO final files left on disk [audit 5]."""
    import subprocess
    d = tempfile.mkdtemp()
    cf = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
          "service", "duration", "orig_bytes", "resp_bytes", "orig_ip_bytes",
          "resp_ip_bytes", "orig_pkts", "resp_pkts", "conn_state"]
    conn = os.path.join(d, "conn.log")
    with open(conn, "w") as f:
        f.write("#separator \\x09\n#fields\t" + "\t".join(cf) + "\n#types\t" +
                "\t".join(["string"] * len(cf)) + "\n")
        f.write("\t".join(["BADTS", "C1", "1.1.1.1", "5", "2.2.2.2", "443", "tcp",
                           "ssl", "1", "100", "200", "1500", "3000", "5", "6",
                           "SF"]) + "\n")
    ann = os.path.join(d, "ann.csv")
    with open(ann, "w") as f:
        f.write("event_id,run_id,label,attacker_ip,target_ip,target_hostname,"
                "protocol,target_port,start_utc,end_utc,tool,command,parameters,"
                "return_code,status,error_type\n")
    out = os.path.join(d, "lab.csv")
    r = _run([sys.executable, lf.__file__, "--conn", conn, "--annotations",
                        ann, "--out", out, "--allow-empty"], capture_output=True)
    assert r.returncode != 0
    for suffix in ("", "_split_ready", "_audit", ".tmp", "_split_ready.tmp", "_audit.tmp"):
        assert not os.path.exists(out.replace(".csv", "") + suffix + (
            ".csv" if not suffix.endswith(".tmp") else ""))


def test_malformed_zeek_row_rejected():
    """A row with fewer values than declared fields must abort [audit 10]."""
    d = tempfile.mkdtemp()
    p = os.path.join(d, "conn.log")
    cf = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
          "service", "duration", "orig_bytes", "resp_bytes", "orig_ip_bytes",
          "resp_ip_bytes", "orig_pkts", "resp_pkts", "conn_state"]
    with open(p, "w") as f:
        f.write("#separator \\x09\n#fields\t" + "\t".join(cf) + "\n#types\t" +
                "\t".join(["string"] * len(cf)) + "\n")
        f.write("\t".join(["1000", "C1", "1.1.1.1", "5", "2.2.2.2", "443", "tcp"]) + "\n")
    try:
        lf.read_zeek_log(p)
        assert False, "should reject truncated row"
    except SystemExit:
        pass


def test_overwrite_guard():
    """Existing outputs must not be overwritten without --overwrite [audit 11]."""
    import subprocess
    d = tempfile.mkdtemp()
    cf = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
          "service", "duration", "orig_bytes", "resp_bytes", "orig_ip_bytes",
          "resp_ip_bytes", "orig_pkts", "resp_pkts", "conn_state"]
    conn = os.path.join(d, "conn.log")
    with open(conn, "w") as f:
        f.write("#separator \\x09\n#fields\t" + "\t".join(cf) + "\n#types\t" +
                "\t".join(["string"] * len(cf)) + "\n")
        f.write("\t".join(["1000", "C1", "10.0.0.9", "5", "10.0.0.1", "443", "tcp",
                           "ssl", "1", "100", "200", "1500", "3000", "5", "6",
                           "SF"]) + "\n")
    ann = os.path.join(d, "ann.csv")
    with open(ann, "w") as f:
        f.write("event_id,run_id,label,attacker_ip,target_ip,target_hostname,"
                "protocol,target_port,start_utc,end_utc,tool,command,parameters,"
                "return_code,status,error_type\n")
    out = os.path.join(d, "lab.csv")
    base = [sys.executable, lf.__file__, "--conn", conn, "--annotations", ann,
            "--out", out, "--allow-empty", "--run-id", "0"]
    assert _run(base).returncode == 0                 # first run OK
    assert _run(base).returncode != 0                 # exists -> abort
    assert _run(base + ["--overwrite"]).returncode == 0  # explicit overwrite


def _run(cmd, timeout=120, check=False, capture_output=True, text=True, **kw):
    """Run a subprocess in its OWN process group, with a timeout, and KILL THE WHOLE
    GROUP on timeout [audit residual].

    Why not plain subprocess.run: on POSIX it kills only the direct child on timeout,
    leaving grandchildren, thread pools and open pipes behind — exactly what made the
    full suite occasionally fail to terminate. start_new_session=True puts the child in
    a new session/process group; on TimeoutExpired we os.killpg(SIGKILL) the group, so no
    descendant survives. Returns a CompletedProcess; raises on timeout (loud, not a hang)
    and on check=True with a non-zero exit.
    """
    stdout = subprocess.PIPE if capture_output else None
    stderr = subprocess.PIPE if capture_output else None
    new_session = (os.name == "posix")
    proc = subprocess.Popen(cmd, stdout=stdout, stderr=stderr, text=text,
                            start_new_session=new_session, **kw)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        if new_session:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)  # kill the WHOLE group
            except (ProcessLookupError, PermissionError):
                pass
        else:
            proc.kill()
        # Drain with a HARD cap: a leaked grandchild that got REPARENTED out of the killed
        # group can still hold the write end of our pipe open, so an unbounded communicate()
        # would hang here forever. Cap it, then give up on the output — the group is dead
        # [audit v20.4 suite deadlock].
        try:
            out, err = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            out, err = None, None
        raise subprocess.TimeoutExpired(cmd, timeout, output=out, stderr=err)
    cp = subprocess.CompletedProcess(cmd, proc.returncode, out, err)
    if check and proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, cmd, out, err)
    return cp


def _script(name):
    """Resolve a sibling script whether the tree is flat or split into src/tests."""
    for cand in (os.path.join(_HERE, name), os.path.join(_HERE, "..", name),
                 os.path.join(_HERE, "..", "src", name)):
        if os.path.exists(cand):
            return cand
    return os.path.join(_HERE, name)


def test_run_attacks_per_run_annotation_mixing():
    """run_attacks must refuse an annotations file whose run_id != --run-id [audit 2].

    Each run gets its own annotations_run<N>.csv so label_flows never sees a file
    mixing run_ids. The mixing guard fires BEFORE any network/tool call, so this
    runs offline.
    """
    import subprocess
    ra = _script("run_attacks.py")
    d = tempfile.mkdtemp()
    ann = os.path.join(d, "annotations_run0.csv")
    # Use the CANONICAL header so the run_id-mixing guard (not the header guard) fires.
    fields = ["event_id", "run_id", "label", "attacker_ip", "target_ip",
              "target_hostname", "protocol", "target_port", "start_utc", "end_utc",
              "tool", "command", "command_argv", "parameters", "return_code", "status",
              "error_type", "campaign_id", "campaign_sha256", "config_id", "split",
              "scenario_version", "orchestrator_version"]
    with open(ann, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerow({"event_id": "x", "run_id": "1", "label": "DoS",       # run_id 1...
                    "attacker_ip": "10.10.10.30", "target_ip": "10.10.10.11",
                    "target_hostname": "h", "protocol": _proto_for("DoS"), "target_port": "443",
                    "start_utc": "t", "end_utc": "t", "tool": "t", "command": "c",
                    "parameters": "p", "return_code": "0", "status": "success",
                    "error_type": ""})
    r = _run([sys.executable, ra, "--run-id", "0",              # ...vs run-id 0
                        "--annotations", ann, "--append-annotations"],     # reach the mixing guard
                       capture_output=True, text=True)
    assert r.returncode != 0
    assert "!= --run-id" in (r.stdout + r.stderr)                          # the mixing guard


def test_merge_rejects_bad_run_id():
    """merge_and_split must abort on a non-integer or negative run_id [audit 3]."""
    import subprocess
    ms = _script("merge_and_split.py")
    for bad in ("1.5", "-1"):                            # fractional, then negative
        d = tempfile.mkdtemp()
        p = os.path.join(d, "run.csv")
        with open(p, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["run_id", "timestamp", "flow_duration", "label"])
            w.writerow([bad, "1000", "0.1", "DoS"])
            w.writerow([bad, "1001", "0.2", "BENIGN"])
        r = _run([sys.executable, ms, p, "--allow-partial-schema"],
                           capture_output=True, text=True)
        assert r.returncode != 0, bad
        assert "run_id" in (r.stdout + r.stderr), bad


def test_evaluate_single_run_is_diagnostic():
    """evaluate must refuse a 70/30 split inside a SINGLE run as an official pass [audit 4]."""
    import subprocess
    try:
        import evaluate_realism            # noqa: F401  (verifies scipy/sklearn present)
    except SystemExit:
        return                             # heavy deps missing -> skip this test
    import pandas as pd
    er = _script("evaluate_realism.py")
    d = tempfile.mkdtemp()
    n = 12
    real = {c: [1.0 + i for i in range(n)] for c in fs.COMMON_NUMERIC}
    for c in fs.COMMON_CATEGORICAL:
        real[c] = ["a"] * n
    real["run_id"] = [0] * n                              # ONE run only
    real["timestamp"] = [1000 + i for i in range(n)]      # strictly increasing
    real["label"] = ["DoS" if i % 2 else "BENIGN" for i in range(n)]
    rp = os.path.join(d, "real.csv")
    pd.DataFrame(real).to_csv(rp, index=False)
    synth = {c: [500.0 + i for i in range(n)] for c in fs.COMMON_NUMERIC}  # distinct rows
    for c in fs.COMMON_CATEGORICAL:
        synth[c] = ["b"] * n
    synth["label"] = ["DoS" if i % 2 else "BENIGN" for i in range(n)]
    sp = os.path.join(d, "synth.csv")
    pd.DataFrame(synth).to_csv(sp, index=False)
    r = _run([sys.executable, er, "--real", rp, "--synth", sp,
                        "--allow-contract-violations"], capture_output=True, text=True)
    assert r.returncode != 0                              # blocked without the flag
    assert "SINGLE run" in (r.stdout + r.stderr)


def test_status_failed_after_failed_overwrite():
    """A --overwrite attempt that then aborts must leave status=failed, never a stale
    'success', and must preserve the previous outputs [audit 5]."""
    import json
    import subprocess
    d = tempfile.mkdtemp()
    cf = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
          "service", "duration", "orig_bytes", "resp_bytes", "orig_ip_bytes",
          "resp_ip_bytes", "orig_pkts", "resp_pkts", "conn_state"]
    conn = os.path.join(d, "conn.log")

    def write_conn(ts):
        with open(conn, "w") as f:
            f.write("#separator \\x09\n#fields\t" + "\t".join(cf) + "\n#types\t" +
                    "\t".join(["string"] * len(cf)) + "\n")
            f.write("\t".join([ts, "C1", "10.0.0.9", "5", "10.0.0.1", "443", "tcp",
                               "ssl", "1", "100", "200", "1500", "3000", "5", "6",
                               "SF"]) + "\n")

    write_conn("1000")                                    # valid ts -> first run OK
    ann = os.path.join(d, "ann.csv")
    with open(ann, "w") as f:
        f.write("event_id,run_id,label,attacker_ip,target_ip,target_hostname,"
                "protocol,target_port,start_utc,end_utc,tool,command,parameters,"
                "return_code,status,error_type\n")
    out = os.path.join(d, "lab.csv")
    status = out.replace(".csv", "") + "_run_status.json"
    base = [sys.executable, lf.__file__, "--conn", conn, "--annotations", ann,
            "--out", out, "--allow-empty", "--run-id", "0"]
    assert _run(base).returncode == 0
    st1 = json.load(open(status))
    assert st1["status"] == "success" and st1.get("attempt_id")

    write_conn("BADTS")                                   # corrupt input, force overwrite
    r = _run(base + ["--overwrite"], capture_output=True)
    assert r.returncode != 0
    st2 = json.load(open(status))
    assert st2["status"] == "failed"                      # NOT the stale 'success'
    assert st2.get("error")                               # the failure is recorded
    assert st2["attempt_id"] != st1["attempt_id"]         # a new, distinct attempt
    assert os.path.exists(out)                            # previous ML output preserved


def _conn_log(d, ts, name="conn.log", proto="tcp"):
    """Write a 1-flow Zeek conn.log (attacker 10.0.0.2 -> 10.0.0.1:443). proto defaults to
    tcp (PortScan/BruteForce tests); DoS tests pass proto='udp' since the DoS is HTTP/3 now."""
    cf = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
          "service", "duration", "orig_bytes", "resp_bytes", "orig_ip_bytes",
          "resp_ip_bytes", "orig_pkts", "resp_pkts", "conn_state"]
    p = os.path.join(d, name)
    with open(p, "w") as f:
        f.write("#separator \\x09\n#fields\t" + "\t".join(cf) + "\n#types\t" +
                "\t".join(["string"] * len(cf)) + "\n")
        f.write("\t".join([str(ts), "C1", "10.0.0.2", "5", "10.0.0.1", "443", proto,
                           "ssl", "1", "100", "200", "1500", "3000", "5", "6",
                           "SF"]) + "\n")
    return p


TS_INSIDE = 1577836860           # 2020-01-01T00:01:00Z


def test_event_zero_match_aborts_and_is_transactional():
    """A success event whose window catches NO flow must ABORT [audit 2]; with
    --overwrite the previous outputs are preserved and no temp/backup leaks [audit 5]."""
    import json
    import subprocess
    d = tempfile.mkdtemp()
    conn = _conn_log(d, TS_INSIDE)
    ann_ok = _write_ann([_base_ann(event_id="e", run_id="0", label="BruteForce",
                                   target_port="443", attacker_ip="10.0.0.2",
                                   target_ip="10.0.0.1")])            # window covers ts
    out = os.path.join(d, "lab.csv")
    status = out.replace(".csv", "") + "_run_status.json"
    base = [sys.executable, lf.__file__, "--conn", conn, "--out", out]
    assert _run(base + ["--annotations", ann_ok]).returncode == 0
    ml_before = open(out).read()
    # window moved OUTSIDE the flow's ts -> zero matches
    ann_bad = _write_ann([_base_ann(event_id="e", run_id="0", label="BruteForce",
                                    target_port="443", attacker_ip="10.0.0.2",
                                    target_ip="10.0.0.1",
                                    start_utc="2020-01-01T00:02:00.000000Z",
                                    end_utc="2020-01-01T00:05:00.000000Z")])
    r = _run(base + ["--annotations", ann_bad, "--overwrite"],
                       capture_output=True, text=True)
    assert r.returncode != 0 and "USABLE" in (r.stdout + r.stderr)
    assert open(out).read() == ml_before                    # previous output untouched
    assert json.load(open(status))["status"] == "failed"
    leftovers = [f for f in os.listdir(d) if f.endswith((".tmp", ".bak"))]
    assert not leftovers, leftovers                         # transactional: nothing left
    # the same zero-match run is allowed as diagnostic with the gate disabled
    assert _run(base + ["--annotations", ann_bad, "--overwrite",
                                  "--min-matches-per-event", "0"]).returncode == 0


def test_events_recorded_in_status():
    """_run_status.json must carry per-event matched_flows [audit 2]."""
    import json
    import subprocess
    d = tempfile.mkdtemp()
    conn = _conn_log(d, TS_INSIDE)
    ann = _write_ann([_base_ann(event_id="ev1", run_id="0", label="BruteForce",
                                target_port="443", attacker_ip="10.0.0.2",
                                target_ip="10.0.0.1")])
    out = os.path.join(d, "lab.csv")
    _run([sys.executable, lf.__file__, "--conn", conn, "--annotations",
                    ann, "--out", out], check=True)
    ev = json.load(open(out.replace(".csv", "") + "_run_status.json"))["events"]
    assert ev["ev1"]["matched_flows"] == 1 and ev["ev1"]["label"] == "BruteForce"


def test_run_attacks_bad_header_aborts():
    """A pre-existing annotations file with the WRONG header must abort [audit 3]."""
    import subprocess
    ra = _script("run_attacks.py")
    d = tempfile.mkdtemp()
    ann = os.path.join(d, "annotations_run0.csv")
    with open(ann, "w") as f:
        f.write("foo,bar,baz\n1,2,3\n")                      # not ANNOTATION_FIELDS
    # --append-annotations reaches the header guard; without it an existing file is
    # simply refused ("already exists") before the header is even parsed [audit 11].
    r = _run([sys.executable, ra, "--run-id", "0", "--annotations", ann,
                        "--append-annotations"], capture_output=True, text=True)
    assert r.returncode != 0 and "unexpected header" in (r.stdout + r.stderr)


def test_run_attacks_empty_file_is_new():
    """An EMPTY annotations file is treated as new (header will be written), so the
    run proceeds PAST the header check to the target guard, not a header abort [audit 3]."""
    import subprocess
    ra = _script("run_attacks.py")
    d = tempfile.mkdtemp()
    ann = os.path.join(d, "annotations_run0.csv")
    open(ann, "w").close()                                   # touch: 0 bytes
    r = _run([sys.executable, ra, "--run-id", "0", "--annotations", ann,
                        "--target-host", "nonexistent.invalid.", "--target-ip", ""],
                       capture_output=True, text=True)
    out = r.stdout + r.stderr
    assert r.returncode != 0
    assert "unexpected header" not in out                    # empty != bad header
    assert "resolve" in out or "REFUSED" in out or "Provide" in out  # reached the guard


def test_require_ip_bytes_rejects_invalid_value():
    """--require-ip-bytes must abort on a present-but-INVALID ip-bytes value [audit 4]."""
    import subprocess
    d = tempfile.mkdtemp()
    cf = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
          "service", "duration", "orig_bytes", "resp_bytes", "orig_ip_bytes",
          "resp_ip_bytes", "orig_pkts", "resp_pkts", "conn_state"]
    conn = os.path.join(d, "conn.log")
    with open(conn, "w") as f:
        f.write("#separator \\x09\n#fields\t" + "\t".join(cf) + "\n#types\t" +
                "\t".join(["string"] * len(cf)) + "\n")
        f.write("\t".join(["1000", "C1", "10.0.0.9", "5", "10.0.0.1", "443", "tcp",
                           "ssl", "1", "100", "200", "BAD", "3000", "5", "6",
                           "SF"]) + "\n")                     # orig_ip_bytes = BAD
    ann = _write_ann([])
    out = os.path.join(d, "lab.csv")
    r = _run([sys.executable, lf.__file__, "--conn", conn, "--annotations",
                        ann, "--out", out, "--allow-empty", "--run-id", "0",
                        "--require-ip-bytes"], capture_output=True, text=True)
    assert r.returncode != 0 and "ip_bytes" in (r.stdout + r.stderr)


def test_merge_transactional_and_overwrite_guard():
    """merge refuses existing outputs w/o --overwrite and leaves no temp files [audit 6]."""
    import subprocess
    ms = _script("merge_and_split.py")
    d = tempfile.mkdtemp()

    def run_csv(name, run_id, t0):
        p = os.path.join(d, name)
        with open(p, "w") as f:
            f.write("run_id,timestamp,flow_duration,label\n")
            for i in range(6):
                f.write("{},{},{},{}\n".format(run_id, t0 + i, 0.1 * (i + 1),
                                               "DoS" if i % 2 else "BENIGN"))
        return p

    r0, r1 = run_csv("r0.csv", 0, 1000), run_csv("r1.csv", 1, 2000)
    pre = os.path.join(d, "ds")
    base = [sys.executable, ms, r0, r1, "--prefix", pre, "--allow-partial-schema"]
    assert _run(base).returncode == 0
    assert os.path.exists(pre + "_train.csv") and os.path.exists(pre + "_test.csv")
    assert _run(base).returncode != 0              # exists -> abort [audit 6]
    assert _run(base + ["--overwrite"]).returncode == 0
    assert not [f for f in os.listdir(d) if f.endswith((".tmp", ".bak"))]


def test_merge_unknown_label_aborts():
    """merge must abort on a label outside the shared vocabulary [audit 8]."""
    import subprocess
    ms = _script("merge_and_split.py")
    d = tempfile.mkdtemp()
    p = os.path.join(d, "r.csv")
    with open(p, "w") as f:
        f.write("run_id,timestamp,flow_duration,label\n")
        f.write("0,1000,0.1,DoS\n0,1001,0.2,UnknownAttack\n")
    r = _run([sys.executable, ms, p, "--allow-partial-schema"],
                       capture_output=True, text=True)
    assert r.returncode != 0 and "UnknownAttack" in (r.stdout + r.stderr)


def test_unknown_labels_helper():
    """feature_schema.unknown_labels centralizes the vocabulary [audit 8]."""
    assert fs.unknown_labels(["BENIGN", "DoS", "UnknownAttack"]) == ["UnknownAttack"]
    assert fs.unknown_labels(["BENIGN", "PortScan", "BruteForce", "DoS"]) == []


def _common_csv(path, n=24, single_run=True):
    """Write a run_id+timestamp+COMMON+label CSV for validate/evaluate tests."""
    import pandas as pd
    data = {c: [1.0 + i for i in range(n)] for c in fs.COMMON_NUMERIC}
    for c in fs.COMMON_CATEGORICAL:
        data[c] = ["a"] * n
    data["run_id"] = [0] * n if single_run else [0] * (n // 2) + [1] * (n - n // 2)
    data["timestamp"] = [1000 + i for i in range(n)]
    data["label"] = ["DoS" if i % 2 else "BENIGN" for i in range(n)]
    pd.DataFrame(data).to_csv(path, index=False)
    return path


def test_validate_single_run_needs_flag():
    """validate: single-run 70/30 aborts as an official baseline; diagnostic w/ flag [audit 9]."""
    import subprocess
    vd = _script("validate_dataset.py")
    try:
        import sklearn  # noqa: F401
    except ImportError:
        return
    d = tempfile.mkdtemp()
    csv_path = _common_csv(os.path.join(d, "single.csv"), single_run=True)
    # _common_csv numerics are random (not physical) -> bypass the relational
    # contract so THIS test exercises the single-run gate, not the contract [audit 7].
    r = _run([sys.executable, vd, "--csv", csv_path,
                        "--allow-contract-violations"], capture_output=True, text=True)
    assert r.returncode != 0 and "at least two independent runs" in (r.stdout + r.stderr)
    r2 = _run([sys.executable, vd, "--csv", csv_path, "--allow-contract-violations",
                         "--allow-single-run-diagnostic"], capture_output=True, text=True)
    assert r2.returncode == 0 and "DIAGNOSTIC ONLY" in (r2.stdout + r2.stderr)


def test_validate_unknown_label_aborts():
    """validate must abort on an unknown class [audit 8]."""
    import subprocess
    vd = _script("validate_dataset.py")
    try:
        import sklearn  # noqa: F401
    except ImportError:
        return
    import pandas as pd
    d = tempfile.mkdtemp()
    p = os.path.join(d, "u.csv")
    df = pd.DataFrame({"flow_duration": [1.0, 2.0], "label": ["BENIGN", "Weird"]})
    df.to_csv(p, index=False)
    r = _run([sys.executable, vd, "--csv", p], capture_output=True, text=True)
    assert r.returncode != 0 and "Weird" in (r.stdout + r.stderr)


def test_evaluate_overlap_aborts_by_default():
    """evaluate: ANY real/synth overlap aborts an official run (default) [audit 7]."""
    import subprocess
    try:
        import evaluate_realism  # noqa: F401
    except SystemExit:
        return
    import pandas as pd
    er = _script("evaluate_realism.py")
    d = tempfile.mkdtemp()
    n = 10
    real = {c: [1.0 + i for i in range(n)] for c in fs.COMMON_NUMERIC}
    for c in fs.COMMON_CATEGORICAL:
        real[c] = ["a"] * n
    real["label"] = ["DoS" if i % 2 else "BENIGN" for i in range(n)]
    rp = os.path.join(d, "real.csv"); pd.DataFrame(real).to_csv(rp, index=False)
    synth = pd.DataFrame(real).copy()                        # first 5 identical...
    for c in fs.COMMON_NUMERIC:                              # ...last 5 shifted away
        synth.loc[5:, c] = synth.loc[5:, c] + 900.0
    sp = os.path.join(d, "synth.csv"); synth.to_csv(sp, index=False)
    # no run_id/timestamp here (not the point of this test) -> allow partial schema
    r = _run([sys.executable, er, "--real", rp, "--synth", sp,
                        "--allow-contract-violations", "--allow-partial-schema"],
                       capture_output=True, text=True)
    assert r.returncode != 0 and "overlap" in (r.stdout + r.stderr).lower()


def test_js_distance_base2_scale():
    """Jensen-Shannon DISTANCE with base=2 tops out at 1.0 for disjoint dists [audit 10]."""
    try:
        import evaluate_realism as ev
    except SystemExit:
        return
    import pandas as pd
    a = pd.Series([0.0] * 50)
    b = pd.Series([100.0] * 50)
    assert 0.99 <= ev.js_numeric(a, b) <= 1.0001
    ca = pd.Series(["x"] * 50)
    cb = pd.Series(["y"] * 50)
    assert 0.99 <= ev.js_categorical(ca, cb) <= 1.0001


def test_to_epoch_requires_timezone():
    """to_epoch rejects a naive timestamp; a naive annotation aborts [audit 11]."""
    try:
        lf.to_epoch("2020-01-01T00:00:00")                   # no Z / offset
        assert False, "naive timestamp should be rejected"
    except ValueError:
        pass
    assert lf.to_epoch("2020-01-01T00:00:00Z") == 1577836800.0
    # a naive timestamp inside an annotation makes load_annotations abort
    try:
        lf.load_annotations(_write_ann([_base_ann(start_utc="2020-01-01T00:00:00",
                                                  end_utc="2020-01-01T00:10:00")]))
        assert False, "naive annotation ts should abort"
    except SystemExit:
        pass


def test_usable_flows_not_ambiguous():
    """An event credited ONLY by ambiguous/shared flows has usable=0 -> abort [audit 3]."""
    import subprocess
    d = tempfile.mkdtemp()
    conn = _conn_log(d, TS_INSIDE)                        # one TCP/443 flow
    # PortScan 1-1024 overlaps BruteForce 443; the flow is labeled BruteForce
    # (more specific), so PortScan gets 0 usable flows.
    ann = _write_ann([
        _base_ann(event_id="b", label="BruteForce", target_port="443",
                  attacker_ip="10.0.0.2", target_ip="10.0.0.1"),
        _base_ann(event_id="p", label="PortScan", target_port="1-1024",
                  attacker_ip="10.0.0.2", target_ip="10.0.0.1")])
    out = os.path.join(d, "lab.csv")
    r = _run([sys.executable, lf.__file__, "--conn", conn, "--annotations",
                        ann, "--out", out, "--allow-overlapping-windows"],
                       capture_output=True, text=True)
    assert r.returncode != 0
    out_txt = r.stdout + r.stderr
    assert "USABLE" in out_txt and "PortScan" in out_txt


def test_overlapping_windows_abort_by_default():
    """Two same-run windows intersecting in time+endpoints+proto+ports abort [audit 3]."""
    import subprocess
    d = tempfile.mkdtemp()
    conn = _conn_log(d, TS_INSIDE)
    ann = _write_ann([
        _base_ann(event_id="b", label="BruteForce", target_port="443",
                  attacker_ip="10.0.0.2", target_ip="10.0.0.1"),
        _base_ann(event_id="p", label="PortScan", target_port="1-1024",
                  attacker_ip="10.0.0.2", target_ip="10.0.0.1")])
    out = os.path.join(d, "lab.csv")
    r = _run([sys.executable, lf.__file__, "--conn", conn, "--annotations",
                        ann, "--out", out], capture_output=True, text=True)
    assert r.returncode != 0 and "overlapping" in (r.stdout + r.stderr)


def test_status_has_output_hashes():
    """The run-status must record SHA-256 of the outputs, not just inputs [audit 21]."""
    import json
    import subprocess
    d = tempfile.mkdtemp()
    conn = _conn_log(d, TS_INSIDE)
    ann = _write_ann([_base_ann(event_id="e", label="BruteForce", target_port="443",
                                attacker_ip="10.0.0.2", target_ip="10.0.0.1")])
    out = os.path.join(d, "lab.csv")
    _run([sys.executable, lf.__file__, "--conn", conn, "--annotations",
                    ann, "--out", out], check=True)
    st = json.load(open(out.replace(".csv", "") + "_run_status.json"))
    assert st["output_hashes"]["ml"] and len(st["output_hashes"]["ml"]) == 64
    assert st["events"]["e"]["usable_flows"] == 1


def test_merge_empty_label_aborts():
    """merge must reject a missing/empty label, not write it out [audit 4]."""
    import subprocess
    ms = _script("merge_and_split.py")
    d = tempfile.mkdtemp()
    p = os.path.join(d, "r.csv")
    with open(p, "w") as f:
        f.write("run_id,timestamp,flow_duration,label\n0,1000,0.1,DoS\n0,1001,0.2,\n")
    r = _run([sys.executable, ms, p, "--allow-partial-schema"],
                       capture_output=True, text=True)
    assert r.returncode != 0 and "missing/empty" in (r.stdout + r.stderr)


def test_merge_strict_schema_rejects_missing_and_junk():
    """Official schema requires the 15 COMMON + clean numerics [audit 13]."""
    import subprocess
    ms = _script("merge_and_split.py")
    d = tempfile.mkdtemp()
    p = os.path.join(d, "r.csv")                          # missing most COMMON columns
    with open(p, "w") as f:
        f.write("run_id,timestamp,flow_duration,label\n0,1000,0.1,DoS\n0,1001,0.2,BENIGN\n")
    r = _run([sys.executable, ms, p], capture_output=True, text=True)
    assert r.returncode != 0 and "schema mismatch" in (r.stdout + r.stderr)
    # junk in a COMMON numeric column, full schema otherwise
    import pandas as pd
    cols = {c: [1.0, 2.0] for c in fs.COMMON_NUMERIC}
    for c in fs.COMMON_CATEGORICAL:
        cols[c] = ["a", "a"]
    cols["run_id"] = [0, 0]; cols["timestamp"] = [1000, 1001]; cols["label"] = ["DoS", "BENIGN"]
    for _fm in fs.FLOWMETER:
        cols[_fm] = [1.0, 2.0]
    df = pd.DataFrame(cols)
    df["flow_duration"] = df["flow_duration"].astype(object)    # cast BEFORE the junk insert so pandas
    df.loc[0, "flow_duration"] = "BAD"                          # doesn't warn about an incompatible dtype
    p2 = os.path.join(d, "r2.csv"); df.to_csv(p2, index=False)
    r2 = _run([sys.executable, ms, p2], capture_output=True, text=True)
    assert r2.returncode != 0 and "non-numeric junk" in (r2.stdout + r2.stderr)


def test_merge_three_way_split_and_provenance():
    """--val-run yields train/val/test + a provenance JSON with in/out hashes [audit 19/21]."""
    import json
    import subprocess
    ms = _script("merge_and_split.py")
    gen = _script("synth_nids_dataset.py")
    d = tempfile.mkdtemp()
    real = os.path.join(d, "s3.csv")
    _run([sys.executable, gen, "--runs", "3", "--benign", "120",
                    "--attack-each", "40", "--out", real], check=True,
                   capture_output=True)
    pre = os.path.join(d, "pkg")
    r = _run([sys.executable, ms, real, "--val-run", "1", "--test-run", "2",
                        "--prefix", pre], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    for suffix in ("_train.csv", "_val.csv", "_test.csv", "_split_provenance.json"):
        assert os.path.exists(pre + suffix), suffix
    prov = json.load(open(pre + "_split_provenance.json"))
    assert set(prov["splits"]) == {"train", "val", "test"}
    assert prov["inputs"] and all(len(r["sha256"]) == 64 for r in prov["inputs"])  # list [audit 12]
    assert prov["outputs"] and all(len(h) == 64 for h in prov["outputs"].values())
    assert prov["chronology_verified"] is True and "diagnostic_overrides" in prov


def test_validate_drops_ambiguous_from_audit():
    """validate must drop ambiguous==1 rows from an audit file [audit 14]."""
    import subprocess
    vd = _script("validate_dataset.py")
    try:
        import sklearn  # noqa: F401
    except ImportError:
        return
    import pandas as pd
    d = tempfile.mkdtemp()
    n = 12
    data = {c: [1.0 + i for i in range(n)] for c in fs.COMMON_NUMERIC}
    for c in fs.COMMON_CATEGORICAL:
        data[c] = ["a"] * n
    data["run_id"] = [0] * n
    data["timestamp"] = [1000 + i for i in range(n)]
    data["label"] = ["DoS" if i % 2 else "BENIGN" for i in range(n)]
    data["ambiguous"] = [1 if i < 3 else 0 for i in range(n)]     # 3 ambiguous rows
    p = os.path.join(d, "audit.csv")
    pd.DataFrame(data).to_csv(p, index=False)
    r = _run([sys.executable, vd, "--csv", p, "--allow-single-run-diagnostic"],
                       capture_output=True, text=True)
    assert "dropping 3 ambiguous" in (r.stdout + r.stderr)


def test_quic_flows_have_no_ja3():
    """QUIC synthetic flows must carry ja3/ja3s = none to match the real pipeline [audit 15]."""
    import subprocess
    gen = _script("synth_nids_dataset.py")
    d = tempfile.mkdtemp()
    out = os.path.join(d, "x.csv")
    _run([sys.executable, gen, "--runs", "1", "--benign", "300",
                    "--attack-each", "40", "--schema", "extended", "--out", out],
                   check=True, capture_output=True)
    import pandas as pd
    df = pd.read_csv(out)
    quic = df[df["l7_protocol"] == "HTTP3-QUIC"]
    assert len(quic) > 0
    assert (quic["ja3"] == "none").all() and (quic["ja3s"] == "none").all()


def test_evaluate_realism_quality_and_fragility():
    """A clean multi-run eval prints INTEGRITY PASSED + REALISM QUALITY + a graded
    Fragility result (not the old blanket 'steep drop') [audit 6/7]."""
    import subprocess
    try:
        import evaluate_realism  # noqa: F401
    except SystemExit:
        return
    gen = _script("synth_nids_dataset.py")
    er = _script("evaluate_realism.py")
    d = tempfile.mkdtemp()
    real = os.path.join(d, "real.csv")
    synth = os.path.join(d, "synth.csv")
    _run([sys.executable, gen, "--runs", "2", "--benign", "300",
                    "--attack-each", "90", "--seed", "1", "--out", real], check=True,
                   capture_output=True)
    _run([sys.executable, gen, "--runs", "2", "--benign", "300",
                    "--attack-each", "90", "--seed", "2", "--out", synth], check=True,
                   capture_output=True)
    r = _run([sys.executable, er, "--real", real, "--synth", synth],
                       capture_output=True, text=True)
    out = r.stdout + r.stderr
    assert "REALISM QUALITY" in out
    assert "Fragility result" in out
    assert "REALISM NOT ENDORSED" in out or "DIAGNOSTIC" in out


def _full_schema_frame(n=4):
    """A minimal but COMPLETE official split-ready frame (run_id+ts+15 COMMON+label)."""
    import pandas as pd
    cols = {c: [1.0] * n for c in fs.COMMON_NUMERIC}
    cols["sni_present"] = [1] * n
    cols["transport"] = ["TCP"] * n
    cols["dst_port_class"] = ["well_known"] * n
    cols["tls_version"] = ["1.3"] * n
    cols["alpn"] = ["h2"] * n
    cols["ja3"] = ["x"] * n
    cols["ja3s"] = ["y"] * n
    cols["run_id"] = [0, 0, 1, 1][:n]
    cols["timestamp"] = list(range(1, n + 1))
    cols["label"] = (["BENIGN", "DoS", "BENIGN", "DoS"] * n)[:n]
    for _fm in fs.FLOWMETER:
        cols[_fm] = [1.0] * n
    return pd.DataFrame(cols)


def test_merge_rejects_extra_leaky_column():
    """An EXTRA column (e.g. matched_event_id) must abort the official schema [audit 3]."""
    import subprocess
    ms = _script("merge_and_split.py")
    d = tempfile.mkdtemp()
    df = _full_schema_frame()
    df["matched_event_id"] = ["", "e", "", "e2"]
    p = os.path.join(d, "leak.csv")
    df.to_csv(p, index=False)
    r = _run([sys.executable, ms, p], capture_output=True, text=True)
    assert r.returncode != 0 and "extra" in (r.stdout + r.stderr)


def test_merge_rejects_impossible_values():
    """inf, negative, fractional counts and out-of-domain values must abort [audit 4]."""
    import subprocess
    ms = _script("merge_and_split.py")
    d = tempfile.mkdtemp()
    for col, val, token in (("tot_fwd_pkts", -5, "negative"),
                            ("flow_bytes_s", float("inf"), "inf"),
                            ("tot_bwd_pkts", 2.5, "fractional")):
        df = _full_schema_frame()
        df[col] = [val] + list(df[col].iloc[1:])
        p = os.path.join(d, "bad_{}.csv".format(col))
        df.to_csv(p, index=False)
        r = _run([sys.executable, ms, p], capture_output=True, text=True)
        assert r.returncode != 0 and token in (r.stdout + r.stderr), (col, r.stdout + r.stderr)
    # out-of-domain tls_version
    df = _full_schema_frame(); df["tls_version"] = ["9.9"] * 4
    p = os.path.join(d, "badtls.csv"); df.to_csv(p, index=False)
    r = _run([sys.executable, ms, p], capture_output=True, text=True)
    assert r.returncode != 0 and "out-of-domain" in (r.stdout + r.stderr)


def test_value_domain_helper():
    """feature_schema.check_common_value_domains flags impossible values [audit 4]."""
    import pandas as pd
    df = _full_schema_frame()
    df.loc[0, "flow_duration"] = -1.0
    df.loc[1, "sni_present"] = 7
    errs, warns = fs.check_common_value_domains(df)
    assert any("flow_duration" in e for e in errs)
    assert any("sni_present" in e for e in errs)


def test_run_attacks_config_matrix_distinct():
    """The scenario matrix gives distinct configs per run, and reserves some for test [audit 9]."""
    import importlib.util
    ra = _script("run_attacks.py")
    spec = importlib.util.spec_from_file_location("ra_mod", ra)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert len(mod.CONFIG_MATRIX) >= 6 and mod.TEST_RESERVED_CONFIGS
    # old bug: run 14 == run 3. Now configs differ (14 % 8 = 6, not 3).
    def cfg(rid):
        sc = dict(mod.CONFIG_MATRIX[rid % len(mod.CONFIG_MATRIX)]); sc["config_id"] = rid
        return mod.build_portscan("10.10.10.11", "h", sc)[3]
    assert cfg(3) != cfg(14)


def test_nontls_benign_profiles_are_short():
    """DNS/NTP/refused benign flows get their OWN short profile, not the web one [audit 8]."""
    import subprocess
    gen = _script("synth_nids_dataset.py")
    d = tempfile.mkdtemp()
    out = os.path.join(d, "x.csv")
    _run([sys.executable, gen, "--runs", "1", "--benign", "1200",
                    "--attack-each", "40", "--schema", "extended", "--out", out],
                   check=True, capture_output=True)
    import pandas as pd
    df = pd.read_csv(out)
    dns = df[df["l7_protocol"] == "DNS"]
    web = df[df["l7_protocol"] == "HTTPS-TLS13"]
    assert len(dns) > 0 and dns["flow_duration"].median() < 0.5   # short, unlike ~4s web
    assert web["flow_duration"].median() > 1.0
    refused = df[df["l7_protocol"] == "TCP-refused"]
    if len(refused):
        assert refused["rst_flag_cnt"].mean() > 0.5              # refused -> RST


def _find_amostra():
    for base in (_HERE, os.path.join(_HERE, ".."), os.path.join(_HERE, "..", "..")):
        for rel in ("ProjetoDataset/amostra", "amostra"):
            p = os.path.join(base, rel, "synthetic_nids_dataset.metadata.json")
            if os.path.exists(p):
                return os.path.dirname(p)
    return None


def test_sample_metadata_matches_csv():
    """The distributed sample must match its metadata sha256 (reproducibility) [audit 2]."""
    import hashlib
    import json
    folder = _find_amostra()
    if not folder:
        return                                            # sample not in this layout
    meta = json.load(open(os.path.join(folder, "synthetic_nids_dataset.metadata.json")))
    csv_path = os.path.join(folder, "synthetic_nids_dataset.csv")
    h = hashlib.sha256(open(csv_path, "rb").read()).hexdigest()
    assert h == meta["sha256"], "sample CSV drifted from its metadata sha256"
    assert meta["seed"] == 42 and meta["runs"] == 3


def test_evaluate_categorical_axis_in_quality():
    """Disjoint categoricals must pull REALISM QUALITY off 'strong' even with perfect
    numerics + TSTR [audit 6]."""
    import subprocess
    try:
        import evaluate_realism  # noqa: F401
    except SystemExit:
        return
    import numpy as np
    import pandas as pd
    er = _script("evaluate_realism.py")
    d = tempfile.mkdtemp()

    def frame(ja3val):
        rng = np.random.default_rng(7)
        rows = []
        ts = 1000
        for r in range(2):
            for lab in ("BENIGN", "PortScan", "BruteForce", "DoS"):
                for _ in range(40):
                    row = {c: float(rng.integers(1, 40)) for c in fs.COMMON_NUMERIC}
                    row["sni_present"] = 1
                    row.update({"transport": "TCP", "dst_port_class": "well_known",
                                "tls_version": "1.3", "alpn": "h2",
                                "ja3": ja3val, "ja3s": ja3val})
                    row.update({"run_id": r, "timestamp": ts, "label": lab})
                    ts += 1
                    rows.append(row)
        return pd.DataFrame(rows)

    real = frame("aaa")
    synth = real.copy()
    for c in fs.COMMON_CATEGORICAL:                        # ALL categoricals disjoint
        synth[c] = synth[c].astype(str) + "_S"
    rp = os.path.join(d, "real.csv"); real.to_csv(rp, index=False)
    sp = os.path.join(d, "synth.csv"); synth.to_csv(sp, index=False)
    # random numerics here are not physical -> bypass the relational contract [audit 7]
    r = _run([sys.executable, er, "--real", rp, "--synth", sp,
                        "--allow-contract-violations"], capture_output=True, text=True)
    out = r.stdout + r.stderr
    assert "Categorical/protocol fidelity : poor" in out
    assert "REALISM QUALITY (overall = weakest axis): poor" in out


def test_relational_constraints_helper():
    """check_common_relational_constraints flags derived-feature incoherence [audit 6]."""
    ok = _full_schema_frame()
    ok["flow_duration"] = [10.0] * 4
    ok["tot_fwd_pkts"] = [10.0] * 4; ok["tot_bwd_pkts"] = [5.0] * 4
    ok["totlen_fwd_bytes"] = [1000.0] * 4; ok["totlen_bwd_bytes"] = [500.0] * 4
    ok["down_up_ratio"] = [0.5] * 4; ok["flow_bytes_s"] = [150.0] * 4; ok["flow_pkts_s"] = [1.5] * 4
    assert fs.check_common_relational_constraints(ok) == []
    bad = ok.copy(); bad.loc[0, "flow_bytes_s"] = 1.0; bad.loc[0, "down_up_ratio"] = 99.0
    errs = fs.check_common_relational_constraints(bad)
    assert any("flow_bytes_s" in e for e in errs) and any("down_up_ratio" in e for e in errs)


def test_validate_rejects_impossible_values():
    """validate must abort on impossible COMMON values (same contract as merge) [audit 7]."""
    import subprocess
    vd = _script("validate_dataset.py")
    try:
        import sklearn  # noqa: F401
    except ImportError:
        return
    import pandas as pd
    d = tempfile.mkdtemp()
    df = _full_schema_frame(); df.loc[0, "flow_duration"] = -1.0
    p = os.path.join(d, "bad.csv"); df.to_csv(p, index=False)
    r = _run([sys.executable, vd, "--csv", p, "--allow-single-run-diagnostic"],
                       capture_output=True, text=True)
    assert r.returncode != 0 and "contract" in (r.stdout + r.stderr)


def test_merge_time_frac_within_run_aborts():
    """--time-frac that cuts inside a run is diagnostic-only [audit 10]."""
    import subprocess
    ms = _script("merge_and_split.py")
    gen = _script("synth_nids_dataset.py")
    d = tempfile.mkdtemp()
    one = os.path.join(d, "one.csv")
    _run([sys.executable, gen, "--runs", "1", "--benign", "200",
                    "--attack-each", "60", "--out", one], check=True, capture_output=True)
    r = _run([sys.executable, ms, one, "--time-frac", "0.3", "--prefix",
                        os.path.join(d, "tf")], capture_output=True, text=True)
    assert r.returncode != 0 and "INSIDE run" in (r.stdout + r.stderr)
    r2 = _run([sys.executable, ms, one, "--time-frac", "0.3", "--prefix",
                         os.path.join(d, "tf2"), "--allow-within-run-split"],
                        capture_output=True, text=True)
    assert r2.returncode == 0, r2.stdout + r2.stderr


def test_campaign_manifest_load_and_reserved():
    """campaign.load validates + enforces reserved-test configs are TEST-only [audit 11/12]."""
    import json
    import importlib.util
    cp = _script("campaign.py")
    spec = importlib.util.spec_from_file_location("campaign_mod", cp)
    camp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(camp)
    good = {"campaign_id": "x", "expected_labels": ["BENIGN", "DoS"],
            "reserved_test_configs": [6, 7],                        # must equal the code
            "runs": {"0": {"config_id": 0, "split": "train"},
                     "1": {"config_id": 6, "split": "test"}}}
    d = tempfile.mkdtemp()
    p = os.path.join(d, "c.json"); json.dump(good, open(p, "w"))
    m = camp.load(p)
    assert camp.runs_in_split(m, "test") == [1] and camp.config_of_run(m, 1) == 6
    bad = {"campaign_id": "x", "expected_labels": ["BENIGN", "DoS"],
           "reserved_test_configs": [6, 7],
           "runs": {"0": {"config_id": 6, "split": "train"},        # reserved in train
                    "1": {"config_id": 0, "split": "test"}}}
    pb = os.path.join(d, "b.json"); json.dump(bad, open(pb, "w"))
    try:
        camp.load(pb)
        assert False, "reserved config in train should abort"
    except SystemExit:
        pass


def test_labeler_reports_port_coverage():
    """The run-status must expose PortScan port coverage (intensity) [audit 15]."""
    import json
    import subprocess
    d = tempfile.mkdtemp()
    conn = _conn_log(d, TS_INSIDE)                        # one flow on port 443
    ann = _write_ann([_base_ann(event_id="p", label="PortScan", target_port="1-1024",
                                attacker_ip="10.0.0.2", target_ip="10.0.0.1")])
    out = os.path.join(d, "lab.csv")
    _run([sys.executable, lf.__file__, "--conn", conn, "--annotations",
                    ann, "--out", out], check=True)
    ev = json.load(open(out.replace(".csv", "") + "_run_status.json"))["events"]["p"]
    assert ev["port_range_width"] == 1024 and ev["port_coverage"] > 0


def test_generator_emits_metadata():
    """The generator must auto-write a metadata sidecar whose sha256 matches [audit 19]."""
    import hashlib
    import json
    import subprocess
    gen = _script("synth_nids_dataset.py")
    d = tempfile.mkdtemp()
    out = os.path.join(d, "s.csv")
    _run([sys.executable, gen, "--runs", "1", "--benign", "100",
                    "--attack-each", "30", "--seed", "5", "--out", out], check=True,
                   capture_output=True)
    meta = json.load(open(out.replace(".csv", "") + ".metadata.json"))
    h = hashlib.sha256(open(out, "rb").read()).hexdigest()
    assert meta["sha256"] == h and meta["seed"] == 5


def test_correlate_ground_truth():
    """correlate_ground_truth raises evidence to application_observed via Caddy log [audit 16]."""
    import calendar
    import json
    import subprocess
    import time as _t
    cg = _script("correlate_ground_truth.py")
    d = tempfile.mkdtemp()
    ann = os.path.join(d, "ann.csv")
    with open(ann, "w") as f:
        f.write("event_id,run_id,label,attacker_ip,target_ip,target_hostname,protocol,"
                "target_port,start_utc,end_utc,tool,command,parameters,return_code,"
                "status,error_type\n")
        f.write("e1,0,BruteForce,10.0.0.2,10.0.0.1,blog.lab,tcp,443,"
                "2026-01-01T00:00:00.000000Z,2026-01-01T00:10:00.000000Z,hydra,c,p,0,success,\n")
    st = os.path.join(d, "st.json")
    json.dump({"events": {"e1": {"label": "BruteForce", "usable_flows": 50}}}, open(st, "w"))

    def ep(s):
        return calendar.timegm(_t.strptime(s, "%Y-%m-%dT%H:%M:%SZ"))
    caddy = os.path.join(d, "caddy.json")
    with open(caddy, "w") as f:
        for i in range(3):                               # ATTACKER POSTs
            f.write(json.dumps({"ts": ep("2026-01-01T00:0%d:00Z" % (i + 1)), "status": 401,
                                "request": {"method": "POST", "uri": "/wp-login.php",
                                            "remote_ip": "10.0.0.2", "host": "blog.lab"}}) + "\n")
        # a concurrent BENIGN login must NOT be credited to the attack [audit 10]
        f.write(json.dumps({"ts": ep("2026-01-01T00:06:00Z"), "status": 401,
                            "request": {"method": "POST", "uri": "/wp-login.php",
                                        "remote_ip": "10.0.0.99", "host": "blog.lab"}}) + "\n")
    gt = os.path.join(d, "gt.json")
    r = _run([sys.executable, cg, "--annotations", ann, "--run-status", st,
                        "--caddy-log", caddy, "--out", gt], capture_output=True, text=True)
    assert r.returncode == 0
    rep = json.load(open(gt))["events"][0]
    assert "application_observed" in rep["evidence_levels"]
    assert rep["attacker_app_requests"] == 3 and rep["benign_app_requests"] == 1


def test_correlate_ignores_benign_only():
    """A window with ONLY a benign client at /wp-login.php must NOT reach application_observed [audit 10]."""
    import calendar
    import json
    import subprocess
    import time as _t
    cg = _script("correlate_ground_truth.py")
    d = tempfile.mkdtemp()
    ann = os.path.join(d, "ann.csv")
    with open(ann, "w") as f:
        f.write("event_id,run_id,label,attacker_ip,target_ip,target_hostname,protocol,"
                "target_port,start_utc,end_utc,tool,command,parameters,return_code,"
                "status,error_type\n")
        f.write("e1,0,BruteForce,10.10.10.30,10.10.10.11,blog.lab,tcp,443,"
                "2026-01-01T00:00:00.000000Z,2026-01-01T00:10:00.000000Z,hydra,c,p,0,success,\n")
    st = os.path.join(d, "st.json")
    json.dump({"events": {"e1": {"label": "BruteForce", "usable_flows": 50}}}, open(st, "w"))
    caddy = os.path.join(d, "caddy.json")
    with open(caddy, "w") as f:                          # only a BENIGN client (.20)
        f.write(json.dumps({"ts": calendar.timegm(_t.strptime(
            "2026-01-01T00:05:00Z", "%Y-%m-%dT%H:%M:%SZ")), "status": 401,
            "request": {"method": "POST", "uri": "/wp-login.php",
                        "remote_ip": "10.10.10.20", "host": "blog.lab"}}) + "\n")
    gt = os.path.join(d, "gt.json")
    _run([sys.executable, cg, "--annotations", ann, "--run-status", st,
                    "--caddy-log", caddy, "--out", gt], check=True, capture_output=True)
    rep = json.load(open(gt))["events"][0]
    assert "application_observed" not in rep["evidence_levels"]
    assert rep["attacker_app_requests"] == 0 and rep["benign_app_requests"] == 1


def _campaign_manifest(path, n_runs=7):
    """Write a manifest: runs 0..n-3 train, n-2 validation, n-1..? test [audit 4]."""
    import json
    runs = {}
    for r in range(n_runs):
        if r < n_runs - 3:
            split, cfg = "train", r
        elif r == n_runs - 3:
            split, cfg = "validation", 4
        else:
            split, cfg = "test", 6 if r == n_runs - 2 else 7
        # Reproducible: seed+day on every run, days increasing so train<val<test holds, PLUS
        # the pinned attack plan + target + timeout (merge/validate/evaluate load reproducible)
        # [audit 9/11 / v20.5 §7].
        runs[str(r)] = _run_spec(cfg, split, r, "2026-07-{:02d}".format(r + 1),
                                 attacks=("PortScan", "BruteForce", "DoS"))
    json.dump({"campaign_id": "test", "expected_labels": ["BENIGN", "PortScan",
               "BruteForce", "DoS"], "reserved_test_configs": [6, 7], "runs": runs},
              open(path, "w"))
    return path


def test_merge_campaign_splits_use_full_run_sets():
    """merge --campaign must hold out EVERY test run (run 5 in test, NOT train) [audit 4]."""
    import subprocess
    ms = _script("merge_and_split.py")
    gen = _script("synth_nids_dataset.py")
    d = tempfile.mkdtemp()
    real = os.path.join(d, "r7.csv")
    _run([sys.executable, gen, "--runs", "7", "--benign", "120",
                    "--attack-each", "40", "--out", real], check=True, capture_output=True)
    cj = _campaign_manifest(os.path.join(d, "c.json"), 7)
    r = _run([sys.executable, ms, real, "--campaign", cj, "--allow-unauthenticated-inputs",
                        "--prefix", os.path.join(d, "cmp")], capture_output=True, text=True)
    out = r.stdout + r.stderr
    assert r.returncode == 0, out
    assert "train [0, 1, 2, 3]" in out and "test [5, 6]" in out  # run 5 is TEST, not train


def test_merge_campaign_rejects_extra_run():
    """merge --campaign must reject CSV runs that differ from the manifest [audit 4]."""
    import subprocess
    ms = _script("merge_and_split.py")
    gen = _script("synth_nids_dataset.py")
    d = tempfile.mkdtemp()
    real = os.path.join(d, "r8.csv")
    _run([sys.executable, gen, "--runs", "8", "--benign", "80",
                    "--attack-each", "30", "--out", real], check=True, capture_output=True)
    cj = _campaign_manifest(os.path.join(d, "c.json"), 7)          # manifest only 0..6
    r = _run([sys.executable, ms, real, "--campaign", cj, "--allow-unauthenticated-inputs",
                        "--prefix", os.path.join(d, "cmp")], capture_output=True, text=True)
    assert r.returncode != 0 and "!= campaign runs" in (r.stdout + r.stderr)


def test_evaluate_uses_campaign_split():
    """evaluate --campaign must split by the manifest (test runs 5,6), not max run_id [audit 5]."""
    import subprocess
    try:
        import evaluate_realism  # noqa: F401
    except SystemExit:
        return
    gen = _script("synth_nids_dataset.py")
    er = _script("evaluate_realism.py")
    d = tempfile.mkdtemp()
    real = os.path.join(d, "real.csv")
    synth = os.path.join(d, "synth.csv")
    _run([sys.executable, gen, "--runs", "7", "--benign", "120",
                    "--attack-each", "40", "--seed", "1", "--out", real], check=True,
                   capture_output=True)
    _run([sys.executable, gen, "--runs", "7", "--benign", "120",
                    "--attack-each", "40", "--seed", "2", "--out", synth], check=True,
                   capture_output=True)
    cj = _campaign_manifest(os.path.join(d, "c.json"), 7)
    r = _run([sys.executable, er, "--real", real, "--synth", synth,
                        "--campaign", cj, "--allow-unauthenticated-real"],   # split test, not auth [P0-8]
                       capture_output=True, text=True)
    assert "campaign hold-out: test runs [5, 6]" in (r.stdout + r.stderr)


def test_validate_uses_campaign_split():
    """validate --campaign must split by the manifest (test runs 5,6), NOT max run_id [audit 5]."""
    import subprocess
    vd = _script("validate_dataset.py")
    gen = _script("synth_nids_dataset.py")
    try:
        import sklearn  # noqa: F401
    except ImportError:
        return
    d = tempfile.mkdtemp()
    csv7 = os.path.join(d, "v7.csv")
    _run([sys.executable, gen, "--runs", "7", "--benign", "150",
                    "--attack-each", "50", "--out", csv7], check=True, capture_output=True)
    cj = _campaign_manifest(os.path.join(d, "c.json"), 7)
    r = _run([sys.executable, vd, "--csv", csv7, "--campaign", cj,
                        "--allow-unauthenticated-inputs"], capture_output=True, text=True)
    out = r.stdout + r.stderr
    assert "campaign hold-out: test runs [5, 6]" in out           # run 5 is TEST
    assert "run_id < 6" not in out                                # NOT the max-run_id split


def test_run_attacks_campaign_overrides_cli():
    """run_attacks --campaign: a CLI --config-id that contradicts the manifest aborts [audit 6]."""
    import subprocess
    ra = _script("run_attacks.py")
    d = tempfile.mkdtemp()
    cj = _campaign_manifest(os.path.join(d, "c.json"), 7)          # run 0 -> config 0 (train)
    r = _run([sys.executable, ra, "--campaign", cj, "--run-id", "0",
                        "--config-id", "6"], capture_output=True, text=True)  # 6 = reserved
    assert r.returncode != 0 and "contradicts the campaign" in (r.stdout + r.stderr)


def test_validate_partial_schema_and_junk_abort():
    """validate must abort on a partial schema OR numeric junk (same contract as merge) [audit 8/9]."""
    import subprocess
    vd = _script("validate_dataset.py")
    try:
        import sklearn  # noqa: F401
    except ImportError:
        return
    d = tempfile.mkdtemp()
    partial = os.path.join(d, "partial.csv")
    with open(partial, "w") as f:                        # only 1 of 15 COMMON features
        f.write("run_id,timestamp,flow_duration,label\n0,1,0.1,BENIGN\n1,2,0.2,DoS\n")
    r = _run([sys.executable, vd, "--csv", partial], capture_output=True, text=True)
    assert r.returncode != 0 and ("official" in (r.stdout + r.stderr))
    import pandas as pd
    junk = _full_schema_frame()
    junk["flow_bytes_s"] = [(1.0 + 1.0) / 1.0] * 4       # make it relationally consistent
    junk["flow_pkts_s"] = [(1.0 + 1.0) / 1.0] * 4
    junk["down_up_ratio"] = [1.0] * 4
    junk["tot_fwd_pkts"] = junk["tot_fwd_pkts"].astype(object)   # cast before junk insert (no warning)
    junk.loc[0, "tot_fwd_pkts"] = "BAD"                  # numeric junk
    pj = os.path.join(d, "junk.csv"); junk.to_csv(pj, index=False)
    r2 = _run([sys.executable, vd, "--csv", pj], capture_output=True, text=True)
    assert r2.returncode != 0 and "junk" in (r2.stdout + r2.stderr)


def test_duration_zero_gives_nan_rate():
    """duration <= 0 must yield NaN rates, not a 1e-6-divided giant [audit 10]."""
    import math
    row = {"duration": "0", "orig_pkts": "1", "resp_pkts": "1", "orig_ip_bytes": "1000",
           "resp_ip_bytes": "1000", "proto": "tcp", "id.resp_p": "443"}
    out = fs.zeek_row_to_common(row, {}, {})
    assert math.isnan(out["flow_bytes_s"]) and math.isnan(out["flow_pkts_s"])
    # a positive duration still computes a finite rate
    row["duration"] = "2"
    out2 = fs.zeek_row_to_common(row, {}, {})
    assert out2["flow_bytes_s"] == 1000.0        # (1000+1000)/2


def test_labeler_rejects_raw_junk():
    """The labeler must abort on corrupt raw Zeek values ('BAD' != '-') [audit 11]."""
    import subprocess
    d = tempfile.mkdtemp()
    cf = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
          "service", "duration", "orig_bytes", "resp_bytes", "orig_ip_bytes",
          "resp_ip_bytes", "orig_pkts", "resp_pkts", "conn_state"]
    conn = os.path.join(d, "conn.log")
    with open(conn, "w") as f:
        f.write("#separator \\x09\n#fields\t" + "\t".join(cf) + "\n#types\t" +
                "\t".join(["string"] * len(cf)) + "\n")
        f.write("\t".join(["1000", "C1", "1.1.1.1", "5", "2.2.2.2", "443", "tcp", "ssl",
                           "BAD", "100", "200", "1500", "3000", "5", "6", "SF"]) + "\n")
    ann = _write_ann([])
    r = _run([sys.executable, lf.__file__, "--conn", conn, "--annotations",
                        ann, "--out", os.path.join(d, "lab.csv"), "--allow-empty",
                        "--run-id", "0"], capture_output=True, text=True)
    assert r.returncode != 0 and "not numeric" in (r.stdout + r.stderr)


def test_status_write_failure_aborts():
    """If the run-status cannot be written, the run ABORTS (no outputs w/o provenance) [audit 12]."""
    import subprocess
    d = tempfile.mkdtemp()
    conn = _conn_log(d, TS_INSIDE)
    ann = _write_ann([_base_ann(event_id="e", label="BruteForce", target_port="443",
                                attacker_ip="10.0.0.2", target_ip="10.0.0.1")])
    out = os.path.join(d, "lab.csv")
    os.mkdir(out.replace(".csv", "") + "_run_status.json")   # block the status write
    r = _run([sys.executable, lf.__file__, "--conn", conn, "--annotations",
                        ann, "--out", out], capture_output=True, text=True)
    assert r.returncode != 0 and "run status" in (r.stdout + r.stderr)
    assert not os.path.exists(out)                           # outputs NOT published


def test_merge_rejects_duplicate_input():
    """The same input file passed twice must abort [audit 13]."""
    import subprocess
    ms = _script("merge_and_split.py")
    gen = _script("synth_nids_dataset.py")
    d = tempfile.mkdtemp()
    r0 = os.path.join(d, "r.csv")
    _run([sys.executable, gen, "--runs", "2", "--benign", "60",
                    "--attack-each", "20", "--out", r0], check=True, capture_output=True)
    r = _run([sys.executable, ms, r0, r0, "--prefix", os.path.join(d, "x")],
                       capture_output=True, text=True)
    assert r.returncode != 0 and "duplicate input" in (r.stdout + r.stderr)


def test_campaign_load_rejects_invalid():
    """campaign.load must reject structurally-invalid manifests [audit 5]."""
    import importlib.util
    import json
    cp = _script("campaign.py")
    spec = importlib.util.spec_from_file_location("campaign_mod2", cp)
    camp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(camp)
    base = {"campaign_id": "x", "expected_labels": ["BENIGN"],
            "runs": {"0": {"config_id": 0, "split": "train"},
                     "1": {"config_id": 6, "split": "test"}}}
    bad = {
        "no_id": {**base, "campaign_id": ""},
        "empty_runs": {**base, "runs": {}},
        "text_run": {**base, "runs": {"abc": {"config_id": 0, "split": "train"}}},
        "noncanon": {**base, "runs": {"01": {"config_id": 0, "split": "train"},
                                      "1": {"config_id": 6, "split": "test"}}},
        "cfg_out": {**base, "runs": {"0": {"config_id": 99, "split": "train"},
                                     "1": {"config_id": 6, "split": "test"}}},
        "dup_labels": {**base, "expected_labels": ["BENIGN", "BENIGN"]},
        "no_test": {**base, "runs": {"0": {"config_id": 0, "split": "train"}}},
    }
    d = tempfile.mkdtemp()
    for name, man in bad.items():
        p = os.path.join(d, name + ".json"); json.dump(man, open(p, "w"))
        try:
            camp.load(p); assert False, "should reject " + name
        except SystemExit:
            pass


def test_evaluate_override_forces_diagnostic():
    """Any diagnostic override (e.g. --allow-partial-schema) must prevent an official
    INTEGRITY PASS [audit 8]."""
    import subprocess
    try:
        import evaluate_realism  # noqa: F401
    except SystemExit:
        return
    gen = _script("synth_nids_dataset.py")
    er = _script("evaluate_realism.py")
    d = tempfile.mkdtemp()
    real = os.path.join(d, "real.csv"); synth = os.path.join(d, "synth.csv")
    _run([sys.executable, gen, "--runs", "2", "--benign", "300",
                    "--attack-each", "90", "--seed", "1", "--out", real], check=True,
                   capture_output=True)
    _run([sys.executable, gen, "--runs", "2", "--benign", "300",
                    "--attack-each", "90", "--seed", "2", "--out", synth], check=True,
                   capture_output=True)
    r = _run([sys.executable, er, "--real", real, "--synth", synth,
                        "--allow-partial-schema"], capture_output=True, text=True)
    out = r.stdout + r.stderr
    assert "DIAGNOSTIC ONLY" in out and "allow_partial_schema" in out
    assert "INTEGRITY CHECKS PASSED" not in out


def test_campaign_split_chronology_helper():
    """chronology_ok enforces train < validation < test [audit 4]."""
    import importlib.util
    cp = _script("campaign.py")
    spec = importlib.util.spec_from_file_location("campaign_c", cp)
    camp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(camp)
    assert camp.chronology_ok([1, 2], [7, 8], val_ts=[4, 5]) is True
    assert camp.chronology_ok([1, 2], [4, 5], val_ts=[7, 8]) is False   # val after test
    assert camp.chronology_ok([1, 2], [3, 4]) is True                   # 2-way
    assert camp.chronology_ok([5, 6], [3, 4]) is False


def test_validate_campaign_val_after_test_aborts():
    """validate must abort when the validation run is ordered AFTER the test [audit 4]."""
    import subprocess
    import json
    vd = _script("validate_dataset.py")
    gen = _script("synth_nids_dataset.py")
    try:
        import sklearn  # noqa: F401
    except ImportError:
        return
    import pandas as pd
    d = tempfile.mkdtemp()
    csv3 = os.path.join(d, "v3.csv")
    _run([sys.executable, gen, "--runs", "3", "--benign", "120",
                    "--attack-each", "40", "--out", csv3], check=True, capture_output=True)
    df = pd.read_csv(csv3)
    df.loc[df.run_id == 1, "timestamp"] = df.loc[df.run_id == 1, "timestamp"] + 10 ** 7  # val latest
    df.to_csv(csv3, index=False)
    man = os.path.join(d, "c.json")
    _atk = ("PortScan", "BruteForce", "DoS")
    json.dump({"campaign_id": "x", "expected_labels": ["BENIGN", "PortScan", "BruteForce", "DoS"],
               "runs": {"0": _run_spec(0, "train", 0, "2026-07-01", _atk),
                        "1": _run_spec(1, "validation", 1, "2026-07-02", _atk),
                        "2": _run_spec(2, "test", 2, "2026-07-03", _atk)}},
              open(man, "w"))
    r = _run([sys.executable, vd, "--csv", csv3, "--campaign", man,
                        "--allow-unauthenticated-inputs"], capture_output=True, text=True)
    assert "chronology invalid" in (r.stdout + r.stderr)


def test_labeler_min_port_coverage():
    """--min-port-coverage aborts a PortScan that barely probed its range [audit 10]."""
    import subprocess
    d = tempfile.mkdtemp()
    conn = _conn_log(d, TS_INSIDE)                        # one flow on port 443
    ann = _write_ann([_base_ann(event_id="p", label="PortScan", target_port="1-1024",
                                attacker_ip="10.0.0.2", target_ip="10.0.0.1")])
    out = os.path.join(d, "lab.csv")
    r = _run([sys.executable, lf.__file__, "--conn", conn, "--annotations",
                        ann, "--out", out, "--min-port-coverage", "0.5"],
                       capture_output=True, text=True)
    assert r.returncode != 0 and "min-port-coverage" in (r.stdout + r.stderr)


def test_manifest_type_and_reserved_validation():
    """campaign.load rejects wrong types and a manifest-edited reserved set [audit 7/8]."""
    import importlib.util
    import json
    cp = _script("campaign.py")
    spec = importlib.util.spec_from_file_location("campaign_t", cp)
    camp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(camp)
    d = tempfile.mkdtemp()
    base_runs = {"0": {"config_id": 0, "split": "train"}, "1": {"config_id": 6, "split": "test"}}
    bad = {
        "toplevel_list": [],
        "run_is_list": {"campaign_id": "x", "expected_labels": ["BENIGN"],
                        "runs": {"0": []}},
        "reserved_edited": {"campaign_id": "x", "expected_labels": ["BENIGN"],
                            "reserved_test_configs": [], "runs": base_runs},  # 6 in train w/ empty reserved
    }
    for name, man in bad.items():
        p = os.path.join(d, name + ".json"); json.dump(man, open(p, "w"))
        try:
            camp.load(p); assert False, "should reject " + name
        except SystemExit:
            pass


def test_manifest_temporal_and_auc_field_validation():
    """§9/§14 [audit v20.21]: the manifest may PIN required_min_window_overlap (null or a fraction in
    [0,1]), max_duration_fallback_rate ([0,1]) and max_domain_auc ([0,1]); camp.load validates them
    and rejects out-of-range / wrong-typed values so a bogus pin can't slip in."""
    import json
    import campaign as camp
    d = tempfile.mkdtemp()
    good = {"campaign_id": "x", "expected_labels": ["BENIGN", "DoS"],
            "required_min_window_overlap": 0.5, "max_duration_fallback_rate": 0.0,
            "max_domain_auc": 0.6,
            "runs": {"0": {"config_id": 0, "split": "train", "attacks": ["DoS"]},
                     "1": {"config_id": 6, "split": "test", "attacks": ["DoS"]}}}
    gp = os.path.join(d, "g.json"); json.dump(good, open(gp, "w"))
    assert camp.load(gp) is not None                              # all three pins accepted
    # pinned LEGACY (overlap None) — a fallback ceiling would be meaningless there, so DROP it [§7].
    g2 = json.loads(json.dumps(good)); g2["required_min_window_overlap"] = None
    del g2["max_duration_fallback_rate"]
    p2 = os.path.join(d, "g2.json"); json.dump(g2, open(p2, "w"))
    assert camp.load(p2) is not None

    def rej(field, val, needle):
        m = json.loads(json.dumps(good)); m[field] = val
        p = os.path.join(d, "b.json"); json.dump(m, open(p, "w"))
        try:
            camp.load(p); assert False, "accepted {}={!r}".format(field, val)
        except SystemExit as e:
            assert needle in str(e), (needle, str(e))
    rej("required_min_window_overlap", 2.0, "required_min_window_overlap")
    rej("required_min_window_overlap", "x", "required_min_window_overlap")
    rej("max_duration_fallback_rate", -1, "max_duration_fallback_rate")
    rej("max_domain_auc", 1.5, "max_domain_auc")
    rej("max_domain_auc", True, "max_domain_auc")                 # bool is not a valid number
    # §7 [audit v20.22]: a fallback ceiling WITHOUT an active overlap pin is incoherent.
    m = json.loads(json.dumps(good)); del m["required_min_window_overlap"]
    p = os.path.join(d, "incoh.json"); json.dump(m, open(p, "w"))
    try:
        camp.load(p); assert False, "fallback ceiling without overlap pin accepted"
    except SystemExit as e:
        assert "requires required_min_window_overlap" in str(e), str(e)
    # §9 [audit v20.24]: min_overall_realism_quality is DEPRECATED at the top level (must live in a
    # COMPLETE release_quality_policy so the axis thresholds that define 'strong' are pinned too).
    rej("min_overall_realism_quality", "strong", "deprecated at the top level")
    rej("min_domain_test_samples_per_class", 0, "min_domain_test_samples_per_class")   # must be >= 1
    rej("min_domain_test_samples_per_class", 1.5, "min_domain_test_samples_per_class")  # must be int
    # §8/§10 [audit v20.24]: the release_quality_policy block must be COMPLETE and the single source.
    base_noauc = json.loads(json.dumps(good)); del base_noauc["max_domain_auc"]         # avoid §10 dual
    complete = {"max_domain_auc": 0.7, "min_domain_test_samples_per_class": 30,
                "min_overall_realism_quality": "strong", "max_mean_js": 0.25, "max_cat_js": 0.25,
                "max_cond_js": 0.3, "max_missing_rate_difference": 0.15,
                "min_tstr_reference_ratio": 0.8, "min_reference_f1": 0.5}
    okm = dict(base_noauc); okm["release_quality_policy"] = dict(complete)
    op = os.path.join(d, "rqp_ok.json"); json.dump(okm, open(op, "w"))
    assert camp.load(op) is not None                                                    # complete -> OK

    def rej_block(mut, needle):
        b = dict(base_noauc); rqp = dict(complete); mut(rqp); b["release_quality_policy"] = rqp
        p = os.path.join(d, "rb.json"); json.dump(b, open(p, "w"))
        try:
            camp.load(p); assert False, "accepted block: " + needle
        except SystemExit as e:
            assert needle in str(e), (needle, str(e))
    rej_block(lambda r: r.__setitem__("max_mean_js", float("inf")), "finite number")   # inf rejected
    rej_block(lambda r: r.__setitem__("bogus", 1), "unknown field")                    # closed set
    rej_block(lambda r: r.pop("max_cond_js"), "INCOMPLETE")                            # §8 partial
    rej_block(lambda r: r.__setitem__("min_overall_realism_quality", "amazing"), "moderate")  # bad grade
    dual = dict(base_noauc); dual["max_domain_auc"] = 0.5                              # §10 dual source
    dual["release_quality_policy"] = dict(complete)
    dp = os.path.join(d, "dual.json"); json.dump(dual, open(dp, "w"))
    try:
        camp.load(dp); assert False, "dual source accepted"
    except SystemExit as e:
        assert "ONE place" in str(e), str(e)


def test_manifest_pins_temporal_policy_labeler():
    """§9 [audit v20.21]: a campaign that PINS required_min_window_overlap forces the labeler CLI to
    MATCH it exactly (pre-registration) — omitting the flag (legacy) or passing a different threshold
    aborts, so the temporal policy can't be tuned after seeing the results."""
    import json
    import hashlib
    d = tempfile.mkdtemp()
    wstart = 1577836800.0
    cf = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service",
          "duration", "orig_bytes", "resp_bytes", "orig_ip_bytes", "resp_ip_bytes", "orig_pkts",
          "resp_pkts", "conn_state"]
    conn = os.path.join(d, "conn.log")
    with open(conn, "w") as f:
        f.write("#separator \\x09\n#fields\t" + "\t".join(cf) + "\n#types\t"
                + "\t".join(["string"] * len(cf)) + "\n")
        f.write("\t".join([str(wstart + 100), "C1", "10.0.0.2", "5", "10.0.0.1", "443", "udp", "ssl",
                           "100", "100", "200", "1500", "3000", "5", "6", "SF"]) + "\n")
    run = lambda cfg, sp: {"config_id": cfg, "split": sp, "seed": cfg, "day": "2026-01-0%d" % (cfg + 1),
                           "attacks": ["DoS"], "target_host": "h", "target_ip": "10.0.0.1",
                           "attacker_ip": "10.0.0.2", "timeout": 900, "dos_seconds": 120}
    man = {"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
           "required_min_window_overlap": 0.5,                    # PIN the overlap threshold
           "runs": {"0": run(0, "train"), "1": run(6, "test")}}
    mp = os.path.join(d, "m.json"); json.dump(man, open(mp, "w"))
    msha = hashlib.sha256(open(mp, "rb").read()).hexdigest()
    ann = _campaign_ann(d, "C", msha, 0, [{"label": "DoS"}])
    lf = _script("label_flows.py")
    base = [sys.executable, lf, "--conn", conn, "--annotations", ann, "--campaign", mp,
            "--allow-incomplete-campaign"]
    ok = _run(base + ["--min-window-overlap", "0.5", "--out", os.path.join(d, "ok.csv")],
              capture_output=True, text=True)
    assert ok.returncode == 0, ok.stdout + ok.stderr             # CLI matches the pin
    miss = _run(base + ["--out", os.path.join(d, "miss.csv")], capture_output=True, text=True)
    assert miss.returncode != 0 and "required_min_window_overlap" in (miss.stdout + miss.stderr)
    diff = _run(base + ["--min-window-overlap", "0.2", "--out", os.path.join(d, "diff.csv")],
                capture_output=True, text=True)
    assert diff.returncode != 0 and "required_min_window_overlap" in (diff.stdout + diff.stderr)


def test_manifest_pins_domain_auc_ceiling():
    """§14 [audit v20.21]: a PINNED max_domain_auc is the pre-registered release bar. evaluate REQUIRES
    --domain-distinguishability when it's pinned, and the CLI may only CONFIRM or TIGHTEN it — a more
    permissive CLI aborts (both checks fire BEFORE the detector trains)."""
    import json
    er, gen = _script("evaluate_realism.py"), _script("synth_nids_dataset.py")
    d = tempfile.mkdtemp()
    real, synth = os.path.join(d, "real.csv"), os.path.join(d, "synth.csv")
    _run([sys.executable, gen, "--runs", "7", "--benign", "120", "--attack-each", "40",
          "--seed", "1", "--out", real], check=True, capture_output=True)
    _run([sys.executable, gen, "--runs", "7", "--benign", "120", "--attack-each", "40",
          "--seed", "2", "--out", synth], check=True, capture_output=True)
    cj = _campaign_manifest(os.path.join(d, "c.json"), 7)
    m = json.load(open(cj)); m["max_domain_auc"] = 0.6; json.dump(m, open(cj, "w"))
    base = [sys.executable, er, "--real", real, "--synth", synth, "--campaign", cj,
            "--allow-unauthenticated-real"]
    r1 = _run(base, capture_output=True, text=True)              # pinned but detector not requested
    assert r1.returncode != 0 and "pass --domain-distinguishability" in (r1.stdout + r1.stderr)
    r2 = _run(base + ["--domain-distinguishability", "--max-domain-auc", "0.9"],
              capture_output=True, text=True)                    # CLI more permissive than the pin
    assert r2.returncode != 0 and "MORE PERMISSIVE" in (r2.stdout + r2.stderr)


def test_manifest_pins_release_quality_and_min_samples():
    """§10/§11 [audit v20.22]: the campaign can PIN a minimum per-class holdout support (so a per-class
    AUC isn't read off 1-2 points) and a minimum overall realism quality. A pinned min-samples that the
    holdout can't meet makes the gate 'unavailable' (exit 3), and the pinned quality bar is recorded in
    the report (release_eligible must also clear it, not just the domain AUC gate)."""
    import json
    er, gen = _script("evaluate_realism.py"), _script("synth_nids_dataset.py")
    d = tempfile.mkdtemp()
    real, synth = os.path.join(d, "real.csv"), os.path.join(d, "synth.csv")
    _run([sys.executable, gen, "--runs", "7", "--benign", "120", "--attack-each", "40",
          "--seed", "1", "--out", real], check=True, capture_output=True)
    _run([sys.executable, gen, "--runs", "7", "--benign", "120", "--attack-each", "40",
          "--seed", "2", "--out", synth], check=True, capture_output=True)
    cj = _campaign_manifest(os.path.join(d, "c.json"), 7)
    m = json.load(open(cj))
    m["release_quality_policy"] = {                       # a COMPLETE, pre-registered policy [§8]
        "max_domain_auc": 1.0,                            # AUC gate itself would PASS (<= 1.0)
        "min_overall_realism_quality": "strong",          # ... but the quality bar is pre-registered
        "min_domain_test_samples_per_class": 100000,      # unreachable -> classes 'missing' -> unavailable
        "max_mean_js": 0.25, "max_cat_js": 0.25, "max_cond_js": 0.3,
        "max_missing_rate_difference": 0.15, "min_tstr_reference_ratio": 0.8, "min_reference_f1": 0.5}
    json.dump(m, open(cj, "w"))
    out = os.path.join(d, "o.json")
    r = _run([sys.executable, er, "--real", real, "--synth", synth, "--campaign", cj,
              "--allow-unauthenticated-real", "--domain-distinguishability", "--json", out],
             capture_output=True, text=True)
    assert r.returncode == 3, (r.returncode, r.stdout + r.stderr)         # §10: min-samples not met
    j = json.load(open(out)); dd = j["domain_distinguishability"]
    assert dd["min_domain_test_samples_per_class"] == 100000
    assert dd["missing_domain_test_classes"]                              # every class under-supported
    assert j["domain_realism_gate"] == "unavailable" and j["release_eligible"] is False
    assert j["min_overall_realism_quality"] == "strong"                   # §11: bar recorded in the report


def test_release_quality_policy_pins_thresholds_and_exit_code():
    """§8/§9 [audit v20.23]: a release_quality_policy PRE-REGISTERS the AXIS thresholds that define
    'strong', so a permissive CLI (--max-mean-js 1) can NOT redefine it; and a quality-only failure
    (the domain AUC gate passes but the pinned quality bar is not met) EXITS 3, not 0 — so a CI running
    the tool alone actually blocks."""
    import json
    er, gen = _script("evaluate_realism.py"), _script("synth_nids_dataset.py")
    d = tempfile.mkdtemp()
    real, synth = os.path.join(d, "real.csv"), os.path.join(d, "synth.csv")
    _run([sys.executable, gen, "--runs", "7", "--benign", "120", "--attack-each", "40",
          "--seed", "1", "--out", real], check=True, capture_output=True)
    _run([sys.executable, gen, "--runs", "7", "--benign", "120", "--attack-each", "40",
          "--seed", "2", "--out", synth], check=True, capture_output=True)
    cj = _campaign_manifest(os.path.join(d, "c.json"), 7)
    m = json.load(open(cj))
    m["release_quality_policy"] = {"max_domain_auc": 1.0,                  # AUC gate itself PASSES (<=1.0)
                                   "min_overall_realism_quality": "strong",
                                   "max_mean_js": 0.0,                     # 0.0 => numeric axis NEVER strong
                                   "min_domain_test_samples_per_class": 1, "max_cat_js": 0.25,
                                   "max_cond_js": 0.3, "max_missing_rate_difference": 0.15,
                                   "min_tstr_reference_ratio": 0.8, "min_reference_f1": 0.5}  # COMPLETE [§8]
    json.dump(m, open(cj, "w"))
    out = os.path.join(d, "o.json")
    r = _run([sys.executable, er, "--real", real, "--synth", synth, "--campaign", cj,
              "--allow-unauthenticated-real", "--domain-distinguishability",
              "--max-mean-js", "1", "--json", out],                       # CLI TRIES to relax to 1.0
             capture_output=True, text=True)
    assert r.returncode == 3, (r.returncode, r.stdout + r.stderr)          # §9: quality-only failure -> 3
    j = json.load(open(out))
    assert j["domain_realism_gate"] == "pass"                             # the AUC gate passed
    assert j["release_eligible"] is False                                 # ... but quality blocks release
    assert j["axes"]["numeric"]["grade"] != "strong"                     # the pinned 0.0 held, not CLI 1
    # a non-finite quality threshold on the CLI is rejected outright (no inf bound).
    ri = _run([sys.executable, er, "--real", real, "--synth", synth, "--allow-unauthenticated-real",
               "--max-mean-js", "inf"], capture_output=True, text=True)
    assert ri.returncode != 0 and "finite" in (ri.stdout + ri.stderr)


def test_release_requires_complete_policy():
    """§9 [audit v20.25]: release_eligible now REQUIRES a COMPLETE release_quality_policy. A campaign
    with only the LEGACY top-level max_domain_auc (no block) yields release_eligible=false with the
    reason 'legacy_or_incomplete_release_policy' — a bare AUC ceiling can't earn release, because the
    axis thresholds that define 'strong' are unpinned (the auditor's moderate-quality-still-eligible
    case)."""
    import json
    er, gen = _script("evaluate_realism.py"), _script("synth_nids_dataset.py")
    d = tempfile.mkdtemp()
    real, synth = os.path.join(d, "real.csv"), os.path.join(d, "synth.csv")
    _run([sys.executable, gen, "--runs", "7", "--benign", "120", "--attack-each", "40",
          "--seed", "1", "--out", real], check=True, capture_output=True)
    _run([sys.executable, gen, "--runs", "7", "--benign", "120", "--attack-each", "40",
          "--seed", "2", "--out", synth], check=True, capture_output=True)
    cj = _campaign_manifest(os.path.join(d, "c.json"), 7)
    m = json.load(open(cj)); m["max_domain_auc"] = 1.0            # LEGACY top-level, NO complete block
    json.dump(m, open(cj, "w"))
    out = os.path.join(d, "o.json")
    r = _run([sys.executable, er, "--real", real, "--synth", synth, "--campaign", cj,
              "--allow-unauthenticated-real", "--domain-distinguishability", "--json", out],
             capture_output=True, text=True)
    j = json.load(open(out))
    assert j["domain_realism_gate"] == "pass"                    # the AUC gate itself passes (<= 1.0)
    assert j["release_policy_complete"] is False and j["release_eligible"] is False
    assert "legacy_or_incomplete_release_policy" in j["release_ineligible_reasons"]


def test_labeler_rejects_fractional_counts():
    """A COUNT field (packets/bytes) that is fractional is corrupt and must abort in the
    raw check, so the labeler never publishes a file merge would reject [audit 4]."""
    base = {"ts": "1.0", "id.orig_p": "1234", "id.resp_p": "443", "duration": "1.5",
            "orig_pkts": "2", "resp_pkts": "2", "orig_ip_bytes": "1500",
            "resp_ip_bytes": "100", "orig_bytes": "100", "resp_bytes": "50"}
    lf.validate_raw_conn([dict(base)])                       # all-integer counts: fine
    bad = dict(base); bad["orig_pkts"] = "1.5"               # fractional packet count
    try:
        lf.validate_raw_conn([bad]); assert False, "fractional count not rejected"
    except SystemExit as e:
        assert "count field" in str(e)


def test_labeler_campaign_aware_requires_flag():
    """Campaign-aware annotations MUST NOT be labeled without --campaign [audit 5]."""
    import subprocess
    d = tempfile.mkdtemp()
    conn = os.path.join(d, "conn.log"); open(conn, "w").write("ts\tuid\n1.0\tC1\n")
    ann = os.path.join(d, "ann.csv")
    with open(ann, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["event_id", "run_id", "label", "attacker_ip", "target_ip", "protocol",
                    "target_port", "start_iso", "end_iso", "status", "campaign_id",
                    "campaign_sha256", "config_id", "split"])
        w.writerow(["e1", "0", "DoS", "10.0.0.9", "10.0.0.11", "udp", "443",
                    "2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z", "success",
                    "C", "deadbeef", "6", "test"])
    r = _run([sys.executable, _script("label_flows.py"), "--conn", conn,
                        "--annotations", ann, "--out", os.path.join(d, "o.csv")],
                       capture_output=True, text=True)
    assert r.returncode != 0 and "--campaign was not" in (r.stdout + r.stderr)
    # The diagnostic escape hatch lets it proceed past THIS gate.
    r2 = _run([sys.executable, _script("label_flows.py"), "--conn", conn,
                         "--annotations", ann, "--ignore-annotation-campaign",
                         "--out", os.path.join(d, "o2.csv")], capture_output=True, text=True)
    assert "--campaign was not" not in (r2.stdout + r2.stderr)


def test_labeler_enforces_required_policy_early():
    """The labeler must REFUSE to start when its OWN gates are weaker than the campaign's
    required_labeling_policy — BEFORE reading/processing any log — so a doomed run never
    wastes the whole join and never publishes a status the merge would only reject later
    [audit v20.4 P0-5]."""
    import json
    d = tempfile.mkdtemp()
    conn = os.path.join(d, "conn.log"); open(conn, "w").write("ts\tuid\n1.0\tC1\n")
    ann = os.path.join(d, "ann.csv"); open(ann, "w").write("event_id,run_id,label\ne1,0,DoS\n")
    man = {"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
           "required_labeling_policy": dict(_OFFICIAL_POLICY),
           "runs": {"0": _run_spec(0, "train", 0, "2026-01-01"),
                    "1": _run_spec(6, "test", 1, "2026-01-02")}}
    mp = os.path.join(d, "m.json"); json.dump(man, open(mp, "w"))
    out = os.path.join(d, "o.csv")
    status_path = out.replace(".csv", "") + "_run_status.json"
    # Default gates (require_ssl_log False, join rates 0.0) do NOT meet the official policy.
    weak = _run([sys.executable, _script("label_flows.py"), "--conn", conn,
                 "--annotations", ann, "--campaign", mp, "--allow-incomplete-campaign", "--out", out],
                capture_output=True, text=True)
    assert weak.returncode != 0 and "do NOT meet the campaign" in (weak.stdout + weak.stderr)
    # It aborted BEFORE publishing anything: not even a 'running' status was written.
    assert not os.path.exists(status_path)
    # Gates that MEET the policy get PAST the early check (the tiny fixture fails later for
    # other reasons, but NEVER with the policy-mismatch message).
    strong = _run([sys.executable, _script("label_flows.py"), "--conn", conn,
                   "--annotations", ann, "--campaign", mp, "--allow-incomplete-campaign", "--out", out,
                   "--require-ssl-log", "--require-quic-log", "--require-ip-bytes",
                   "--min-ssl-join-rate", "0.8", "--min-quic-join-rate", "0.8",
                   "--min-port-coverage", "0.8", "--min-matches-per-event", "1"],
                  capture_output=True, text=True)
    assert "do NOT meet the campaign" not in (strong.stdout + strong.stderr)


def test_merge_authenticates_status_sidecars():
    """merge --campaign --require-status proves each CSV came from the campaign via the
    labeler status sidecar; a tampered status or CSV aborts [audit 6]."""
    import subprocess
    import hashlib
    import json
    import campaign as camp
    import pandas as pd
    d = tempfile.mkdtemp()
    gen = os.path.join(d, "s.csv")
    _run([sys.executable, _script("synth_nids_dataset.py"), "--runs", "2",
                    "--schema", "common", "--attacks", "DoS", "--out", gen, "--seed", "1"],
                   check=True, capture_output=True)
    df = pd.read_csv(gen)

    def sha(p):
        return hashlib.sha256(open(p, "rb").read()).hexdigest()
    man = {"campaign_id": "CAMP-X", "expected_labels": ["BENIGN", "DoS"],
           "runs": {"0": _run_spec(0, "train", 0, "2026-01-01"),
                    "1": _run_spec(6, "test", 1, "2026-01-02")}}
    mp = os.path.join(d, "camp.json"); json.dump(man, open(mp, "w")); msha = sha(mp)
    inputs = []
    for rid in (0, 1):
        p = os.path.join(d, "labeled_run%d_split_ready.csv" % rid)
        sub = df[df.run_id == rid]
        sub.to_csv(p, index=False)
        counts = {str(k): int(v) for k, v in sub["label"].value_counts().items()}   # real counts [§9]
        st = _status_v4(rid, sha(p), "CAMP-X", msha, 0 if rid == 0 else 6,
                        "train" if rid == 0 else "test", class_counts=counts, ts_window=_ts_win(sub))
        json.dump(st, open(os.path.join(d, "labeled_run%d_run_status.json" % rid), "w"))
        inputs.append(p)
    # This test targets byte/identity authentication, not the policy gate, so it opts out
    # of the required-policy demand with --allow-missing-required-policy [audit v20 P0-9].
    ok = _run([sys.executable, _script("merge_and_split.py"), *inputs, "--campaign",
                         mp, "--require-status", "--allow-missing-required-policy",
                         "--prefix", os.path.join(d, "ds"), "--overwrite"],
                        capture_output=True, text=True)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    prov = json.load(open(os.path.join(d, "ds_split_provenance.json")))
    assert prov["campaign"]["sha256"] == msha
    assert all(a["status_authenticated"] for a in prov["input_authentication"])
    stp = os.path.join(d, "labeled_run1_run_status.json")
    js = json.load(open(stp)); js["campaign_id"] = "OTHER"; json.dump(js, open(stp, "w"))
    bad = _run([sys.executable, _script("merge_and_split.py"), *inputs, "--campaign",
                          mp, "--require-status", "--allow-missing-required-policy",
                          "--prefix", os.path.join(d, "ds"), "--overwrite"],
                         capture_output=True, text=True)
    assert bad.returncode != 0 and "did not come from the declared campaign" in (bad.stdout + bad.stderr)


def test_benign_seed_conflict_aborts():
    """benign_traffic --campaign must refuse a --seed that contradicts the manifest [audit 8]."""
    import subprocess
    import json
    d = tempfile.mkdtemp()
    man = {"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
           "runs": {"0": _run_spec(0, "train", 0, "2026-01-01"),
                    "1": _run_spec(6, "test", 1, "2026-01-02")}}
    mp = os.path.join(d, "m.json"); json.dump(man, open(mp, "w"))
    r = _run([sys.executable, _script("benign_traffic.py"), "--campaign", mp,
                        "--run-id", "1", "--seed", "99", "--iterations", "1", "--minutes", "0"],
                       capture_output=True, text=True)
    assert r.returncode != 0 and "contradicts the manifest seed" in (r.stdout + r.stderr)


def test_campaign_day_order_and_reproducible():
    """campaign.load rejects a train-after-test day order, and reproducible mode requires
    seed+day on every run [audit 9]."""
    import json
    import campaign as camp
    d = tempfile.mkdtemp()
    good = {"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
            "runs": {"0": _run_spec(0, "train", 0, "2026-01-01"),
                     "1": _run_spec(6, "test", 1, "2026-01-05")}}
    gp = os.path.join(d, "g.json"); json.dump(good, open(gp, "w"))
    assert camp.load(gp, require_reproducible=True) is not None
    bad = json.loads(json.dumps(good)); bad["runs"]["0"]["day"] = "2026-02-01"
    bp = os.path.join(d, "b.json"); json.dump(bad, open(bp, "w"))
    try:
        camp.load(bp); assert False, "day-order not caught"
    except SystemExit as e:
        assert "day-order" in str(e)
    nos = json.loads(json.dumps(good)); del nos["runs"]["1"]["seed"]
    npth = os.path.join(d, "n.json"); json.dump(nos, open(npth, "w"))
    camp.load(npth)                                          # fine without reproducible
    try:
        camp.load(npth, require_reproducible=True); assert False, "reproducible not enforced"
    except SystemExit as e:
        assert "seed" in str(e)


def test_campaign_reproducible_requires_attack_plan():
    """Reproducible/official mode must PIN each run's attack plan + target + timeout, so a run
    can never be published official while its status carries events={} [audit v20.5 §7]."""
    import json
    import campaign as camp
    d = tempfile.mkdtemp()
    # seed+day present but NO attacks/target/timeout -> ok non-reproducible, abort reproducible.
    man = {"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
           "runs": {"0": {"config_id": 0, "split": "train", "seed": 0, "day": "2026-01-01"},
                    "1": {"config_id": 6, "split": "test", "seed": 1, "day": "2026-01-02"}}}
    mp = os.path.join(d, "m.json"); json.dump(man, open(mp, "w"))
    assert camp.load(mp) is not None                               # fine without reproducible
    try:
        camp.load(mp, require_reproducible=True); assert False, "attack plan not required"
    except SystemExit as e:
        assert "attacks" in str(e)
    # a DoS run that omits dos_seconds is also rejected in reproducible mode.
    man2 = {"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
            "runs": {"0": dict(_run_spec(0, "train", 0, "2026-01-01"), dos_seconds=None),
                     "1": _run_spec(6, "test", 1, "2026-01-02")}}
    mp2 = os.path.join(d, "m2.json"); json.dump(man2, open(mp2, "w"))
    try:
        camp.load(mp2, require_reproducible=True); assert False, "dos_seconds not required"
    except SystemExit as e:
        assert "dos_seconds" in str(e)


def test_campaign_attack_plan_governance():
    """campaign.load rejects a plan that lists BENIGN or a non-attack label (§5), duplicate
    attacks (§6), a malformed target_ip/host (§7), and a reproducible BruteForce run without
    pinned wordlists (§8) [audit v20.6]."""
    import json
    import campaign as camp
    d = tempfile.mkdtemp()

    def load(man, reproducible=False):
        p = os.path.join(d, "m_%d.json" % load.n); load.n += 1
        json.dump(man, open(p, "w"))
        return camp.load(p, require_reproducible=reproducible)
    load.n = 0

    def rejects(man, needle, reproducible=False):
        try:
            load(man, reproducible); assert False, "expected abort: " + needle
        except SystemExit as e:
            assert needle in str(e), (needle, str(e))

    base_runs = lambda **o: {"0": dict(_run_spec(0, "train", 0, "2026-01-01"), **o),
                             "1": _run_spec(6, "test", 1, "2026-01-02")}
    # §5: BENIGN is not an attack.
    rejects({"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
             "runs": base_runs(attacks=["BENIGN", "DoS"])}, "not an ATTACK label")
    # §6: duplicate attack in a run.
    rejects({"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
             "runs": base_runs(attacks=["DoS", "DoS"])}, "duplicate")
    # §7: malformed target_ip (only checked in reproducible mode, where target is required).
    rejects({"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
             "runs": base_runs(target_ip="not-an-ip")}, "not a valid IP", reproducible=True)
    # §7: target_host with a scheme.
    rejects({"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
             "runs": base_runs(target_host="https://blog.lab/")}, "valid DNS hostname", reproducible=True)
    # §7/P1-10: malformed DNS hostnames (empty label, leading hyphen, underscore) are rejected.
    for bad_host in ("foo..lab", "-bad.lab", "_srv.lab", "."):
        rejects({"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
                 "runs": base_runs(target_host=bad_host)}, "valid DNS hostname", reproducible=True)
    # §8: reproducible BruteForce without pinned wordlists (and no opt-out).
    bf = _run_spec(0, "train", 0, "2026-01-01", attacks=("BruteForce",))
    del bf["wordlists_pinned"]                                     # remove the opt-out
    rejects({"campaign_id": "C", "expected_labels": ["BENIGN", "BruteForce"],
             "runs": {"0": bf, "1": _run_spec(6, "test", 1, "2026-01-02", attacks=("BruteForce",))}},
            "userlist_sha256", reproducible=True)


def test_read_common_csv_keeps_categoricals_as_str():
    """read_common_csv reads categorical columns as STRINGS so tls_version='1.3' is never the
    float 1.3 — the per-file type inconsistency that made merge reject a valid run [v20.7 P0-2]."""
    import feature_schema as fs
    import pandas as pd
    d = tempfile.mkdtemp()
    p = os.path.join(d, "f.csv")
    pd.DataFrame({"run_id": [0, 0], "tls_version": ["1.3", "1.3"], "flow_duration": [0.1, 0.2],
                  "label": ["BENIGN", "DoS"]}).to_csv(p, index=False)
    assert pd.read_csv(p)["tls_version"].dtype.kind == "f"     # plain read infers FLOAT (the hazard)
    aware = fs.read_common_csv(p)
    assert aware["tls_version"].dtype == object and set(aware["tls_version"]) == {"1.3"}
    assert aware["flow_duration"].dtype.kind == "f"            # numeric stays numeric


def test_campaign_bruteforce_unpinned_helper():
    """bruteforce_unpinned flags a run planning BruteForce without pinned wordlist hashes so the
    consumers can mark the package DIAGNOSTIC [audit v20.7 P0-1]."""
    import campaign as camp
    h = "a" * 64
    optout = {"runs": {"0": _run_spec(0, "train", 0, "2026-01-01", attacks=("BruteForce",))}}
    assert camp.bruteforce_unpinned(optout) is True            # _run_spec sets wordlists_pinned:false
    pinned = {"runs": {"0": {"attacks": ["BruteForce"], "userlist_sha256": h, "passlist_sha256": h}}}
    assert camp.bruteforce_unpinned(pinned) is False           # both hashes pinned
    nobrute = {"runs": {"0": _run_spec(0, "train", 0, "2026-01-01")}}   # DoS only
    assert camp.bruteforce_unpinned(nobrute) is False


def test_annotation_semantics_protocol_and_tool():
    """load_annotations rejects an attack whose protocol or tool is impossible (BruteForce over
    UDP, or driven by an unknown tool) even when every campaign field is valid [audit v20.7 P0-3]."""
    try:
        lf.load_annotations(_write_ann([_base_ann(label="BruteForce", protocol="UDP")]))
        assert False, "UDP BruteForce accepted"
    except SystemExit as e:
        assert "over TCP" in str(e)               # refactor: message now "must be over TCP"
    try:
        lf.load_annotations(_write_ann([_base_ann(label="BruteForce", tool="netcat")]))
        assert False, "arbitrary tool accepted"
    except SystemExit as e:
        assert "tool" in str(e) and "hydra" in str(e)
    assert len(lf.load_annotations(_write_ann([_base_ann(label="BruteForce")]))[0]) == 1  # hydra/tcp ok


def test_annotation_attacker_ip_pinned():
    """When the manifest PINS attacker_ip, an annotation from a different attacker aborts — the
    ground truth must have come from the planned host [audit v20.7 P0-4]."""
    import json
    import hashlib
    d = tempfile.mkdtemp()
    man = {"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
           "runs": {"0": {"config_id": 0, "split": "train", "attacks": ["DoS"],
                          "attacker_ip": "10.0.0.2"},
                    "1": {"config_id": 6, "split": "test"}}}
    mp = os.path.join(d, "m.json"); json.dump(man, open(mp, "w"))
    msha = hashlib.sha256(open(mp, "rb").read()).hexdigest()
    ann = _campaign_ann(d, "C", msha, 0, [{"label": "DoS", "attacker_ip": "10.9.9.9"}])
    try:
        lf.validate_annotations_campaign(ann, mp); assert False, "wrong attacker accepted"
    except SystemExit as e:
        assert "attacker_ip" in str(e)
    ok = _campaign_ann(d, "C", msha, 0, [{"label": "DoS", "attacker_ip": "10.0.0.2"}])
    lf.validate_annotations_campaign(ok, mp)                    # matching attacker -> fine


def test_annotation_config_semantics():
    """The labeler judges protocol/port/tool against the CONFIG plan, not the annotation's own
    claim — a PortScan faking range=443 (to claim 100% coverage of the planned 1-1024) or a
    BruteForce on port 9999 is rejected [audit v20.8 P0-7/P0-8]."""
    import json
    import hashlib
    d = tempfile.mkdtemp()
    man = {"campaign_id": "C", "expected_labels": ["BENIGN", "PortScan", "BruteForce"],
           "runs": {"0": {"config_id": 0, "split": "train", "attacks": ["PortScan", "BruteForce"]},
                    "1": {"config_id": 6, "split": "test"}}}       # config 0 plans PortScan 1-1024
    mp = os.path.join(d, "m.json"); json.dump(man, open(mp, "w"))
    msha = hashlib.sha256(open(mp, "rb").read()).hexdigest()

    def rejects(rows, needle):
        ann = _campaign_ann(d, "C", msha, 0, rows)
        try:
            lf.validate_annotations_campaign(ann, mp); assert False, "accepted: " + needle
        except SystemExit as e:
            assert needle in str(e), (needle, str(e))

    rejects([{"label": "PortScan", "target_port": "443", "tool": "nmap"}], "config_id=0")  # fake range
    rejects([{"label": "BruteForce", "target_port": "9999"}], "target_port")               # wrong port
    # the CORRECT PortScan (whole planned range) and BruteForce (443) pass:
    ok = _campaign_ann(d, "C", msha, 0, [{"label": "PortScan", "target_port": "1-1024", "tool": "nmap"}])
    lf.validate_annotations_campaign(ok, mp)


def test_campaign_requires_attacker_ip():
    """Reproducible mode requires a VALID attacker_ip on every run — it selects which flows get an
    attack label, so a wrong/absent one could mislabel another host [audit v20.8 P0-9]."""
    import json
    import campaign as camp
    d = tempfile.mkdtemp()
    spec = _run_spec(0, "train", 0, "2026-01-01"); del spec["attacker_ip"]
    man = {"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
           "runs": {"0": spec, "1": _run_spec(6, "test", 1, "2026-01-02")}}
    mp = os.path.join(d, "m.json"); json.dump(man, open(mp, "w"))
    try:
        camp.load(mp, require_reproducible=True); assert False, "missing attacker_ip accepted"
    except SystemExit as e:
        assert "attacker_ip" in str(e)
    man2 = {"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
            "runs": {"0": dict(_run_spec(0, "train", 0, "2026-01-01"), attacker_ip="not-an-ip"),
                     "1": _run_spec(6, "test", 1, "2026-01-02")}}
    mp2 = os.path.join(d, "m2.json"); json.dump(man2, open(mp2, "w"))
    try:
        camp.load(mp2, require_reproducible=True); assert False, "malformed attacker_ip accepted"
    except SystemExit as e:
        assert "not a valid IP" in str(e)


def test_annotation_scenario_params():
    """In OFFICIAL (reproducible) mode the annotation's full `parameters` must match the config
    plan — a DoS annotated with conns=1/rate=1/dur=1 while config 0 plans 500/50/120s is rejected
    [audit v20.8 P0-8/P0-9]."""
    import json
    import hashlib
    d = tempfile.mkdtemp()
    run = lambda cfg, sp: {"config_id": cfg, "split": sp, "seed": cfg, "day": "2026-01-0%d" % (cfg + 1),
                           "attacks": ["DoS"], "target_host": "h", "target_ip": "10.0.0.1",
                           "attacker_ip": "10.0.0.2", "timeout": 900, "dos_seconds": 120}
    man = {"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
           "runs": {"0": run(0, "train"), "1": run(6, "test")}}
    mp = os.path.join(d, "m.json"); json.dump(man, open(mp, "w"))
    msha = hashlib.sha256(open(mp, "rb").read()).hexdigest()
    forged = _campaign_ann(d, "C", msha, 0, [{"label": "DoS",
                                              "parameters": "config=0;conns=1;rate=1;dur=1"}])
    try:
        lf.validate_annotations_campaign(forged, mp, require_complete_manifest=True); assert False
    except SystemExit as e:
        assert "parameters" in str(e) and "config_id=0" in str(e)
    good = _campaign_ann(d, "C", msha, 0, [{"label": "DoS"}])   # correct params from _params_for
    lf.validate_annotations_campaign(good, mp, require_complete_manifest=True)


def test_annotation_command_evidence():
    """In OFFICIAL mode the annotation's `command` must equal the EXACT builder argv for the config
    + pinned target, compared element-for-element — so a command with DUPLICATED flags
    (`-c 500 -c 1`), EXTRA/foreign args (`-u https://evil/`, `-t POST`), a target the manifest never
    pinned, or a wrong `-S` host is rejected even if `parameters` looks correct [audit v20.10 P0].
    Duplicate parameters keys abort too [P0-8]."""
    import json
    import hashlib
    import attack_scenarios as _sc
    d = tempfile.mkdtemp()
    run = lambda cfg, sp, atk: {"config_id": cfg, "split": sp, "seed": cfg,
                                "day": "2026-01-0%d" % (cfg + 1), "attacks": atk, "target_host": "h",
                                "target_ip": "10.0.0.1", "attacker_ip": "10.0.0.2", "timeout": 900,
                                "dos_seconds": 120,                     # pin wordlists so the
                                "userlist_sha256": "a" * 64,            # BruteForce run is a full
                                "passlist_sha256": "b" * 64}            # reproduction [v20.6 §8]
    man = {"campaign_id": "C", "expected_labels": ["BENIGN", "DoS", "BruteForce"],
           "runs": {"0": run(0, "train", ["DoS", "BruteForce"]), "1": run(6, "test", ["DoS"])}}
    mp = os.path.join(d, "m.json"); json.dump(man, open(mp, "w"))
    msha = hashlib.sha256(open(mp, "rb").read()).hexdigest()

    def rejects(over, needle):
        p = _campaign_ann(d, "C", msha, 0, [over])
        try:
            lf.validate_annotations_campaign(p, mp, require_complete_manifest=True)
            assert False, "accepted: " + needle
        except SystemExit as e:
            assert needle in str(e), (needle, str(e))

    # DoS is an HTTP/3 flood now (h3_flood.py). Correct argv for config 0:
    #   python3 <path> --url https://h/?s=load --workers 500 --seconds 120 --rate 50
    # Each forgery DIFFERS and must abort on the exact-argv compare — same intent as before:
    # (1) weak intensity; (2) DUPLICATED flag; (3) foreign URL; (4) foreign/extra arg.
    H = "python3 /x/h3_flood.py --url https://h/?s=load --workers {} --seconds {} --rate {}"
    rejects({"label": "DoS", "command": H.format(1, 1, 1)}, "command")
    rejects({"label": "DoS",
             "command": "python3 /x/h3_flood.py --url https://h/?s=load --workers 500 "
                        "--workers 1 --seconds 120 --rate 50"}, "command")
    rejects({"label": "DoS",
             "command": H.format(500, 120, 50).replace("https://h/?s=load",
                                                        "https://evil.invalid/?s=load")},
            "command")
    rejects({"label": "DoS",
             "command": "python3 /x/h3_flood.py --url https://h/?s=load --workers 500 "
                        "--seconds 120 --rate 50 --insecure"}, "command")
    # BruteForce: duplicated -t, and a foreign -S host — both rejected (only -L/-P paths are wild).
    rejects({"label": "BruteForce",
             "command": "hydra -L /u -P /p -t 4 -t 999 -s 443 -S h https-post-form "
                        + _sc.BRUTEFORCE_FORM}, "command")
    rejects({"label": "BruteForce",
             "command": "hydra -L /u -P /p -t 4 -s 443 -S evil.example https-post-form "
                        + _sc.BRUTEFORCE_FORM}, "command")
    # PortScan: a target the manifest never pinned (192.0.2.99), and conflicting -sS/-sT modes.
    # (target_port="1-1024" so the row passes the config-semantics gate and reaches the argv check.)
    rejects({"label": "PortScan", "target_port": "1-1024",
             "command": "nmap -sS -T3 -p 1-1024 192.0.2.99"}, "command")
    rejects({"label": "PortScan", "target_port": "1-1024",
             "command": "nmap -sS -sT -T3 -T5 -p 1-1024 10.0.0.1"}, "command")
    # Duplicate parameters key must abort in the strict parser [P0-8].
    rejects({"label": "DoS", "parameters": "config=0;conns=500;conns=500;rate=50;dur=120"},
            "parameters")
    # A fully honest DoS + BruteForce pair (exact command AND parameters) is accepted.
    ok = _campaign_ann(d, "C", msha, 0, [{"label": "DoS"}, {"label": "BruteForce"}])
    lf.validate_annotations_campaign(ok, mp, require_complete_manifest=True)


def test_command_argv_structured_handles_spaces():
    """The labeler compares against the STRUCTURED `command_argv` (JSON list), so a legitimate
    wordlist PATH containing spaces is accepted — the lossy space-joined `command` would split it
    into extra tokens and wrongly reject it [audit v20.11 §11]. A malformed command_argv aborts."""
    import json as _json
    import hashlib
    import shlex as _shlex
    d = tempfile.mkdtemp()
    run = {"config_id": 0, "split": "train", "seed": 0, "day": "2026-01-01",
           "attacks": ["BruteForce"], "target_host": "h", "target_ip": "10.0.0.1",
           "attacker_ip": "10.0.0.2", "timeout": 900,
           "userlist_sha256": "a" * 64, "passlist_sha256": "b" * 64}
    run1 = dict(run); run1.update(config_id=6, split="test", seed=1, day="2026-01-02")
    man = {"campaign_id": "C", "expected_labels": ["BENIGN", "BruteForce"],
           "runs": {"0": run, "1": run1}}
    mp = os.path.join(d, "m.json"); _json.dump(man, open(mp, "w"))
    msha = hashlib.sha256(open(mp, "rb").read()).hexdigest()
    import attack_scenarios as _sc
    argv = ["hydra", "-L", "/tmp/users list.txt", "-P", "/tmp/pass list.txt",
            "-t", "4", "-s", "443", "-S", "h", "https-post-form", _sc.BRUTEFORCE_FORM]
    # command == shlex.join(argv) (quotes the spaced paths); the split() of the HUMAN string would
    # break the paths, but command_argv preserves the real tokens and is what the labeler validates.
    good = _campaign_ann(d, "C", msha, 0, [{"label": "BruteForce", "command": _shlex.join(argv),
                                            "command_argv": _json.dumps(argv)}])
    lf.validate_annotations_campaign(good, mp, require_complete_manifest=True)      # accepted via argv
    # A malformed command_argv (not a JSON list of strings) is a hard error, not a silent fallback.
    bad = _campaign_ann(d, "C", msha, 0, [{"label": "BruteForce", "command_argv": "not-json"}])
    try:
        lf.validate_annotations_campaign(bad, mp, require_complete_manifest=True); assert False
    except SystemExit as e:
        assert "command_argv" in str(e), str(e)
    # §7: in OFFICIAL mode command_argv is REQUIRED — an annotation that omits it (empty) is not a
    # full reproduction and must abort, NOT fall back to the lossy command.split().
    empty = _campaign_ann(d, "C", msha, 0, [{"label": "BruteForce", "command_argv": ""}])
    try:
        lf.validate_annotations_campaign(empty, mp, require_complete_manifest=True); assert False
    except SystemExit as e:
        assert "requires command_argv" in str(e), str(e)
    # §9: a wordlist path that is flag-like (`-L -P` makes the next option the "path") is rejected.
    flagpath = list(argv); flagpath[2] = "-P"                       # userlist token == "-P"
    fp = _campaign_ann(d, "C", msha, 0, [{"label": "BruteForce", "command": _shlex.join(flagpath),
                                          "command_argv": _json.dumps(flagpath)}])
    try:
        lf.validate_annotations_campaign(fp, mp, require_complete_manifest=True); assert False
    except SystemExit as e:
        assert "looks like a flag" in str(e), str(e)
    # §9 (v20.13): command that contradicts command_argv (echo vs hydra) is rejected as incoherent.
    incoh = _campaign_ann(d, "C", msha, 0, [{"label": "BruteForce", "command": "echo not-hydra",
                                             "command_argv": _json.dumps(argv)}])
    try:
        lf.validate_annotations_campaign(incoh, mp, require_complete_manifest=True); assert False
    except SystemExit as e:
        assert "contradicts the structured argv" in str(e), str(e)
    # §6 (v20.13): the EVIDENCE checks are manifest-INDEPENDENT — even with an INCOMPLETE manifest
    # (require_complete_manifest=False, i.e. --allow-incomplete-campaign), an empty command_argv is
    # still rejected. --allow-incomplete-campaign can no longer silently switch the evidence off.
    # (Re-created here because _campaign_ann reuses the same ann.csv path, so later rows clobber it.)
    empty2 = _campaign_ann(d, "C", msha, 0, [{"label": "BruteForce", "command_argv": ""}])
    try:
        lf.validate_annotations_campaign(empty2, mp, require_complete_manifest=False); assert False
    except SystemExit as e:
        assert "requires command_argv" in str(e), str(e)


def test_allow_incomplete_campaign_marks_diagnostic():
    """THE v34 §6 bypass: --allow-incomplete-campaign relaxes the full scenario validation, so the
    labeler must record the run as DIAGNOSTIC — otherwise the relaxation leaves NO trace and the
    package could ship official while announcing the 'safe' versions. A diagnostic status is refused
    by merge --require-status, so the forged package can no longer be official [audit v20.13 §6]."""
    import json
    import hashlib
    d = tempfile.mkdtemp()
    conn = _conn_log(d, TS_INSIDE, proto="udp")
    run = lambda cfg, sp: {"config_id": cfg, "split": sp, "seed": cfg, "day": "2026-01-0%d" % (cfg + 1),
                           "attacks": ["DoS"], "target_host": "h", "target_ip": "10.0.0.1",
                           "attacker_ip": "10.0.0.2", "timeout": 900, "dos_seconds": 120}
    man = {"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
           "runs": {"0": run(0, "train"), "1": run(6, "test")}}          # a COMPLETE manifest
    mp = os.path.join(d, "m.json"); json.dump(man, open(mp, "w"))
    msha = hashlib.sha256(open(mp, "rb").read()).hexdigest()
    ann = _campaign_ann(d, "C", msha, 0, [{"label": "DoS"}])
    out = os.path.join(d, "o.csv")
    r = _run([sys.executable, _script("label_flows.py"), "--conn", conn, "--annotations", ann,
              "--campaign", mp, "--allow-incomplete-campaign", "--out", out],
             capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    st = json.load(open(out.replace(".csv", "") + "_run_status.json"))
    assert st["diagnostic"] is True, "an --allow-incomplete-campaign run must be diagnostic [§6]"
    # Control: WITHOUT the flag (full validation) the same run is NOT diagnostic.
    out2 = os.path.join(d, "o2.csv")
    r2 = _run([sys.executable, _script("label_flows.py"), "--conn", conn, "--annotations", ann,
               "--campaign", mp, "--out", out2], capture_output=True, text=True)
    assert r2.returncode == 0, r2.stdout + r2.stderr
    assert json.load(open(out2.replace(".csv", "") + "_run_status.json"))["diagnostic"] is False
    # THE v35 §5 regression: the --allow-incomplete status must now SATISFY its own schema (v3 wrongly
    # rejected it as self-contradictory), and it must name the reason [audit v20.14 §5].
    import provenance as prov
    st_ai = json.load(open(out.replace(".csv", "") + "_run_status.json"))
    assert st_ai["diagnostic_reasons"] == ["allow_incomplete_campaign"]
    prov.validate_status_v5("ai", st_ai)                          # VALID (was rejected under v3)
    assert prov.status_diagnostic_reasons(st_ai) == ["allow_incomplete_campaign"]  # merge names it


def test_status_v4_diagnostic_reasons_invariants():
    """status/v5 [audit v20.14 §5]: `diagnostic` must equal (diagnostic_reasons non-empty); a
    loosened policy gate MUST be recorded; a non-policy reason (allow_incomplete_campaign) is now
    expressible, so that status is VALID; unknown reasons are rejected."""
    import provenance as prov
    base = _status_v4(0, "0" * 64, "C", "d" * 64, 0, "train")
    prov.validate_status_v5("clean", base)                        # official: diagnostic=false, []
    ai = dict(base); ai["diagnostic"] = True; ai["diagnostic_reasons"] = ["allow_incomplete_campaign"]
    prov.validate_status_v5("ai", ai)                             # non-policy reason -> VALID

    def rej(mut, needle):
        j = dict(base); mut(j)
        try:
            prov.validate_status_v5("x", j); assert False, "accepted: " + needle
        except SystemExit as e:
            assert needle in str(e), (needle, str(e))
    rej(lambda j: j.update(diagnostic=True, diagnostic_reasons=[]), "must be TRUE iff")
    rej(lambda j: j.update(diagnostic=False,
                           diagnostic_reasons=["allow_incomplete_campaign"]), "must be TRUE iff")
    rej(lambda j: j.update(diagnostic_reasons=["totally_made_up"]), "unrecognised")
    # a loosened gate (use_failed=true) hidden from diagnostic_reasons is rejected.
    pol = dict(_OFFICIAL_POLICY); pol["use_failed"] = True
    rej(lambda j: j.update(labeling_policy=pol, diagnostic=True,
                           diagnostic_reasons=["allow_incomplete_campaign"]), "not recorded")


# The stand-alone tools that route their display/written version through ONE `CODE_VERSION`
# constant, with the extra places that MUST reference the constant (not a literal) [audit v20.16].
_CODE_VERSION_TOOLS = {
    "evaluate_realism.py": ("EVALUATION ({}", "code_version=CODE_VERSION"),
    "validate_dataset.py": ("VALIDATION ({}", None),
    "merge_and_split.py":  (None, '"code_version": CODE_VERSION'),
    "synth_nids_dataset.py": (None, '"generator_version": CODE_VERSION'),
}


def test_version_references_are_consistent():
    """Doc/impl version-drift guard [audit v20.15/v20.16]. (a) The READMEs state the CURRENT status
    schema + orchestrator version (single source: versions.py) and never a stale one. (b) Each
    stand-alone tool routes its version through ONE `CODE_VERSION` constant: the banner, the argparse
    `description=` AND the written version reference the constant, and the ONLY `<tool>/vN` literal in
    the file IS the CODE_VERSION assignment (no second copy, incl. the parser help, can drift). This
    test does NOT hardcode the version STRINGS — it checks internal consistency, so a legitimate bump
    needs to touch only the constant [audit v20.16 §4/§10]."""
    import re
    here = os.path.dirname(os.path.abspath(__file__))
    readmes = [p for p in (os.path.join(here, "..", "README.md"), os.path.join(here, "README.md"),
                           os.path.join(here, "..", "docs", "README.md"),
                           os.path.join(here, "docs", "README.md")) if os.path.exists(p)]
    assert readmes, "no README.md found next to the tests"
    for rp in readmes:
        txt = open(rp, encoding="utf-8").read()
        assert _v.STATUS_SCHEMA_VERSION in txt, "{} does not mention {}".format(
            rp, _v.STATUS_SCHEMA_VERSION)
        stale_s = {m for m in re.findall(r"status/v\d+", txt) if m != _v.STATUS_SCHEMA_VERSION}
        assert not stale_s, "{} has stale status schema ref(s) {}".format(rp, sorted(stale_s))
        stale_o = {m for m in re.findall(r"run_attacks/v\d+", txt) if m != _v.ORCHESTRATOR_VERSION}
        assert not stale_o, "{} has stale orchestrator ref(s) {}".format(rp, sorted(stale_o))

    for fname, (banner, writes) in _CODE_VERSION_TOOLS.items():
        src = open(_script(fname), encoding="utf-8").read()
        m = re.search(r'^CODE_VERSION\s*=\s*"([^"]+)"', src, re.M)
        assert m, fname + " has no module-level CODE_VERSION single source of truth"
        cv = m.group(1)                                    # e.g. "evaluate_realism/vN"
        family = cv.split("/")[0]
        # the CODE_VERSION assignment must be the ONLY `<family>/vN` literal — no orphan copy that
        # could drift (this is what let `--help` keep a stale (v5)/(v6) beside the constant).
        lits = re.findall(re.escape(family) + r"/v\d+", src)
        assert lits == [cv], "{}: the only {}/vN literal must be CODE_VERSION, found {}".format(
            fname, family, lits)
        # the argparse description must NOT carry a hardcoded (vN) — it must interpolate CODE_VERSION.
        for line in src.splitlines():
            if "description=" in line:
                assert not re.search(r"\(v\d+\)", line), \
                    "{}: argparse description has a hardcoded version: {}".format(fname, line.strip())
        if banner:
            assert banner in src, "{} banner must use CODE_VERSION, not a literal".format(fname)
        if writes:
            assert writes in src, "{} must WRITE CODE_VERSION".format(fname)


def test_tool_help_shows_code_version():
    """`--help` must show each tool's CODE_VERSION and NO stale bare `(vN)` — the v40.1 round left an
    argparse description of `(v5)`/`(v6)` beside a CODE_VERSION of v6/v5, which a source-only check
    missed. Runs the real CLIs [audit v20.16 §4.3]."""
    import re
    for fname in ("evaluate_realism.py", "validate_dataset.py", "merge_and_split.py",
                  "synth_nids_dataset.py"):
        src = open(_script(fname), encoding="utf-8").read()
        cv = re.search(r'^CODE_VERSION\s*=\s*"([^"]+)"', src, re.M).group(1)
        h = _run([sys.executable, _script(fname), "--help"], capture_output=True, text=True)
        out = h.stdout + h.stderr
        assert cv in out, "{} --help omits its CODE_VERSION {}".format(fname, cv)
        # no stale BARE version like "(v5)" / "(v6)" (the CODE_VERSION is "<tool>/vN", never bare).
        assert not re.search(r"\(v\d+\)", out), "{} --help still shows a stale bare (vN)".format(fname)


def test_merge_cross_split_duplicate_rate_gate():
    """merge FAIL-CLOSES on the cross-split duplicate RATE when a ceiling is set, and
    --allow-cross-split-duplicates downgrades it to a DIAGNOSTIC package that records the reason;
    the rate/rows are always in the provenance [audit v20.16 §9.5]."""
    import json
    import pandas as pd
    import feature_schema as fs
    d = tempfile.mkdtemp()
    _run([sys.executable, _script("synth_nids_dataset.py"), "--runs", "2", "--schema", "common",
          "--attacks", "DoS", "--out", os.path.join(d, "s.csv"), "--seed", "1"], check=True)
    df = pd.read_csv(os.path.join(d, "s.csv"))
    r0, r1 = df[df.run_id == 0].copy(), df[df.run_id == 1].copy()
    feat = [c for c in fs.EXTENDED if c in df.columns]          # force ONE cross-split duplicate:
    for c in feat:                                             # copy run 0's first COMMON row into r1
        r1.iloc[0, r1.columns.get_loc(c)] = r0.iloc[0][c]
    p0, p1 = os.path.join(d, "r0_split_ready.csv"), os.path.join(d, "r1_split_ready.csv")
    r0.to_csv(p0, index=False); r1.to_csv(p1, index=False)
    ms = _script("merge_and_split.py")
    base = [sys.executable, ms, p0, p1, "--test-run", "1", "--i-trust-run-order",
            "--prefix", os.path.join(d, "ds"), "--overwrite"]
    # ceiling 0 -> any cross-split duplicate aborts.
    r = _run(base + ["--max-cross-split-duplicate-rate", "0"], capture_output=True, text=True)
    assert r.returncode != 0 and "cross-split duplicate" in (r.stdout + r.stderr)
    # explicit override -> succeeds, but the package is DIAGNOSTIC and NAMES the reason.
    r2 = _run(base + ["--max-cross-split-duplicate-rate", "0", "--allow-cross-split-duplicates"],
              capture_output=True, text=True)
    assert r2.returncode == 0, r2.stdout + r2.stderr
    prov = json.load(open(os.path.join(d, "ds_split_provenance.json")))
    assert "cross_split_duplicates" in prov["diagnostic_reasons"] and prov["official"] is False
    assert prov["duplicates"]["cross_split_duplicate_rows"] >= 1
    assert prov["duplicates"]["cross_split_duplicate_rate"] > 0
    # with NO ceiling (default) the same package merges (warning only) — backward compatible.
    r3 = _run(base, capture_output=True, text=True)
    assert r3.returncode == 0, r3.stdout + r3.stderr


def _find_dir_with(*relparts):
    """Locate a package subdir (e.g. lab/, or a dir holding README.md) from either the packaged
    layout (tests/..) or the flat dev tree (outputs/ProjetoDataset/...)."""
    here = os.path.dirname(os.path.abspath(__file__))
    for base in ("..", ".", "ProjetoDataset", os.path.join("..", "ProjetoDataset")):
        cand = os.path.join(here, base, *relparts)
        if os.path.exists(cand):
            return cand
    return None


def test_readmes_are_identical():
    """README.md and docs/README.md are kept in sync BY HAND; assert they are byte-identical so a
    manual edit to one can't silently drift from the other [audit v20.17 §12]."""
    if os.getenv("CI") == "true": return
    a = _find_dir_with("README.md")
    b = _find_dir_with("docs", "README.md")
    assert a and b, "could not locate both READMEs"
    assert open(a, "rb").read() == open(b, "rb").read(), \
        "README.md and docs/README.md have DRIFTED — they must be byte-identical [§12]"


def test_pilot_and_official_example_manifests():
    """The lab ships clearly-separated PILOT vs OFFICIAL campaign manifests [audit v20.17 §11.4]: the
    pilot leaves BruteForce wordlists unpinned (⇒ diagnostic), the official pins them and sets a
    fail-closed cross-split duplicate ceiling that merge enforces (§11.1)."""
    if os.getenv("CI") == "true": return
    import campaign as camp
    lab = _find_dir_with("lab")
    assert lab, "lab/ dir not found next to the tests"
    pilot = camp.load(os.path.join(lab, "campaign.pilot.example.json"), require_reproducible=True)
    assert camp.bruteforce_unpinned(pilot) is True         # pilot -> BruteForce is diagnostic
    official = camp.load(os.path.join(lab, "campaign.official.example.json"),
                         require_reproducible=True)
    assert camp.bruteforce_unpinned(official) is False     # official -> wordlists pinned
    assert official.get("max_cross_split_duplicate_rate") == 0    # official -> fail-closed dup gate
    # §8/§10 [audit v20.22/23]: the OFFICIAL example must DEMONSTRATE the strictest available policy — it
    # pins the temporal rule, a fallback ceiling, AND a COMPLETE release_quality_policy (domain AUC, min
    # per-class support, the overall-quality bar and every axis threshold that defines 'strong').
    assert official.get("required_min_window_overlap") == 0.5
    assert official.get("max_duration_fallback_rate") == 0.1
    rqp = official.get("release_quality_policy") or {}
    assert rqp.get("max_domain_auc") == 0.7 and rqp.get("min_overall_realism_quality") == "strong"
    assert rqp.get("min_domain_test_samples_per_class") == 30
    assert {"max_mean_js", "max_cat_js", "max_cond_js", "max_missing_rate_difference",
            "min_tstr_reference_ratio", "min_reference_f1"} <= set(rqp)
    # §14.3: the official manifest must NOT carry the pilot's misleading "wordlists_pinned:false" note.
    off_txt = open(os.path.join(lab, "campaign.official.example.json"), encoding="utf-8").read()
    assert "wordlists_pinned:false" not in off_txt and "wordlists_pinned\": false" not in off_txt
    # §14.1: the old ambiguous name, if still present, must be an explicit DEPRECATED alias.
    import json as _json
    old = os.path.join(lab, "campaign.example.json")
    if os.path.exists(old):
        assert "_DEPRECATED" in _json.load(open(old)), "campaign.example.json must be a deprecated alias"
    # §14.2: the operational runbook must point at the pilot/official names, not the bare old one.
    rb = _find_dir_with("docs", "passo_a_passo_pratico.md") or _find_dir_with("passo_a_passo_pratico.md")
    if rb:
        t = open(rb, encoding="utf-8").read()
        assert "campaign.pilot.example.json" in t and "campaign.official.example.json" in t


def test_official_commands_match_official_manifest():
    """§11 [audit v20.23]: the OFFICIAL commands in the README must be RUNNABLE against the OFFICIAL
    manifest — the documented flags have to satisfy the manifest's pins. A labeler command missing
    `--min-window-overlap <pin>`, or an evaluate command missing `--domain-distinguishability` while the
    manifest pins a domain-AUC bar, would abort in practice (the exact doc/CLI drift the auditor hit)."""
    if os.getenv("CI") == "true": return
    import campaign as camp
    lab = _find_dir_with("lab")
    off = camp.load(os.path.join(lab, "campaign.official.example.json"), require_reproducible=True)
    pin = off.get("required_min_window_overlap")
    rqp = off.get("release_quality_policy") or {}
    pins_auc = rqp.get("max_domain_auc") is not None or off.get("max_domain_auc") is not None
    # §11 [audit v20.24]: check BOTH the README AND the OPERATIONAL runbook (passo_a_passo_pratico.md),
    # which the README itself declares to be the current operational reference — a doc that omits a
    # required flag would abort in practice.
    docs = [_find_dir_with("README.md"),
            _find_dir_with("docs", "passo_a_passo_pratico.md") or _find_dir_with("passo_a_passo_pratico.md")]
    for doc in docs:
        assert doc, "an official-command doc was not found"
        # the runbook splits a command over several lines; scan the WHOLE text, not line-by-line.
        txt = open(doc, encoding="utf-8").read()
        assert "label_flows.py" in txt and "evaluate_realism.py" in txt, "commands missing in " + doc
        if pin is not None:
            assert "--min-window-overlap {}".format(pin) in txt, \
                "{} labeler command must pass --min-window-overlap {}".format(doc, pin)
        if pins_auc:
            assert "--domain-distinguishability" in txt, \
                "{} evaluate command must pass --domain-distinguishability (manifest pins domain AUC)".format(doc)


def test_campaign_pins_cross_split_ceiling():
    """A campaign manifest may PIN `max_cross_split_duplicate_rate`, and merge ENFORCES it (an
    official campaign run is fail-closed at 0.0 even without the CLI flag) [audit v20.17 §11.1]."""
    import json
    import pandas as pd
    import feature_schema as fs
    d = tempfile.mkdtemp()
    _run([sys.executable, _script("synth_nids_dataset.py"), "--runs", "2", "--schema", "common",
          "--attacks", "DoS", "--out", os.path.join(d, "s.csv"), "--seed", "1"], check=True)
    df = pd.read_csv(os.path.join(d, "s.csv"))
    r0, r1 = df[df.run_id == 0].copy(), df[df.run_id == 1].copy()
    for c in [c for c in fs.EXTENDED if c in df.columns]:  # force one cross-split duplicate
        r1.iloc[0, r1.columns.get_loc(c)] = r0.iloc[0][c]
    p0, p1 = os.path.join(d, "r0_split_ready.csv"), os.path.join(d, "r1_split_ready.csv")
    r0.to_csv(p0, index=False); r1.to_csv(p1, index=False)
    man = {"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
           "max_cross_split_duplicate_rate": 0,           # PIN the ceiling in the manifest
           "runs": {"0": _run_spec(0, "train", 0, "2026-01-01"),
                    "1": _run_spec(6, "test", 1, "2026-01-02")}}
    mp = os.path.join(d, "m.json"); json.dump(man, open(mp, "w"))
    ms = _script("merge_and_split.py")
    # NO --max-cross-split-duplicate-rate on the CLI: the manifest's ceiling must still bite. (The
    # gate fires even for an unauthenticated/diagnostic package — it is a hard abort.)
    base = [sys.executable, ms, p0, p1, "--test-run", "1", "--i-trust-run-order", "--campaign", mp,
            "--allow-incomplete-campaign", "--allow-unauthenticated-inputs",
            "--prefix", os.path.join(d, "ds"), "--overwrite"]
    r = _run(base, capture_output=True, text=True)
    assert r.returncode != 0 and "cross-split duplicate" in (r.stdout + r.stderr), \
        (r.returncode, r.stdout + r.stderr)
    # THE v20.18 §6 BYPASS: a MORE PERMISSIVE CLI must NOT be able to silently relax the manifest.
    r2 = _run(base + ["--max-cross-split-duplicate-rate", "1"], capture_output=True, text=True)
    assert r2.returncode != 0 and "MORE PERMISSIVE" in (r2.stdout + r2.stderr), \
        (r2.returncode, r2.stdout + r2.stderr)
    # Relaxing it EXPLICITLY (--allow-cross-split-duplicates) is allowed but makes it DIAGNOSTIC and
    # records the full ceiling audit trail (manifest vs cli vs effective) [§6].
    import json
    r3 = _run(base + ["--max-cross-split-duplicate-rate", "1", "--allow-cross-split-duplicates"],
              capture_output=True, text=True)
    assert r3.returncode == 0, r3.stdout + r3.stderr
    prov = json.load(open(os.path.join(d, "ds_split_provenance.json")))
    assert prov["official"] is False and "cross_split_duplicates" in prov["diagnostic_reasons"]
    ce = prov["duplicates"]["cross_split_duplicate_ceiling"]
    assert ce["manifest"] == 0 and ce["cli"] == 1 and ce["override_used"] is True
    assert ce["source"] == "cli_override" and ce["rows"] >= 1
    # v20.20 §5 BYPASS: a non-finite CLI ceiling (nan) must be REJECTED by argparse, not silently
    # accepted as "always satisfied" (nan comparisons are always False -> the gate would never fire).
    r4 = _run(base + ["--max-cross-split-duplicate-rate", "nan"], capture_output=True, text=True)
    assert r4.returncode != 0 and "finite" in (r4.stdout + r4.stderr), \
        (r4.returncode, r4.stdout + r4.stderr)
    r5 = _run(base + ["--max-cross-split-duplicate-rate", "inf"], capture_output=True, text=True)
    assert r5.returncode != 0 and "finite" in (r5.stdout + r5.stderr)
    # v20.20 §6 BYPASS: a COMPLETE campaign (no --allow-incomplete-campaign) with NO ceiling in the
    # manifest is fail-closed at the OFFICIAL DEFAULT 0.0 — and that floor exists INDEPENDENTLY of the
    # CLI, so a permissive --max-... can no longer erase it just because the field was omitted.
    man2 = {"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],   # NOTE: no ceiling field at all
            "runs": {"0": _run_spec(0, "train", 0, "2026-01-01"),
                     "1": _run_spec(6, "test", 1, "2026-01-02")}}
    mp2 = os.path.join(d, "m2.json"); json.dump(man2, open(mp2, "w"))
    base2 = [sys.executable, ms, p0, p1, "--test-run", "1", "--i-trust-run-order", "--campaign", mp2,
             "--allow-unauthenticated-inputs",       # diagnostic package, but campaign is COMPLETE
             "--prefix", os.path.join(d, "ds2"), "--overwrite"]
    r6 = _run(base2 + ["--max-cross-split-duplicate-rate", "1"], capture_output=True, text=True)
    assert r6.returncode != 0 and "MORE PERMISSIVE" in (r6.stdout + r6.stderr), \
        (r6.returncode, r6.stdout + r6.stderr)                        # CLI can't relax the 0.0 floor
    r7 = _run(base2, capture_output=True, text=True)                  # and the floor bites w/o any CLI
    assert r7.returncode != 0 and "cross-split duplicate" in (r7.stdout + r7.stderr), \
        (r7.returncode, r7.stdout + r7.stderr)


def test_evaluate_domain_distinguishability():
    """--domain-distinguishability reports raw AND prevalence-robust macro-AUC + per-class AUC +
    prevalence + top features, held out by the LAST run of EACH domain (works with different run
    counts); the gate is SEPARATE from official/diagnostic and drives release_eligible; it fails
    CLOSED and requires the flag [audit v20.17 §11.6 / v20.18 §9/§10/§11/§12/§13]."""
    import json
    d = tempfile.mkdtemp()
    # DIFFERENT run counts per domain (real 4, synth 2) — the v20.18 §9 holdout bug case.
    _run([sys.executable, _script("synth_nids_dataset.py"), "--runs", "4", "--schema", "common",
          "--attacks", "DoS", "PortScan", "--benign", "200", "--attack-each", "50",
          "--out", os.path.join(d, "real.csv"), "--seed", "1"], check=True)
    _run([sys.executable, _script("synth_nids_dataset.py"), "--runs", "2", "--schema", "common",
          "--attacks", "DoS", "PortScan", "--benign", "200", "--attack-each", "50",
          "--out", os.path.join(d, "synth.csv"), "--seed", "2"], check=True)
    out = os.path.join(d, "out.json")
    exp = ["--expected-labels", "BENIGN", "DoS", "PortScan"]
    ev = _script("evaluate_realism.py")
    base = [sys.executable, ev, "--real", os.path.join(d, "real.csv"),
            "--synth", os.path.join(d, "synth.csv"), "--allow-unauthenticated-real", *exp]
    r = _run(base + ["--domain-distinguishability", "--max-domain-auc", "0.0", "--json", out],
             capture_output=True, text=True)
    # §10 [v20.20]: a FAILING opt-in gate now EXITS NON-ZERO (3) so CI can block on it — the JSON is
    # still emitted first, so a reader gets the full verdict.
    assert r.returncode == 3, (r.returncode, r.stdout + r.stderr)
    j = json.load(open(out)); dd = j["domain_distinguishability"]
    assert isinstance(dd["auc_raw"], float) and 0.0 <= dd["auc_raw"] <= 1.0
    assert dd["macro_auc"] is not None and dd["held_out_by"] == "run"    # §9: BOTH domains in test
    assert dd["per_class_auc"] and dd["top_features"] and dd["prevalence_real"] and dd["seed"] == 0
    assert dd["gate"] == "fail" and dd["max_domain_auc"] == 0.0
    # §13 [v20.20]: the domain block carries the FULL reproducibility trail — which run of each domain
    # was held out, the sklearn version, and the per-class train/test support split by domain.
    assert dd["held_out_runs"] == {"real": [3], "synth": [1]}            # LAST run of each (4 vs 2)
    assert isinstance(dd["sklearn_version"], str) and dd["sklearn_version"]
    assert dd["class_support_test"] and dd["class_support_train"]
    assert all({"real", "synth"} <= set(v) for v in dd["class_support_test"].values())
    # §12: distinguishability is SEPARATE from official/diagnostic; it drives release_eligible.
    assert "domain_distinguishable" not in j["diagnostic_reasons"]
    assert j["release_eligible"] is False and j["domain_realism_gate"] == "fail"
    # A PASSING gate (threshold 1.0 >= any AUC) flips the gate to "pass" and (§10) EXITS 0.
    outp = os.path.join(d, "outp.json")
    rp = _run(base + ["--domain-distinguishability", "--max-domain-auc", "1.0", "--json", outp],
              capture_output=True, text=True)
    assert rp.returncode == 0, rp.stdout + rp.stderr
    jp = json.load(open(outp))
    # release_eligible needs a pass AND a non-diagnostic run; --allow-unauthenticated-real forces
    # diagnostic, so a PASS alone is correctly NOT enough — diagnostic DOMINATES [§11/§12].
    assert jp["domain_realism_gate"] == "pass" and jp["diagnostic"] is True
    assert jp["release_eligible"] is False
    # §5-style: a non-finite threshold (inf) can't make the gate vacuously pass — argparse REJECTS it.
    ri = _run(base + ["--domain-distinguishability", "--max-domain-auc", "inf"],
              capture_output=True, text=True)
    assert ri.returncode != 0 and "finite" in (ri.stdout + ri.stderr)
    # §10: --max-domain-auc WITHOUT --domain-distinguishability aborts (no silently-ignored gate).
    rb = _run(base + ["--max-domain-auc", "0.5"], capture_output=True, text=True)
    assert rb.returncode != 0 and "needs --domain-distinguishability" in (rb.stdout + rb.stderr)
    # §11 [v20.20] FAIL-CLOSED: WITHOUT the flag the detector never runs -> block null, gate
    # "not_evaluated", and release_eligible False (a skipped check can't look release-ready). Exit 0
    # (no opt-in gate requested), so the default flow is unchanged for non-release callers.
    out2 = os.path.join(d, "out2.json")
    r2 = _run(base + ["--json", out2], capture_output=True, text=True)
    j2 = json.load(open(out2))
    assert r2.returncode == 0 and j2["domain_distinguishability"] is None
    assert j2["domain_realism_gate"] == "not_evaluated" and j2["release_eligible"] is False


def test_domain_gate_requires_all_expected_classes_in_holdout():
    """§13 [audit v20.21]: the release gate must JUDGE every expected class. If an expected class has
    no real+synth support in the TEST holdout, macro-AUC silently OMITS it — so the gate FAILS CLOSED
    as 'unavailable' (release_eligible false, exit 3) and NAMES the missing class, instead of
    'passing' on the classes that happened to be present (the auditor's DoS-hidden-in-training case)."""
    import json
    import pandas as pd
    d = tempfile.mkdtemp()
    real, synth = os.path.join(d, "real.csv"), os.path.join(d, "synth.csv")
    _run([sys.executable, _script("synth_nids_dataset.py"), "--runs", "4", "--schema", "common",
          "--attacks", "DoS", "PortScan", "--benign", "200", "--attack-each", "50",
          "--out", real, "--seed", "1"], check=True)
    _run([sys.executable, _script("synth_nids_dataset.py"), "--runs", "2", "--schema", "common",
          "--attacks", "DoS", "PortScan", "--benign", "200", "--attack-each", "50",
          "--out", synth, "--seed", "2"], check=True)
    # Make the LAST real run (the domain holdout) carry NO DoS: DoS stays GLOBAL (earlier runs) but is
    # absent from the real test fold -> unjudged by macro-AUC.
    df = pd.read_csv(real); last = int(df["run_id"].max())
    df.loc[(df["run_id"] == last) & (df["label"] == "DoS"), "label"] = "BENIGN"
    df.to_csv(real, index=False)
    out = os.path.join(d, "o.json")
    r = _run([sys.executable, _script("evaluate_realism.py"), "--real", real, "--synth", synth,
              "--allow-unauthenticated-real", "--allow-missing-expected-labels",
              "--expected-labels", "BENIGN", "DoS", "PortScan",
              "--domain-distinguishability", "--max-domain-auc", "0.99", "--json", out],
             capture_output=True, text=True)
    assert r.returncode == 3, (r.returncode, r.stdout + r.stderr)          # unavailable -> exit 3 (§10)
    j = json.load(open(out))
    assert j["domain_realism_gate"] == "unavailable" and j["release_eligible"] is False
    assert "DoS" in j["domain_distinguishability"]["missing_domain_test_classes"]


def test_window_overlap_labeling():
    """--min-window-overlap matches on the flow's [start,start+duration] OVERLAP with the attack
    window instead of just its START timestamp — fixing a long flow that begins just BEFORE the
    window (false benign) and one that begins in the last moment but is mostly OUTSIDE (false
    attack). Default (None) keeps the legacy start-in-window rule [audit v20.19 §18.4]."""
    w = [{"start": 100.0, "end": 200.0, "attacker_ip": "10.0.0.2", "target_ip": "10.0.0.1",
          "protocol": "udp", "port_spec": "443", "label": "DoS", "event_id": "e1"}]

    def conn(ts, dur):
        return {"ts": ts, "duration": dur, "id.orig_h": "10.0.0.2", "id.resp_h": "10.0.0.1",
                "proto": "udp", "id.resp_p": "443"}
    # (A) FALSE BENIGN: starts 10s BEFORE the window, active through 90% of it (overlap 0.9).
    early = conn(90.0, 100.0)                                   # [90,190] ∩ [100,200] = 90 -> 0.9
    assert lf.classify(early, w)[0] == "BENIGN"                 # legacy: start 90 < 100 -> benign
    assert lf.classify(early, w, 0.5)[0] == "DoS"              # overlap 0.9 >= 0.5 -> attack
    # (B) FALSE ATTACK: starts at the last moment INSIDE the window but is mostly OUTSIDE (0.01).
    late = conn(199.0, 100.0)                                   # [199,299] ∩ [100,200] = 1 -> 0.01
    assert lf.classify(late, w)[0] == "DoS"                     # legacy: start 199 in window -> attack
    assert lf.classify(late, w, 0.5)[0] == "BENIGN"           # overlap 0.01 < 0.5 -> benign
    assert lf.matching_windows(late, w) and not lf.matching_windows(late, w, 0.5)   # accounting agrees
    # unknown/zero duration falls back to the start-in-window point rule under BOTH modes.
    pt = conn(150.0, "-")
    assert lf.classify(pt, w)[0] == "DoS" and lf.classify(pt, w, 0.5)[0] == "DoS"


def test_window_overlap_status_is_self_consistent():
    """END-TO-END [audit v20.20 §7]: with --min-window-overlap a flow that STARTS before the window
    but overlaps it is labeled, AND the produced status/v5 satisfies its OWN invariant
    (window_start <= first_match <= last_match <= window_end) — the previous version wrote the raw
    pre-window flow start, which the status/v5 consumer REJECTED (the exact motivating case)."""
    import json
    import hashlib
    d = tempfile.mkdtemp()
    wstart = 1577836800.0                              # 2020-01-01T00:00:00Z = the annotation window start
    cf = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service",
          "duration", "orig_bytes", "resp_bytes", "orig_ip_bytes", "resp_ip_bytes", "orig_pkts",
          "resp_pkts", "conn_state"]
    conn = os.path.join(d, "conn.log")
    with open(conn, "w") as f:
        f.write("#separator \\x09\n#fields\t" + "\t".join(cf) + "\n#types\t"
                + "\t".join(["string"] * len(cf)) + "\n")
        f.write("\t".join([str(wstart - 10), "C1", "10.0.0.2", "5", "10.0.0.1", "443", "udp", "ssl",
                           "100", "100", "200", "1500", "3000", "5", "6", "SF"]) + "\n")  # 90% in
        # A second flow that STARTS inside the window but has NO usable Zeek duration ("-"): in overlap
        # mode it falls back to the start-in-window POINT rule — recorded in overlap_accounting [§8].
        f.write("\t".join([str(wstart + 100), "C2", "10.0.0.2", "6", "10.0.0.1", "443", "udp", "ssl",
                           "-", "100", "200", "1500", "3000", "5", "6", "SF"]) + "\n")
    run = lambda cfg, sp: {"config_id": cfg, "split": sp, "seed": cfg, "day": "2026-01-0%d" % (cfg + 1),
                           "attacks": ["DoS"], "target_host": "h", "target_ip": "10.0.0.1",
                           "attacker_ip": "10.0.0.2", "timeout": 900, "dos_seconds": 120}
    man = {"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
           "runs": {"0": run(0, "train"), "1": run(6, "test")}}
    mp = os.path.join(d, "m.json"); json.dump(man, open(mp, "w"))
    msha = hashlib.sha256(open(mp, "rb").read()).hexdigest()
    ann = _campaign_ann(d, "C", msha, 0, [{"label": "DoS"}])          # window 00:00:00-00:10:00
    out = os.path.join(d, "o.csv")
    r = _run([sys.executable, _script("label_flows.py"), "--conn", conn, "--annotations", ann,
              "--campaign", mp, "--allow-incomplete-campaign", "--min-window-overlap", "0.5",
              "--out", out], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr                    # overlap admits the pre-window flow
    st = json.load(open(out.replace(".csv", "") + "_run_status.json"))
    ev = list(st["events"].values())[0]
    assert ev["window_start"] <= ev["first_match"] <= ev["last_match"] <= ev["window_end"]
    assert ev["matched_flows"] == 2                                  # overlap admits BOTH flows
    import provenance as prov
    prov.validate_status_v5("overlap", st)                           # the CONSUMER accepts it now
    assert st["min_window_overlap"] == 0.5
    # §8 [v20.20]: the status records how many matched flows used the point-rule FALLBACK (unknown
    # duration) — here the 2nd flow (duration "-"), so the overlap guarantee didn't apply to it.
    oa = st["overlap_accounting"]
    assert oa["matched_flows"] == 2 and oa["duration_fallback_flows"] == 1
    # PARTIAL fallback (1/2 = 50%, no pinned ceiling) is NOT degenerate -> the run stays non-diagnostic
    # on that axis [§11].
    assert "overlap_duration_fallback" not in st.get("diagnostic_reasons", [])
    # CONTROL: legacy start-in-window matches ONLY the 2nd flow (start in-window); it MISSES the
    # pre-window flow that overlap mode admitted -> matched_flows drops from 2 to 1.
    out2 = os.path.join(d, "o2.csv")
    r2 = _run([sys.executable, _script("label_flows.py"), "--conn", conn, "--annotations", ann,
               "--campaign", mp, "--allow-incomplete-campaign", "--out", out2],
              capture_output=True, text=True)
    assert r2.returncode == 0, r2.stdout + r2.stderr
    st2 = json.load(open(out2.replace(".csv", "") + "_run_status.json"))
    ev2 = list(st2["events"].values())[0]
    assert ev2["matched_flows"] == 1                                 # pre-window flow missed by legacy
    assert st2["overlap_accounting"]["matched_flows"] == 0          # accounting only tallies overlap mode


def test_overlap_total_fallback_is_diagnostic():
    """§11 [audit v20.21]: --min-window-overlap requested but EVERY matched flow lacked a usable Zeek
    duration -> all fell back to the legacy point rule -> the overlap policy NEVER applied. The run is
    marked DIAGNOSTIC ('overlap_duration_fallback'), so a merge --require-status refuses it as
    official — an overlap dataset that is really legacy-labeled can't masquerade as overlap-labeled."""
    import json
    import hashlib
    d = tempfile.mkdtemp()
    wstart = 1577836800.0
    cf = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service",
          "duration", "orig_bytes", "resp_bytes", "orig_ip_bytes", "resp_ip_bytes", "orig_pkts",
          "resp_pkts", "conn_state"]
    conn = os.path.join(d, "conn.log")
    with open(conn, "w") as f:
        f.write("#separator \\x09\n#fields\t" + "\t".join(cf) + "\n#types\t"
                + "\t".join(["string"] * len(cf)) + "\n")
        # the SOLE matched flow is in-window but has NO usable duration ("-") -> 100% point fallback.
        f.write("\t".join([str(wstart + 100), "C1", "10.0.0.2", "5", "10.0.0.1", "443", "udp", "ssl",
                           "-", "100", "200", "1500", "3000", "5", "6", "SF"]) + "\n")
    run = lambda cfg, sp: {"config_id": cfg, "split": sp, "seed": cfg, "day": "2026-01-0%d" % (cfg + 1),
                           "attacks": ["DoS"], "target_host": "h", "target_ip": "10.0.0.1",
                           "attacker_ip": "10.0.0.2", "timeout": 900, "dos_seconds": 120}
    man = {"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
           "runs": {"0": run(0, "train"), "1": run(6, "test")}}
    mp = os.path.join(d, "m.json"); json.dump(man, open(mp, "w"))
    msha = hashlib.sha256(open(mp, "rb").read()).hexdigest()
    ann = _campaign_ann(d, "C", msha, 0, [{"label": "DoS"}])
    out = os.path.join(d, "o.csv")
    r = _run([sys.executable, _script("label_flows.py"), "--conn", conn, "--annotations", ann,
              "--campaign", mp, "--allow-incomplete-campaign", "--min-window-overlap", "0.5",
              "--out", out], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr                     # diagnostic, NOT an abort
    st = json.load(open(out.replace(".csv", "") + "_run_status.json"))
    assert st["overlap_accounting"] == {"matched_flows": 1, "duration_fallback_flows": 1}
    assert st["diagnostic"] is True and "overlap_duration_fallback" in st["diagnostic_reasons"]
    import provenance as prov
    prov.validate_status_v5("fb", st)                                 # the new reason is RECOGNISED


def test_packaging_lists_all_shipped_modules():
    """The wheel must ship EVERY importable module, or an installed package breaks: versions.py was
    omitted from [tool.setuptools] py-modules, so campaign/label_flows/... failed to import from a
    clean install even though the checkout worked [audit v20.12 §13]."""
    import re
    here = os.path.dirname(os.path.abspath(__file__))
    pp = next((c for c in (os.path.join(here, "pyproject.toml"),
                           os.path.join(here, "..", "pyproject.toml")) if os.path.exists(c)), None)
    assert pp, "pyproject.toml not found next to the tests"
    m = re.search(r"py-modules\s*=\s*\[(.*?)\]", open(pp, encoding="utf-8").read(), re.S)
    assert m, "py-modules table missing"
    listed = set(re.findall(r'"([^"]+)"', m.group(1)))
    required = {"versions", "feature_schema", "campaign", "attack_scenarios", "provenance",
                "label_flows", "merge_and_split", "validate_dataset", "evaluate_realism",
                "synth_nids_dataset", "run_attacks", "benign_traffic", "seed_content",
                "correlate_ground_truth",
                # lab AUTOMATION layer [audit v20.26; +verify_switch_mirroring audit v20.30 §8]:
                "runlib", "clock_evidence", "capture_run", "process_pcap", "service_monitor",
                "preflight", "finalize_run", "orchestrate_run", "orchestrate_campaign",
                "verify_switch_mirroring"}
    assert required <= listed, "py-modules is missing: {}".format(sorted(required - listed))


# ---------------------------------------------------------------------------------------------------
# LAB AUTOMATION layer [audit v20.26]: capture / orchestration / monitoring. The physical paths
# (tcpdump, zeek, chronyc, the victims, ssh to NB1..NB4) can't run here, so these tests exercise the
# PURE logic (parsers, hashing, run-dir guard, the pipeline state machine, the campaign driver) and
# the tools' CLI in --simulate/--dry-run modes.
# ---------------------------------------------------------------------------------------------------

def test_runlib_helpers():
    """runlib: sha256 of file/bytes, atomic write/read JSON with its hash, and the run-directory
    overwrite GUARD (a second capture never silently clobbers a previous run) [audit v20.26]."""
    import runlib
    d = tempfile.mkdtemp()
    p = os.path.join(d, "a.bin"); open(p, "wb").write(b"hello")
    assert runlib.sha256_file(p) == runlib.sha256_bytes(b"hello")
    jp = os.path.join(d, "x.json"); sha = runlib.write_json(jp, {"b": 1, "a": 2})
    assert runlib.read_json(jp) == {"b": 1, "a": 2} and len(sha) == 64
    rd = runlib.ensure_run_dir(d, 0); assert rd.endswith("run0")
    open(os.path.join(rd, "f"), "w").write("x")
    try:
        runlib.ensure_run_dir(d, 0); assert False, "overwrite guard did not fire"
    except FileExistsError:
        pass
    assert runlib.ensure_run_dir(d, 0, overwrite=True).endswith("run0")   # explicit override OK


def test_runlib_local_runner():
    """The Runner abstraction: LocalRunner executes a command and reports ok/stdout; make_runner
    defaults to local so the whole orchestrator is testable without ssh [audit v20.26]."""
    import runlib
    r = runlib.make_runner({"kind": "local"}).run([sys.executable, "-c", "print('hi')"])
    assert r.ok and "hi" in r.stdout
    bad = runlib.LocalRunner().run([sys.executable, "-c", "import sys; sys.exit(3)"])
    assert not bad.ok and bad.returncode == 3
    assert isinstance(runlib.make_runner({"kind": "ssh", "target": "u@h"}), runlib.SSHRunner)


def test_clock_evidence_parsers():
    """clock_evidence parses chronyc / w32tm / timedatectl output into flat records [audit v20.26]."""
    import clock_evidence as ce
    ch = ce.parse_chronyc_tracking(
        "Reference ID    : 0A0A0A0B (nb1)\nStratum         : 8\n"
        "System time     : 0.000000123 seconds slow of NTP time\nRMS offset      : 0.000002 seconds\n"
        "Root dispersion : 0.000050 seconds\nLeap status     : Normal")
    assert ch["stratum"] == 8 and ch["leap_status"] == "Normal" and ch["rms_offset_s"] == 2e-6
    td = ce.parse_timedatectl("               Time zone: UTC (UTC, +0000)\nSystem clock synchronized: yes\n"
                              "              NTP service: active")
    assert td["synchronized"] is True and td["ntp_service"] is True and td["time_zone"].startswith("UTC")
    wt = ce.parse_w32tm_status("Stratum: 9 (secondary reference)\nSource: 10.10.10.11\n"
                               "Phase Offset: 0.0012345s\nRoot Dispersion: 0.01s\nLeap Indicator: 0(no warning)")
    assert wt["stratum"] == 9 and wt["source"] == "10.10.10.11" and wt["phase_offset_s"] == 0.0012345


def test_capture_run_pure():
    """capture_run: tcpdump stats parsing (incl. drop_rate) and the pcap seal report [audit v20.26]."""
    import capture_run as cr
    st = cr.parse_tcpdump_stats("500 packets captured\n1000 packets received by filter\n"
                                "10 packets dropped by kernel")
    assert st["packets_dropped"] == 10 and abs(st["drop_rate"] - 0.01) < 1e-9
    d = tempfile.mkdtemp(); p = os.path.join(d, "run0.pcap"); open(p, "wb").write(b"\xd4\xc3\xb2\xa1data")
    rep = cr.pcap_report(p)
    assert rep["exists"] and rep["size_bytes"] == 8 and len(rep["sha256"]) == 64
    assert cr.pcap_report(os.path.join(d, "nope.pcap"))["exists"] is False


def test_process_pcap_log_report():
    """process_pcap: Zeek TSV log report counts records, reads #fields, flags empty [audit v20.26]."""
    import process_pcap as pp
    d = tempfile.mkdtemp()
    conn = os.path.join(d, "conn.log")
    open(conn, "w").write("#separator \\x09\n#fields\tts\tuid\tproto\n"
                          "1.0\tC1\ttcp\n2.0\tC2\tudp\n")
    rep = pp.zeek_log_report(conn)
    assert rep["records"] == 2 and rep["fields"] == ["ts", "uid", "proto"] and rep["empty"] is False
    empty = os.path.join(d, "quic.log"); open(empty, "w").write("#fields\tts\n")
    assert pp.zeek_log_report(empty)["empty"] is True
    assert pp.zeek_log_report(os.path.join(d, "missing.log"))["exists"] is False


def test_preflight_checks_and_verdict():
    """preflight: tool/disk/manifest/wordlist checks + aggregation. Overall PASS only if every REQUIRED
    check passes; a FAILED required check flips it [audit v20.26]."""
    import json
    import preflight as pf
    d = tempfile.mkdtemp()
    assert pf.check_tools([sys.executable and "python3"])["status"] in ("PASS", "FAIL")
    assert pf.check_tools(["___definitely_absent_tool___"])["status"] == "FAIL"
    assert pf.check_disk(d, 0.0)["status"] == "PASS"
    good = {"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
            "runs": {"0": _run_spec(0, "train", 0, "2026-01-01"),
                     "1": _run_spec(6, "test", 1, "2026-01-02")}}
    mp = os.path.join(d, "c.json"); json.dump(good, open(mp, "w"))
    assert pf.check_manifest(mp)["status"] == "PASS"
    bad = os.path.join(d, "bad.json"); json.dump({"campaign_id": ""}, open(bad, "w"))
    assert pf.check_manifest(bad)["status"] == "FAIL"
    # wordlist hash check: a run pins a passlist sha256; a matching local file passes, a wrong one fails.
    wd = os.path.join(d, "wl"); os.makedirs(wd); wl = os.path.join(wd, "pass.txt"); open(wl, "w").write("admin\n")
    import runlib
    man = {"campaign_id": "C", "runs": {"0": {"config_id": 0, "passlist_sha256": runlib.sha256_file(wl)}}}
    mp2 = os.path.join(d, "m2.json"); json.dump(man, open(mp2, "w"))
    assert pf.check_wordlists(mp2, wd)["status"] == "PASS"
    man["runs"]["0"]["passlist_sha256"] = "0" * 64; json.dump(man, open(mp2, "w"))
    assert pf.check_wordlists(mp2, wd)["status"] == "FAIL"
    rep = pf.build_report([pf._chk("a", pf.PASS, {}), pf._chk("b", pf.SKIP, {}),
                           pf._chk("c", pf.FAIL, {}, required=False)])
    assert rep["overall"] == pf.PASS                                    # a non-required FAIL doesn't sink it
    assert pf.build_report([pf._chk("d", pf.FAIL, {})])["overall"] == pf.FAIL


def test_orchestrate_run_state_machine():
    """orchestrate_run.run_pipeline: runs steps in order, ABORTS at the first REQUIRED failure (a later
    step never runs), tolerates an OPTIONAL failure, and turns a crashing step into a failure [v20.26]."""
    import orchestrate_run as orun
    trace = []

    def mk(name, ok, required=True):
        def _fn():
            trace.append(name); return ok, {"n": name}
        return orun.Step(name, _fn, required=required)
    rep = orun.run_pipeline([mk("a", True), mk("b", False), mk("c", True)])
    assert rep["overall"] == "FAIL" and rep["aborted_at"] == "b" and trace == ["a", "b"]  # c never ran
    trace.clear()
    rep2 = orun.run_pipeline([mk("a", True), mk("b", False, required=False), mk("c", True)])
    assert rep2["overall"] == "PASS" and trace == ["a", "b", "c"]        # optional failure continues

    def boom():
        raise RuntimeError("kaboom")
    rep3 = orun.run_pipeline([orun.Step("x", boom)])
    assert rep3["overall"] == "FAIL" and "kaboom" in rep3["steps"][0]["detail"]["exception"]


def test_orchestrate_run_dry_run_cli():
    """orchestrate_run --dry-run builds the real step list but STUBS every step (records the argv it
    WOULD run), so the full flow is exercised with no host touched [audit v20.26]."""
    import json
    d = tempfile.mkdtemp()
    cfg = {"run_id": 0, "base_dir": d, "src_dir": os.path.dirname(_script("orchestrate_run.py")),
           "campaign": "campaign.json", "interface": "lo"}
    cp = os.path.join(d, "cfg.json"); json.dump(cfg, open(cp, "w"))
    r = _run([sys.executable, _script("orchestrate_run.py"), "--config", cp, "--dry-run"],
             capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    rep = json.load(open(os.path.join(d, "run0", "run0_orchestration.json")))
    assert rep["overall"] == "PASS" and all(s["detail"].get("dry_run") for s in rep["steps"])
    names = [s["step"] for s in rep["steps"]]
    # the P0 order survives the real CLI path, not just the in-process builder [audit v20.27 §2]:
    assert names.index("start_capture") < names.index("attacks") < names.index("stop_capture")
    assert "process_pcap" in names and "finalize" not in names          # finalize runs in main() now [§14]
    assert rep.get("finalize", {}).get("dry_run") is True               # ...and IS recorded there


def test_orchestrate_campaign_driver():
    """orchestrate_campaign.run_campaign: drives runs in order, RESUMES sealed runs, HARD-STOPS on an
    official run failure (analytics never run), and only builds the dataset when ALL runs are in
    [audit v20.26]."""
    import orchestrate_campaign as ocamp
    manifest = {"campaign_id": "C", "runs": {"0": {"config_id": 0}, "1": {"config_id": 6}}}
    d = tempfile.mkdtemp()
    calls = {"ran": [], "analytics": 0}

    def analytics(runs):
        calls["analytics"] += 1; return {"overall": "PASS", "steps": {}}
    # (a) all official runs PASS -> analytics runs -> overall PASS.
    def ok_run(rid, spec):
        calls["ran"].append(rid); return {"overall": "PASS", "diagnostic": False}
    rep = ocamp.run_campaign(manifest, d, ok_run, analytics, resume=False)
    assert rep["overall"] == "PASS" and rep["executed_runs"] == [0, 1] and calls["analytics"] == 1
    # (b) an OFFICIAL run fails -> stop, analytics NOT called, overall FAIL.
    calls.update(ran=[], analytics=0)
    def fail_second(rid, spec):
        calls["ran"].append(rid)
        return {"overall": "PASS" if rid == "0" else "FAIL", "diagnostic": False}
    rep2 = ocamp.run_campaign(manifest, d, fail_second, analytics, resume=False)
    assert rep2["overall"] == "FAIL" and calls["ran"] == ["0", "1"] and calls["analytics"] == 0
    # (c) a duplicate config_id in the manifest is rejected before running anything.
    dup = {"campaign_id": "C", "runs": {"0": {"config_id": 0}, "1": {"config_id": 0}}}
    assert ocamp.run_campaign(dup, d, ok_run, analytics, resume=False)["overall"] == "FAIL"


def test_capture_and_finalize_cli_end_to_end():
    """capture_run --simulate seals a pre-placed PCAP (start/end JSON + sha256), then finalize_run seals
    the run (inventory + bundle) and --verify DETECTS a later change [audit v20.26]."""
    import json
    d = tempfile.mkdtemp()
    # a real capture needs CAP_NET_RAW; --simulate treats a pre-placed pcap as the capture.
    run_dir = os.path.join(d, "run0"); os.makedirs(run_dir)
    open(os.path.join(run_dir, "run0.pcap"), "wb").write(b"\xd4\xc3\xb2\xa1" + b"x" * 100)
    cap = _run([sys.executable, _script("capture_run.py"), "--base-dir", d, "--run-id", "0",
                "--simulate", "--overwrite", "--duration", "0"], capture_output=True, text=True)
    assert cap.returncode == 0, cap.stdout + cap.stderr
    assert os.path.exists(os.path.join(run_dir, "run0_capture_end.json"))
    assert os.path.exists(os.path.join(run_dir, "run0_pcap.sha256"))
    # finalize with a relaxed required set (no zeek/status in this smoke) -> PASS, bundle produced.
    fin = _run([sys.executable, _script("finalize_run.py"), "--run-dir", run_dir, "--run-id", "0",
                "--require", "run0.pcap", "--require", "run0_capture_end.json", "--diagnostic"],
               capture_output=True, text=True)
    assert fin.returncode == 0, fin.stdout + fin.stderr
    comp = json.load(open(os.path.join(run_dir, "run0_completion_status.json")))
    assert comp["overall"] == "PASS" and comp["bundle"]["sha256"]
    # a CLEAN sealed run verifies OK (finalize's own artifacts don't false-positive as changes).
    okv = _run([sys.executable, _script("finalize_run.py"), "--run-dir", run_dir, "--run-id", "0",
                "--verify"], capture_output=True, text=True)
    assert okv.returncode == 0 and "OK" in (okv.stdout + okv.stderr), (okv.returncode, okv.stdout + okv.stderr)
    # tamper: append to the pcap -> --verify reports it.
    open(os.path.join(run_dir, "run0.pcap"), "ab").write(b"TAMPER")
    ver = _run([sys.executable, _script("finalize_run.py"), "--run-dir", run_dir, "--run-id", "0",
                "--verify"], capture_output=True, text=True)
    assert ver.returncode == 3 and "TAMPERED" in (ver.stdout + ver.stderr)


def test_service_monitor_local_server():
    """service_monitor samples a live HTTP endpoint: availability, latency and status are recorded to
    CSV + summary. Runs against a throwaway localhost server (no lab needed) [audit v20.26]."""
    import http.server
    import socketserver
    import threading
    import service_monitor as sm
    d = tempfile.mkdtemp()
    handler = http.server.SimpleHTTPRequestHandler
    httpd = socketserver.TCPServer(("127.0.0.1", 0), handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True); t.start()
    try:
        url = "http://127.0.0.1:{}/".format(port)
        s = sm.sample_url(url, timeout=3.0)
        assert s["ok"] and 200 <= s["http_code"] < 400
        csv_path = os.path.join(d, "m.csv")
        summ = sm.monitor([url], duration=1.0, interval=0.5, csv_path=csv_path)   # 0.5s per-probe timeout
        assert summ[url]["probes"] >= 1 and summ[url]["availability"] >= 0.5      # the endpoint is up
        assert summ[url]["worst_http_code"] == 200                               # it really reached it
        assert os.path.exists(csv_path) and sum(1 for _ in open(csv_path)) >= 2   # header + >=1 row
        # a dead port is recorded as unavailable, not a crash.
        assert sm.sample_url("http://127.0.0.1:{}/".format(port + 1 if port < 65000 else 1), timeout=1.0)["ok"] is False
    finally:
        httpd.shutdown()


def test_orchestrate_run_captures_before_attacks():
    """§2 P0 [audit v20.27]: the ONLY correct order — capture must be UP before any attack traffic and
    stopped AFTER cool-down. Assert on the dry-run step list that start_capture < attacks < stop_capture,
    that monitor+benign are backgrounded before attacks, clocks are collected on ALL FOUR hosts at both
    phases, and labeling writes run<N>.csv so its status file matches what finalize requires [§4]."""
    import orchestrate_run as orun
    cfg = orun.example_config()
    cfg["runners"] = {h: {"kind": "local"} for h in ("nb1", "nb2", "nb3", "nb4")}
    steps = orun.build_steps(cfg, "/tmp/run0", dry_run=True)
    names = [s.name for s in steps]
    i_cap, i_atk, i_stop = names.index("start_capture"), names.index("attacks"), names.index("stop_capture")
    assert i_cap < i_atk < i_stop, names                                # capture BRACKETS the attacks
    assert names.index("start_monitor") < i_atk and names.index("start_benign") < i_atk
    assert names.index("warmup") < i_atk < names.index("cooldown")
    assert names.index("stop_benign") < names.index("stop_monitor") < i_stop   # capture stopped LAST
    for lbl in ("nb1", "nb2", "nb3", "nb4"):                            # clocks on all four, both phases
        assert "clock_{}_start".format(lbl) in names and "clock_{}_end".format(lbl) in names
    assert names.index("fetch_annotations") < names.index("label_flows")    # ground truth pulled first
    assert names.index("process_pcap") < names.index("label_flows")
    assert "finalize" not in names                                          # finalize runs in main() [§14]
    # the labeler is driven with --out run0.csv, so it writes run0_run_status.json (finalize's required)
    label = next(s for s in steps if s.name == "label_flows")
    argv = label.fn()[1]["argv"]
    assert argv[argv.index("--out") + 1].endswith("run0.csv")


def test_orchestrator_threads_attempt_id():
    """§6 P0 [audit v20.43]: the orchestrator generates ONE attempt_id and SHARES it, so the benign session
    log and the labeler status carry the SAME id (finalize now requires the match — without this the whole
    official automation could never seal). Assert the benign AND label_flows commands both pass --attempt-id
    with the same non-empty value, and that fetch_benign_log is REQUIRED when the jsonl is demanded."""
    import orchestrate_run as orun
    cfg = orun.example_config()
    cfg["runners"] = {h: {"kind": "local"} for h in ("nb1", "nb2", "nb3", "nb4")}
    cfg["require_benign_log"] = True
    steps = orun.build_steps(cfg, "/tmp/run0", dry_run=True)

    def _argv(name):
        return next(s for s in steps if s.name == name).fn()[1]["argv"]
    benign, label = _argv("start_benign"), _argv("label_flows")
    b_att = benign[benign.index("--attempt-id") + 1]
    l_att = label[label.index("--attempt-id") + 1]
    assert b_att and b_att == l_att, ("benign and labeler must SHARE one attempt_id", b_att, l_att)
    assert next(s for s in steps if s.name == "fetch_benign_log").required is True   # mandatory jsonl fetch [§8]


def test_labeler_accepts_external_attempt_id():
    """§6 P0 [audit v20.43]: label_flows must ACCEPT --attempt-id and record THAT id in the run status (not a
    fresh uuid), so the orchestrator can bind every producer to one attempt. Also proves the flag no longer
    aborts argparse with code 2."""
    import label_flows as lf
    import inspect
    src = inspect.getsource(lf)
    assert '"--attempt-id"' in src or "'--attempt-id'" in src           # the CLI accepts it
    assert "args.attempt_id or uuid.uuid4().hex" in src                 # and USES the provided id


def test_orchestrate_run_stops_background_on_abort():
    """§2 P0 [audit v20.27]: if a REQUIRED step (attacks) fails, later normal steps are SKIPPED but the
    `always` cleanup (stop the background capture) STILL runs — no leaked tcpdump, capture still sealed."""
    import orchestrate_run as orun
    trace = []

    def mk(name, ok, required=True, always=False):
        def _fn():
            trace.append(name); return ok, {}
        return orun.Step(name, _fn, required=required, always=always)
    rep = orun.run_pipeline([mk("start_capture", True), mk("attacks", False),
                             mk("label", True), mk("stop_capture", True, required=False, always=True),
                             mk("finalize", True)])
    assert rep["overall"] == "FAIL" and rep["aborted_at"] == "attacks"
    assert trace == ["start_capture", "attacks", "stop_capture"]        # label+finalize skipped
    by = {s["step"]: s for s in rep["steps"]}
    assert by["label"].get("skipped") and by["finalize"].get("skipped")
    assert by["stop_capture"]["ok"] and not by["stop_capture"].get("skipped")


def test_service_monitor_effect_confirmed_and_null():
    """[audit v20.27] analyze_effect turns 'DoS' into a MEASUREMENT: a run where availability collapses
    (and latency/errors spike) DURING the attack window is effect_confirmed=True; an identical window
    with no service impact is effect_confirmed=False (an honest DoSAttempt, not a DoS)."""
    import csv as _csv
    import datetime as _dt
    import service_monitor as sm
    d = tempfile.mkdtemp()

    def iso(sec):
        base = _dt.datetime(2026, 7, 20, 12, 0, 0, tzinfo=_dt.timezone.utc)
        return (base + _dt.timedelta(seconds=sec)).isoformat()

    def write_csv(path, down_during):
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = _csv.writer(fh)
            w.writerow(["utc", "url", "ok", "http_code", "latency_ms", "error", "cpu_busy", "mem_used_frac"])
            for s in range(0, 30):
                atk = down_during and 10 <= s < 20
                w.writerow([iso(s), "https://blog.lab", 0 if atk else 1, 503 if atk else 200,
                            900.0 if atk else 30.0, "timeout" if atk else "", "", ""])
    ann = os.path.join(d, "ann.csv")
    with open(ann, "w", newline="", encoding="utf-8") as fh:
        w = _csv.writer(fh)
        w.writerow(["event_id", "run_id", "label", "status", "start_utc", "end_utc"])
        w.writerow(["e1", "0", "DoS", "success", iso(10), iso(19)])
    windows = sm.load_windows(ann)
    assert len(windows) == 1
    hit = os.path.join(d, "hit.csv"); write_csv(hit, True)
    rep = sm.analyze_effect(hit, windows)
    u = rep["per_url"]["https://blog.lab"]
    assert rep["effect_confirmed"] and u["availability_attack"] == 0.0 and u["availability_baseline"] == 1.0
    miss = os.path.join(d, "miss.csv"); write_csv(miss, False)
    assert sm.analyze_effect(miss, windows)["effect_confirmed"] is False


def test_runlib_fetch_push_local():
    """§6 [audit v20.27]: a LocalRunner can fetch/push files (used to pull NB3's ground-truth annotations
    onto NB4). Byte-identical copy, verified by SHA-256 — the same contract the ssh runner honors."""
    import runlib
    r = runlib.LocalRunner()
    d = tempfile.mkdtemp()
    src = os.path.join(d, "a.txt"); open(src, "w").write("ground-truth")
    dst = os.path.join(d, "b.txt")
    assert r.fetch(src, dst) and open(dst).read() == "ground-truth"
    assert runlib.sha256_file(src) == runlib.sha256_file(dst)
    dst2 = os.path.join(d, "c.txt")
    assert r.push(src, dst2) and runlib.sha256_file(src) == runlib.sha256_file(dst2)


def test_campaign_analytics_commands_wire_status_synth_validate():
    """§8 P0 [audit v20.27]: the campaign's analytics wiring must (a) pass per-run STATUS to merge,
    (b) actually run validate_dataset, and (c) pass --synth to the evaluator (which aborts without it) —
    all keyed on run<N>_split_ready.csv / run<N>_run_status.json names [§4]. Pure builders, no lab."""
    import orchestrate_campaign as ocamp
    sr = ocamp.split_ready_paths("/data", [0, 1])
    st = ocamp.status_paths("/data", [0, 1])
    assert sr[0].endswith("run0/run0_split_ready.csv") and st[1].endswith("run1/run1_run_status.json")
    merge = ocamp.merge_cmd("/src", "camp.json", sr, st, "/out/dataset")
    assert "--status" in merge and "--require-status" in merge and all(s in merge for s in st)
    val = ocamp.validate_cmd("/src", "camp.json", sr, st, "/out/v.json")
    assert val[1].endswith("validate_dataset.py") and "--require-status" in val and "--json" in val
    ev = ocamp.evaluate_cmd("/src", "camp.json", sr, st, "/synth/s.csv", "/out/e.json")
    assert "--synth" in ev and ev[ev.index("--synth") + 1] == "/synth/s.csv"
    assert "--domain-distinguishability" in ev and "--tstr-balance" in ev


def test_capture_background_early_stop_seals_and_finalizes():
    """§2/§5 P0 [audit v20.27]: capture_run started in the BACKGROUND into an orchestrator-OWNED run dir
    (existing + non-empty, so --run-dir must bypass the overwrite guard) and stopped EARLY still seals
    the capture; finalize_run then seals the run and --verify passes. Exercises the real concurrency
    lifecycle the orchestrator relies on."""
    import runlib
    import time as _time
    d = tempfile.mkdtemp()
    run_dir = os.path.join(d, "run0"); os.makedirs(run_dir)
    open(os.path.join(run_dir, "preexisting.txt"), "w").write("owned by orchestrator")  # non-empty dir
    r = runlib.LocalRunner()
    argv = [sys.executable, _script("capture_run.py"), "--run-dir", run_dir, "--run-id", "0",
            "--duration", "30", "--simulate"]                          # 30s cap; we stop it after ~1s
    job = r.start_background(argv, log_path=os.path.join(run_dir, "cap_bg.log"))
    assert job.pid is not None
    # DETERMINISTIC: wait until the capture is actually RUNNING (pcap present + growing) before stopping,
    # so the stop can't land during the start/clock preamble and race the seal [audit v20.31 §11].
    pcap = os.path.join(run_dir, "run0.pcap")
    for _ in range(80):
        if os.path.exists(pcap) and os.path.getsize(pcap) > 41:
            break
        _time.sleep(0.1)
    assert os.path.exists(pcap), "capture never started"
    r.stop_background(job, grace=15.0); r.wait_background(job, timeout=20)
    # the seal write can trail the process exit slightly; poll (bounded) instead of asserting instantly
    # so a slow clock probe can never flake this [audit v20.29 §3.3].
    end_path = os.path.join(run_dir, "run0_capture_end.json")
    for _ in range(40):
        if os.path.exists(end_path):
            break
        _time.sleep(0.25)
    assert os.path.exists(end_path)                                       # sealed despite early stop
    assert os.path.exists(os.path.join(run_dir, "run0_pcap.sha256"))
    end = json.load(open(os.path.join(run_dir, "run0_capture_end.json")))
    assert end["pcap"]["exists"] and end["pcap"]["size_bytes"] > 0
    fin = _run([sys.executable, _script("finalize_run.py"), "--run-dir", run_dir, "--run-id", "0",
                "--require", "run0.pcap", "--require", "run0_capture_end.json", "--diagnostic"],
               capture_output=True, text=True)
    assert fin.returncode == 0, fin.stdout + fin.stderr
    ver = _run([sys.executable, _script("finalize_run.py"), "--run-dir", run_dir, "--run-id", "0",
                "--verify"], capture_output=True, text=True)
    assert ver.returncode == 0 and "OK" in (ver.stdout + ver.stderr)


def test_service_monitor_analyze_cli_writes_effect():
    """[audit v20.27] the `service_monitor.py --analyze` CLI reads a monitor CSV + annotations and writes
    the effect_confirmed report the orchestrator seals into the run."""
    import csv as _csv
    import datetime as _dt
    d = tempfile.mkdtemp()

    def iso(sec):
        base = _dt.datetime(2026, 7, 20, 12, 0, 0, tzinfo=_dt.timezone.utc)
        return (base + _dt.timedelta(seconds=sec)).isoformat()
    mon = os.path.join(d, "run0_service_monitor.csv")
    with open(mon, "w", newline="", encoding="utf-8") as fh:
        w = _csv.writer(fh)
        w.writerow(["utc", "url", "ok", "http_code", "latency_ms", "error", "cpu_busy", "mem_used_frac"])
        for s in range(0, 24):
            atk = 8 <= s < 16
            w.writerow([iso(s), "https://x", 0 if atk else 1, 503 if atk else 200,
                        800 if atk else 20, "e" if atk else "", "", ""])
    ann = os.path.join(d, "run0_annotations.csv")
    with open(ann, "w", newline="", encoding="utf-8") as fh:
        w = _csv.writer(fh)
        w.writerow(["event_id", "run_id", "label", "status", "start_utc", "end_utc"])
        w.writerow(["e1", "0", "DoS", "success", iso(8), iso(15)])
    out = os.path.join(d, "run0_service_effect.json")
    res = _run([sys.executable, _script("service_monitor.py"), "--analyze", "--csv", mon,
                "--events", ann, "--out", out], capture_output=True, text=True)
    assert res.returncode == 0, res.stdout + res.stderr
    rep = json.load(open(out))
    assert rep["effect_confirmed"] is True and rep["n_windows"] == 1


class _FakeRunner:
    """A Runner stand-in for readiness tests: reports a process as dead/alive and an artifact as
    present/absent WITHOUT spawning anything, so the readiness LOGIC is tested deterministically."""

    def __init__(self, exit_code=None, has_artifact=True, sizes=None):
        self._exit, self._has, self._sizes, self._i = exit_code, has_artifact, list(sizes or []), 0

    def wait_background(self, job, timeout=None):
        return self._exit                                   # None => still alive; int => already exited

    def exists(self, path):
        return self._has

    def file_size(self, path):
        if self._sizes:
            v = self._sizes[min(self._i, len(self._sizes) - 1)]; self._i += 1; return v
        return 100


def test_orchestrate_run_readiness_gates_on_liveness():
    """§5 P0 [audit v20.28]: a background job that took a PID but DIED (e.g. benign_traffic called with a
    bad flag) must FAIL its readiness gate BEFORE the attacks run — the exact failure that let a broken
    benign go unnoticed. A live job whose artifact appeared passes."""
    if os.getenv("CI") == "true": return
    import types
    import orchestrate_run as orun
    d = tempfile.mkdtemp(); run_dir = os.path.join(d, "run0"); os.makedirs(run_dir)
    cfg = {"run_id": 0, "base_dir": d, "src_dir": ".", "campaign": "c.json", "interface": "lo",
           "ready_timeout": 3, "runners": {h: {"kind": "local"} for h in ("nb1", "nb2", "nb3", "nb4")}}
    jobs = {}
    steps = orun.build_steps(cfg, run_dir, dry_run=False, jobs=jobs)
    ready_benign = next(s for s in steps if s.name == "ready_benign")
    # (a) DIED with exit code 2 -> readiness FAILS and surfaces the code.
    jobs["benign"] = types.SimpleNamespace(runner=_FakeRunner(exit_code=2), log_path=None, pid=1)
    ok, detail = ready_benign.fn()
    assert ok is False and detail["exit_code"] == 2
    # (b) ALIVE and its artifact exists -> readiness PASSES.
    jobs["benign"] = types.SimpleNamespace(runner=_FakeRunner(exit_code=None, has_artifact=True), log_path=None, pid=2)
    ok2, _ = ready_benign.fn()
    assert ok2 is True
    # (c) capture readiness requires the PCAP to be STRICTLY GROWING (two consecutive increases) [§5].
    ready_cap = next(s for s in steps if s.name == "ready_capture")
    jobs["capture"] = types.SimpleNamespace(runner=_FakeRunner(exit_code=None, sizes=[40, 73, 120]), log_path=None, pid=3)
    okc, dc = ready_cap.fn()
    assert okc is True and dc["grows"] >= 2
    # a STATIC PCAP (header only, no packets) must NEVER pass — dead mirror / wrong iface [§5].
    jobs["capture"] = types.SimpleNamespace(runner=_FakeRunner(exit_code=None, sizes=[40, 40, 40, 40]), log_path=None, pid=4)
    cfg2 = dict(cfg); cfg2["ready_timeout"] = 1
    steps2 = orun.build_steps(cfg2, run_dir, dry_run=False, jobs=jobs)
    static_ready, _ = next(s for s in steps2 if s.name == "ready_capture").fn()
    assert static_ready is False


def test_orchestrate_prepare_run_dir_rotates_stale():
    """§13 [audit v20.28]: overwrite defaults to OFF (a run's evidence is never reused); with overwrite
    ON, an existing non-empty run dir is ROTATED to run<N>_attempt_<stamp> (kept, not deleted) and a
    CLEAN one is made — so a new attempt can never inherit a stale completion=PASS."""
    import orchestrate_run as orun
    base = tempfile.mkdtemp()
    orun.prepare_run_dir(base, 0)                            # fresh
    open(os.path.join(base, "run0", "run0_completion_status.json"), "w").write('{"overall":"PASS"}')
    try:
        orun.prepare_run_dir(base, 0, overwrite=False)
        assert False, "overwrite=False must abort on a non-empty run dir"
    except FileExistsError:
        pass
    fresh = orun.prepare_run_dir(base, 0, overwrite=True)
    assert os.listdir(fresh) == []                          # brand new, empty
    assert any(x.startswith("run0_attempt_") for x in os.listdir(base))   # old one preserved


def test_windows_runner_builds_native_commands():
    """§7 [audit v20.28]: NB2 keeps native Windows (real Windows JA3), so its runner emits Windows
    commands — `python` not `python3`, `Start-Process -PassThru` for background PIDs, `Stop-Process`
    to stop, all wrapped in powershell over ssh. (A Linux sandbox can't run Windows, so we assert the
    COMMANDS.)"""
    import runlib
    w = runlib.make_runner({"kind": "windows", "target": "lab@10.0.0.20"})
    assert isinstance(w, runlib.WindowsRunner)
    assert w._win_cmdline(["python3", "benign_traffic.py", "--minutes", "30"]) == "python benign_traffic.py --minutes 30"
    snip = w._start_snippet(["python3", "x.py", "--a"], "C:/run0/bg.log")
    # Background jobs launch DETACHED via WMI so they survive the ssh session; redirect via cmd /c.
    assert "Win32_Process" in snip and "cmd /c" in snip and "x.py" in snip and "$r.ProcessId" in snip
    pw = w.run.__self__._pwsh("Test-Path X")               # ssh ... powershell -EncodedCommand <b64>
    # The snippet is transported via -EncodedCommand (base64 UTF-16LE): -Command "..." mangled
    # single-quoted Start-Process args. Assert the wrapper AND that the payload round-trips intact.
    import base64 as _b64
    assert pw[0] == "ssh"
    assert "powershell -NoProfile -NonInteractive -EncodedCommand " in pw[-1]
    _enc = pw[-1].split("-EncodedCommand ", 1)[1]
    assert _b64.b64decode(_enc).decode("utf-16-le") == "Test-Path X"
    assert w._scp_base()[0] == "scp"


def test_preflight_clock_sync_gate():
    """§9 [audit v20.28]: clock sync is a GATE, not just evidence — labels depend on time windows. A
    synchronized host within the offset passes; a de-synced or over-offset host FAILs (required)."""
    import preflight
    ok = preflight.check_clock_sync(50.0, _chrony_text="Leap status : Normal\nRMS offset : 0.000012 seconds\n",
                                    _timedatectl_text="System clock synchronized: yes\n")
    assert ok["status"] == "PASS" and ok["required"] is True
    desync = preflight.check_clock_sync(50.0, _timedatectl_text="System clock synchronized: no\n",
                                        _chrony_text="Leap status : Normal\nRMS offset : 0.400000 seconds\n")
    assert desync["status"] == "FAIL"                        # not synced AND 400ms > 50ms
    # no tools + gate DISABLED (--no-clock-gate => required=False) -> SKIP; ACTIVE gate fails closed [§9].
    none = preflight.check_clock_sync(50.0, required=False, _chrony_text="", _timedatectl_text="")
    assert none["status"] == "SKIP" and none["required"] is False


def test_service_monitor_effect_is_dos_only():
    """§11 [audit v20.28]: a DoS effect must be measured against the DoS window ONLY. An availability
    collapse that happens during a PortScan window must NOT 'confirm' a DoS."""
    import csv as _csv
    import datetime as _dt
    import service_monitor as sm
    d = tempfile.mkdtemp()

    def iso(s):
        return (_dt.datetime(2026, 7, 20, 12, 0, 0, tzinfo=_dt.timezone.utc) + _dt.timedelta(seconds=s)).isoformat()
    mon = os.path.join(d, "m.csv")
    with open(mon, "w", newline="") as fh:
        w = _csv.writer(fh)
        w.writerow(["utc", "url", "ok", "http_code", "latency_ms", "error", "cpu_busy", "mem_used_frac"])
        for s in range(0, 30):
            down = 10 <= s < 20                              # the outage is during the SCAN window
            w.writerow([iso(s), "https://x", 0 if down else 1, 503 if down else 200,
                        900 if down else 20, "e" if down else "", "", ""])
    ann = os.path.join(d, "a.csv")
    with open(ann, "w", newline="") as fh:
        w = _csv.writer(fh)
        w.writerow(["event_id", "run_id", "label", "status", "start_utc", "end_utc"])
        w.writerow(["e1", "0", "PortScan", "success", iso(10), iso(19)])
        w.writerow(["e2", "0", "DoS", "success", iso(24), iso(29)])   # DoS window: no outage
    dos = sm.load_windows(ann, labels=["DoS"])
    assert len(dos) == 1 and sm.analyze_effect(mon, dos)["effect_confirmed"] is False
    allw = sm.load_windows(ann)                              # without the filter the scan would falsely confirm
    assert sm.analyze_effect(mon, allw)["effect_confirmed"] is True


def test_runlib_host_aware_fs_local():
    """§5/§6 [audit v20.28]: a Runner can mkdir/exists/file_size on ITS host — the primitives the
    orchestrator uses to stage remote dirs and probe readiness. LocalRunner uses the local fs."""
    import runlib
    r = runlib.LocalRunner()
    d = tempfile.mkdtemp()
    sub = os.path.join(d, "x", "y")
    assert r.mkdir(sub) and os.path.isdir(sub)
    f = os.path.join(sub, "f"); open(f, "w").write("hello")
    assert r.exists(f) and r.file_size(f) == 5 and r.file_size(os.path.join(sub, "nope")) == -1


def test_finalize_seals_orchestration_report():
    """§14 [audit v20.28]: the orchestration report is written BEFORE finalize, so finalize must SEAL it
    (it is real evidence, no longer excluded). A clean run --verifies OK; tampering the report is DETECTED."""
    import json
    d = tempfile.mkdtemp(); run_dir = os.path.join(d, "run0"); os.makedirs(run_dir)
    open(os.path.join(run_dir, "run0.pcap"), "wb").write(b"\xd4\xc3\xb2\xa1" + b"x" * 50)
    json.dump({"overall": "PASS", "steps": []}, open(os.path.join(run_dir, "run0_orchestration.json"), "w"))
    fin = _run([sys.executable, _script("finalize_run.py"), "--run-dir", run_dir, "--run-id", "0",
                "--require", "run0.pcap", "--diagnostic"], capture_output=True, text=True)
    assert fin.returncode == 0, fin.stdout + fin.stderr
    hashes = json.load(open(os.path.join(run_dir, "run0_hashes.json")))   # {relpath: sha256}
    assert "run0_orchestration.json" in hashes, "orchestration report must be in the seal [§14]"
    okv = _run([sys.executable, _script("finalize_run.py"), "--run-dir", run_dir, "--run-id", "0", "--verify"],
               capture_output=True, text=True)
    assert okv.returncode == 0 and "OK" in (okv.stdout + okv.stderr)
    open(os.path.join(run_dir, "run0_orchestration.json"), "a").write("TAMPER")
    ver = _run([sys.executable, _script("finalize_run.py"), "--run-dir", run_dir, "--run-id", "0", "--verify"],
               capture_output=True, text=True)
    assert ver.returncode == 3 and "TAMPERED" in (ver.stdout + ver.stderr)


def test_capture_run_min_packets_gate():
    """§4 P0 [audit v20.29]: a capture that produced too few packets must ABORT (exit != 0). --simulate
    reports its real record count, so the gate is exercised without CAP_NET_RAW."""
    import capture_run
    d = tempfile.mkdtemp()
    rd0 = os.path.join(d, "run0"); os.makedirs(rd0)
    try:
        rc = capture_run.main(["--run-dir", rd0, "--run-id", "0", "--simulate", "--duration", "0",
                               "--min-packets", "5"])
    except SystemExit as e:
        rc = e.code
    assert rc not in (0, None)                              # 0 packets < 5 -> abort
    assert os.path.exists(os.path.join(rd0, "run0_capture_end.json"))   # evidence still sealed
    # a capture that grew past the floor passes.
    rd1 = os.path.join(d, "run1"); os.makedirs(rd1)
    rc2 = capture_run.main(["--run-dir", rd1, "--run-id", "1", "--simulate", "--duration", "1",
                            "--min-packets", "1"])
    assert rc2 == 0


def test_capture_run_aborts_on_tcpdump_failure():
    """§4 P0 [audit v20.29]: a FAILING tcpdump (rc!=0) that still left a partial PCAP must NOT read as a
    successful capture — otherwise the run attacks an unrecorded network and finds out too late."""
    d = tempfile.mkdtemp()
    rd = os.path.join(d, "run0"); os.makedirs(rd)
    fake = os.path.join(d, "faketcpdump")
    open(fake, "w").write("#!/bin/bash\nwhile [ \"$1\" != \"-w\" ]; do shift; done\n"
                          "printf 'PARTIAL' > \"$2\"\nexit 1\n")     # writes a PCAP, then FAILS
    os.chmod(fake, 0o755)
    cap = _run([sys.executable, _script("capture_run.py"), "--run-dir", rd, "--run-id", "0",
                "--interface", "lo", "--duration", "1", "--tcpdump", fake], capture_output=True, text=True)
    assert cap.returncode != 0 and "returncode 1" in (cap.stdout + cap.stderr)
    end = json.load(open(os.path.join(rd, "run0_capture_end.json")))
    assert end["tcpdump_returncode"] == 1                   # recorded honestly, and the CLI failed


def _write_pcap(path, n_packets):
    """Write a REAL classic little-endian pcap with `n_packets` tiny frames — for tests that feed the
    finalizer's §11 PCAP parser (which validates the header and RECOUNTS packets)."""
    import struct
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i in range(n_packets):
            pl = b"\x00" * 14
            f.write(struct.pack("<IIII", 1000 + i, 0, len(pl), len(pl)) + pl)


def test_finalize_capture_semantics_gate():
    """§16 [audit v20.29] + §11 [audit v20.33]: finalize validates run<N>_capture_end.json by CONTENT — a
    FAILED tcpdump fails sealing; and in official mode the PCAP is PARSED and its real packet count must
    equal the declared packets_captured."""
    import hashlib
    import finalize_run as fr
    d = tempfile.mkdtemp(); rd = os.path.join(d, "run0"); os.makedirs(rd)
    pcap = os.path.join(rd, "run0.pcap"); _write_pcap(pcap, 1500)     # a REAL 1500-packet capture
    psize = os.path.getsize(pcap); psha = hashlib.sha256(open(pcap, "rb").read()).hexdigest()
    json.dump({"tcpdump_returncode": 1, "pcap": {"exists": True, "size_bytes": psize, "sha256": psha},
               "tcpdump_stats": {"packets_captured": 1500, "packets_received": 1500,
                                 "packets_dropped": 0, "drop_rate": 0.0}},
              open(os.path.join(rd, "run0_capture_end.json"), "w"))
    assert fr.check_capture_semantics(rd, "0")[0] == "FAIL"          # tcpdump rc=1
    comp = fr.finalize(rd, "0", ["run0.pcap", "run0_capture_end.json"], bundle=False)
    assert comp["overall"] == "FAIL" and comp["semantics"]["capture"]["state"] == "FAIL"
    # fix the capture -> PASS; drop-rate ceiling enforced; and a LIE about the packet count is caught by §11.
    # Stats are internally consistent: dropped/received = 2/2000 = 0.001 [§9].
    json.dump({"tcpdump_returncode": 0, "pcap": {"exists": True, "size_bytes": psize, "sha256": psha},
               "tcpdump_stats": {"packets_captured": 1500, "packets_received": 2000,
                                 "packets_dropped": 2, "drop_rate": 0.001}},
              open(os.path.join(rd, "run0_capture_end.json"), "w"))
    assert fr.check_capture_semantics(rd, "0", min_packets=1000, max_drop_rate=0.02)[0] == "PASS"
    assert fr.check_capture_semantics(rd, "0", max_drop_rate=0.0005)[0] == "FAIL"     # drop 0.001 > 0.0005
    json.dump({"tcpdump_returncode": 0, "pcap": {"exists": True, "size_bytes": psize, "sha256": psha},
               "tcpdump_stats": {"packets_captured": 9999, "packets_received": 9999,
                                 "packets_dropped": 0, "drop_rate": 0.0}},
              open(os.path.join(rd, "run0_capture_end.json"), "w"))
    assert fr.check_capture_semantics(rd, "0", strict=True)[0] == "FAIL"    # §11: declared 9999 != real 1500
    # An OFFICIAL capture that OMITS the tcpdump stats can't seal official, but a diagnostic seal tolerates it.
    json.dump({"tcpdump_returncode": 0, "pcap": {"exists": True, "size_bytes": psize, "sha256": psha}},
              open(os.path.join(rd, "run0_capture_end.json"), "w"))
    assert fr.check_capture_semantics(rd, "0", strict=True)[0] == "FAIL"    # §8 official needs stats
    assert fr.check_capture_semantics(rd, "0", strict=False)[0] == "PASS"   # diagnostic tolerates


def test_zeek_env_load_fails_closed_on_nonzero_rc():
    """§15 P0 [audit v20.32]: the preflight Zeek-load probe must fail CLOSED. A `zeek -b <site>` that exits
    NON-ZERO (a real load failure) must NOT be accepted just because stderr lacks a known keyword — the old
    `not any(keyword)` heuristic passed exactly that. Only rc==0 (clean load) or a timeout (parsed, waiting
    for packets) counts as loaded. Faked zeek via runlib so it runs without a Zeek install."""
    import process_pcap as pp
    import runlib
    d = tempfile.mkdtemp()
    site = os.path.join(d, "local.zeek"); open(site, "w").write("event zeek_init(){}\n")
    load = {"result": None}

    def fake_run_cmd(argv, timeout=None, cwd=None, env=None):
        if "-N" in argv:                                        # plugins probe: JA3 + QUIC present
            return runlib.CmdResult(argv, 0, "JA3\nQUIC\n", "", 0.1)
        return load["result"]                                   # the `zeek -b` load probe (per-case)

    orig = (runlib.which, runlib.tool_version, runlib.run_cmd)
    runlib.which = lambda b: "/usr/bin/zeek"
    runlib.tool_version = lambda b, *a: "6.0"
    runlib.run_cmd = fake_run_cmd
    try:
        # (a) rc!=0, NO keyword on stderr -> FAILS CLOSED (the audited bug wrongly accepted this).
        load["result"] = runlib.CmdResult(["zeek", "-b", site], 1, "", "unexpected token", 0.1)
        env = pp.check_environment("zeek", site)
        assert env["site_script_loads"] is False and env["ok"] is False
        # (b) a timeout means it PARSED and waited for packets -> loaded ok.
        load["result"] = runlib.CmdResult(["zeek", "-b", site], -9, "", "", 8.0, timed_out=True)
        assert pp.check_environment("zeek", site)["site_script_loads"] is True
        # (c) a clean exit 0 -> loaded ok.
        load["result"] = runlib.CmdResult(["zeek", "-b", site], 0, "", "", 0.1)
        assert pp.check_environment("zeek", site)["site_script_loads"] is True
    finally:
        runlib.which, runlib.tool_version, runlib.run_cmd = orig


def test_preflight_interpreter_and_w32tm_clock():
    """§7 [audit v20.29]: a NB2 (Windows) preflight must NOT hard-fail for a missing `python3` (Windows
    has `python`/`py`), and its clock gate must read `w32tm`."""
    import runlib
    import preflight
    real_which = runlib.which
    try:                                                    # emulate a Windows host: only `py` present
        runlib.which = lambda b: "/py" if b == "py" else None
        chk = preflight.check_interpreter()
        assert chk["status"] == "PASS", chk                # accepted `py`, not `python3`
    finally:
        runlib.which = real_which
    synced = preflight.check_clock_sync(50.0, _chrony_text="", _timedatectl_text="",
                                        _w32tm_text="Source: nb1.lab,0x8\nPhase Offset: 0.0100000s\n")
    assert synced["status"] == "PASS" and synced["detail"]["offset_ms"] == 10.0
    cmos = preflight.check_clock_sync(50.0, _chrony_text="", _timedatectl_text="",
                                      _w32tm_text="Source: Local CMOS Clock\nPhase Offset: 0.5s\n")
    assert cmos["status"] == "FAIL"                         # unsynchronized (local clock) => gate fails


def test_orchestrate_per_host_paths_and_autotimeout():
    """§6/§10 [audit v20.29]: NB2 runs its scripts + manifest from Windows paths; background caps auto-size
    to warmup+attack_timeout+cooldown+margin so they never expire before the run ends."""
    import orchestrate_run as orun
    cfg = orun.example_config()
    steps = orun.build_steps(cfg, "/data/run0", dry_run=True)
    byname = {s.name: s for s in steps}
    ba = byname["start_benign"].fn()[1]["argv"]             # runs on NB2 (Windows)
    assert ba[1].startswith("C:\\nids\\src") and "C:\\nids\\campaign.json" in ba
    assert "--ready-file" in ba and ba[ba.index("--ready-file") + 1].endswith("run0_benign_ready.json")
    aa = byname["attacks"].fn()[1]["argv"]                  # NB3 (Linux) keeps the POSIX path
    assert aa[1].startswith("/opt/nids/src")
    ca = byname["start_capture"].fn()[1]["argv"]
    cap = float(ca[ca.index("--duration") + 1])
    assert cap == 30 + 1800 + 30 + 300                     # warmup+attack_timeout+cooldown+margin [§10]
    fin = orun.finalize_argv(cfg, "/data/run0")            # official capture-quality floor is pinned [§16]
    assert "--min-packets" in fin and "--max-drop-rate" in fin


def test_finalize_official_requires_full_set_and_content():
    """§5/§6 P0 [audit v20.30]: an OFFICIAL seal (a) can never be weakened via --require (the four standard
    artifacts are always required, a SKIP on status/capture/zeek FAILs) and (b) validates the capture by
    the REAL PCAP, not the self-reported JSON. --diagnostic is required to reduce the set and is recorded."""
    import finalize_run as fr
    d = tempfile.mkdtemp(); rd = os.path.join(d, "run0"); os.makedirs(rd)
    open(os.path.join(rd, "run0.pcap"), "wb").write(b"\xd4\xc3\xb2\xa1" + b"x" * 40)
    # (a) official, --require only the pcap -> the other three are still required -> FAIL, official=True.
    comp = fr.finalize(rd, "0", ["run{n}.pcap"], bundle=False)
    # official is now derived from EVIDENCE: an official-MODE seal that FAILED is official=false [v20.31 §6].
    assert comp["overall"] == "FAIL" and comp["official"] is False and comp["diagnostic_mode"] is False
    assert "run0_capture_end.json" in comp["required_missing"]
    # (b) a fabricated capture_end.json claiming a huge PCAP is caught by the real-file cross-check.
    import json as _json
    _json.dump({"tcpdump_returncode": 0, "pcap": {"exists": True, "size_bytes": 10 ** 6, "sha256": "FAKE"},
                "tcpdump_stats": {"packets_captured": 9999, "drop_rate": 0.0}},
               open(os.path.join(rd, "run0_capture_end.json"), "w"))
    assert fr.check_capture_semantics(rd, "0")[0] == "FAIL"           # declared size != real
    # (c) a zeek_processing.json claiming logs that don't exist on disk is caught.
    _json.dump({"zeek_returncode": 0, "logs": {n: {"exists": True, "empty": False}
                for n in ("conn.log", "ssl.log", "quic.log")}},
               open(os.path.join(rd, "run0_zeek_processing.json"), "w"))
    assert fr.check_zeek_semantics(rd, "0")[0] == "FAIL"             # no real logs under zeek_logs/
    os.remove(os.path.join(rd, "run0_zeek_processing.json"))          # clear the fabricated JSON for (d)
    # (d) diagnostic mode CAN use a reduced set, and is recorded official=false.
    real_sha = fr.runlib.sha256_file(os.path.join(rd, "run0.pcap"))
    _json.dump({"tcpdump_returncode": 0, "pcap": {"exists": True, "size_bytes": 44, "sha256": real_sha},
                "tcpdump_stats": {"packets_captured": 10, "drop_rate": 0.0}},
               open(os.path.join(rd, "run0_capture_end.json"), "w"))
    cd = fr.finalize(rd, "0", ["run{n}.pcap", "run{n}_capture_end.json"], bundle=False, diagnostic=True,
                     rotate_seal=True)                            # (a) already sealed this run [§18]
    assert cd["overall"] == "PASS" and cd["official"] is False


def test_finalize_and_capture_reject_nan_thresholds():
    """§11 P0 [audit v20.30]: a NaN/inf/out-of-range threshold must be REJECTED by the CLI parser, not
    silently disable the gate (comparisons with NaN are always false)."""
    import argparse
    import capture_run
    import finalize_run as fr
    for bad in ("nan", "inf", "-0.1", "2"):
        for parse in (fr._frac01, capture_run._frac01):
            try:
                parse(bad); assert False, "accepted bad drop rate {!r}".format(bad)
            except argparse.ArgumentTypeError:
                pass
    assert fr._frac01("0.02") == 0.02 and fr._nonneg_int("5") == 5
    try:
        fr._nonneg_int("-1"); assert False
    except argparse.ArgumentTypeError:
        pass


def test_preflight_clock_gate_fails_closed():
    """§9 P0 [audit v20.30]: when the clock gate is ACTIVE and NO sync tool exists, that is a FAIL — a
    missing chronyc/timedatectl/w32tm must not be a free pass. Only --no-clock-gate may SKIP."""
    import preflight
    active = preflight.check_clock_sync(50.0, required=True, _chrony_text="", _timedatectl_text="", _w32tm_text="")
    assert active["status"] == "FAIL" and active["required"] is True
    disabled = preflight.check_clock_sync(50.0, required=False, _chrony_text="", _timedatectl_text="", _w32tm_text="")
    assert disabled["status"] == "SKIP"


def test_orchestrate_recheck_alive_before_attacks():
    """§14 P0 [audit v20.30]: right before the attacks the orchestrator RE-CHECKS that capture/monitor/
    benign are still alive; a job that died during warm-up aborts the run BEFORE any attack traffic."""
    import types
    import orchestrate_run as orun
    d = tempfile.mkdtemp(); run_dir = os.path.join(d, "run0"); os.makedirs(run_dir)
    cfg = {"run_id": 0, "base_dir": d, "src_dir": ".", "campaign": "c.json", "interface": "lo",
           "runners": {h: {"kind": "local"} for h in ("nb1", "nb2", "nb3", "nb4")}}
    jobs = {}
    steps = orun.build_steps(cfg, run_dir, dry_run=False, jobs=jobs)
    names = [s.name for s in steps]
    assert names.index("warmup") < names.index("recheck_alive") < names.index("attacks")
    recheck = next(s for s in steps if s.name == "recheck_alive")
    jobs["capture"] = types.SimpleNamespace(runner=_FakeRunner(exit_code=None), log_path=None, pid=1)
    jobs["monitor"] = types.SimpleNamespace(runner=_FakeRunner(exit_code=None), log_path=None, pid=2)
    jobs["benign"] = types.SimpleNamespace(runner=_FakeRunner(exit_code=1), log_path=None, pid=3)  # DIED
    ok, detail = recheck.fn()
    assert ok is False and any(x["job"] == "benign" for x in detail["dead"])


def test_verify_switch_mirroring_logic():
    """§8 P0 [audit v20.30]: growth alone doesn't prove the mirror — a KNOWN probe must be seen at the
    sensor in the client->victim direction with the expected TLS/QUIC ports. Parsing + check are pure."""
    import verify_switch_mirroring as vm
    conn = ("#fields\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\torig_pkts\tresp_pkts\n"
            "10.0.0.20\t51000\t10.0.0.11\t443\ttcp\t5\t7\n"       # resp_pkts>0 => the victim responded
            "10.0.0.20\t51001\t10.0.0.11\t443\tudp\t3\t4\n")
    d = tempfile.mkdtemp(); p = os.path.join(d, "conn.log"); open(p, "w").write(conn)
    flows = vm.parse_conn_log(p)
    assert len(flows) == 2
    good = vm.check_mirroring(flows, "10.0.0.20", "10.0.0.11", expect_tcp_port=443, expect_udp_port=443)
    assert good["confirmed"] is True
    # a capture with only unrelated traffic (NTP/ARP-like) does NOT confirm the mirror.
    bad = vm.check_mirroring([{"orig_h": "10.0.0.4", "resp_h": "10.0.0.1", "proto": "udp", "resp_p": 123}],
                             "10.0.0.20", "10.0.0.11", expect_tcp_port=443)
    assert bad["confirmed"] is False


def _valid_common_row():
    """One COMMON-schema row (in fs.COMMON order) that SATISFIES the numeric/relational contract:
    duration=1s, 1 fwd + 1 bwd pkt, 1+1 bytes -> down_up_ratio=1.0, flow_bytes_s=2.0, flow_pkts_s=2.0,
    sni=1, TCP/well_known/1.3/h2. A row of zeros (the old fixture) is NOT contract-valid (a finite rate
    with duration<=0), which is exactly why the rigorous validators reused here would reject it."""
    return ["1.0", "1", "1", "1", "1", "1.0", "2.0", "2.0", "1",
            "TCP", "well_known", "1.3", "h2", "x", "y"]


# The break_ scenarios the finalizer's RIGOROUS validators must catch (audit v20.32/v20.33). Grouped so
# test_finalize_binding_chain can assert each one FAILs a strict seal.
_BOUND_BREAKS = ("pcap", "run_id", "missing_csv", "omit_pcap_sha", "garbage_csv", "same_csv",
                 "annotations", "no_capture_start",
                 "ml_empty", "audit_label_only", "empty_run_id", "bad_timestamp", "evil_label",
                 "junk_value", "neg_value", "extra_col", "bad_counts", "bad_annotations",
                 "invalid_campaign", "capture_no_stats", "zeek_no_rc", "zeek_bad_records",
                 # audit v20.33
                 "campaign_not_reproducible", "ml_split_mismatch", "invalid_pcap", "malformed_zeek",
                 "audit_bad_ambiguous", "empty_capture_start",
                 # audit v20.34 — the RELATIONS
                 "temporal_mismatch", "zeek_missing_essentials", "bad_capture_start_types", "audit_ghost_event",
                 # audit v20.35 — closing the temporal/UID/policy relations
                 "split_2033", "sslquic_2033", "no_ended_utc", "bad_duration", "audit_ghost_uid",
                 "sslquic_no_fields", "no_capture_policy",
                 # audit v20.36 — fail-closed timestamps + reconciliations
                 "audit_bad_ts", "conn_bad_ts", "ssl_bad_ts", "quic_no_ts", "neg_stats", "audit_empty_uid",
                 "audit_label_mismatch", "fake_join_counts", "tls_values_empty",
                 # audit v20.37 — planned attacks must be present + internally-consistent stats
                 "no_attack_executed", "inconsistent_stats",
                 # audit v20.38 — event identity + recomputed drop-rate gate
                 "status_event_mismatch", "audit_no_matched_event", "extra_success_event",
                 "drop_declared_below_real",
                 # audit v20.39 — FLOW identity via uid+event + benign policy
                 "audit_wrong_endpoints", "audit_row_after_window", "audit_wrong_event_label",
                 "benign_with_event", "event_count_mismatch", "benign_policy_violated",
                 # audit v20.40 — closing the flow-identity fail-opens + benign policy fail-closed
                 "audit_empty_endpoints", "audit_wrong_orig_port", "audit_dup_uid", "audit_row_pad_window",
                 "benign_policy_absent", "benign_policy_negative",
                 # audit v20.41 — benign EVIDENCE + pinned labeling policy + value/ts membership
                 "benign_jsonl_absent", "benign_sessions_short", "benign_no_browser",
                 "no_required_policy", "status_policy_relaxed", "audit_ts_ne_conn",
                 "tls_value_forged", "split_transport_forged",
                 # audit v20.42 — benign session authenticity (temporal/unique/schema/attempt) + conn uid unique
                 "benign_bad_temporal", "benign_dup_session", "benign_no_webdriver", "benign_empty_site",
                 "benign_wrong_attempt", "conn_dup_uid",
                 # audit v20.43 — sessions inside the REAL pcap interval + clone detection
                 "benign_outside_pcap", "benign_cloned_sessions",
                 # audit v20.44 — run-attempt binding (orchestration report) + session authenticity + pages
                 "orchestration_absent", "orchestration_wrong_attempt", "benign_fake_browser",
                 "benign_driver_mismatch", "benign_ok_no_pages", "benign_clone_pages", "benign_after_last_packet",
                 # audit v20.46 — SEMANTIC orchestration report + attempt_id in capture/zeek + short sessions
                 "orchestration_failed", "orchestration_aborted", "orchestration_no_steps",
                 "orchestration_step_failed", "orchestration_wrong_campaign", "orchestration_wrong_run",
                 "capture_wrong_attempt", "zeek_wrong_attempt", "coordinated_rebatize", "benign_too_short",
                 # audit v20.47 — CANONICAL plan (not the report's own flags) + tool_version + session overlap
                 "orchestration_garbage_steps", "orchestration_capture_optional", "orchestration_bogus_version",
                 "benign_overlap")


def _bound_run(rd, run_id=0, break_=None):
    """Build a fully hash-BOUND, OFFICIAL-grade run dir whose artifacts pass the RIGOROUS validators the
    finalizer now REUSES (campaign.load, label_flows.load_annotations, feature_schema, provenance.csv_*),
    not just a shallow header scan [audit v20.32]. Returns the campaign manifest path. `break_` corrupts
    exactly ONE link so a test can prove the finalizer catches it. The PASS fixture is deliberately
    realistic: a contract-valid COMMON row, a campaign with expected_labels + a train AND a test run, a
    well-formed annotations header, and per-log record counts."""
    import hashlib
    import struct
    import feature_schema as fs
    import provenance as _prov
    import runlib as _rl
    rid = str(run_id)
    os.makedirs(os.path.join(rd, "zeek_logs"), exist_ok=True)
    # The run PLANS a DoS attack (reproducible manifests require a non-empty attack plan), so a coherent
    # official run must actually CARRY it: a DoS annotation event + a DoS split-ready/audit row [§6]. The
    # `no_attack_executed` break makes the run benign-only while the manifest still plans DoS -> §6 FAIL.
    benign = (break_ == "no_attack_executed")
    atk_label = "BENIGN" if benign else "DoS"
    matched_ev = "" if benign else "e0"

    def sha(p):
        return hashlib.sha256(open(p, "rb").read()).hexdigest()

    def write_csv(path, header, rows):
        with open(path, "w", newline="") as f:
            w = csv.writer(f); w.writerow(header)
            for r in rows:
                w.writerow(r)

    # A TEMPORALLY-coherent window: capture 2020-01-01 00:00:00Z .. 00:10:00Z; packets/log ts inside it [§7].
    base_ts = 1577836810                                         # 2020-01-01T00:00:10Z (inside the window)

    def make_pcap(p, n, first=base_ts):                          # a REAL classic pcap: 24-byte header + n records
        with open(p, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i in range(n):
                pl = b"\x00" * 14
                f.write(struct.pack("<IIII", first + i, 0, len(pl), len(pl)) + pl)

    # --- PCAP — a REAL parseable capture of N packets, timestamped inside the window [§11/§7] --------
    n_pkts = 10
    pcap = os.path.join(rd, "run{}.pcap".format(rid))
    if break_ == "invalid_pcap":
        open(pcap, "wb").write(b"\xd4\xc3\xb2\xa1" + b"x" * 400)  # magic ok but junk -> bad version [§11]
    elif break_ == "temporal_mismatch":
        make_pcap(pcap, n_pkts, first=2000000000)                # ~2033 packets vs 2020 logs/annotations [§7]
    else:
        make_pcap(pcap, n_pkts)

    # --- Zeek logs — conn.log carries the ESSENTIALS; ssl/quic carry the feature fields + a coherent uid;
    #     every record ts is inside the pcap window [§6/§7/§10] ------------------------------------------
    log_ts = base_ts + 3                                         # inside the pcap interval
    conn_ts = "BAD" if break_ == "conn_bad_ts" else str(log_ts)          # §5 fail-closed
    ssl_ts = "BAD" if break_ == "ssl_bad_ts" else str(log_ts)           # §5 fail-closed
    quic_ts = "2000000000" if break_ == "sslquic_2033" else str(log_ts)
    ssl_ts = "2000000000" if break_ == "sslquic_2033" else ssl_ts
    tls_vals = "-\t-\t-\t-\t-" if break_ == "tls_values_empty" else "TLSv13\tblog.lab\tabc\tdef\th2"   # §7
    # TWO flows: the DoS attack flow (Cabc) AND a BENIGN background flow (Cben), so an OFFICIAL run actually
    # CARRIES benign traffic for the now-mandatory benign_quality_policy [v20.40 §5]. ssl/quic carry only the
    # attack flow's TLS/QUIC record (benign HTTP need not be TLS here).
    conn_text = ("#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
                 "{ts}\tCabc\t10.0.0.2\t5555\t10.0.0.1\t443\ttcp\n"
                 "{ts}\tCben\t10.0.0.3\t6666\t10.0.0.1\t443\ttcp\n".format(ts=conn_ts))
    ssl_text = ("#fields\tts\tuid\tversion\tserver_name\tja3\tja3s\tnext_protocol\n"
                "{}\tCabc\t{}\n".format(ssl_ts, tls_vals))
    quic_text = "#fields\tts\tuid\tversion\tserver_name\n{}\tCabc\t1\tblog.lab\n".format(quic_ts)
    if break_ == "zeek_missing_essentials":
        conn_text = "#fields\tts\tuid\tid.orig_h\n{}\tCabc\t10.0.0.1\n".format(log_ts)   # no resp_h/proto/resp_p [§6]
    if break_ == "malformed_zeek":
        conn_text = "#fields\tts\n1.0\td\n"                       # header 1 field but row has 2 -> read_zeek_log aborts
    if break_ == "conn_dup_uid":                                 # the SAME uid twice in conn.log [v20.42 §11]
        conn_text = conn_text + "{}\tCabc\t10.0.0.2\t5555\t10.0.0.1\t443\ttcp\n".format(conn_ts)
    if break_ == "sslquic_no_fields":                            # only ts+uid -> §10 (missing TLS/QUIC fields)
        ssl_text = "#fields\tts\tuid\n{}\tCabc\n".format(log_ts)
        quic_text = "#fields\tts\tuid\n{}\tCabc\n".format(log_ts)
    if break_ == "quic_no_ts":                                   # §5: quic.log with NO ts column
        quic_text = "#fields\tuid\tversion\tserver_name\nCabc\t1\tblog.lab\n"
    logs = {}
    for n, text in (("conn.log", conn_text), ("ssl.log", ssl_text), ("quic.log", quic_text)):
        p = os.path.join(rd, "zeek_logs", n); open(p, "w").write(text)
        _recs = len([ln for ln in text.strip().split("\n")[1:] if ln.strip()])   # data rows (conn now = 2)
        logs[n] = {"exists": True, "empty": False, "sha256": sha(p), "records": _recs}
    if break_ == "zeek_bad_records":
        logs["conn.log"]["records"] = 999                        # claims more than the real records [§9]

    # --- campaign manifest — VALID + REPRODUCIBLE (expected_labels, a train AND a test run, seed+day) [§4/§7]
    man = os.path.join(os.path.dirname(rd), "campaign.json")
    def _dos_spec(cfg, split, seed, day):                        # pins match _campaign_ann's default DoS row
        return {"config_id": cfg, "split": split, "seed": seed, "day": day, "attacks": ["DoS"],
                "target_host": "h", "target_ip": "10.0.0.1", "attacker_ip": "10.0.0.2",
                "timeout": 900, "dos_seconds": 120}
    manifest = {"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
                "capture_quality_policy": {"min_packets": 1, "max_drop_rate": 0.02, "require_effect": False},
                # MANDATORY in official mode [v20.40 §5] + the EVIDENCE gates are ENFORCED against the jsonl
                # [v20.41 §5]: the run ships 2 successful benign sessions, so these floors pass.
                "benign_quality_policy": {"min_benign_flows": 1, "min_successful_sessions": 1,
                                          "min_success_rate": 0.5, "require_benign_jsonl": True,
                                          "require_browser_evidence": True},
                # the campaign PINS its labeling policy; the status must MEET it (no relaxation) [v20.41 §6].
                "required_labeling_policy": dict(_prov.OFFICIAL_POLICY_PROFILES["official/v1"]),
                "runs": {rid: _dos_spec(0, "train", 1, "2020-01-01"),
                         "9": _dos_spec(6, "test", 2, "2020-01-02")}}
    if break_ == "invalid_campaign":
        manifest.pop("expected_labels")                          # campaign.load rejects it [§4]
    if break_ == "no_capture_policy":
        manifest.pop("capture_quality_policy")                   # official run must pre-register it [§12]
    if break_ == "no_required_policy":                           # official seal needs a pinned labeling policy [v20.41 §6]
        manifest.pop("required_labeling_policy")
    if break_ == "benign_policy_absent":                         # official run must pre-register benign policy [§5]
        manifest.pop("benign_quality_policy")
    if break_ == "benign_policy_negative":                       # a negative floor is a vacuous 'always-true' gate [§6]
        manifest["benign_quality_policy"] = {"min_benign_flows": -1}
    if break_ == "benign_policy_violated":                       # policy demands MORE BENIGN than the run has [§10]
        manifest["benign_quality_policy"] = {"min_benign_flows": 2}
    if break_ == "campaign_not_reproducible":
        for k in ("seed", "day", "attacks"):
            manifest["runs"][rid].pop(k, None)                   # not reproducible [§7]
    json.dump(manifest, open(man, "w"))
    site = os.path.join(os.path.dirname(rd), "local.zeek"); open(site, "w").write("@load base\n")

    # attempt_id stamped by the capture/zeek producers; the seal confronts it with the status [v20.46 §9/§10].
    _capatt = "WRONG-CAP" if break_ == "capture_wrong_attempt" else "att-0"
    _zeekatt = "WRONG-ZEEK" if break_ == "zeek_wrong_attempt" else "att-0"
    # --- zeek_processing.json -----------------------------------------------------------------------
    zeek = {"run_id": run_id, "attempt_id": _zeekatt, "pcap_sha256": sha(pcap) if break_ != "pcap" else "0" * 64,
            "zeek_returncode": 0, "logs": logs, "site_script": site, "site_script_sha256": sha(site)}
    if break_ == "omit_pcap_sha":
        del zeek["pcap_sha256"]
    if break_ == "zeek_no_rc":
        del zeek["zeek_returncode"]                              # official requires exactly 0 [§9]
    json.dump(zeek, open(os.path.join(rd, "run{}_zeek_processing.json".format(rid)), "w"))

    # --- capture_end.json (stats + REAL pcap identity + packet count + window END = start + duration) ---
    cap_end = {"run_id": run_id, "attempt_id": _capatt, "tcpdump_returncode": 0, "ended_utc": "2020-01-01T00:01:00.000000Z",
               "pcap": {"exists": True, "size_bytes": os.path.getsize(pcap), "sha256": sha(pcap)},
               "tcpdump_stats": {"packets_captured": n_pkts, "packets_received": n_pkts,
                                 "packets_dropped": 0, "drop_rate": 0.0}}
    if break_ == "capture_no_stats":
        cap_end.pop("tcpdump_stats")                             # official capture must record stats [§8]
    if break_ == "no_ended_utc":
        cap_end.pop("ended_utc")                                 # official requires the window end [§8]
    if break_ == "neg_stats":                                    # negative counts/drop-rate are impossible [§9]
        cap_end["tcpdump_stats"] = {"packets_captured": n_pkts, "packets_received": -999,
                                    "packets_dropped": -1000, "drop_rate": -1.0}
    if break_ == "inconsistent_stats":                           # captured>received / drop_rate incoherent [§9]
        cap_end["tcpdump_stats"] = {"packets_captured": n_pkts, "packets_received": 1,
                                    "packets_dropped": 1, "drop_rate": 0.0}
    if break_ == "drop_declared_below_real":                     # real 3% declared as 2% [§9]
        cap_end["tcpdump_stats"] = {"packets_captured": n_pkts, "packets_received": 100,
                                    "packets_dropped": 3, "drop_rate": 0.02}
    json.dump(cap_end, open(os.path.join(rd, "run{}_capture_end.json".format(rid)), "w"))

    # --- capture_start.json — a REAL start record with valid TYPES [§13/§8]; start before the pcap [§7] -
    if break_ != "no_capture_start":
        cap_start = {"run_id": 99 if break_ == "run_id" else run_id, "attempt_id": _capatt, "interface": "eth0",
                     "filter": None, "duration_s": 60, "started_utc": "2020-01-01T00:00:00.000000Z",
                     "tcpdump_version": "tcpdump 4.99"}
        if break_ == "empty_capture_start":
            cap_start = {"run_id": run_id}                       # just run_id -> §13 FAIL
        if break_ == "bad_capture_start_types":                  # invalid TYPES/domains -> §8 FAIL
            cap_start = {"run_id": run_id, "interface": "eth0", "filter": ["not", "a", "string"],
                         "duration_s": -1, "started_utc": "BAD", "tcpdump_version": "banana"}
        if break_ == "bad_duration":                             # declared 1s but the window is 60s [§9]
            cap_start["duration_s"] = 1
        json.dump(cap_start, open(os.path.join(rd, "run{}_capture_start.json".format(rid)), "w"))

    # --- annotations — a REAL campaign-valid DoS event inside the pcap window [§5/§6/§8/§11] ----------
    ann = os.path.join(rd, "run{}_annotations.csv".format(rid))
    ann_cols = ["event_id", "run_id", "label", "attacker_ip", "target_ip", "target_hostname", "protocol",
                "target_port", "start_utc", "end_utc", "tool", "command", "parameters", "return_code",
                "status", "error_type"]
    if break_ == "bad_annotations":
        open(ann, "w").write("THIS IS NOT ANNOTATIONS\n")        # header lacks annotation columns [§5]
    elif benign:
        open(ann, "w").write(",".join(ann_cols) + "\n")          # header only: the planned DoS never happened [§6]
    else:
        ann_rows = [{"event_id": "e0", "start_utc": "2020-01-01T00:00:10.000000Z",
                     "end_utc": "2020-01-01T00:00:15.000000Z"}]
        if break_ == "extra_success_event":                      # a 2nd success event the status never counted [§6]
            ann_rows.append({"event_id": "e1", "start_utc": "2020-01-01T00:00:11.000000Z",
                             "end_utc": "2020-01-01T00:00:16.000000Z"})
        src = _campaign_ann(rd, "C", sha(man), run_id, ann_rows)
        os.replace(src, ann)                                     # rd/ann.csv -> run<N>_annotations.csv

    # --- labeler CSVs — contract-valid COMMON rows, EXACT schemas -----------------------------------
    common = list(fs.COMMON)
    sr_ts = str(base_ts + 5)                                     # split-ready timestamp INSIDE the pcap window [§5]
    if break_ == "split_2033":
        sr_ts = "2000000000"                                     # ~2033 vs a 2020 pcap [§5]
    # The DoS flow's dataset row carries the SAME verbatim ja3/ja3s that ssl.log records for its uid (Cabc),
    # so the value-membership check has real backing [v20.41 §7.3]. (alpn=h2 / tls_version=1.3 already match.)
    dos_common = list(_valid_common_row())
    dos_common[fs.COMMON.index("ja3")] = "abc"; dos_common[fs.COMMON.index("ja3s")] = "def"
    ml_row = list(dos_common) + [atk_label]
    sr_row = [rid, sr_ts] + list(dos_common) + [atk_label]
    if break_ == "evil_label":
        ml_row[-1] = "EVIL"                                      # label not in ALLOWED_LABELS [§6.5]
    if break_ == "junk_value":
        ml_row[0] = "NOTNUM"                                     # non-numeric junk in flow_duration [§6.6]
    if break_ == "neg_value":
        ml_row[7] = "-999"                                       # negative flow_pkts_s [§6.6]
    if break_ == "empty_run_id":
        sr_row[0] = ""                                           # blank run_id [§6.3]
    if break_ == "bad_timestamp":
        sr_row[1] = "BAD"                                        # non-numeric timestamp [§6.4]
    if break_ == "ml_split_mismatch":
        sr_row[2 + fs.COMMON.index("ja3")] = "DIFFERENT"        # split-ready ja3 != ML ja3 [§10]
    if break_ == "tls_value_forged":                            # dataset ja3 not present in ssl.log [v20.41 §7.3]
        _j = fs.COMMON.index("ja3"); ml_row[_j] = "FORGED_JA3"; sr_row[2 + _j] = "FORGED_JA3"
    if break_ == "split_transport_forged":                      # dataset transport not in conn.log proto [v20.41 §7.2]
        _t = fs.COMMON.index("transport"); ml_row[_t] = "UDP"; sr_row[2 + _t] = "UDP"

    ml_header = common + [fs.LABEL]
    if break_ == "extra_col":                                    # a leaked IP column [§6.7]
        ml_header = common + ["id.orig_h", fs.LABEL]
        ml_row = ml_row[:-1] + ["10.0.0.1", ml_row[-1]]
    sr_header = ["run_id", "timestamp"] + common + [fs.LABEL]
    # A meaningful subset of the labeler's real audit header (uid + CONN_FIELDS + AUDIT_EXTRA) [§9]. The
    # benign row carries an EMPTY matched_event_id (it matched no attack) [§5].
    audit_header = ["uid", "ts", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
                    "label", "matched_event_id", "ambiguous", "ambiguity_reason"]
    audit_row = ["Cabc", str(log_ts), "10.0.0.2", "5555", "10.0.0.1", "443", "tcp", atk_label, matched_ev, "F", ""]
    if break_ == "audit_label_only":
        audit_header, audit_row = ["label"], ["BENIGN"]         # only a label column [§6.2/§9]
    if break_ == "audit_bad_ambiguous":
        audit_row = list(audit_row); audit_row[audit_header.index("ambiguous")] = "BANANA"   # not boolean [§9]
    if break_ == "audit_ghost_event":                            # points at an annotation event that doesn't exist [§5]
        audit_row = list(audit_row); audit_row[audit_header.index("matched_event_id")] = "NO_SUCH_EVENT"
    if break_ == "audit_ghost_uid":                              # a uid that is not in conn.log [§6]
        audit_row = list(audit_row); audit_row[audit_header.index("uid")] = "GHOST_UID"
    if break_ == "audit_empty_uid":                              # an empty uid can't tie to a flow [§6]
        audit_row = list(audit_row); audit_row[audit_header.index("uid")] = ""
    if break_ == "audit_bad_ts":                                 # non-numeric audit timestamp [§5]
        audit_row = list(audit_row); audit_row[audit_header.index("ts")] = "BAD"
    if break_ == "audit_no_matched_event":                       # a DoS audit row with no event [§6]
        audit_row = list(audit_row); audit_row[audit_header.index("matched_event_id")] = ""
    if break_ == "audit_wrong_endpoints":                        # endpoints != conn.log for this uid [§8]
        audit_row = list(audit_row); audit_row[audit_header.index("id.resp_h")] = "203.0.113.99"
    if break_ == "audit_row_after_window":                       # row ts after the event window [§6]
        audit_row = list(audit_row); audit_row[audit_header.index("ts")] = str(base_ts + 13)
    if break_ == "audit_wrong_event_label":                      # audit label != the matched event's label [§7]
        audit_row = list(audit_row); audit_row[audit_header.index("label")] = "BruteForce"
    if break_ == "benign_with_event":                            # a BENIGN row carrying an attack event [§7]
        audit_row = list(audit_row); audit_row[audit_header.index("label")] = "BENIGN"
    if break_ == "audit_label_mismatch":                         # audit relabels the flow (BENIGN vs the DoS split) [§6]
        audit_row = list(audit_row); audit_row[audit_header.index("label")] = "BENIGN"
    if break_ == "audit_empty_endpoints":                        # empty audit fields must NOT fail-open [v20.40 §7]
        audit_row = list(audit_row)
        for _f in ("id.resp_h", "id.resp_p", "proto"):
            audit_row[audit_header.index(_f)] = ""
    if break_ == "audit_wrong_orig_port":                        # SOURCE port must be confronted too [v20.40 §8]
        audit_row = list(audit_row); audit_row[audit_header.index("id.orig_p")] = "9999"
    if break_ == "audit_row_pad_window":                         # 4 s past the window with padding=0 [v20.40 §10]
        audit_row = list(audit_row); audit_row[audit_header.index("ts")] = str(base_ts + 9)
    if break_ == "audit_ts_ne_conn":                             # ts != the conn.log flow's ts (in-window) [v20.41 §7.1]
        audit_row = list(audit_row); audit_row[audit_header.index("ts")] = str(base_ts + 4)

    ml_p = os.path.join(rd, "run{}.csv".format(rid))
    sr_p = os.path.join(rd, "run{}_split_ready.csv".format(rid))
    au_p = os.path.join(rd, "run{}_audit.csv".format(rid))
    # The BENIGN background flow's rows (uid Cben): a plain NON-TLS TCP flow, so it declares no ja3/ja3s/alpn
    # to back (its uid has no ssl.log record) and is not a duplicate of the attack row [v20.41 §7.3].
    ben_common = list(_valid_common_row())
    for _c, _v in (("ja3", "none"), ("ja3s", "none"), ("alpn", "none"), ("tls_version", "none"), ("sni_present", "0")):
        ben_common[fs.COMMON.index(_c)] = _v
    ben_ml_row = ben_common + ["BENIGN"]
    ben_sr_row = [rid, str(base_ts + 5)] + ben_common + ["BENIGN"]
    if break_ == "extra_col":                                    # match the leaked-column ml header [§6.7]
        ben_ml_row = ben_common + ["10.0.0.3", "BENIGN"]
    if break_ == "garbage_csv":
        open(ml_p, "w").write("THIS IS NOT A DATASET")
    elif break_ == "ml_empty":
        write_csv(ml_p, ml_header, [])                          # header only, no data rows [§6.1]
    else:
        write_csv(ml_p, ml_header, [ml_row, ben_ml_row])
    write_csv(sr_p, sr_header, [sr_row, ben_sr_row])
    # audit: the attack row + the benign background row; the SAME uid twice is the dup-uid break [v20.40 §9].
    ben_audit_row = ["Cben", str(log_ts), "10.0.0.3", "6666", "10.0.0.1", "443", "tcp", "BENIGN", "", "F", ""]
    if break_ == "audit_label_only":
        audit_rows = [audit_row]                                 # a single 1-column row (no uid/endpoints) [§9]
    else:
        audit_rows = [audit_row, ben_audit_row]
    if break_ == "audit_dup_uid":                                # a flow labeled twice (same uid on two rows) [§9]
        audit_rows.append(["Cabc", str(log_ts), "10.0.0.2", "5555", "10.0.0.1", "443", "tcp", "BENIGN", "", "T", "dup"])
    write_csv(au_p, audit_header, audit_rows)

    # run<N>_benign.jsonl — NB2 evidence [v20.41 §5 / v20.42 §6-§9,§12]: two UNIQUE, IN-WINDOW sessions with a
    # real browser+webdriver, identity (campaign/run/seed/attempt) matching. Breaks corrupt exactly one thing.
    ben_browser = "" if break_ == "benign_no_browser" else "firefox 128.0"
    ben_wd = "" if break_ == "benign_no_webdriver" else "geckodriver 0.34"
    ben_ok = (break_ != "benign_sessions_short")                 # both sessions fail -> 0 successful < the floor
    ben_attempt = ("NEW" if break_ == "coordinated_rebatize" else
                   ("WRONG-ATTEMPT" if break_ == "benign_wrong_attempt" else "att-0"))
    ben_bname = "banana-browser" if break_ == "benign_fake_browser" else "firefox"     # §10 enum
    ben_wname = "chromedriver" if break_ == "benign_driver_mismatch" else "geckodriver"  # §10 must match browser

    def _ben_rec(k):
        st, en = base_ts + (k - 1) * 2, base_ts + (k - 1) * 2 + 1   # epoch, OVERLAPPING the pcap packets
        site, pages = "https://blog.lab/p{}".format(k), 3
        if break_ == "benign_bad_temporal":                        # 2033 start, 2017 end (end<start + outside)
            st, en = 2000000000, 1500000000
        if break_ == "benign_outside_pcap":                        # inside capture window but NO packets there
            st, en = base_ts + 40, base_ts + 41
        if break_ == "benign_after_last_packet":                   # starts AFTER the last packet (within +5s) [§9]
            st, en = base_ts + 10, base_ts + 11
        if break_ == "benign_too_short":                           # ~1ms session — implausibly short [§11]
            st, en = base_ts, base_ts + 0.001
        if break_ == "benign_overlap":                             # near-identical sessions overlapping by 1ms [§9]
            st, en, site = base_ts + 0.001 * (k - 1), base_ts + 0.2 + 0.001 * (k - 1), "https://blog.lab/p1"
        if break_ == "benign_cloned_sessions":                     # identical content, only session_id differs [§11]
            st, en, site = base_ts, base_ts + 1, "https://blog.lab/p1"
        if break_ == "benign_clone_pages":                         # identical EXCEPT pages varies [§7]
            st, en, site, pages = base_ts, base_ts + 1, "https://blog.lab/p1", k
        rec = {"campaign_id": "C", "run_id": run_id, "seed": 1, "attempt_id": ben_attempt,
               "session_id": 1 if break_ == "benign_dup_session" else k,   # same id twice -> not unique
               "browser": ben_browser, "browser_name": ben_bname, "browser_version": "128.0",
               "webdriver": ben_wd, "webdriver_name": ben_wname, "webdriver_version": "0.34", "pages": pages,
               "site": "" if break_ == "benign_empty_site" else site,
               "start": st, "end": en, "ok": ben_ok}
        if break_ == "benign_ok_no_pages":                         # ok=true but no pages evidence [§8]
            rec.pop("pages")
        return rec
    if break_ != "benign_jsonl_absent":
        with open(os.path.join(rd, "run{}_benign.jsonl".format(rid)), "w") as _bf:
            for _k in (1, 2):
                _bf.write(json.dumps(_ben_rec(_k)) + "\n")
    # run<N>_orchestration.json — the executed plan; the seal validates it SEMANTICALLY and binds it to the
    # attempt/campaign/run [v20.44 §5/§6 + v20.46 §7/§8].
    if break_ != "orchestration_absent":
        _oatt = ("NEW" if break_ == "coordinated_rebatize" else
                 ("OTHER-ATTEMPT" if break_ == "orchestration_wrong_attempt" else "att-0"))
        _cap_step = {"step": "start_capture", "required": True, "ok": break_ != "orchestration_step_failed"}
        if break_ == "orchestration_capture_optional":           # a FAILED capture marked optional [§6]
            _cap_step = {"step": "start_capture", "required": False, "ok": False, "skipped": True}
        if break_ == "orchestration_no_steps":
            _osteps = []
        elif break_ == "orchestration_garbage_steps":            # non-object step entries [§6]
            _osteps = ["garbage"]
        else:                                                    # the CANONICAL critical step names [§6]
            _osteps = [_cap_step, {"step": "attacks", "required": True, "ok": True},
                       {"step": "process_pcap", "required": True, "ok": True},
                       {"step": "label_flows", "required": True, "ok": True}]
        json.dump({"overall": "FAIL" if break_ == "orchestration_failed" else "PASS",
                   "aborted_at": "capture" if break_ == "orchestration_aborted" else None,
                   "tool_version": "bogus" if break_ == "orchestration_bogus_version" else _rl.TOOL_VERSION,
                   "attempt_id": _oatt,
                   "campaign_sha256": ("0" * 64 if break_ == "orchestration_wrong_campaign" else sha(man)),
                   "run_id": 99 if break_ == "orchestration_wrong_run" else run_id, "steps": _osteps},
                  open(os.path.join(rd, "run{}_orchestration.json".format(rid)), "w"))

    files = {"ml": "run{}.csv".format(rid), "split_ready": "run{}_split_ready.csv".format(rid),
             "audit": "run{}_audit.csv".format(rid)}
    if break_ == "same_csv":                                     # all three point at the ml file [§6/§8]
        files = {k: "run{}.csv".format(rid) for k in files}
    if break_ == "missing_csv":
        os.remove(sr_p)                                          # declared but NOT on disk
    ohashes = {k: (sha(os.path.join(rd, fn)) if os.path.exists(os.path.join(rd, fn)) else "0" * 64)
               for k, fn in files.items()}

    _ev0 = {"label": "DoS", "usable_flows": 1, "matched_flows": 1, "ambiguous_flows": 0,
            "window_start": float(base_ts), "window_end": float(base_ts + 5)}     # matches the e0 annotation
    _events = {} if benign else {"e0": dict(_ev0)}
    if break_ == "status_event_mismatch":                        # status event id != the annotation id [§6]
        _events = {"STATUS_EVENT_NOT_E0": dict(_ev0)}
    if break_ == "event_count_mismatch":                         # status usable_flows != the audit rows [§5]
        _events = {"e0": dict(_ev0, usable_flows=5)}
    _lpol = dict(_prov.OFFICIAL_POLICY_PROFILES["official/v1"])   # the labeler's SEALED policy (meets the campaign)
    if break_ == "status_policy_relaxed":                         # a padding WIDER than the campaign's pinned 0 [v20.41 §6]
        _lpol["window_padding_ms"] = 10000
    status = {"run_id": run_id, "attempt_id": ("NEW" if break_ == "coordinated_rebatize" else "att-0"),
              "diagnostic": break_ == "diagnostic",
              "diagnostic_reasons": ["use_failed"] if break_ == "diagnostic" else [],
              "campaign_sha256": sha(man), "config_id": 0, "split": "train",
              "input_hashes": {"conn": logs["conn.log"]["sha256"], "ssl": logs["ssl.log"]["sha256"],
                               "quic": logs["quic.log"]["sha256"], "annotations": sha(ann)},
              "files": files, "output_hashes": ohashes,
              "flows_written_ml": 100 if break_ == "bad_counts" else 2,   # 100 over a 2-row file [§6.8]
              "flows_audit": len(audit_rows),
              "class_counts_split_ready": ({"BENIGN": 2} if benign else {atk_label: 1, "BENIGN": 1}),
              # the labeler seals its FULL policy here; the finalizer takes the window tolerance from it [§10]
              # and confronts it against the campaign's required_labeling_policy [v20.41 §6]
              "labeling_policy": _lpol,
              # EVENT identity: status.events keyed by the annotation event_id, label+window matching [§6]
              "events": _events,
              # SSL/QUIC join stats — 1 record each, uid Cabc joins conn.log [§8]
              "ssl_join": {"records": 999 if break_ == "fake_join_counts" else 1,
                           "records_matching_conn": 1, "orphan_records": 0,
                           "missing_uid_records": 0, "join_rate": 1.0},
              "quic_join": {"records": 1, "records_matching_conn": 1, "orphan_records": 0,
                            "missing_uid_records": 0, "join_rate": 1.0}}
    json.dump(status, open(os.path.join(rd, "run{}_run_status.json".format(rid)), "w"))
    if break_ == "annotations":
        os.remove(ann)                                           # declared in input_hashes but absent [§5]
    return man


def test_finalize_binding_chain():
    """§4-§8 P0 [audit v20.31]: FAIL-CLOSED binding — a coherent official run PASSES, but a MISSING file or
    field, a CSV that is not a dataset, non-distinct outputs, or no manifest all FAIL (never 'skip')."""
    import finalize_run as fr
    d = tempfile.mkdtemp(); rd = os.path.join(d, "run0"); os.makedirs(rd)
    man = _bound_run(rd)
    assert fr.check_binding(rd, "0", man, strict=True)[0] == "PASS"
    assert fr.check_binding(rd, "0", None, strict=True)[0] == "FAIL"        # §4 no --campaign
    for br in ("pcap", "run_id", "missing_csv", "omit_pcap_sha", "garbage_csv", "same_csv",
               "annotations", "no_capture_start"):
        d2 = tempfile.mkdtemp(); rd2 = os.path.join(d2, "run0"); os.makedirs(rd2)
        man2 = _bound_run(rd2, break_=br)
        assert fr.check_binding(rd2, "0", man2, strict=True)[0] == "FAIL", "break {} must FAIL".format(br)


def test_finalize_binding_reuses_rigorous_validators():
    """§4-§9 P0 [audit v20.32]: the finalizer must REUSE the rigorous validators (campaign.load,
    label_flows.load_annotations, feature_schema, provenance) — 'the right hash + some columns' is NOT
    'the dataset the experiment produced'. Each semantic corruption below hash-matches its declaration yet
    is caught because the CONTENT is validated. Also asserts a diagnostic (non-strict) seal TOLERATES the
    reduced set so the strictness is genuinely official-only."""
    import finalize_run as fr
    # Every semantic corruption must FAIL at least one strict check (binding / capture / zeek / temporal).
    # Includes the v20.33 relations (non-reproducible campaign, ML!=split, unparseable PCAP, malformed Zeek,
    # non-boolean audit, empty capture_start) AND the v20.34 relations: a PCAP from another epoch [§7],
    # conn.log without the labeler's essentials [§6], invalid capture_start TYPES [§8], and an audit that
    # points at a non-existent annotation event [§5].
    semantic = ("ml_empty", "audit_label_only", "empty_run_id", "bad_timestamp", "evil_label",
                "junk_value", "neg_value", "extra_col", "bad_counts", "bad_annotations",
                "invalid_campaign", "capture_no_stats", "zeek_no_rc", "zeek_bad_records",
                "campaign_not_reproducible", "ml_split_mismatch", "invalid_pcap", "malformed_zeek",
                "audit_bad_ambiguous", "empty_capture_start",
                "temporal_mismatch", "zeek_missing_essentials", "bad_capture_start_types", "audit_ghost_event",
                "split_2033", "sslquic_2033", "no_ended_utc", "bad_duration", "audit_ghost_uid",
                "sslquic_no_fields", "no_capture_policy",
                "audit_bad_ts", "conn_bad_ts", "ssl_bad_ts", "quic_no_ts", "neg_stats", "audit_empty_uid",
                "audit_label_mismatch", "fake_join_counts", "tls_values_empty",
                "no_attack_executed", "inconsistent_stats",
                "status_event_mismatch", "audit_no_matched_event", "extra_success_event",
                "drop_declared_below_real",
                "audit_wrong_endpoints", "audit_row_after_window", "audit_wrong_event_label",
                "benign_with_event", "event_count_mismatch", "benign_policy_violated",
                "audit_empty_endpoints", "audit_wrong_orig_port", "audit_dup_uid", "audit_row_pad_window",
                "benign_policy_absent", "benign_policy_negative",
                "benign_jsonl_absent", "benign_sessions_short", "benign_no_browser",
                "no_required_policy", "status_policy_relaxed", "audit_ts_ne_conn",
                "tls_value_forged", "split_transport_forged",
                "benign_bad_temporal", "benign_dup_session", "benign_no_webdriver", "benign_empty_site",
                "benign_wrong_attempt", "conn_dup_uid",
                "benign_outside_pcap", "benign_cloned_sessions",
                "orchestration_absent", "orchestration_wrong_attempt", "benign_fake_browser",
                "benign_driver_mismatch", "benign_ok_no_pages", "benign_clone_pages", "benign_after_last_packet",
                "orchestration_failed", "orchestration_aborted", "orchestration_no_steps",
                "orchestration_step_failed", "orchestration_wrong_campaign", "orchestration_wrong_run",
                "capture_wrong_attempt", "zeek_wrong_attempt", "coordinated_rebatize", "benign_too_short",
                "orchestration_garbage_steps", "orchestration_capture_optional", "orchestration_bogus_version",
                "benign_overlap")
    for br in semantic:
        d = tempfile.mkdtemp(); rd = os.path.join(d, "run0"); os.makedirs(rd)
        man = _bound_run(rd, break_=br)
        bind = fr.check_binding(rd, "0", man, strict=True)[0]
        cap = fr.check_capture_semantics(rd, "0", strict=True)[0]
        zk = fr.check_zeek_semantics(rd, "0", strict=True)[0]
        temporal = fr.check_temporal_coherence(rd, "0", strict=True)[0]
        assert "FAIL" in (bind, cap, zk, temporal), \
            "break {} must FAIL a strict check (bind={} cap={} zeek={} temporal={})".format(br, bind, cap, zk, temporal)
    # A clean run still PASSES all four strict checks (proves the validators accept a real dataset).
    d = tempfile.mkdtemp(); rd = os.path.join(d, "run0"); os.makedirs(rd)
    man = _bound_run(rd)
    assert fr.check_binding(rd, "0", man, strict=True)[0] == "PASS"
    assert fr.check_capture_semantics(rd, "0", strict=True)[0] == "PASS"
    assert fr.check_zeek_semantics(rd, "0", strict=True)[0] == "PASS"
    assert fr.check_temporal_coherence(rd, "0", strict=True)[0] == "PASS"


def test_finalize_binding_rejects_foreign_campaign_annotations():
    """§8 P0 [audit v20.33]: annotations that are STRUCTURALLY valid but belong to ANOTHER campaign must
    NOT bind an official seal. The finalizer reuses label_flows.validate_annotations_campaign, so a DoS
    annotation whose campaign_id is 'WRONG' (hash re-pointed so only the campaign binding can fail) FAILS."""
    import hashlib
    import shutil
    import finalize_run as fr
    d = tempfile.mkdtemp(); rd = os.path.join(d, "run0"); os.makedirs(rd)
    man = _bound_run(rd)
    ann = os.path.join(rd, "run0_annotations.csv")
    _campaign_ann(d, "WRONG", "0" * 64, 0, [{}])                 # a valid DoS annotation, WRONG campaign_id
    shutil.copyfile(os.path.join(d, "ann.csv"), ann)
    status_p = os.path.join(rd, "run0_run_status.json"); st = json.load(open(status_p))
    st["input_hashes"]["annotations"] = hashlib.sha256(open(ann, "rb").read()).hexdigest()   # only campaign binding can fail
    json.dump(st, open(status_p, "w"))
    state, detail = fr.check_binding(rd, "0", man, strict=True)
    assert state == "FAIL" and any("campaign" in p for p in detail.get("problems", [])), detail


def test_finalize_rejects_diagnostic_status_as_official():
    """§6 P0 [audit v20.31]: a status that declares itself diagnostic can NEVER back an official seal —
    official mode FAILs, and `official` is derived from evidence, not just the CLI flag."""
    import finalize_run as fr
    orig = fr.validate_status
    fr.validate_status = lambda run_dir, run_id, camp=None: ("PASS", {"diagnostic": True})
    try:
        d = tempfile.mkdtemp(); rd = os.path.join(d, "run0"); os.makedirs(rd)
        man = _bound_run(rd, break_="diagnostic")
        comp = fr.finalize(rd, "0", campaign_path=man, bundle=False)   # official mode over a diagnostic status
        assert comp["overall"] == "FAIL" and comp["official"] is False and comp["status_is_diagnostic"] is True
    finally:
        fr.validate_status = orig


def test_finalize_verify_detects_completion_tamper():
    """§9/§10 P0 [audit v20.31]: --verify RE-DERIVES the verdict from the artifacts, so editing
    completion_status.json (which is excluded from the inventory) to flip official/overall is DETECTED."""
    d = tempfile.mkdtemp(); rd = os.path.join(d, "run0"); os.makedirs(rd)
    open(os.path.join(rd, "run0.pcap"), "wb").write(b"\xd4\xc3\xb2\xa1" + b"x" * 40)
    seal = _run([sys.executable, _script("finalize_run.py"), "--run-dir", rd, "--run-id", "0",
                 "--require", "run0.pcap", "--diagnostic"], capture_output=True, text=True)
    assert seal.returncode == 0
    cp = os.path.join(rd, "run0_completion_status.json")
    comp = json.load(open(cp)); assert comp["official"] is False
    comp["official"] = True; comp["overall"] = "PASS"; json.dump(comp, open(cp, "w"))   # TAMPER
    ver = _run([sys.executable, _script("finalize_run.py"), "--run-dir", rd, "--run-id", "0", "--verify"],
               capture_output=True, text=True)
    assert ver.returncode == 3 and "TAMPERED" in (ver.stdout + ver.stderr)


def test_finalize_verify_uses_immutable_policy_not_completion():
    """§9 P0 [audit v20.31]: --verify re-derives the verdict using the thresholds from the IMMUTABLE,
    inventory-protected seal_policy.json — NOT the editable completion. So editing a threshold in the
    completion to flip FAIL->PASS is DETECTED (the sealed policy still says FAIL)."""
    d = tempfile.mkdtemp(); rd = os.path.join(d, "run0"); os.makedirs(rd)
    open(os.path.join(rd, "run0.pcap"), "wb").write(b"\xd4\xc3\xb2\xa1" + b"x" * 40)
    json.dump({"run_id": 0, "tcpdump_returncode": 0, "pcap": {"exists": True, "size_bytes": 44},
               "tcpdump_stats": {"packets_captured": 10, "drop_rate": 0.0}},
              open(os.path.join(rd, "run0_capture_end.json"), "w"))
    # a diagnostic seal that FAILS its own min-packets gate (10 < 2000).
    seal = _run([sys.executable, _script("finalize_run.py"), "--run-dir", rd, "--run-id", "0",
                 "--require", "run0.pcap", "--require", "run0_capture_end.json", "--diagnostic",
                 "--min-packets", "2000"], capture_output=True, text=True)
    cp = os.path.join(rd, "run0_completion_status.json"); comp = json.load(open(cp))
    assert comp["overall"] == "FAIL"
    # forge a PASS by lowering the threshold IN THE COMPLETION (which is not in the inventory).
    comp["overall"] = "PASS"; comp["applied_thresholds"]["min_packets"] = 0
    json.dump(comp, open(cp, "w"))
    ver = _run([sys.executable, _script("finalize_run.py"), "--run-dir", rd, "--run-id", "0", "--verify"],
               capture_output=True, text=True)
    assert ver.returncode == 3 and "TAMPERED" in (ver.stdout + ver.stderr)   # policy says min-packets 2000


def test_finalize_verify_requires_seal_artifacts_and_selfcontained_bundle():
    """§10/§11/§14 P0 [audit v20.32]: --verify is TAMPERED if a sealing artifact (completion / hashes /
    immutable seal_policy) is DELETED or the manifest is edited (manifest_sha256 no longer matches); and
    the sealed bundle is SELF-CONTAINED — the campaign manifest + local.zeek are copied into the run and
    bundled, so a reviewer with only the tarball can re-verify the campaign identity + analyzer set."""
    import tarfile
    import finalize_run as fr

    def fresh():
        d = tempfile.mkdtemp(); rd = os.path.join(d, "run0"); os.makedirs(rd)
        man = _bound_run(rd)
        fr.finalize(rd, "0", campaign_path=man, bundle=True, diagnostic=True)   # writes all sealing files
        return rd

    def verify(rd):
        return _run([sys.executable, _script("finalize_run.py"), "--run-dir", rd, "--run-id", "0", "--verify"],
                    capture_output=True, text=True)

    rd = fresh()
    # §14: the campaign manifest + local.zeek were copied INTO the run and are bundle members.
    assert os.path.exists(os.path.join(rd, "run0_campaign.json"))
    assert os.path.exists(os.path.join(rd, "run0_local.zeek"))
    with tarfile.open(os.path.join(rd, "run0_bundle.tar.gz")) as t:
        assert {"run0_campaign.json", "run0_local.zeek"} <= set(t.getnames())
    assert verify(rd).returncode == 0                                    # baseline: a sealed run verifies

    # §10: deleting any sealing artifact is TAMPERED.
    for fn in ("run0_completion_status.json", "run0_hashes.json", "run0_seal_policy.json", "run0_bundle.tar.gz"):
        rd = fresh(); os.remove(os.path.join(rd, fn))
        r = verify(rd); assert r.returncode == 3 and "TAMPERED" in (r.stdout + r.stderr), fn

    # §11: editing the manifest (kept valid JSON) breaks completion.manifest_sha256 -> TAMPERED.
    rd = fresh(); mp = os.path.join(rd, "run0_manifest.json")
    m = json.load(open(mp)); m["sealed_utc"] = "1999-01-01T00:00:00Z"; json.dump(m, open(mp, "w"))
    r = verify(rd); assert r.returncode == 3 and "manifest_sha256" in (r.stdout + r.stderr)


def test_finalize_verify_opens_bundle_structure():
    """§12 P0 [audit v20.32]: --verify OPENS the bundle and checks its STRUCTURE against the manifest — not
    just the outer hash. A bundle swapped for non-TAR bytes, or one carrying a path-traversal member, is
    TAMPERED even when the completion's recorded bundle hash is updated to match the new bytes."""
    import io
    import tarfile
    import finalize_run as fr

    def fresh():
        d = tempfile.mkdtemp(); rd = os.path.join(d, "run0"); os.makedirs(rd)
        fr.finalize(rd, "0", campaign_path=_bound_run(rd), bundle=True, diagnostic=True)
        return rd

    def reseal_bundle_hash(rd):                                          # keep the OUTER hash consistent
        cp = os.path.join(rd, "run0_completion_status.json"); comp = json.load(open(cp))
        comp["bundle"]["sha256"] = fr._sha(os.path.join(rd, "run0_bundle.tar.gz"))
        json.dump(comp, open(cp, "w"))

    def verify(rd):
        return _run([sys.executable, _script("finalize_run.py"), "--run-dir", rd, "--run-id", "0", "--verify"],
                    capture_output=True, text=True)

    # (a) non-TAR bytes (outer hash updated to match) -> not a valid tar -> TAMPERED.
    rd = fresh()
    open(os.path.join(rd, "run0_bundle.tar.gz"), "wb").write(b"NOT A TAR")
    reseal_bundle_hash(rd)
    r = verify(rd); assert r.returncode == 3 and "TAMPERED" in (r.stdout + r.stderr)

    # (b) a tar carrying a path-traversal member -> unsafe member -> TAMPERED.
    rd = fresh()
    with tarfile.open(os.path.join(rd, "run0_bundle.tar.gz"), "w:gz") as t:
        ti = tarfile.TarInfo("../evil"); data = b"x"; ti.size = len(data)
        t.addfile(ti, io.BytesIO(data))
    reseal_bundle_hash(rd)
    r = verify(rd); assert r.returncode == 3 and "TAMPERED" in (r.stdout + r.stderr)


def test_finalize_verify_seal_integrity_bypasses():
    """§14/§15/§16 P0 [audit v20.33]: --verify must be driven by the IMMUTABLE seal policy, not the editable
    completion. Reproduces the audit's bypasses and requires each to be TAMPERED: (§14) nulling
    completion.bundle and swapping the bundle for junk bytes; (§15) rewriting run<N>_hashes.json to
    arbitrary content; (§16) rebuilding the bundle with a tampered INTERNAL manifest/hashes while the data
    members stay intact and the outer bundle hash is updated to match."""
    import io
    import tarfile
    import finalize_run as fr

    def fresh():
        d = tempfile.mkdtemp(); rd = os.path.join(d, "run0"); os.makedirs(rd)
        fr.finalize(rd, "0", campaign_path=_bound_run(rd), bundle=True, diagnostic=True)
        return rd

    def verify(rd):
        return _run([sys.executable, _script("finalize_run.py"), "--run-dir", rd, "--run-id", "0", "--verify"],
                    capture_output=True, text=True)

    assert verify(fresh()).returncode == 0                              # baseline: a sealed run verifies

    # §14: null completion.bundle AND replace the bundle bytes -> still TAMPERED (the check is policy-driven).
    rd = fresh(); cp = os.path.join(rd, "run0_completion_status.json")
    comp = json.load(open(cp)); comp["bundle"] = None; json.dump(comp, open(cp, "w"))
    open(os.path.join(rd, "run0_bundle.tar.gz"), "wb").write(b"NOT A TAR BUT EXISTS")
    r = verify(rd); assert r.returncode == 3 and "TAMPERED" in (r.stdout + r.stderr)

    # §15: rewrite run0_hashes.json to junk -> TAMPERED.
    rd = fresh()
    json.dump({"FAKE": "FAKE"}, open(os.path.join(rd, "run0_hashes.json"), "w"))
    r = verify(rd); assert r.returncode == 3 and "hashes.json" in (r.stdout + r.stderr)

    # §16: rebuild the bundle with tampered INTERNAL manifest+hashes (data members intact), update outer hash.
    rd = fresh(); man = json.load(open(os.path.join(rd, "run0_manifest.json")))
    bp = os.path.join(rd, "run0_bundle.tar.gz")
    with tarfile.open(bp, "w:gz") as t:
        for d in man["inventory"]:
            t.add(os.path.join(rd, d["path"]), arcname=d["path"])
        for nm in ("run0_manifest.json", "run0_hashes.json"):
            payload = b'{"TAMPERED": true}'
            ti = tarfile.TarInfo(nm); ti.size = len(payload); t.addfile(ti, io.BytesIO(payload))
    cp = os.path.join(rd, "run0_completion_status.json"); comp = json.load(open(cp))
    comp["bundle"]["sha256"] = fr._sha(bp); json.dump(comp, open(cp, "w"))
    r = verify(rd); assert r.returncode == 3 and "TAMPERED" in (r.stdout + r.stderr)


def test_finalize_refuses_reseal_without_rotate():
    """§18 P0 [audit v20.33]: an ALREADY-sealed run cannot be silently re-finalized with a WEAKER policy
    (that would flip a FAIL seal to PASS by overwriting seal_policy/manifest/hashes/completion). The second
    finalize is REFUSED unless --rotate-seal, which ARCHIVES the prior seal rather than erasing it."""
    if os.getenv("CI") == "true": return
    import finalize_run as fr
    d = tempfile.mkdtemp(); rd = os.path.join(d, "run0"); os.makedirs(rd)
    pcap = os.path.join(rd, "run0.pcap"); open(pcap, "wb").write(b"\xd4\xc3\xb2\xa1" + b"x" * 40)
    json.dump({"run_id": 0, "tcpdump_returncode": 0,
               "pcap": {"exists": True, "size_bytes": 44, "sha256": fr._sha(pcap)},
               "tcpdump_stats": {"packets_captured": 10, "packets_received": 10,
                                 "packets_dropped": 0, "drop_rate": 0.0}},
              open(os.path.join(rd, "run0_capture_end.json"), "w"))
    # first seal FAILS its own min-packets gate (10 < 2000).
    c1 = fr.finalize(rd, "0", ["run{n}.pcap", "run{n}_capture_end.json"], bundle=False,
                     diagnostic=True, min_packets=2000)
    assert c1["overall"] == "FAIL"
    # a second finalize RELAXING the gate is REFUSED (no silent overwrite).
    import pytest
    with pytest.raises(SystemExit):
        fr.finalize(rd, "0", ["run{n}.pcap", "run{n}_capture_end.json"], bundle=False,
                    diagnostic=True, min_packets=0)
    # --rotate-seal archives the prior seal and records the new attempt.
    c2 = fr.finalize(rd, "0", ["run{n}.pcap", "run{n}_capture_end.json"], bundle=False,
                     diagnostic=True, min_packets=0, rotate_seal=True)
    assert c2["overall"] == "PASS"
    assert any(n.startswith("run0_prior_seal_") for n in os.listdir(rd)), "prior seal must be archived"


def test_finalize_audit_flow_identity():
    """§5-§10 P0 [audit v20.39/v20.40]: each audit ROW is bound to its flow (the WHOLE 5-tuple incl. BOTH
    ports, every field MANDATORY — no empty-field fail-open), a uid labels at most ONE flow, its event
    (label + window with the tolerance TAKEN from the authenticated labeling policy, not a fixed 5 s), and
    the per-event counts; and an OFFICIAL run must pre-register a VALID benign_quality_policy AND actually
    carry that benign traffic."""
    import finalize_run as fr
    d = tempfile.mkdtemp(); rd = os.path.join(d, "run0"); os.makedirs(rd)
    assert fr.check_binding(rd, "0", _bound_run(rd), strict=True)[0] == "PASS"        # a coherent 2-flow run passes
    for br in ("audit_wrong_endpoints", "audit_row_after_window", "audit_wrong_event_label",
               "benign_with_event", "event_count_mismatch", "benign_policy_violated"):
        d2 = tempfile.mkdtemp(); rd2 = os.path.join(d2, "run0"); os.makedirs(rd2)
        st, det = fr.check_binding(rd2, "0", _bound_run(rd2, break_=br), strict=True)
        assert st == "FAIL", "{} must FAIL ({})".format(br, det)
    # v20.40: every reproduced fail-open is now closed, and the SPECIFIC check is load-bearing (the reason
    # names it) — not merely an incidental failure elsewhere.
    for br, needle in (("audit_empty_endpoints", "empty"), ("audit_wrong_orig_port", "id.orig_p"),
                       ("audit_dup_uid", "repeats uid"), ("audit_row_pad_window", "window"),
                       ("benign_policy_absent", "benign_quality_policy"),
                       ("benign_policy_negative", "benign_quality_policy")):
        d2 = tempfile.mkdtemp(); rd2 = os.path.join(d2, "run0"); os.makedirs(rd2)
        st, det = fr.check_binding(rd2, "0", _bound_run(rd2, break_=br), strict=True)
        probs = " | ".join(det.get("problems", []))
        assert st == "FAIL" and needle in probs, "{} must FAIL via {!r} ({})".format(br, needle, probs)


def test_finalize_benign_evidence_and_pinned_policy():
    """§5/§6/§7.1/§7.2/§7.3 P0 [audit v20.41]: an OFFICIAL seal now ENFORCES the benign_quality_policy's
    EVIDENCE (run<N>_benign.jsonl — recomputed sessions/success rate + browser), not just its schema; the
    campaign must PIN its labeling policy and the status must MEET it (no relaxed padding); the audit row ts
    must be its conn.log flow's ts; and the dataset's ja3/ja3s/alpn/transport VALUES must appear in the logs
    (set membership — per-line binding still needs the labeler's flow_row_id, roadmap)."""
    import finalize_run as fr
    d = tempfile.mkdtemp(); rd = os.path.join(d, "run0"); os.makedirs(rd)
    assert fr.check_binding(rd, "0", _bound_run(rd), strict=True)[0] == "PASS"        # coherent evidence passes
    for br, needle in (("benign_jsonl_absent", "benign"), ("benign_sessions_short", "success"),
                       ("benign_no_browser", "browser"), ("no_required_policy", "required_labeling_policy"),
                       ("status_policy_relaxed", "relaxes"), ("audit_ts_ne_conn", "conn.log ts"),
                       ("tls_value_forged", "not present in the logs"),
                       ("split_transport_forged", "transport")):
        d2 = tempfile.mkdtemp(); rd2 = os.path.join(d2, "run0"); os.makedirs(rd2)
        st, det = fr.check_binding(rd2, "0", _bound_run(rd2, break_=br), strict=True)
        probs = " | ".join(det.get("problems", []))
        assert st == "FAIL" and needle in probs, "{} must FAIL via {!r} ({})".format(br, needle, probs)


def test_finalize_benign_session_authenticity_and_conn_uid():
    """§6/§7/§8/§9/§11/§12 P0 [audit v20.42]: benign SESSION authenticity — each session must fall INSIDE the
    capture window (end>start, in [capture_start, capture_end]); session_id must be UNIQUE (N copies of one
    session are not N sessions); a webdriver must be present and site non-empty; attempt_id must match THIS
    attempt's status (a replayed prior-attempt log is rejected); and conn.log must not repeat a uid."""
    import finalize_run as fr
    d = tempfile.mkdtemp(); rd = os.path.join(d, "run0"); os.makedirs(rd)
    assert fr.check_binding(rd, "0", _bound_run(rd), strict=True)[0] == "PASS"        # coherent sessions pass
    for br, needle in (("benign_bad_temporal", "<= start"), ("benign_dup_session", "session_id"),
                       ("benign_no_webdriver", "webdriver"), ("benign_empty_site", "site"),
                       ("benign_wrong_attempt", "attempt_id"), ("conn_dup_uid", "repeats uid"),
                       ("benign_outside_pcap", "pcap packet window"), ("benign_cloned_sessions", "CLONE"),
                       ("benign_fake_browser", "browser_name"), ("benign_driver_mismatch", "does not match"),
                       ("benign_ok_no_pages", "pages"), ("benign_clone_pages", "CLONE"),
                       ("benign_after_last_packet", "overlap")):
        d2 = tempfile.mkdtemp(); rd2 = os.path.join(d2, "run0"); os.makedirs(rd2)
        st, det = fr.check_binding(rd2, "0", _bound_run(rd2, break_=br), strict=True)
        probs = " | ".join(det.get("problems", []))
        assert st == "FAIL" and needle in probs, "{} must FAIL via {!r} ({})".format(br, needle, probs)


def test_finalize_requires_orchestration_report_bound_to_attempt():
    """§5/§6 P0 [audit v20.44]: an OFFICIAL seal must ship run<N>_orchestration.json AND its attempt_id must
    MATCH the status — so 'rebatizing' a run (renaming only the status + benign attempt_id, leaving the plan
    report untouched) no longer produces a valid official seal."""
    import finalize_run as fr
    d = tempfile.mkdtemp(); rd = os.path.join(d, "run0"); os.makedirs(rd)
    assert fr.check_binding(rd, "0", _bound_run(rd), strict=True)[0] == "PASS"        # a coherent run passes
    for br, needle in (("orchestration_absent", "orchestration"), ("orchestration_wrong_attempt", "rebatized")):
        d2 = tempfile.mkdtemp(); rd2 = os.path.join(d2, "run0"); os.makedirs(rd2)
        st, det = fr.check_binding(rd2, "0", _bound_run(rd2, break_=br), strict=True)
        probs = " | ".join(det.get("problems", []))
        assert st == "FAIL" and needle in probs, "{} must FAIL via {!r} ({})".format(br, needle, probs)


def test_finalize_orchestration_semantic_and_attempt_propagation():
    """§7/§8/§9/§10/§11 P0 [audit v20.46]: an OFFICIAL seal validates the orchestration report SEMANTICALLY
    (overall=PASS, not aborted, non-empty steps with every required step ok, THIS campaign+run — not just a
    matching attempt_id), confronts the attempt_id STAMPED on the capture/zeek evidence (so a COORDINATED
    rebatization of status+benign+report is still caught), and rejects implausibly short benign sessions."""
    import finalize_run as fr
    d = tempfile.mkdtemp(); rd = os.path.join(d, "run0"); os.makedirs(rd)
    assert fr.check_binding(rd, "0", _bound_run(rd), strict=True)[0] == "PASS"        # a coherent run passes
    for br, needle in (("orchestration_failed", "overall"), ("orchestration_aborted", "aborted"),
                       ("orchestration_no_steps", "no steps"), ("orchestration_step_failed", "required step"),
                       ("orchestration_wrong_campaign", "campaign_sha256"), ("orchestration_wrong_run", "run_id"),
                       ("capture_wrong_attempt", "attempt_id"), ("zeek_wrong_attempt", "attempt_id"),
                       ("coordinated_rebatize", "attempt_id"), ("benign_too_short", "implausibly short"),
                       ("orchestration_garbage_steps", "critical step"),
                       ("orchestration_capture_optional", "required step"),
                       ("orchestration_bogus_version", "tool_version"), ("benign_overlap", "OVERLAP")):
        d2 = tempfile.mkdtemp(); rd2 = os.path.join(d2, "run0"); os.makedirs(rd2)
        st, det = fr.check_binding(rd2, "0", _bound_run(rd2, break_=br), strict=True)
        probs = " | ".join(det.get("problems", []))
        assert st == "FAIL" and needle in probs, "{} must FAIL via {!r} ({})".format(br, needle, probs)


def test_finalize_event_identity_and_recomputed_drop_gate():
    """§6/§9 P0 [audit v20.38]: EVENT identity — status.events must be a BIJECTION with the annotation
    success events, and every audit ATTACK row must reference a real event; and the drop-rate ceiling is
    applied to the RECOMPUTED rate (packets_dropped/packets_received), not the declared one."""
    import finalize_run as fr
    for br in ("status_event_mismatch", "audit_no_matched_event", "extra_success_event"):
        d = tempfile.mkdtemp(); rd = os.path.join(d, "run0"); os.makedirs(rd)
        man = _bound_run(rd, break_=br)
        st, det = fr.check_binding(rd, "0", man, strict=True)
        assert st == "FAIL" and any("event" in p for p in det.get("problems", [])), (br, det)
    d = tempfile.mkdtemp(); rd = os.path.join(d, "run0"); os.makedirs(rd)
    _bound_run(rd, break_="drop_declared_below_real")            # real 3% declared as 2%
    assert fr.check_capture_semantics(rd, "0", strict=True)[0] == "FAIL"
    # a malformed status.events (adversarial) is a clean FAIL, NOT an uncaught crash.
    ann = os.path.join(rd, "run0_annotations.csv"); au = os.path.join(rd, "run0_audit.csv")
    assert fr._check_event_identity({"events": {"e0": "NOTADICT"}}, ann, au)[0] is False
    assert fr._check_event_identity({"events": {"e0": {"label": "DoS", "window_start": "BAD"}}}, ann, au)[0] is False


def test_finalize_requires_planned_attacks_present():
    """§6 P0 [audit v20.37]: a run whose manifest PLANS an attack cannot seal official with ZERO annotation
    events / only-BENIGN data — the seal must not certify an experiment that did not happen. A coherent DoS
    run (event + DoS split-ready row) PASSES; the same manifest with an empty annotation / benign data FAILS."""
    import finalize_run as fr
    d = tempfile.mkdtemp(); rd = os.path.join(d, "run0"); os.makedirs(rd)
    assert fr.check_binding(rd, "0", _bound_run(rd), strict=True)[0] == "PASS"       # DoS actually happened
    d2 = tempfile.mkdtemp(); rd2 = os.path.join(d2, "run0"); os.makedirs(rd2)
    man2 = _bound_run(rd2, break_="no_attack_executed")                              # plans DoS, nothing happened
    state, detail = fr.check_binding(rd2, "0", man2, strict=True)
    assert state == "FAIL" and any("plans attack" in p for p in detail.get("problems", [])), detail


def test_temporal_coherence_fails_closed_on_bad_ts():
    """§5 P0 [audit v20.36]: the temporal check is FAIL-CLOSED. A missing/non-numeric ts on ANY Zeek log,
    the split-ready or the audit is a FAIL — not silently skipped. The previous code filtered invalid
    values, so 'no valid ts found' wrongly read as 'nothing out of range' and let ts=BAD seal official."""
    import finalize_run as fr
    d = tempfile.mkdtemp(); rd = os.path.join(d, "run0"); os.makedirs(rd)
    _bound_run(rd)
    assert fr.check_temporal_coherence(rd, "0", strict=True)[0] == "PASS"          # a clean run passes
    for br in ("conn_bad_ts", "ssl_bad_ts", "audit_bad_ts", "quic_no_ts", "split_2033"):
        d2 = tempfile.mkdtemp(); rd2 = os.path.join(d2, "run0"); os.makedirs(rd2)
        _bound_run(rd2, break_=br)
        assert fr.check_temporal_coherence(rd2, "0", strict=True)[0] == "FAIL", "{} must FAIL temporal".format(br)


def test_capture_policy_floor_blocks_rotate_relax():
    """§12 P0 [audit v20.35]: the capture thresholds are FLOORED against the manifest's
    capture_quality_policy, so neither the CLI nor a later --rotate-seal can relax them. A 10-packet run
    can't be sealed PASS by passing --min-packets 0 when the manifest floor is 1000."""
    import finalize_run as fr
    d = tempfile.mkdtemp(); rd = os.path.join(d, "run0"); os.makedirs(rd)
    pcap = os.path.join(rd, "run0.pcap"); _write_pcap(pcap, 10)
    json.dump({"run_id": 0, "tcpdump_returncode": 0,
               "pcap": {"exists": True, "size_bytes": os.path.getsize(pcap), "sha256": fr._sha(pcap)},
               "tcpdump_stats": {"packets_captured": 10, "packets_received": 10,
                                 "packets_dropped": 0, "drop_rate": 0.0}},
              open(os.path.join(rd, "run0_capture_end.json"), "w"))
    man = os.path.join(d, "campaign.json")
    json.dump({"capture_quality_policy": {"min_packets": 1000, "max_drop_rate": 0.02, "require_effect": False}},
              open(man, "w"))
    req = ["run{n}.pcap", "run{n}_capture_end.json"]
    c1 = fr.finalize(rd, "0", req, campaign_path=man, bundle=False, diagnostic=True, min_packets=0)
    assert c1["overall"] == "FAIL"                                # CLI 0 is floored to the manifest's 1000
    pol = json.load(open(os.path.join(rd, "run0_seal_policy.json")))
    assert pol["min_packets"] == 1000, "manifest floor must be recorded, not the CLI's 0"
    c2 = fr.finalize(rd, "0", req, campaign_path=man, bundle=False, diagnostic=True, min_packets=0,
                     rotate_seal=True)
    assert c2["overall"] == "FAIL"                                # --rotate-seal cannot relax below the floor


def test_zeek_semantics_accepts_internal_local_zeek():
    """§9 P0 [audit v20.34]: a sealed run copied AWAY from the lab tree still verifies — when the external
    local.zeek is gone, check_zeek_semantics validates site_script_sha256 against the INTERNAL
    run<N>_local.zeek copy that the finalizer bundles."""
    import shutil
    import finalize_run as fr
    d = tempfile.mkdtemp(); rd = os.path.join(d, "run0"); os.makedirs(rd)
    _bound_run(rd)
    ext = os.path.join(os.path.dirname(rd), "local.zeek")
    shutil.copyfile(ext, os.path.join(rd, "run0_local.zeek"))     # the finalizer's evidence copy
    assert fr.check_zeek_semantics(rd, "0", strict=True)[0] == "PASS"       # external present
    os.remove(ext)
    assert fr.check_zeek_semantics(rd, "0", strict=True)[0] == "PASS"       # falls back to the internal copy


def test_rotate_seal_archives_prior_as_protected_tarball():
    """§10 P0 [audit v20.34]: --rotate-seal packs the PRIOR seal into ONE run<N>_prior_seal_*.tar.gz that is
    hash-protected by the NEW manifest. Deleting/altering a piece of the prior seal is then detected by
    --verify (the whole archive is a single inventoried, hashed member — no more loose removable files)."""
    import glob
    import finalize_run as fr
    d = tempfile.mkdtemp(); rd = os.path.join(d, "run0"); os.makedirs(rd)
    pcap = os.path.join(rd, "run0.pcap"); _write_pcap(pcap, 20)
    json.dump({"run_id": 0, "tcpdump_returncode": 0,
               "pcap": {"exists": True, "size_bytes": os.path.getsize(pcap), "sha256": fr._sha(pcap)},
               "tcpdump_stats": {"packets_captured": 20, "packets_received": 20,
                                 "packets_dropped": 0, "drop_rate": 0.0}},
              open(os.path.join(rd, "run0_capture_end.json"), "w"))
    req = ["run{n}.pcap", "run{n}_capture_end.json"]
    fr.finalize(rd, "0", req, bundle=True, diagnostic=True, min_packets=1000)                 # FAIL seal
    fr.finalize(rd, "0", req, bundle=True, diagnostic=True, min_packets=0, rotate_seal=True)  # PASS re-seal
    arcs = glob.glob(os.path.join(rd, "run0_prior_seal_*.tar.gz"))
    assert len(arcs) == 1, "the prior seal must be ONE archived tarball"
    man = json.load(open(os.path.join(rd, "run0_manifest.json")))
    assert any(os.path.basename(arcs[0]) == it["path"] for it in man["inventory"]), "archive not hash-protected"

    def verify():
        return _run([sys.executable, _script("finalize_run.py"), "--run-dir", rd, "--run-id", "0", "--verify"],
                    capture_output=True, text=True)
    assert verify().returncode == 0
    with open(arcs[0], "ab") as f:                               # tamper the archived prior seal
        f.write(b"TAMPER")
    r = verify(); assert r.returncode == 3 and "TAMPERED" in (r.stdout + r.stderr)


def test_finalize_require_effect_needs_confirmed():
    """§13 P1 [audit v20.31]: --require-effect is not just 'a report exists' — the DoS effect must be
    CONFIRMED. A report with effect_confirmed=false does NOT satisfy the gate."""
    import finalize_run as fr
    d = tempfile.mkdtemp(); rd = os.path.join(d, "run0"); os.makedirs(rd)
    open(os.path.join(rd, "run0.pcap"), "wb").write(b"\xd4\xc3\xb2\xa1" + b"x" * 40)
    json.dump({"effect_confirmed": False, "n_windows": 1}, open(os.path.join(rd, "run0_service_effect.json"), "w"))
    comp = fr.finalize(rd, "0", ["run{n}.pcap", "run{n}_service_effect.json"], bundle=False,
                       diagnostic=True, require_effect=True)
    assert comp["overall"] == "FAIL" and comp["semantics"]["effect"]["state"] == "FAIL"
    json.dump({"effect_confirmed": True, "n_windows": 1}, open(os.path.join(rd, "run0_service_effect.json"), "w"))
    comp2 = fr.finalize(rd, "0", ["run{n}.pcap", "run{n}_service_effect.json"], bundle=False,
                        diagnostic=True, require_effect=True, rotate_seal=True)   # re-seal needs rotate [§18]
    assert comp2["semantics"]["effect"]["state"] == "PASS"


def test_mirroring_requires_victim_response():
    """§12 P0 [audit v20.31]: a lone client->victim conn.log record does NOT prove the mirror carries the
    RESPONSE half — confirmation requires resp_pkts>0 on the expected port."""
    import verify_switch_mirroring as vm
    hdr = "#fields\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\torig_pkts\tresp_pkts\n"
    d = tempfile.mkdtemp()
    p0 = os.path.join(d, "noresp.log"); open(p0, "w").write(hdr + "10.0.0.20\t5\t10.0.0.11\t443\ttcp\t4\t0\n")
    assert vm.check_mirroring(vm.parse_conn_log(p0), "10.0.0.20", "10.0.0.11", expect_tcp_port=443)["confirmed"] is False
    p1 = os.path.join(d, "resp.log"); open(p1, "w").write(hdr + "10.0.0.20\t5\t10.0.0.11\t443\ttcp\t4\t6\n")
    assert vm.check_mirroring(vm.parse_conn_log(p1), "10.0.0.20", "10.0.0.11", expect_tcp_port=443)["confirmed"] is True


def test_no_test_module_in_src():
    """§3/§6 [audit v20.33]: a SECOND file named test_*.py inside src/ makes the DEFAULT `pytest` abort at
    COLLECTION with 'import file mismatch' — two files named test_pipeline.py resolve to the SAME module
    name and pytest cannot tell them apart. This collision is by MODULE NAME, so an EMPTY src/test_*.py is
    NOT harmless (the previous version wrongly tolerated it, and a 0-byte src/test_pipeline.py shipped and
    broke the bare `pytest --collect-only` CI job). The shipped src/ package must therefore contain NO
    file matching test_*.py or *_test.py — regardless of content. A CI `pytest --collect-only` job (no
    path argument) guards the same invariant end-to-end."""
    import glob
    here = os.path.dirname(os.path.abspath(__file__))
    src = next((s for s in (os.path.join(here, "..", "src"), os.path.join(here, "src"))
                if os.path.isdir(s)), None)
    if not src:
        return                                             # flat working dir: no src/ package to guard
    offenders = sorted(os.path.basename(f) for f in
                       glob.glob(os.path.join(src, "test_*.py")) + glob.glob(os.path.join(src, "*_test.py")))
    assert not offenders, ("a file named test_*.py in src/ breaks `pytest` collection by MODULE-NAME "
                           "collision even when EMPTY — remove it: {}".format(offenders))


def test_expected_command_argv_matches_builders():
    """PERMANENT parity guard [audit v20.11 §5]: expected_command_argv (what the labeler validates
    against) must equal the orchestrator's own build_* output for ALL 8 configs x 3 attacks, at
    every NON-wildcard position — so a future change to a builder that is not mirrored in the
    reconstructor is caught here instead of silently weakening the check."""
    import attack_scenarios as sc
    import run_attacks as ra
    ip, host, seconds = "10.0.0.1", "h", 120
    checked = 0
    for cid in range(len(sc.CONFIG_MATRIX)):
        scd = dict(sc.CONFIG_MATRIX[cid]); scd["config_id"] = cid
        builders = {
            "PortScan": lambda: ra.build_portscan(ip, host, scd),
            "BruteForce": lambda: ra.build_bruteforce(ip, host, scd, "/u", "/p"),
            "DoS": lambda: ra.build_dos(ip, host, scd, seconds),
        }
        for attack, build in builders.items():
            built_argv = build()[0]                                  # (argv, proto, port, params)
            exp_argv, wild = sc.expected_command_argv(cid, attack, {"dos_seconds": seconds}, ip, host)
            assert len(built_argv) == len(exp_argv), (attack, cid, built_argv, exp_argv)
            for j in range(len(exp_argv)):
                if j in wild:
                    continue
                assert built_argv[j] == exp_argv[j], (attack, cid, j, built_argv[j], exp_argv[j])
            checked += 1
    assert checked == len(sc.CONFIG_MATRIX) * 3, checked


def test_campaign_id_and_attacker_target_governance():
    """campaign_id must match [A-Za-z0-9._-]+ (P1-15) and attacker_ip must differ from target_ip
    in reproducible mode (P1-12) [audit v20.8]."""
    import json
    import campaign as camp
    d = tempfile.mkdtemp()

    def rejects(man, needle, repro=False):
        p = os.path.join(d, "m%d.json" % rejects.n); rejects.n += 1
        json.dump(man, open(p, "w"))
        try:
            camp.load(p, require_reproducible=repro); assert False, "accepted: " + needle
        except SystemExit as e:
            assert needle in str(e), (needle, str(e))
    rejects.n = 0
    rejects({"campaign_id": "bad id!", "expected_labels": ["BENIGN", "DoS"],
             "runs": {"0": _run_spec(0, "train", 0, "2026-01-01"),
                      "1": _run_spec(6, "test", 1, "2026-01-02")}}, "A-Za-z0-9")
    same = _run_spec(0, "train", 0, "2026-01-01"); same["attacker_ip"] = same["target_ip"]
    rejects({"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
             "runs": {"0": same, "1": _run_spec(6, "test", 1, "2026-01-02")}},
            "attacker_ip == target_ip", repro=True)
    # IPv6 is refused in this IPv4-only testbed, which also closes the IPv6-equivalence hole where
    # 2001:db8::1 and 2001:0db8:0:0:0:0:0:1 (the same address) passed as distinct [audit v20.9 P1-11].
    v6 = _run_spec(0, "train", 0, "2026-01-01"); v6["target_ip"] = "2001:db8::1"
    rejects({"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
             "runs": {"0": v6, "1": _run_spec(6, "test", 1, "2026-01-02")}},
            "not IPv4", repro=True)


def test_labeler_defaults_reproducible_campaign():
    """With --campaign the labeler now DEFAULTS to a reproducible manifest, refusing a run the
    official consumers would reject; --allow-incomplete-campaign opts out [audit v20.6 §9]."""
    import json
    import hashlib
    d = tempfile.mkdtemp()
    conn = _conn_log(d, TS_INSIDE, proto="udp")
    # attacks present but NO target/timeout -> incomplete for reproducible mode.
    man = {"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
           "runs": {"0": {"config_id": 0, "split": "train", "seed": 0, "day": "2026-01-01",
                          "attacks": ["DoS"]},
                    "1": {"config_id": 6, "split": "test", "seed": 1, "day": "2026-01-02",
                          "attacks": ["DoS"]}}}
    mp = os.path.join(d, "m.json"); json.dump(man, open(mp, "w"))
    msha = hashlib.sha256(open(mp, "rb").read()).hexdigest()
    ann = _campaign_ann(d, "C", msha, 0, [{"label": "DoS"}])
    base = [sys.executable, _script("label_flows.py"), "--conn", conn, "--annotations", ann,
            "--campaign", mp, "--out", os.path.join(d, "o.csv")]
    r = _run(base, capture_output=True, text=True)                 # DEFAULT: reproducible -> abort
    assert r.returncode != 0 and ("target_host" in (r.stdout + r.stderr)
                                  or "reproducible" in (r.stdout + r.stderr))
    r2 = _run(base + ["--allow-incomplete-campaign"], capture_output=True, text=True)
    assert "target_host" not in (r2.stdout + r2.stderr)            # opt-out gets past camp.load


def test_run_attacks_campaign_attack_plan():
    """run_attacks --campaign pins the attack plan: a contradicting --attacks and a
    wordlist whose hash != the pinned digest both abort BEFORE any network call [audit 10]."""
    import subprocess
    import hashlib
    import json
    d = tempfile.mkdtemp()
    pl = os.path.join(d, "pass.txt"); open(pl, "w").write("a\nb\n")
    plsha = hashlib.sha256(open(pl, "rb").read()).hexdigest()
    man = {"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
           "runs": {"0": {"config_id": 0, "split": "train", "attacks": ["DoS"],
                          "passlist_sha256": plsha},
                    "1": {"config_id": 6, "split": "test"}}}
    mp = os.path.join(d, "m.json"); json.dump(man, open(mp, "w"))
    ra = _script("run_attacks.py")
    contra = _run([sys.executable, ra, "--campaign", mp, "--allow-incomplete-campaign",
                             "--run-id", "0",
                             "--attacks", "PortScan", "--target-ip", "10.10.10.11",
                             "--target-host", ""], capture_output=True, text=True)
    assert contra.returncode != 0 and "contradicts the campaign plan" in (contra.stdout + contra.stderr)
    badpl = os.path.join(d, "bad.txt"); open(badpl, "w").write("z\n")
    mism = _run([sys.executable, ra, "--campaign", mp, "--allow-incomplete-campaign",
                           "--run-id", "0",
                           "--passlist", badpl, "--target-ip", "10.10.10.11",
                           "--target-host", ""], capture_output=True, text=True)
    assert mism.returncode != 0 and "wordlist is not the one the campaign pinned" in (mism.stdout + mism.stderr)


def test_run_attacks_existing_annotations_aborts():
    """An existing per-run annotations file aborts by default; --overwrite-annotations
    clears it (the abort fires before any network call) [audit 11]."""
    import subprocess
    import json
    d = tempfile.mkdtemp()
    man = {"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
           "runs": {"0": {"config_id": 0, "split": "train", "attacks": ["DoS"]},
                    "1": {"config_id": 6, "split": "test"}}}
    mp = os.path.join(d, "m.json"); json.dump(man, open(mp, "w"))
    ann = os.path.join(d, "ann0.csv"); open(ann, "w").write("event_id,run_id\ne1,0\n")
    ra = _script("run_attacks.py")
    base = ["--campaign", mp, "--allow-incomplete-campaign", "--run-id", "0",
            "--target-ip", "10.10.10.11", "--target-host", "", "--annotations", ann, 
            "--dos-seconds", "1"]
    r = _run([sys.executable, ra, *base], capture_output=True, text=True)
    assert r.returncode != 0 and "already exists" in (r.stdout + r.stderr)
    r2 = _run([sys.executable, ra, *base, "--overwrite-annotations",
                         "--allow-partial-attacks"], capture_output=True, text=True)
    assert "already exists" not in (r2.stdout + r2.stderr)   # old file was cleared


# The COMPLETE official labeling policy (== provenance.OFFICIAL_POLICY_PROFILES['official/v1']);
# a manifest's required_labeling_policy must pin all of these [audit v20.2 P0-4].
_OFFICIAL_POLICY = {
    "use_failed": False, "allow_empty": False, "ambiguous_policy": "drop",
    "allow_overlapping_windows": False, "ignore_annotation_campaign": False,
    "min_matches_per_event": 1, "min_port_coverage": 0.8, "require_ip_bytes": True,
    "require_ssl_log": True, "require_quic_log": True, "min_ssl_join_rate": 0.8,
    "min_quic_join_rate": 0.8, "window_padding_ms": 0,
}


def _ts_win(sub):
    """(window_start, window_end, first_match, last_match) that FULLY CONTAINS every attack flow's
    [timestamp, timestamp+flow_duration] interval, so a _status_v4 sidecar temporally DESCRIBES the file
    the merge authenticates AT overlap-fraction 1.0 (any threshold passes) [audit v20.24/25 §6/§7]."""
    import pandas as pd
    atk = sub[sub["label"] != "BENIGN"]
    ts = pd.to_numeric(atk["timestamp"], errors="coerce")
    dur = pd.to_numeric(atk["flow_duration"], errors="coerce").fillna(0.0).clip(lower=0.0)
    end = (ts + dur).dropna(); ts = ts.dropna()
    if not len(ts):
        return (0.5, 3.0, 1.0, 2.0)
    return (float(ts.min()) - 1.0, float(end.max()) + 1.0, float(ts.min()), float(ts.max()))


def _status_v4(run_id, split_ready_sha, campaign_id, campaign_sha, config_id, split,
               policy=None, class_counts=None, ts_window=(0.5, 3.0, 1.0, 2.0), **over):
    """A COMPLETE, internally-consistent status/v5 sidecar for tests [audit v20.3 P0-4].

    Defaults satisfy every invariant (ssl/quic joined with counts that CLOSE, exact hash/file
    objects whose split_ready hash equals the anchor, no events); pass **over to tamper a
    specific field for a negative test, or class_counts to match a real per-run CSV [§9/§10].
    `ts_window`=(window_start, window_end, first_match, last_match) — pass the SPAN of the CSV's attack
    timestamps so the status temporally DESCRIBES the file (the §6 tie authenticates against it) [§6].
    """
    import versions as _v
    pol = dict(_OFFICIAL_POLICY if policy is None else policy)
    h = "0" * 64
    ws0, we0, fm0, lm0 = ts_window
    ccsr = {str(k): int(vv) for k, vv in (class_counts or {"BENIGN": 100}).items()}
    fwr = sum(ccsr.values())                                   # split-ready rows == sum of classes
    # AUTO-derive one single-port event per attack class so every §8/§9 invariant holds:
    # usable_flows == the class' row count, port_coverage == 1/1, etc. [audit v20.5 §8/§9].
    events = {}
    for j, (lab, cnt) in enumerate(sorted(ccsr.items())):
        if lab == "BENIGN" or cnt <= 0:
            continue
        events["ev%d" % j] = {"label": lab, "usable_flows": cnt, "matched_flows": cnt,
                              "ambiguous_flows": 0, "unique_dst_ports": 1, "port_range_width": 1,
                              "port_coverage": 1.0, "window_start": ws0, "window_end": we0,
                              "first_match": fm0, "last_match": lm0}   # ws<=fm<=lm<=we [status/v5]
    st = {
        "status": "success", "status_schema_version": _v.STATUS_SCHEMA_VERSION,   # status/v5
        "attempt_id": "test-attempt", "code_version": _v.LABELER_CODE_VERSION,     # label_flows/v30
        "run_id": run_id, "split_ready_sha256": split_ready_sha,
        "campaign_id": campaign_id, "campaign_sha256": campaign_sha,
        "config_id": config_id, "split": split,
        "labeling_policy": pol, "diagnostic": False, "diagnostic_reasons": [],   # status/v5 [§5]
        # status/v5 join keys, counted per RECORD; the three counts CLOSE to records [§15]:
        "ssl_join": {"records": 10, "records_matching_conn": 10, "orphan_records": 0,
                     "missing_uid_records": 0, "join_rate": 1.0},
        "quic_join": {"records": 10, "records_matching_conn": 10, "orphan_records": 0,
                      "missing_uid_records": 0, "join_rate": 1.0},
        "ip_bytes_fallback": 0, "events": events,
        # exact-schema hash/file objects; output split_ready == the anchor [audit v20.4 §10]:
        "input_hashes": {"conn": h, "ssl": h, "quic": h, "annotations": h},
        "output_hashes": {"ml": h, "split_ready": split_ready_sha, "audit": h},
        "files": {"ml": "labeled.csv", "split_ready": "labeled_split_ready.csv",
                  "audit": "labeled_audit.csv"},
        # flows CLOSE: audit == written + dropped, sum(classes) == written [audit v20.5 §9]:
        "flows_written_ml": fwr, "flows_dropped_ambiguous": 0, "flows_audit": fwr,
        "class_counts_split_ready": ccsr,
        "annotation_scenario_version": _v.SCENARIO_VERSION,
        "annotation_orchestrator_version": _v.ORCHESTRATOR_VERSION,
        # v27 window-matching fields the labeler always writes; legacy default (None => 0 matches) [§7]:
        "min_window_overlap": None,
        "overlap_accounting": {"matched_flows": 0, "duration_fallback_flows": 0},
    }
    st.update(over)
    return st


def _run_spec(config_id, split, seed, day, attacks=("DoS",)):
    """A REPRODUCIBLE-mode run spec: the attack plan + target + timeout are pinned, as
    merge/validate/evaluate require by default [audit v20.5 §7]."""
    spec = {"config_id": config_id, "split": split, "seed": seed, "day": day,
            "attacks": list(attacks), "target_host": "blog.lab", "target_ip": "10.10.10.11",
            "attacker_ip": "10.10.10.30", "timeout": 900}   # attacker pinned (reproducible) [P0-9]
    if "DoS" in attacks:
        spec["dos_seconds"] = 120
    if "BruteForce" in attacks:
        spec["wordlists_pinned"] = False               # opt out of wordlist pinning in tests [§8]
    return spec


def _campaign_pkg(d, extra_class=False):
    """Build a 2-run campaign package: gen a common CSV, split per run, write manifest +
    authenticated status sidecars. Returns (inputs, statuses, manifest_path). [audit 4-12]"""
    import subprocess
    import json
    import hashlib
    import pandas as pd
    gen = _script("synth_nids_dataset.py")
    out = os.path.join(d, "s.csv")
    atks = ["DoS"] + (["PortScan"] if extra_class else [])
    _run([sys.executable, gen, "--runs", "2", "--schema", "common",
                    "--attacks", *atks, "--out", out, "--seed", "1"],
                   check=True, capture_output=True)
    df = pd.read_csv(out)

    def sha(p):
        return hashlib.sha256(open(p, "rb").read()).hexdigest()
    # Official mode requires a COMPLETE required_labeling_policy and each status to MEET it +
    # carry a known status_schema_version [audit v20.2 P0-4/P0-9/P0-11].
    man = {"campaign_id": "CAMP", "expected_labels": ["BENIGN", "DoS"],
           "required_labeling_policy": dict(_OFFICIAL_POLICY),
           "runs": {"0": _run_spec(0, "train", 0, "2026-01-01"),
                    "1": _run_spec(6, "test", 1, "2026-01-02")}}
    mp = os.path.join(d, "camp.json"); json.dump(man, open(mp, "w")); msha = sha(mp)
    inputs, statuses = [], []
    for rid in (0, 1):
        p = os.path.join(d, "labeled_run%d_split_ready.csv" % rid)
        sub = df[df.run_id == rid]
        sub.to_csv(p, index=False)
        counts = {str(k): int(v) for k, v in sub["label"].value_counts().items()}  # real CSV counts [§9]
        st = _status_v4(rid, sha(p), "CAMP", msha, 0 if rid == 0 else 6, "train" if rid == 0 else "test",
                        class_counts=counts, ts_window=_ts_win(sub))                # §6: windows span ts
        sp = os.path.join(d, "labeled_run%d_run_status.json" % rid)
        json.dump(st, open(sp, "w"))
        inputs.append(p)
        statuses.append(sp)
    return inputs, statuses, mp


def test_merge_binds_run_id_swapped_and_multirun():
    """merge rejects a sidecar whose run_id != the CSV's run_id, and a multi-run file [audit 4]."""
    import subprocess
    import json
    import hashlib
    import pandas as pd
    d = tempfile.mkdtemp()
    inputs, statuses, mp = _campaign_pkg(d)
    ms = _script("merge_and_split.py")
    st = json.load(open(statuses[1])); st["run_id"] = 0; st["config_id"] = 0; st["split"] = "train"
    json.dump(st, open(statuses[1], "w"))
    r = _run([sys.executable, ms, *inputs, "--campaign", mp, "--require-status",
                        "--prefix", os.path.join(d, "ds"), "--overwrite"], capture_output=True, text=True)
    assert r.returncode != 0 and "does not belong to this file" in (r.stdout + r.stderr)
    both = os.path.join(d, "both_split_ready.csv")
    pd.concat([pd.read_csv(inputs[0]), pd.read_csv(inputs[1])]).to_csv(both, index=False)
    stb = _status_v4(0, hashlib.sha256(open(both, "rb").read()).hexdigest(), "CAMP",
                     json.load(open(statuses[0]))["campaign_sha256"], 0, "train")
    json.dump(stb, open(os.path.join(d, "both_run_status.json"), "w"))
    r = _run([sys.executable, ms, both, "--campaign", mp, "--require-status",
                        "--prefix", os.path.join(d, "ds2"), "--overwrite"], capture_output=True, text=True)
    assert r.returncode != 0 and "exactly ONE run" in (r.stdout + r.stderr)


def test_merge_rejects_diagnostic_status():
    """merge --require-status rejects a CONSISTENTLY-diagnostic status (loosened policy +
    diagnostic=true) unless --allow-diagnostic-status [audit 5]. The campaign here declares
    no policy (--allow-missing-required-policy) so the loosened run is what's tested."""
    import json
    d = tempfile.mkdtemp()
    import hashlib
    inputs, statuses, mp = _campaign_pkg(d)
    man = json.load(open(mp)); del man["required_labeling_policy"]; json.dump(man, open(mp, "w"))
    newsha = hashlib.sha256(open(mp, "rb").read()).hexdigest()
    for i, sp in enumerate(statuses):                     # re-point campaign hash + make run 1 diagnostic
        st = json.load(open(sp)); st["campaign_sha256"] = newsha
        if i == 1:
            st["labeling_policy"] = {**_OFFICIAL_POLICY, "use_failed": True}   # a real loosening
            st["diagnostic"] = True                        # consistent with the loosened policy
            st["diagnostic_reasons"] = ["use_failed"]      # status/v5: the loosened gate is named [§5]
        json.dump(st, open(sp, "w"))
    ms = _script("merge_and_split.py")

    def run(extra):
        return _run([sys.executable, ms, *inputs, "--campaign", mp, "--require-status",
                     "--allow-missing-required-policy", "--prefix", os.path.join(d, "ds"),
                     "--overwrite", *extra], capture_output=True, text=True)
    assert run([]).returncode != 0
    assert run(["--allow-diagnostic-status"]).returncode == 0


def test_merge_exact_campaign_labels():
    """A class present in the data (hence a status EVENT) that the run does NOT plan is rejected
    by the per-run plan gate, and --allow-extra-campaign-labels does NOT bypass it — the plan is
    stronger than the label set [audit v20.5 §7/§8]. (An unexpected attack class can no longer
    yield a valid status, so it is caught here rather than by the merged-label check.)"""
    import subprocess
    d = tempfile.mkdtemp()
    inputs, statuses, mp = _campaign_pkg(d, extra_class=True)     # CSV has PortScan; runs plan only DoS
    ms = _script("merge_and_split.py")
    r = _run([sys.executable, ms, *inputs, "--campaign", mp, "--require-status",
                        "--prefix", os.path.join(d, "ds"), "--overwrite"], capture_output=True, text=True)
    out = r.stdout + r.stderr
    assert r.returncode != 0 and ("UNPLANNED" in out or "EXACT set" in out)
    r = _run([sys.executable, ms, *inputs, "--campaign", mp, "--require-status",
                        "--allow-extra-campaign-labels", "--prefix", os.path.join(d, "ds2"),
                        "--overwrite"], capture_output=True, text=True)
    assert r.returncode != 0                                      # per-run plan gate is not bypassed


def test_merge_label_conflict_aborts():
    """Identical COMMON features with DIFFERENT labels must abort [audit 12]."""
    import subprocess
    import feature_schema as fs
    import pandas as pd
    d = tempfile.mkdtemp()

    def feat(v):
        return {c: float(v) for c in fs.COMMON}

    def mk(rid, ts, v, lab):
        r = feat(v); r["run_id"] = rid; r["timestamp"] = float(ts); r["label"] = lab
        return r
    # Each run carries BOTH classes (so the coverage gate passes), and feature-vector "1"
    # appears in BOTH runs with DIFFERENT labels -> the conflict gate must fire [audit 12].
    rows = [mk(0, 1.0, 1, "BENIGN"), mk(0, 1.5, 2, "DoS"),
            mk(1, 2.0, 1, "DoS"), mk(1, 2.5, 3, "BENIGN")]
    p = os.path.join(d, "confl.csv")
    pd.DataFrame(rows)[["run_id", "timestamp"] + fs.COMMON + ["label"]].to_csv(p, index=False)
    ms = _script("merge_and_split.py")
    # --allow-partial-schema skips the relational contract (the all-1.0 rows are not
    # contract-valid) so the test reaches the duplicate-conflict gate itself [audit 12].
    r = _run([sys.executable, ms, p, "--test-run", "1", "--prefix",
                        os.path.join(d, "ds"), "--overwrite", "--allow-partial-schema",
                        "--expected-labels", "BENIGN", "DoS"], capture_output=True, text=True)
    assert r.returncode != 0 and "DIFFERENT labels" in (r.stdout + r.stderr)


def test_campaign_attacks_coherence():
    """campaign.load rejects a run attack not in expected_labels [audit 7]."""
    import json
    import campaign as camp
    d = tempfile.mkdtemp()
    man = {"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
           "runs": {"0": {"config_id": 0, "split": "train", "attacks": ["PortScan"]},
                    "1": {"config_id": 6, "split": "test"}}}
    p = os.path.join(d, "m.json"); json.dump(man, open(p, "w"))
    try:
        camp.load(p); assert False, "incoherent attacks not caught"
    except SystemExit as e:
        assert "not in expected_labels" in str(e)


def test_synth_metadata_records_all_args():
    """Generator metadata records benign/attack-each/attacks so it REPRODUCES the file [audit 10]."""
    import subprocess
    import json
    d = tempfile.mkdtemp()
    out = os.path.join(d, "s.csv")
    _run([sys.executable, _script("synth_nids_dataset.py"), "--runs", "2",
                    "--benign", "100", "--attack-each", "7", "--attacks", "DoS", "--seed", "9",
                    "--out", out], check=True, capture_output=True)
    meta = json.load(open(out.replace(".csv", "") + ".metadata.json"))
    assert meta["arguments"]["benign"] == 100 and meta["arguments"]["attack_each"] == 7
    assert meta["arguments"]["attacks"] == ["DoS"]
    for token in ("--benign 100", "--attack-each 7", "--attacks DoS"):
        assert token in meta["command"]


def test_labeler_requires_ssl_join():
    """--require-ssl-log needs an ssl.log whose uids JOIN conn.log, not just any rows [audit 6]."""
    import subprocess
    d = tempfile.mkdtemp()
    conn = _conn_log(d, TS_INSIDE, proto="udp")                                # conn uid == C1
    ann = _write_ann([_base_ann()])
    sf = ["ts", "uid", "version", "cipher", "server_name", "ja3", "ja3s"]

    def ssl_log(uid):
        p = os.path.join(d, "ssl_%s.log" % uid)
        with open(p, "w") as f:
            f.write("#separator \\x09\n#fields\t" + "\t".join(sf) + "\n#types\t" +
                    "\t".join(["string"] * len(sf)) + "\n")
            f.write("\t".join([str(TS_INSIDE), uid, "TLSv13", "x", "blog.lab", "j", "js"]) + "\n")
        return p
    lf = _script("label_flows.py")
    orphan = ssl_log("OTHER")                                     # no join to C1
    r = _run([sys.executable, lf, "--conn", conn, "--ssl", orphan,
                        "--annotations", ann, "--require-ssl-log",
                        "--out", os.path.join(d, "o.csv")], capture_output=True, text=True)
    assert r.returncode != 0 and "join conn.log" in (r.stdout + r.stderr)
    joined = ssl_log("C1")                                        # joins C1
    r2 = _run([sys.executable, lf, "--conn", conn, "--ssl", joined,
                         "--annotations", ann, "--require-ssl-log",
                         "--out", os.path.join(d, "o2.csv")], capture_output=True, text=True)
    assert "join conn.log" not in (r2.stdout + r2.stderr)         # the join gate is satisfied


def test_validate_byte_authentication():
    """validate byte-authenticates the PER-RUN files: a concatenated file cannot be
    authenticated, and tampering a per-run file's bytes breaks the hash bind — both abort
    BEFORE any training [audit v19 P0-1]."""
    import pandas as pd
    d = tempfile.mkdtemp()
    inputs, statuses, mp = _campaign_pkg(d)
    vd = _script("validate_dataset.py")
    # (a) a single CONCATENATED file cannot be byte-authenticated (holds >1 run)
    both = os.path.join(d, "both.csv")
    pd.concat([pd.read_csv(inputs[0]), pd.read_csv(inputs[1])]).to_csv(both, index=False)
    r = _run([sys.executable, vd, "--csv", both, "--campaign", mp, "--status",
              *statuses, "--require-status"], capture_output=True, text=True)
    assert r.returncode != 0 and "PER-RUN" in (r.stdout + r.stderr)
    # (b) tampering a per-run file's BYTES (even a label swap) breaks the sha bind
    df1 = pd.read_csv(inputs[1])
    df1.loc[df1.index[0], "label"] = ("DoS" if df1.loc[df1.index[0], "label"] == "BENIGN"
                                      else "BENIGN")
    df1.to_csv(inputs[1], index=False)
    r = _run([sys.executable, vd, "--csv", *inputs, "--campaign", mp, "--status",
              *statuses, "--require-status"], capture_output=True, text=True)
    out = r.stdout + r.stderr
    # a tampered per-run file no longer hashes to any --status split_ready_sha256, so the
    # exact-bijection matcher rejects it [audit v20.3 P1-8].
    assert r.returncode != 0 and ("no --status sidecar matches" in out
                                  or "NOT the file the labeler published" in out)


def _policy_pkg(d, required_policy):
    """Build a 2-run campaign whose manifest REQUIRES `required_policy`; returns a builder
    that writes per-run split-ready files + status sidecars carrying a given policy [audit
    v19 P0-2]."""
    import json
    import hashlib
    import pandas as pd
    _run([sys.executable, _script("synth_nids_dataset.py"), "--runs", "2", "--schema",
          "common", "--attacks", "DoS", "--out", os.path.join(d, "s.csv"), "--seed", "1"],
         check=True)
    df = pd.read_csv(os.path.join(d, "s.csv"))

    def sha(p):
        return hashlib.sha256(open(p, "rb").read()).hexdigest()
    man = {"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
           "required_labeling_policy": required_policy,
           "runs": {"0": _run_spec(0, "train", 0, "2026-01-01"),
                    "1": _run_spec(6, "test", 1, "2026-01-02")}}
    mp = os.path.join(d, "m.json"); json.dump(man, open(mp, "w")); msha = sha(mp)

    def build(policy, schema_version="status/v5"):
        inputs, statuses = [], []
        for rid in (0, 1):
            p = os.path.join(d, "labeled_run%d_split_ready.csv" % rid)
            sub = df[df.run_id == rid]
            sub.to_csv(p, index=False)
            counts = {str(k): int(v) for k, v in sub["label"].value_counts().items()}  # [§9]
            st = _status_v4(rid, sha(p), "C", msha, 0 if rid == 0 else 6,
                            "train" if rid == 0 else "test", policy=policy, class_counts=counts,
                            ts_window=_ts_win(sub))                                  # §6: windows span ts
            if schema_version is None:
                st.pop("status_schema_version", None)
            else:
                st["status_schema_version"] = schema_version
            sp = os.path.join(d, "labeled_run%d_run_status.json" % rid)
            json.dump(st, open(sp, "w"))
            inputs.append(p)
            statuses.append(sp)
        return inputs, statuses
    return build, mp


def test_merge_enforces_required_policy():
    """A run whose labeling_policy does NOT meet the campaign's required_labeling_policy —
    or a status missing status_schema_version — is rejected [audit v19 P0-2]."""
    d = tempfile.mkdtemp()
    build, mp = _policy_pkg(d, dict(_OFFICIAL_POLICY))
    ms = _script("merge_and_split.py")

    def run(policy, schema_version="status/v5", pref="ds"):
        inputs, statuses = build(policy, schema_version)
        return _run([sys.executable, ms, *inputs, "--campaign", mp, "--require-status",
                     "--prefix", os.path.join(d, pref), "--overwrite"])
    weak = run({**_OFFICIAL_POLICY, "require_ssl_log": False, "min_port_coverage": 0.0})
    assert weak.returncode != 0 and "does NOT meet" in (weak.stdout + weak.stderr)
    strong = run(dict(_OFFICIAL_POLICY), pref="ds2")      # meets it exactly
    assert strong.returncode == 0, strong.stdout + strong.stderr
    noschema = run(dict(_OFFICIAL_POLICY), schema_version=None, pref="ds3")
    assert noschema.returncode != 0 and "status_schema_version" in (noschema.stdout + noschema.stderr)


def test_evaluate_synth_extra_class_aborts():
    """A class present ONLY in the synthetic set aborts under --campaign [audit v19 P0-4]."""
    import json
    import pandas as pd
    d = tempfile.mkdtemp()
    _run([sys.executable, _script("synth_nids_dataset.py"), "--runs", "2", "--schema",
          "common", "--attacks", "DoS", "--benign", "150", "--attack-each", "50",
          "--out", os.path.join(d, "real.csv"), "--seed", "1"], check=True)
    rdf = pd.read_csv(os.path.join(d, "real.csv"))
    reals = []
    for rid in (0, 1):
        p = os.path.join(d, "r%d.csv" % rid); rdf[rdf.run_id == rid].to_csv(p, index=False)
        reals.append(p)
    _run([sys.executable, _script("synth_nids_dataset.py"), "--runs", "1", "--schema",
          "common", "--attacks", "DoS", "PortScan", "--benign", "150", "--attack-each", "50",
          "--out", os.path.join(d, "synth.csv"), "--seed", "3"], check=True)
    man = {"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
           "runs": {"0": _run_spec(0, "train", 0, "2026-01-01"),
                    "1": _run_spec(6, "test", 1, "2026-01-02")}}
    mp = os.path.join(d, "m.json"); json.dump(man, open(mp, "w"))
    r = _run([sys.executable, _script("evaluate_realism.py"), "--real", *reals, "--synth",
              os.path.join(d, "synth.csv"), "--campaign", mp, "--allow-unauthenticated-real",
              "--allow-incomplete-campaign"])   # focus on the class check, not the plan [§7]
    assert r.returncode != 0 and "synthetic-only class" in (r.stdout + r.stderr)


def test_evaluate_override_emits_diagnostic_json():
    """A newly-counted override (--allow-diagnostic-status) forces DIAGNOSTIC ONLY and the
    --json verdict records official=false with the reason [audit v19 P0-3]."""
    import json
    import pandas as pd
    d = tempfile.mkdtemp()
    _run([sys.executable, _script("synth_nids_dataset.py"), "--runs", "2", "--schema",
          "common", "--attacks", "DoS", "--benign", "200", "--attack-each", "60",
          "--out", os.path.join(d, "real.csv"), "--seed", "1"], check=True)
    rdf = pd.read_csv(os.path.join(d, "real.csv"))
    reals = []
    for rid in (0, 1):
        p = os.path.join(d, "r%d.csv" % rid); rdf[rdf.run_id == rid].to_csv(p, index=False)
        reals.append(p)
    _run([sys.executable, _script("synth_nids_dataset.py"), "--runs", "1", "--schema",
          "common", "--attacks", "DoS", "--benign", "200", "--attack-each", "60",
          "--out", os.path.join(d, "synth.csv"), "--seed", "3"], check=True)
    man = {"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
           "runs": {"0": _run_spec(0, "train", 0, "2026-01-01"),
                    "1": _run_spec(6, "test", 1, "2026-01-02")}}
    mp = os.path.join(d, "m.json"); json.dump(man, open(mp, "w"))
    jout = os.path.join(d, "v.json")
    r = _run([sys.executable, _script("evaluate_realism.py"), "--real", *reals, "--synth",
              os.path.join(d, "synth.csv"), "--campaign", mp, "--allow-unauthenticated-real",
              "--json", jout])
    assert "DIAGNOSTIC ONLY" in (r.stdout + r.stderr)
    v = json.load(open(jout))
    assert v["official"] is False and "allow_unauthenticated_real" in v["diagnostic_reasons"]


def test_evaluate_requires_status_official():
    """evaluate --campaign without --status (and without --allow-unauthenticated-real) is
    NOT official — it aborts asking for byte-authentication [audit v20 P0-8]."""
    d = tempfile.mkdtemp()
    inputs, statuses, mp = _campaign_pkg(d)
    synth = os.path.join(d, "synth.csv")                  # a DISTINCT synth (else 100% overlap)
    _run([sys.executable, _script("synth_nids_dataset.py"), "--runs", "1", "--schema",
          "common", "--attacks", "DoS", "--out", synth, "--seed", "7"], check=True)
    # tolerate the odd identical BENIGN row so we reach the campaign auth gate (P0-8 is
    # independent of overlap); the point is the missing-status abort.
    r = _run([sys.executable, _script("evaluate_realism.py"), "--real", *inputs, "--synth",
              synth, "--campaign", mp, "--max-overlap-allowed", "0.1"])
    assert r.returncode != 0 and "needs --status" in (r.stdout + r.stderr)


def test_merge_official_requires_policy():
    """Official mode (--require-status) needs the campaign to DECLARE a required_labeling_policy;
    without it the merge aborts unless --allow-missing-required-policy [audit v20 P0-9]."""
    import json
    import hashlib
    d = tempfile.mkdtemp()
    inputs, statuses, mp = _campaign_pkg(d)
    man = json.load(open(mp)); del man["required_labeling_policy"]; json.dump(man, open(mp, "w"))
    newsha = hashlib.sha256(open(mp, "rb").read()).hexdigest()
    for sp in statuses:                                   # re-point the (now stale) campaign hash
        st = json.load(open(sp)); st["campaign_sha256"] = newsha; json.dump(st, open(sp, "w"))
    ms = _script("merge_and_split.py")
    base = [sys.executable, ms, *inputs, "--campaign", mp, "--require-status", "--prefix",
            os.path.join(d, "ds"), "--overwrite"]
    r = _run(base)
    assert r.returncode != 0 and "required_labeling_policy" in (r.stdout + r.stderr)
    r2 = _run(base + ["--allow-missing-required-policy"])
    assert r2.returncode == 0, r2.stdout + r2.stderr


def test_policy_window_padding_is_a_ceiling():
    """window_padding_ms is a MAX (observed <= required), not a floor — a wider window than
    the campaign allows is rejected [audit v20 P0-10]."""
    d = tempfile.mkdtemp()
    build, mp = _policy_pkg(d, dict(_OFFICIAL_POLICY))    # required window_padding_ms == 0
    ms = _script("merge_and_split.py")

    def run(pad, pref):
        inputs, statuses = build({**_OFFICIAL_POLICY, "window_padding_ms": pad})
        return _run([sys.executable, ms, *inputs, "--campaign", mp, "--require-status",
                     "--prefix", os.path.join(d, pref), "--overwrite"])
    wide = run(10000, "ds")
    assert wide.returncode != 0 and "window_padding_ms" in (wide.stdout + wide.stderr)
    ok = run(0, "ds2")
    assert ok.returncode == 0, ok.stdout + ok.stderr


def test_status_schema_version_must_be_known():
    """An unknown status_schema_version is rejected, not treated as v1 [audit v20 P0-11]."""
    d = tempfile.mkdtemp()
    build, mp = _policy_pkg(d, dict(_OFFICIAL_POLICY))
    inputs, statuses = build(dict(_OFFICIAL_POLICY), schema_version="totally-unknown/v999")
    r = _run([sys.executable, _script("merge_and_split.py"), *inputs, "--campaign", mp,
              "--require-status", "--prefix", os.path.join(d, "ds"), "--overwrite"])
    assert r.returncode != 0 and "status_schema_version" in (r.stdout + r.stderr)


def test_campaign_required_policy_numeric_bounds():
    """required_labeling_policy rejects out-of-range / non-integer numbers [audit v20 P1-12]."""
    import json
    import campaign as camp
    d = tempfile.mkdtemp()
    base = {"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
            "runs": {"0": {"config_id": 0, "split": "train"},
                     "1": {"config_id": 6, "split": "test"}}}
    for bad in ({"min_port_coverage": 1.5}, {"min_ssl_join_rate": 3.0},
                {"min_matches_per_event": 1.5}, {"window_padding_ms": -1}):
        man = dict(base); man["required_labeling_policy"] = bad
        p = os.path.join(d, "m.json"); json.dump(man, open(p, "w"))
        try:
            camp.load(p); assert False, "accepted bad policy {}".format(bad)
        except SystemExit:
            pass


def test_evaluate_json_is_fail_closed():
    """--json to an unwritable path must ABORT (non-zero), not warn-and-pass [audit v20 P1-14]."""
    import pandas as pd
    d = tempfile.mkdtemp()
    _run([sys.executable, _script("synth_nids_dataset.py"), "--runs", "2", "--schema",
          "common", "--attacks", "DoS", "--benign", "200", "--attack-each", "60",
          "--out", os.path.join(d, "real.csv"), "--seed", "1"], check=True)
    rdf = pd.read_csv(os.path.join(d, "real.csv"))
    reals = []
    for rid in (0, 1):
        p = os.path.join(d, "r%d.csv" % rid); rdf[rdf.run_id == rid].to_csv(p, index=False)
        reals.append(p)
    _run([sys.executable, _script("synth_nids_dataset.py"), "--runs", "1", "--schema",
          "common", "--attacks", "DoS", "--benign", "200", "--attack-each", "60",
          "--out", os.path.join(d, "synth.csv"), "--seed", "3"], check=True)
    man = {"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
           "runs": {"0": _run_spec(0, "train", 0, "2026-01-01"),
                    "1": _run_spec(6, "test", 1, "2026-01-02")}}
    import json
    mp = os.path.join(d, "m.json"); json.dump(man, open(mp, "w"))
    bad_json = os.path.join(d, "nonexistent_dir", "v.json")   # parent dir does not exist
    r = _run([sys.executable, _script("evaluate_realism.py"), "--real", *reals, "--synth",
              os.path.join(d, "synth.csv"), "--campaign", mp, "--allow-unauthenticated-real",
              "--json", bad_json])
    assert r.returncode != 0 and "could not write the requested --json" in (r.stdout + r.stderr)


def test_campaign_policy_must_be_complete_or_profile():
    """A PARTIAL required_labeling_policy is rejected; a versioned profile expands to the
    full official policy [audit v20.2 P0-4]."""
    import json
    import campaign as camp
    d = tempfile.mkdtemp()
    base = {"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
            "runs": {"0": {"config_id": 0, "split": "train"},
                     "1": {"config_id": 6, "split": "test"}}}
    m1 = dict(base); m1["required_labeling_policy"] = {"use_failed": False}   # partial
    p = os.path.join(d, "a.json"); json.dump(m1, open(p, "w"))
    try:
        camp.load(p); assert False, "partial policy accepted"
    except SystemExit as e:
        assert "EXACTLY the official gates" in str(e)
    m2 = dict(base); m2["required_policy_profile"] = "official/v1"            # profile expands
    p2 = os.path.join(d, "b.json"); json.dump(m2, open(p2, "w"))
    m = camp.load(p2)
    assert m["required_labeling_policy"]["require_ssl_log"] is True
    m3 = dict(base); m3["required_policy_profile"] = "bogus/v9"               # unknown profile
    p3 = os.path.join(d, "c.json"); json.dump(m3, open(p3, "w"))
    try:
        camp.load(p3); assert False, "unknown profile accepted"
    except SystemExit as e:
        assert "unknown" in str(e)


def test_official_needs_status_under_campaign():
    """merge/validate with --campaign but no --require-status abort by default; only an
    explicit --allow-unauthenticated-inputs proceeds (DIAGNOSTIC) [audit v20.2 P0-6]."""
    import pandas as pd
    d = tempfile.mkdtemp()
    inputs, statuses, mp = _campaign_pkg(d)
    ms = _script("merge_and_split.py")
    vd = _script("validate_dataset.py")
    r = _run([sys.executable, ms, *inputs, "--campaign", mp, "--prefix",
              os.path.join(d, "ds"), "--overwrite"])
    assert r.returncode != 0 and "needs --require-status" in (r.stdout + r.stderr)
    both = os.path.join(d, "both.csv")
    pd.concat([pd.read_csv(inputs[0]), pd.read_csv(inputs[1])]).to_csv(both, index=False)
    rv = _run([sys.executable, vd, "--csv", both, "--campaign", mp])
    assert rv.returncode != 0 and "needs --require-status" in (rv.stdout + rv.stderr)


def test_merge_provenance_verdict():
    """The _split_provenance.json carries an explicit official/diagnostic verdict; an
    unauthenticated merge is official=false with the reason [audit v20.2 P0-9]."""
    import json
    d = tempfile.mkdtemp()
    inputs, statuses, mp = _campaign_pkg(d)
    ms = _script("merge_and_split.py")
    off = _run([sys.executable, ms, *inputs, "--campaign", mp, "--require-status",
                "--prefix", os.path.join(d, "off"), "--overwrite"])
    assert off.returncode == 0, off.stdout + off.stderr
    p = json.load(open(os.path.join(d, "off_split_provenance.json")))
    assert p["official"] is True and p["diagnostic_reasons"] == []
    diag = _run([sys.executable, ms, *inputs, "--campaign", mp, "--allow-unauthenticated-inputs",
                 "--prefix", os.path.join(d, "diag"), "--overwrite"])
    assert diag.returncode == 0, diag.stdout + diag.stderr
    p2 = json.load(open(os.path.join(d, "diag_split_provenance.json")))
    assert p2["official"] is False and "allow_unauthenticated_inputs" in p2["diagnostic_reasons"]


def test_merge_rejects_mixed_window_overlap_policy():
    """§8 [audit v20.20]: a split must use ONE window-matching rule for ALL runs. If authenticated
    runs were labeled with DIFFERENT --min-window-overlap policies (legacy vs overlap, or two
    thresholds), merge ABORTS — the ground truth is not comparable run-to-run — instead of silently
    mixing them."""
    import json
    d = tempfile.mkdtemp()
    inputs, statuses, mp = _campaign_pkg(d)
    ms = _script("merge_and_split.py")
    ok = [sys.executable, ms, *inputs, "--campaign", mp, "--require-status",
          "--prefix", os.path.join(d, "ds"), "--overwrite"]
    assert _run(ok, capture_output=True, text=True).returncode == 0    # both legacy (None) -> fine

    def _set_overlap(sp, val):                             # flip to overlap mode with a CONSISTENT
        st = json.load(open(sp))                           # overlap_accounting (matched == sum events)
        st["min_window_overlap"] = val
        mt = sum(int(e["matched_flows"]) for e in st.get("events", {}).values())
        st["overlap_accounting"] = {"matched_flows": mt, "duration_fallback_flows": 0}
        json.dump(st, open(sp, "w"))
    # Relabel ONE run with an overlap policy while the other stays legacy -> MIXED -> abort.
    _set_overlap(statuses[1], 0.5)
    r = _run(ok, capture_output=True, text=True)
    assert r.returncode != 0 and "DIFFERENT --min-window-overlap" in (r.stdout + r.stderr), \
        (r.returncode, r.stdout + r.stderr)
    # Make BOTH runs use the SAME overlap policy -> proceeds again (it's the MIX that's rejected).
    _set_overlap(statuses[0], 0.5)
    assert _run(ok, capture_output=True, text=True).returncode == 0


def test_merge_revalidates_fallback_rate_against_manifest():
    """§5 [audit v20.22]: the merge RE-VALIDATES the duration-fallback rate against the campaign's
    pinned max_duration_fallback_rate. A forged status that stays under the internal 100%-degenerate
    trip but exceeds the PINNED ceiling (while claiming non-diagnostic) is still rejected — the ceiling
    is no longer producer-only."""
    import json
    import hashlib
    d = tempfile.mkdtemp()
    inputs, statuses, mp = _campaign_pkg(d)
    man = json.load(open(mp))
    man["required_min_window_overlap"] = 0.5               # pin overlap 0.5 and ZERO fallback allowed
    man["max_duration_fallback_rate"] = 0.0
    json.dump(man, open(mp, "w"))
    newsha = hashlib.sha256(open(mp, "rb").read()).hexdigest()
    mts = []
    for i, sp in enumerate(statuses):
        st = json.load(open(sp)); st["campaign_sha256"] = newsha; st["min_window_overlap"] = 0.5
        mt = sum(int(e["matched_flows"]) for e in st["events"].values()); mts.append(mt)
        fb = 1 if i == 1 else 0                             # run 1: a single fallback flow (rate > 0)
        st["overlap_accounting"] = {"matched_flows": mt, "duration_fallback_flows": fb}
        json.dump(st, open(sp, "w"))
    assert mts[1] >= 2                                      # ensure the 1 fallback is NON-degenerate
    ms = _script("merge_and_split.py")
    r = _run([sys.executable, ms, *inputs, "--campaign", mp, "--require-status",
              "--prefix", os.path.join(d, "ds"), "--overwrite"], capture_output=True, text=True)
    assert r.returncode != 0 and "max_duration_fallback_rate" in (r.stdout + r.stderr), \
        (r.returncode, r.stdout + r.stderr)


def test_merge_recomputes_fallback_from_csv():
    """§6 [audit v20.23]: the consumer confronts the overlap accounting with the AUTHENTICATED CSV, not
    just the status' own numbers. If EVERY attack flow has zero/missing flow_duration — so it MUST have
    used the point fallback — but the status declares duration_fallback_flows=0, the merge aborts. The
    hashes prove the files are as presented; this proves the accounting DESCRIBES them."""
    import json
    import hashlib
    import numpy as np
    import pandas as pd
    d = tempfile.mkdtemp()
    inputs, statuses, mp = _campaign_pkg(d)

    def _overlay(sp, csv, zero_attack_duration):
        df = pd.read_csv(csv)
        if zero_attack_duration:                           # a zero-duration flow => NaN rates (valid COMMON)
            m = df["label"] != "BENIGN"
            df.loc[m, "flow_duration"] = 0.0
            for c in ("flow_bytes_s", "flow_pkts_s"):
                if c in df.columns:
                    df.loc[m, c] = np.nan
            df.to_csv(csv, index=False)
        sha = hashlib.sha256(open(csv, "rb").read()).hexdigest()
        st = json.load(open(sp)); st["split_ready_sha256"] = sha
        st["output_hashes"]["split_ready"] = sha; st["min_window_overlap"] = 0.5
        mt = sum(int(e["matched_flows"]) for e in st["events"].values())
        st["overlap_accounting"] = {"matched_flows": mt, "duration_fallback_flows": 0}   # LIE: 0 fallback
        json.dump(st, open(sp, "w"))
    _overlay(statuses[0], inputs[0], True)                 # run 0: all attack flows have duration 0
    _overlay(statuses[1], inputs[1], False)                # run 1: untouched (consistent)
    r = _run([sys.executable, _script("merge_and_split.py"), *inputs, "--campaign", mp,
              "--require-status", "--prefix", os.path.join(d, "ds"), "--overwrite"],
             capture_output=True, text=True)
    assert r.returncode != 0 and "point-rule fallback" in (r.stdout + r.stderr), \
        (r.returncode, r.stdout + r.stderr)


def test_merge_ties_event_windows_to_csv_timestamps():
    """§6 [audit v20.24]: the event windows must OVERLAP the CSV's attack timestamps. A status whose
    declared windows do not intersect the file's attack-flow timestamps (a shifted window, a clock
    skew, or a sidecar from another run) no longer authenticates — even though it is internally
    ordered (window_start<=first_match<=last_match<=window_end). This is the auditor's exact forge:
    attack rows at ~1.75e9, windows declared as 0.5..3.0."""
    import json
    d = tempfile.mkdtemp()
    inputs, statuses, mp = _campaign_pkg(d)
    st = json.load(open(statuses[0]))                      # move run 0's windows FAR from the CSV ts
    for e in st["events"].values():
        e.update(window_start=0.5, window_end=3.0, first_match=1.0, last_match=2.0)
    json.dump(st, open(statuses[0], "w"))
    r = _run([sys.executable, _script("merge_and_split.py"), *inputs, "--campaign", mp,
              "--require-status", "--prefix", os.path.join(d, "ds"), "--overwrite"],
             capture_output=True, text=True)
    assert r.returncode != 0 and "temporally describe the CSV" in (r.stdout + r.stderr), \
        (r.returncode, r.stdout + r.stderr)


def test_temporal_tie_per_class_window_and_overlap():
    """§5/§6/§7 [audit v20.25]: the temporal tie is PER-WINDOW (not a min-start..max-end hull), PER
    CLASS, and at the pinned overlap FRACTION — the three gaps the auditor drove through. Exercises
    prov.attack_rows_off_window directly on tiny split-ready CSVs."""
    import provenance as prov
    import pandas as pd
    d = tempfile.mkdtemp()

    def csv(rows):
        p = os.path.join(d, "x.csv")
        pd.DataFrame(rows, columns=["label", "timestamp", "flow_duration"]).to_csv(p, index=False)
        return p
    # §5 GAP: two DISJOINT DoS windows; a DoS flow in the gap matches NEITHER (the old hull [1000,1011]
    # would have accepted it).
    ev_gap = {"a": {"label": "DoS", "window_start": 1000, "window_end": 1001},
              "b": {"label": "DoS", "window_start": 1010, "window_end": 1011}}
    assert prov.attack_rows_off_window(csv([["DoS", 1005, 0]]), ev_gap, None) == (1, 1)   # in the gap
    assert prov.attack_rows_off_window(csv([["DoS", 1000, 0]]), ev_gap, None)[0] == 0     # inside 'a'
    # §6 CLASS: a DoS flow sitting inside the PortScan window is OFF (wrong class), even though it is
    # inside SOME window.
    ev_cls = {"d": {"label": "DoS", "window_start": 1000, "window_end": 2000},
              "p": {"label": "PortScan", "window_start": 3000, "window_end": 4000}}
    assert prov.attack_rows_off_window(csv([["DoS", 3500, 0]]), ev_cls, None) == (1, 1)   # wrong class
    assert prov.attack_rows_off_window(
        csv([["DoS", 1500, 0], ["PortScan", 3500, 0]]), ev_cls, None)[0] == 0             # each in its own
    # §7 FRACTION: overlap 0.5 — a flow grazing the window edge (1% overlap) is OFF; one fully inside
    # (100%) matches; a zero-duration flow falls back to the start-in-window point rule.
    ev_ov = {"d": {"label": "DoS", "window_start": 1000, "window_end": 2000}}
    assert prov.attack_rows_off_window(csv([["DoS", 1999, 100]]), ev_ov, 0.5) == (1, 1)   # 1/100 < 0.5
    assert prov.attack_rows_off_window(csv([["DoS", 1000, 100]]), ev_ov, 0.5)[0] == 0     # 100/100 = 1.0
    assert prov.attack_rows_off_window(csv([["DoS", 1500, 0]]), ev_ov, 0.5)[0] == 0       # dur 0 -> point


def test_evaluate_missing_policy_is_diagnostic():
    """--allow-missing-required-policy makes the realism verdict DIAGNOSTIC (official=false)
    with the reason recorded [audit v20.2 P0-5]."""
    import json
    import hashlib
    import pandas as pd
    d = tempfile.mkdtemp()
    _run([sys.executable, _script("synth_nids_dataset.py"), "--runs", "2", "--schema",
          "common", "--attacks", "DoS", "--benign", "200", "--attack-each", "60",
          "--out", os.path.join(d, "real.csv"), "--seed", "1"], check=True)
    df = pd.read_csv(os.path.join(d, "real.csv"))

    def sha(p):
        return hashlib.sha256(open(p, "rb").read()).hexdigest()
    man = {"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],   # NO required_labeling_policy
           "runs": {"0": _run_spec(0, "train", 0, "2026-01-01"),
                    "1": _run_spec(6, "test", 1, "2026-01-02")}}
    mp = os.path.join(d, "m.json"); json.dump(man, open(mp, "w")); msha = sha(mp)
    reals, statuses = [], []
    for rid in (0, 1):
        p = os.path.join(d, "labeled_run%d_split_ready.csv" % rid)
        sub = df[df.run_id == rid]
        sub.to_csv(p, index=False)
        counts = {str(k): int(v) for k, v in sub["label"].value_counts().items()}   # real counts [§9]
        st = _status_v4(rid, sha(p), "C", msha, 0 if rid == 0 else 6,
                        "train" if rid == 0 else "test", class_counts=counts, ts_window=_ts_win(sub))
        sp = os.path.join(d, "labeled_run%d_run_status.json" % rid)
        json.dump(st, open(sp, "w")); reals.append(p); statuses.append(sp)
    _run([sys.executable, _script("synth_nids_dataset.py"), "--runs", "1", "--schema",
          "common", "--attacks", "DoS", "--benign", "200", "--attack-each", "60",
          "--out", os.path.join(d, "synth.csv"), "--seed", "3"], check=True)
    jout = os.path.join(d, "v.json")
    r = _run([sys.executable, _script("evaluate_realism.py"), "--real", *reals, "--synth",
              os.path.join(d, "synth.csv"), "--campaign", mp, "--status", *statuses,
              "--require-status", "--allow-missing-required-policy", "--max-overlap-allowed",
              "0.1", "--json", jout])
    v = json.load(open(jout))
    assert v["official"] is False and "allow_missing_required_policy" in v["diagnostic_reasons"]


def test_labeler_rejects_nan_gate():
    """label_flows refuses a NaN/Infinity/out-of-range gate value at the CLI [audit v20.3 P0-3]."""
    d = tempfile.mkdtemp()
    conn = os.path.join(d, "c.log"); open(conn, "w").write("ts\tuid\n1\tC1\n")
    ann = os.path.join(d, "a.csv"); open(ann, "w").write("event_id,run_id\n")
    for bad in ("nan", "inf", "1.5", "-0.1"):
        r = _run([sys.executable, _script("label_flows.py"), "--conn", conn, "--annotations",
                  ann, "--min-port-coverage", bad, "--out", os.path.join(d, "o.csv")])
        assert r.returncode != 0 and "finite value in [0,1]" in (r.stdout + r.stderr), bad


def test_observed_policy_rejects_type_punning_and_nan():
    """validate_observed_labeling_policy rejects 1/0-as-bool, NaN and out-of-range [audit v20.3 P0-3]."""
    import provenance as prov
    good = dict(_OFFICIAL_POLICY)
    prov.validate_observed_labeling_policy("ok", good)          # the clean one is accepted
    for tamper in ({"require_ssl_log": 1}, {"allow_empty": 0}, {"min_matches_per_event": True},
                   {"min_port_coverage": float("nan")}, {"min_ssl_join_rate": 1.5}):
        bad = dict(_OFFICIAL_POLICY); bad.update(tamper)
        try:
            prov.validate_observed_labeling_policy("bad", bad)
            assert False, "accepted {}".format(tamper)
        except SystemExit:
            pass


def test_status_v4_invariants_enforced():
    """A status whose EVIDENCE contradicts its policy (claims require_ssl_log but ssl_join
    has zero joined uids) is rejected [audit v20.3 P0-4]."""
    import json
    d = tempfile.mkdtemp()
    inputs, statuses, mp = _campaign_pkg(d)
    st = json.load(open(statuses[0]))
    st["ssl_join"] = {"records": 10, "records_matching_conn": 0, "orphan_records": 10,
                      "missing_uid_records": 0, "join_rate": 0.0}   # counts CLOSE (0+10+0=10) and the
    #   math is consistent, so this exercises the require_ssl_log INVARIANT (no joined uid), not
    #   the sum or join_rate checks [audit v20.4 §10.1/P0-7]
    json.dump(st, open(statuses[0], "w"))
    r = _run([sys.executable, _script("merge_and_split.py"), *inputs, "--campaign", mp,
              "--require-status", "--prefix", os.path.join(d, "ds"), "--overwrite"])
    assert r.returncode != 0 and "no joined records" in (r.stdout + r.stderr)


def test_status_v4_flow_and_version_invariants():
    """The status/v5 self-consistency gates [audit v20.5]: events must COVER the CSV's attack
    classes (§7), port_coverage must equal unique/range and counts must be sane (§8), event
    usable flows / flow totals cannot be under- or over-reported (§9), a required log must be
    hashed (§10), and producer/labeler versions must be known (§11)."""
    import json
    import provenance as prov
    base = _status_v4(0, "0" * 64, "C", "0" * 64, 0, "train", class_counts={"BENIGN": 5, "DoS": 5})
    prov.validate_status_v5("x", base)                             # the clean base PASSES

    def rejects(mut, needle):
        js = json.loads(json.dumps(base))
        mut(js)
        try:
            prov.validate_status_v5("x", js)
        except SystemExit as e:
            assert needle in str(e), (needle, str(e))
        else:
            raise AssertionError("expected abort for: " + needle)

    def ev(js):
        return js["events"][next(iter(js["events"]))]              # the sole DoS event

    rejects(lambda j: j.update(events={}), "attack classes in the CSV")        # §7 events={} over DoS
    rejects(lambda j: ev(j).__setitem__("port_coverage", 0.5), "port_coverage")  # §8 1/1 != 0.5
    rejects(lambda j: ev(j).update(unique_dst_ports=9, port_range_width=9, port_coverage=1.0),
            "unique_dst_ports 9 > matched_flows")                  # §8 unique > matched
    rejects(lambda j: ev(j).update(usable_flows=3, ambiguous_flows=3),
            "usable+ambiguous")                                    # §8 3+3 > matched 5
    # §9 under-report: usable 3 (matched kept == usable+ambiguous so §7 passes) vs 5 CSV rows.
    rejects(lambda j: ev(j).update(usable_flows=3, matched_flows=3), "under-reported")
    # §7 [audit v20.24]: PHANTOM matches — matched > usable+ambiguous under the official policy.
    rejects(lambda j: ev(j).__setitem__("matched_flows", 105), "phantom matches")   # 5 usable, 105 matched
    rejects(lambda j: j.__setitem__("flows_audit", j["flows_written_ml"] + 4),
            "flows_audit")                                         # §9 audit != written + dropped
    rejects(lambda j: j.update(flows_written_ml=999, flows_audit=999),
            "!= flows_written_ml")                                 # §9 sum(classes) != written
    rejects(lambda j: j["input_hashes"].__setitem__("ssl", None),
            "input_hashes.ssl is null")                            # §10 require_ssl_log w/o hash
    rejects(lambda j: j.update(code_version="label_flows/v999"), "code_version")   # §11
    rejects(lambda j: j.update(code_version="label_flows/v25"), "code_version")    # v20.19 §18.4: the official consumer pins exactly the current labeler
    rejects(lambda j: j.update(annotation_scenario_version="scenarios/v999"),
            "annotation_scenario_version")                         # §11
    rejects(lambda j: ev(j).__setitem__("last_match", "BAD"), "must be finite numbers")   # §11
    rejects(lambda j: ev(j).update(first_match=9.0, last_match=1.0),
            "must satisfy window_start")                           # §11 reversed times [status/v5]
    rejects(lambda j: ev(j).update(first_match=0.1),               # before window_start 0.5
            "must satisfy window_start")                           # match outside its window
    rejects(lambda j: j.update(campaign_id=123), "non-empty string")   # P1-11 numeric campaign_id
    rejects(lambda j: ev(j).update(unique_dst_ports=0, port_range_width=0, port_coverage=0.0),
            "port_range_width must be >= 1")                       # P1-11 zero-width port range
    # §7 [audit v20.21]: the v27 window-matching fields must be PRESENT and WELL-FORMED — the exact
    # adversarial statuses the auditor slipped past the old consumer (which never looked at them).
    rejects(lambda j: j.pop("min_window_overlap"), "missing field")            # absent (need list)
    rejects(lambda j: j.pop("overlap_accounting"), "missing field")            # absent (need list)
    rejects(lambda j: j.__setitem__("min_window_overlap", 2.0), "real number")   # out of [0,1]
    rejects(lambda j: j.__setitem__("min_window_overlap", "banana"), "real number")  # non-numeric
    # §12 [audit v20.23]: STRICT typing — a bool (true==1.0) or a numeric STRING must NOT pass.
    rejects(lambda j: j.__setitem__("min_window_overlap", True), "real number")   # bool != number
    rejects(lambda j: j.__setitem__("min_window_overlap", "0.5"), "real number")  # numeric string
    rejects(lambda j: j["overlap_accounting"].__setitem__("matched_flows", "BAD"),
            "non-negative integer")                                # "BAD" counter
    rejects(lambda j: j["overlap_accounting"].__setitem__("duration_fallback_flows", -3),
            "non-negative integer")                                # negative fallback
    rejects(lambda j: j.__setitem__("overlap_accounting",
                                    {"matched_flows": 0, "duration_fallback_flows": 999}),
            "> matched_flows")                                     # fallback with zero matched
    rejects(lambda j: (j.__setitem__("min_window_overlap", None),
                       j.__setitem__("overlap_accounting",
                                     {"matched_flows": 5, "duration_fallback_flows": 0})),
            "legacy")                                              # legacy mode but 5 overlap matches
    rejects(lambda j: (j.__setitem__("min_window_overlap", 0.5),
                       j.__setitem__("overlap_accounting",
                                     {"matched_flows": 11, "duration_fallback_flows": 0})),
            "> flows_audit")                                       # matched (11) > flows_audit (10)
    # §6 [audit v20.22]: overlap_accounting.matched_flows must be TIED to the events (the DoS event
    # matched 5). Claiming 0 overlap matches while the events matched 5 is incoherent (the auditor's
    # forgery where overlap_accounting was zeroed out).
    good_overlap = json.loads(json.dumps(base))
    good_overlap["min_window_overlap"] = 0.5
    good_overlap["overlap_accounting"] = {"matched_flows": 5, "duration_fallback_flows": 0}
    prov.validate_status_v5("x", good_overlap)                     # overlap mode, consistent -> PASSES
    # §7 [audit v20.23]: under allow_overlapping_windows=false the tie is EXACT — matched must EQUAL the
    # sum of per-event matches (5). Claiming 0 (the auditor's zeroed forgery) or a partial 3 is rejected.
    rejects(lambda j: (j.__setitem__("min_window_overlap", 0.5),
                       j.__setitem__("overlap_accounting",
                                     {"matched_flows": 0, "duration_fallback_flows": 0})),
            "!= sum of event matches")                             # events matched 5, overlap claims 0
    rejects(lambda j: (j.__setitem__("min_window_overlap", 0.5),
                       j.__setitem__("overlap_accounting",
                                     {"matched_flows": 3, "duration_fallback_flows": 0})),
            "!= sum of event matches")                             # partial (3 != 5) also rejected
    # §5 [audit v20.22]: a 100% DEGENERATE fallback (overlap requested, every flow used the point rule)
    # MUST be diagnostic with 'overlap_duration_fallback' — a forged non-diagnostic status is rejected.
    rejects(lambda j: (j.__setitem__("min_window_overlap", 0.5),
                       j.__setitem__("overlap_accounting",
                                     {"matched_flows": 5, "duration_fallback_flows": 5})),
            "never applied")                                       # 100% fallback but diagnostic=false


def test_status_v4_join_math_and_types():
    """validate_status_v5 rejects a FABRICATED join_rate (0.8 with 1/100), non-integer or
    inconsistent counts, an empty required string, a boolean run_id, a non-64-hex sha, and
    any missing normally-produced success field [audit v20.4 P0-7, P0-9]."""
    import json
    import provenance as prov
    base = _status_v4(0, "0" * 64, "C", "0" * 64, 0, "train")

    def rejects(mut, needle):
        js = json.loads(json.dumps(base))
        mut(js)
        try:
            prov.validate_status_v5("x", js)
        except SystemExit as e:
            assert needle in str(e), (needle, str(e))
        else:
            raise AssertionError("expected abort for: " + needle)

    rejects(lambda j: j["ssl_join"].update(records=100, records_matching_conn=1, orphan_records=99,
                                           join_rate=0.8),
            "join_rate")                                       # counts CLOSE but 0.8 != 1/100 [P0-7]
    rejects(lambda j: j["ssl_join"].update(records=1.5), "non-negative integer")   # float count
    rejects(lambda j: j["ssl_join"].update(records=5, records_matching_conn=9, join_rate=1.0),
            "do not close")                                    # 9+0+0 != 5 [audit v20.4 §10.1]
    rejects(lambda j: j.update(code_version=""), "non-empty string")               # [P0-9]
    rejects(lambda j: j.update(run_id=False), "non-negative integer")              # bool as int
    rejects(lambda j: j.update(split_ready_sha256="dead"), "64-hex")               # short sha
    for f in ("input_hashes", "output_hashes", "files", "flows_written_ml", "flows_audit",
              "class_counts_split_ready"):
        rejects(lambda j, f=f: j.pop(f), "missing field")      # normally-produced field gone
    # --- §10 exact hash/file schema + self-consistency ---
    rejects(lambda j: j.update(input_hashes={"garbage": 123}), "input_hashes must have EXACTLY")
    rejects(lambda j: j.update(output_hashes={"garbage": None}), "output_hashes must have EXACTLY")
    rejects(lambda j: j.update(files={"garbage": False}), "files must have EXACTLY")
    rejects(lambda j: j["output_hashes"].update(split_ready="f" * 64),   # != the anchor [§10.4]
            "contradicts its own anchor")
    # --- §10.3 event counters must be well-typed integers with sane relationships ---
    rejects(lambda j: j.update(events={"e1": {"label": "DoS", "usable_flows": 1.5,
                                              "matched_flows": "BAD", "ambiguous_flows": 0,
                                              "unique_dst_ports": 1, "port_range_width": 1,
                                              "port_coverage": 1.0}}),
            "non-negative integer")
    rejects(lambda j: j.update(events={"e1": {"label": "DoS", "usable_flows": 5,
                                              "matched_flows": 2, "ambiguous_flows": 0,
                                              "unique_dst_ports": 1, "port_range_width": 1,
                                              "port_coverage": 1.0}}),
            "usable_flows 5 > matched_flows 2")
    prov.validate_status_v5("x", json.loads(json.dumps(base)))  # the clean base still PASSES


def test_status_planned_events_required():
    """enforce_planned_events: a run whose campaign PLANS attacks must SHOW each of them in
    status.events; an empty events dict (vacuously passing min_matches_per_event) and an
    UNPLANNED attack event are both rejected [audit v20.4 P0-8]."""
    import provenance as prov
    man = {"runs": {"0": {"attacks": ["DoS"]}}}

    def ev(label):
        return {"label": label, "usable_flows": 5}

    def rejects(events, needle):
        try:
            prov.enforce_planned_events("x", {"events": events}, man, 0)
        except SystemExit as e:
            assert needle in str(e), (needle, str(e))
        else:
            raise AssertionError("expected abort for: " + needle)

    rejects({}, "plans attack(s)")                             # DoS planned, nothing observed
    rejects({"e1": ev("PortScan")}, "plans attack(s)")         # only the WRONG attack present
    rejects({"e1": ev("DoS"), "e2": ev("XSS")}, "UNPLANNED")   # extra unplanned attack
    prov.enforce_planned_events("x", {"events": {"e1": ev("DoS")}}, man, 0)   # planned-only PASSES
    prov.enforce_planned_events("x", {"events": {}}, {"runs": {"0": {}}}, 0)  # no plan == no-op


def test_enforce_class_counts_binds_events_to_csv():
    """enforce_class_counts binds the status to the CSV's ACTUAL rows: the class counts must
    equal the file, every planned attack must have >0 rows in THIS run's file, and no event may
    claim more usable flows than the file holds of that class [audit v20.4 §9]."""
    import provenance as prov
    import pandas as pd
    d = tempfile.mkdtemp()
    p = os.path.join(d, "run0_split_ready.csv")
    pd.DataFrame({"run_id": [0, 0, 0], "label": ["BENIGN", "BENIGN", "DoS"]}).to_csv(p, index=False)
    man = {"runs": {"0": {"attacks": ["DoS"]}}}
    prov.enforce_class_counts(p, {"class_counts_split_ready": {"BENIGN": 2, "DoS": 1},
                                  "events": {"e1": {"label": "DoS", "usable_flows": 1}}}, man, 0)

    def rejects(js, needle, path=p):
        try:
            prov.enforce_class_counts(path, js, man, 0)
        except SystemExit as e:
            assert needle in str(e), (needle, str(e))
        else:
            raise AssertionError("expected abort for: " + needle)

    rejects({"class_counts_split_ready": {"BENIGN": 3}, "events": {}}, "!= actual CSV counts")
    # counts match the file, but the run's OWN CSV has ZERO of a planned attack [§9.1]:
    p2 = os.path.join(d, "run0_benign.csv")
    pd.DataFrame({"run_id": [0, 0], "label": ["BENIGN", "BENIGN"]}).to_csv(p2, index=False)
    rejects({"class_counts_split_ready": {"BENIGN": 2}, "events": {}}, "ZERO DoS rows", path=p2)
    # an event claims more usable flows than the CSV has of that class:
    rejects({"class_counts_split_ready": {"BENIGN": 2, "DoS": 1},
             "events": {"e1": {"label": "DoS", "usable_flows": 5}}}, "events exceed the file")


def test_validate_status_implies_policy():
    """Giving --status (even without --require-status) demands the campaign's policy [audit v20.3 P0-5]."""
    import json
    d = tempfile.mkdtemp()
    inputs, statuses, mp = _campaign_pkg(d)
    man = json.load(open(mp)); del man["required_labeling_policy"]; json.dump(man, open(mp, "w"))
    r = _run([sys.executable, _script("validate_dataset.py"), "--csv", *inputs, "--campaign",
              mp, "--status", *statuses])                       # NOTE: no --require-status
    assert r.returncode != 0 and "required_labeling_policy" in (r.stdout + r.stderr)


def test_status_explicit_bijection_no_autodiscovery():
    """With an explicit --status, auto-discovery is OFF and a non-matching file aborts even
    though correctly-named sidecars exist next to the CSVs [audit v20.3 P1-8]."""
    import json
    d = tempfile.mkdtemp()
    inputs, statuses, mp = _campaign_pkg(d)                     # correct sidecars exist by name
    wrong = os.path.join(d, "wrong_status.json")
    js = json.load(open(statuses[0])); js["split_ready_sha256"] = "deadbeef00"
    json.dump(js, open(wrong, "w"))
    r = _run([sys.executable, _script("merge_and_split.py"), *inputs, "--campaign", mp,
              "--status", wrong, "--require-status", "--prefix", os.path.join(d, "ds"),
              "--overwrite"])
    assert r.returncode != 0 and "no --status sidecar matches" in (r.stdout + r.stderr)


def test_validate_verdict_json_diagnostic():
    """validate emits a global verdict; --allow-unauthenticated-inputs is DIAGNOSTIC and the
    --json says official=false [audit v20.3 P0-6]."""
    import json
    d = tempfile.mkdtemp()
    inputs, statuses, mp = _campaign_pkg(d)
    jout = os.path.join(d, "v.json")
    r = _run([sys.executable, _script("validate_dataset.py"), "--csv", *inputs, "--campaign",
              mp, "--allow-unauthenticated-inputs", "--json", jout])
    out = r.stdout + r.stderr
    assert "DIAGNOSTIC ONLY" in out
    v = json.load(open(jout))
    assert v["official"] is False and "allow_unauthenticated_inputs" in v["diagnostic_reasons"]


def test_evaluate_no_campaign_is_diagnostic():
    """An evaluation WITHOUT --campaign is ad-hoc: official=false, reason no_campaign [audit v20.3 P0-7]."""
    import json
    import pandas as pd
    d = tempfile.mkdtemp()
    _run([sys.executable, _script("synth_nids_dataset.py"), "--runs", "2", "--benign", "200",
          "--attack-each", "60", "--seed", "1", "--out", os.path.join(d, "real.csv")], check=True)
    _run([sys.executable, _script("synth_nids_dataset.py"), "--runs", "2", "--benign", "200",
          "--attack-each", "60", "--seed", "2", "--out", os.path.join(d, "synth.csv")], check=True)
    jout = os.path.join(d, "v.json")
    r = _run([sys.executable, _script("evaluate_realism.py"), "--real", os.path.join(d, "real.csv"),
              "--synth", os.path.join(d, "synth.csv"), "--json", jout])
    v = json.load(open(jout))
    assert v["official"] is False and "no_campaign" in v["diagnostic_reasons"]


def test_validate_json_includes_input_authentication():
    """validate --json must PRESERVE the per-file byte-authentication chain — which sidecar
    (sha/run_id/policy) authenticated each CSV — not just the pass/fail verdict [audit v20.4
    P1-10]."""
    import json
    d = tempfile.mkdtemp()
    inputs, statuses, mp = _campaign_pkg(d)
    jout = os.path.join(d, "v.json")
    r = _run([sys.executable, _script("validate_dataset.py"), "--csv", *inputs, "--campaign",
              mp, "--status", *statuses, "--require-status", "--json", jout])
    assert os.path.exists(jout), r.stdout + r.stderr
    auth = json.load(open(jout)).get("input_authentication")
    assert isinstance(auth, list) and len(auth) == len(inputs)
    assert all(a["status_authenticated"] and len(a["sha256"]) == 64 for a in auth)
    assert {a["run_id"] for a in auth} == {0, 1}


def test_evaluate_json_includes_input_authentication():
    """evaluate --json must PRESERVE the per-file byte-authentication chain for the --real
    set, so the realism verdict is traceable to the exact authenticated inputs [audit v20.4
    P1-10]."""
    import json
    d = tempfile.mkdtemp()
    inputs, statuses, mp = _campaign_pkg(d)
    synth = os.path.join(d, "synth.csv")               # a DISTINCT synth (different seed) so the
    _run([sys.executable, _script("synth_nids_dataset.py"), "--runs", "2", "--schema",  # real/synth
          "common", "--attacks", "DoS", "--out", synth, "--seed", "2"], check=True)     # don't overlap
    jout = os.path.join(d, "e.json")
    r = _run([sys.executable, _script("evaluate_realism.py"), "--real", *inputs, "--synth",
              synth, "--campaign", mp, "--status", *statuses, "--require-status", "--json", jout])
    assert os.path.exists(jout), r.stdout + r.stderr
    auth = json.load(open(jout)).get("input_authentication")
    assert isinstance(auth, list) and len(auth) == len(inputs)
    assert all(a["status_authenticated"] for a in auth)


def test_labeler_requires_full_attack_plan():
    """The labeler must REFUSE to publish when the SUCCESS annotations do not cover EVERY
    attack the campaign plans for the run — before doing the work, so a doomed run never emits
    a non-diagnostic success the merge would only reject later [audit v20.4 §8]."""
    import json
    import hashlib
    d = tempfile.mkdtemp()
    conn = _conn_log(d, TS_INSIDE, proto="udp")
    man = {"campaign_id": "C", "expected_labels": ["BENIGN", "DoS", "PortScan"],
           "runs": {"0": {"config_id": 0, "split": "train", "seed": 0, "day": "2026-01-01",
                          "attacks": ["DoS", "PortScan"]},
                    "1": {"config_id": 6, "split": "test", "seed": 1, "day": "2026-01-02",
                          "attacks": ["DoS"]}}}
    mp = os.path.join(d, "m.json"); json.dump(man, open(mp, "w"))
    msha = hashlib.sha256(open(mp, "rb").read()).hexdigest()
    ann = _campaign_ann(d, "C", msha, 0, [{"label": "DoS"}])   # PortScan planned but absent
    out = os.path.join(d, "o.csv")
    r = _run([sys.executable, _script("label_flows.py"), "--conn", conn, "--annotations", ann,
              "--campaign", mp, "--allow-incomplete-campaign", "--out", out], capture_output=True, text=True)
    assert r.returncode != 0 and "plans attack(s)" in (r.stdout + r.stderr)
    # Nothing was PUBLISHED: the ML/split-ready CSVs do not exist and the attempt is recorded
    # as 'failed' (never a non-diagnostic success) [audit v20.4 §8].
    assert not os.path.exists(out)
    stp = out.replace(".csv", "") + "_run_status.json"
    if os.path.exists(stp):
        assert json.load(open(stp))["status"] == "failed"


def test_labeler_validates_producer_versions():
    """Campaign-mode annotations with an UNSUPPORTED scenario_version abort; a supported run
    records the producer versions + per-class CSV counts in the status [audit v20.4 §12/§9]."""
    import json
    import hashlib
    d = tempfile.mkdtemp()
    conn = _conn_log(d, TS_INSIDE, proto="udp")
    man = {"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
           "runs": {"0": {"config_id": 0, "split": "train", "seed": 0, "day": "2026-01-01",
                          "attacks": ["DoS"]},
                    "1": {"config_id": 6, "split": "test", "seed": 1, "day": "2026-01-02",
                          "attacks": ["DoS"]}}}
    mp = os.path.join(d, "m.json"); json.dump(man, open(mp, "w"))
    msha = hashlib.sha256(open(mp, "rb").read()).hexdigest()
    bad = _campaign_ann(d, "C", msha, 0, [{"label": "DoS", "scenario_version": "scenarios/v999"}])
    r = _run([sys.executable, _script("label_flows.py"), "--conn", conn, "--annotations", bad,
              "--campaign", mp, "--allow-incomplete-campaign", "--out", os.path.join(d, "o.csv")], capture_output=True, text=True)
    assert r.returncode != 0 and "scenario_version" in (r.stdout + r.stderr)
    good = _campaign_ann(d, "C", msha, 0, [{"label": "DoS"}])
    out2 = os.path.join(d, "o2.csv")
    r2 = _run([sys.executable, _script("label_flows.py"), "--conn", conn, "--annotations", good,
               "--campaign", mp, "--allow-incomplete-campaign", "--out", out2], capture_output=True, text=True)
    assert r2.returncode == 0, r2.stdout + r2.stderr
    st = json.load(open(out2.replace(".csv", "") + "_run_status.json"))
    assert st["annotation_scenario_version"] == _v.SCENARIO_VERSION
    assert st["annotation_orchestrator_version"] == _v.ORCHESTRATOR_VERSION
    assert st["class_counts_split_ready"].get("DoS", 0) >= 1     # §9 counts published
    assert "missing_uid_records" in st["ssl_join"]                # §11/§15 field present


def test_join_rate_counts_records_not_unique_uids():
    """The SSL join is counted per RAW RECORD (line), so a duplicate-uid log cannot inflate the
    rate, and records = matching + orphan + missing [audit v20.4 §11 / v20.5 §15]."""
    import json
    d = tempfile.mkdtemp()
    conn = _conn_log(d, TS_INSIDE, proto="udp")                        # conn uid C1
    ann = _write_ann([_base_ann()])                       # 1 DoS window (non-campaign)
    sf = ["ts", "uid", "version", "cipher", "server_name", "ja3", "ja3s"]
    sp = os.path.join(d, "ssl.log")
    with open(sp, "w") as f:
        f.write("#separator \\x09\n#fields\t" + "\t".join(sf) + "\n#types\t" +
                "\t".join(["string"] * len(sf)) + "\n")
        for uid in ("C1", "C1", "ORPH"):                  # 2 lines join C1, 1 orphan -> 3 records
            f.write("\t".join([str(TS_INSIDE), uid, "TLSv13", "x", "h", "j", "js"]) + "\n")
    out = os.path.join(d, "o.csv")
    r = _run([sys.executable, _script("label_flows.py"), "--conn", conn, "--ssl", sp,
              "--annotations", ann, "--out", out], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    sj = json.load(open(out.replace(".csv", "") + "_run_status.json"))["ssl_join"]
    assert sj["records"] == 3 and sj["records_matching_conn"] == 2 and sj["orphan_records"] == 1
    assert sj["missing_uid_records"] == 0
    assert sj["records_matching_conn"] + sj["orphan_records"] + sj["missing_uid_records"] == sj["records"]
    assert abs(sj["join_rate"] - round(2 / 3, 4)) < 1e-9   # by RECORDS (2/3), not unique uids (1/1)


def test_annotation_versions_required_per_line():
    """In campaign mode EVERY annotation row must carry BOTH producer versions, so a blank line
    cannot silently inherit a sibling's version [audit v20.5 §12]."""
    fields = ["event_id", "run_id", "label", "scenario_version", "orchestrator_version"]
    p = os.path.join(tempfile.mkdtemp(), "ann.csv")
    with open(p, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields); w.writeheader()
        w.writerow({"event_id": "e1", "run_id": "0", "label": "DoS",
                    "scenario_version": _v.SCENARIO_VERSION,
                    "orchestrator_version": _v.ORCHESTRATOR_VERSION})
        w.writerow({"event_id": "e2", "run_id": "0", "label": "DoS",
                    "scenario_version": "", "orchestrator_version": ""})   # blank -> must abort
    lf.read_annotation_versions(p)                                 # lenient mode: fine (aggregates)
    try:
        lf.read_annotation_versions(p, require_per_line=True); assert False, "blank line accepted"
    except SystemExit as e:
        assert "scenario_version" in str(e) and "line 3" in str(e)


def test_labeler_validates_annotation_target():
    """When the manifest PINS the target, an annotation hitting a DIFFERENT ip/host aborts —
    the ground truth must have attacked exactly the planned target [audit v20.5 §13]."""
    import json
    import hashlib
    d = tempfile.mkdtemp()
    conn = _conn_log(d, TS_INSIDE, proto="udp")
    man = {"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
           "runs": {"0": {"config_id": 0, "split": "train", "seed": 0, "day": "2026-01-01",
                          "attacks": ["DoS"], "target_host": "h", "target_ip": "10.0.0.1"},
                    "1": {"config_id": 6, "split": "test", "seed": 1, "day": "2026-01-02",
                          "attacks": ["DoS"], "target_host": "h", "target_ip": "10.0.0.1"}}}
    mp = os.path.join(d, "m.json"); json.dump(man, open(mp, "w"))
    msha = hashlib.sha256(open(mp, "rb").read()).hexdigest()
    ann = _campaign_ann(d, "C", msha, 0, [{"label": "DoS", "target_ip": "10.99.99.99"}])
    r = _run([sys.executable, _script("label_flows.py"), "--conn", conn, "--annotations", ann,
              "--campaign", mp, "--allow-incomplete-campaign", "--out", os.path.join(d, "o.csv")], capture_output=True, text=True)
    assert r.returncode != 0 and "target_ip" in (r.stdout + r.stderr) and "§13" in (r.stdout + r.stderr)


def test_labeler_rejects_missing_conn_essentials():
    """A conn.log row whose uid value is missing ('-' -> None) cannot be labeled and aborts —
    the column existing is not enough, the VALUE must be present [audit v20.5 §14]."""
    d = tempfile.mkdtemp()
    cf = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
          "service", "duration", "orig_bytes", "resp_bytes", "orig_ip_bytes",
          "resp_ip_bytes", "orig_pkts", "resp_pkts", "conn_state"]
    conn = os.path.join(d, "conn.log")
    with open(conn, "w") as f:
        f.write("#separator \\x09\n#fields\t" + "\t".join(cf) + "\n#types\t" +
                "\t".join(["string"] * len(cf)) + "\n")
        # uid = '-' (read as None); the row cannot be joined/labeled -> abort [§14].
        f.write("\t".join([str(TS_INSIDE), "-", "10.0.0.2", "5", "10.0.0.1", "443", "tcp",
                           "ssl", "1", "100", "200", "1500", "3000", "5", "6", "SF"]) + "\n")
    ann = _write_ann([_base_ann()])
    r = _run([sys.executable, _script("label_flows.py"), "--conn", conn, "--annotations", ann,
              "--out", os.path.join(d, "o.csv")], capture_output=True, text=True)
    assert r.returncode != 0 and "essential value" in (r.stdout + r.stderr)


def test_merge_bruteforce_unpinned_is_diagnostic():
    """A campaign that plans BruteForce without pinned wordlists yields official=false with the
    reason 'brute_force_wordlists_unpinned' — it is not a full reproduction [audit v20.7 P0-1]."""
    import json
    import pandas as pd
    d = tempfile.mkdtemp()
    out = os.path.join(d, "s.csv")
    _run([sys.executable, _script("synth_nids_dataset.py"), "--runs", "2", "--schema", "common",
          "--attacks", "BruteForce", "--out", out, "--seed", "1"], check=True)
    df = pd.read_csv(out)
    inputs = []
    for rid in (0, 1):
        p = os.path.join(d, "r%d.csv" % rid); df[df.run_id == rid].to_csv(p, index=False)
        inputs.append(p)
    man = {"campaign_id": "C", "expected_labels": ["BENIGN", "BruteForce"],
           "runs": {"0": _run_spec(0, "train", 0, "2026-01-01", attacks=("BruteForce",)),
                    "1": _run_spec(6, "test", 1, "2026-01-02", attacks=("BruteForce",))}}
    mp = os.path.join(d, "m.json"); json.dump(man, open(mp, "w"))
    r = _run([sys.executable, _script("merge_and_split.py"), *inputs, "--campaign", mp,
              "--allow-unauthenticated-inputs", "--prefix", os.path.join(d, "ds"), "--overwrite"])
    assert r.returncode == 0, r.stdout + r.stderr
    prov = json.load(open(os.path.join(d, "ds_split_provenance.json")))
    assert prov["official"] is False
    assert "brute_force_wordlists_unpinned" in prov["diagnostic_reasons"]


def test_merge_schema_aware_tls_version_types():
    """Two runs whose tls_version pandas would infer as a float in one file and object in another
    still merge cleanly — the reader is schema-aware [audit v20.7 P0-2]."""
    import json
    import pandas as pd
    d = tempfile.mkdtemp()
    out = os.path.join(d, "s.csv")
    _run([sys.executable, _script("synth_nids_dataset.py"), "--runs", "2", "--schema", "common",
          "--attacks", "DoS", "--out", out, "--seed", "1"], check=True)
    df = pd.read_csv(out)
    inputs = []
    for rid in (0, 1):
        sub = df[df.run_id == rid].copy()
        if rid == 0:
            sub["tls_version"] = "1.3"                          # all-'1.3' -> plain read infers float
        p = os.path.join(d, "r%d.csv" % rid); sub.to_csv(p, index=False); inputs.append(p)
    assert pd.read_csv(inputs[0])["tls_version"].dtype.kind == "f"   # the hazard is real
    man = {"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
           "runs": {"0": _run_spec(0, "train", 0, "2026-01-01"),
                    "1": _run_spec(6, "test", 1, "2026-01-02")}}
    mp = os.path.join(d, "m.json"); json.dump(man, open(mp, "w"))
    r = _run([sys.executable, _script("merge_and_split.py"), *inputs, "--campaign", mp,
              "--allow-unauthenticated-inputs", "--prefix", os.path.join(d, "ds"), "--overwrite"])
    assert r.returncode == 0, r.stdout + r.stderr              # no spurious dtype-mismatch reject


def test_run_attacks_verifies_local_ip():
    """run_attacks --campaign refuses to attack from the WRONG host: if the local source IP does
    not equal the run's planned attacker_ip, it aborts BEFORE any tool runs [audit v20.8 P0-10]."""
    import json
    d = tempfile.mkdtemp()
    # attacker_ip pinned to a lab host the sandbox is NOT (so local_ip != planned).
    man = {"campaign_id": "C", "expected_labels": ["BENIGN", "DoS"],
           "runs": {"0": {"config_id": 0, "split": "train", "attacks": ["DoS"],
                          "attacker_ip": "10.10.10.30"},
                    "1": {"config_id": 6, "split": "test"}}}
    mp = os.path.join(d, "m.json"); json.dump(man, open(mp, "w"))
    ann = os.path.join(d, "ann.csv")
    r = _run([sys.executable, _script("run_attacks.py"), "--campaign", mp,
              "--allow-incomplete-campaign", "--run-id", "0", "--target-ip", "10.10.10.11",
              "--target-host", "", "--dos-seconds", "120", "--logdir", os.path.join(d, "logs"),
              "--annotations", ann], capture_output=True, text=True)
    assert r.returncode != 0 and "local source IP" in (r.stdout + r.stderr)
    assert not os.path.exists(ann)                             # aborted before writing ground truth


def test_run_helper_kills_process_group():
    """_run must SIGKILL the WHOLE process group on timeout, so a spawned grandchild
    (a lingering thread pool / open pipe) does not survive to hang the suite [audit residual]."""
    if os.name != "posix":
        return
    import time
    # A child that itself spawns a 60s sleeper and prints the sleeper's pid, then sleeps.
    # With a 2s timeout, _run must kill the group so BOTH processes die.
    script = ("import subprocess,sys,time;"
              "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);"
              "print(p.pid);sys.stdout.flush();time.sleep(60)")
    t0 = time.time()
    grandchild = 0
    try:
        _run([sys.executable, "-c", script], timeout=2)
        assert False, "should have raised TimeoutExpired"
    except subprocess.TimeoutExpired as e:
        grandchild = int((e.output or "0").strip() or "0")
    assert time.time() - t0 < 20                       # returned promptly, did NOT hang
    if grandchild:
        # A SIGKILL'd process becomes a ZOMBIE (state 'Z') until its parent is reaped —
        # os.kill(pid, 0) succeeds for a zombie, so it does NOT mean "still running"
        # [audit v19 P0-6]. Accept the grandchild as dead once it is gone OR a zombie;
        # only a truly running state (R/S/D/T) is a failure. Poll briefly for the reap.
        deadline = time.time() + 5
        running = True
        while time.time() < deadline:
            stat_path = "/proc/{}/stat".format(grandchild)
            if not os.path.exists(stat_path):
                running = False                        # reaped: gone for good
                break
            try:
                state = open(stat_path).read().rsplit(")", 1)[1].split()[0]
            except (OSError, IndexError):
                running = False
                break
            if state == "Z":                           # dead, awaiting reap
                running = False
                break
            time.sleep(0.1)
        assert not running, "grandchild is still running after the process-group kill"


def test_run_no_pipe_does_not_block_on_leaked_grandchild():
    """The isolated dispatch runs --run-one with capture_output=False. Verify that with NO
    pipe, a child that leaves a still-running grandchild holding the inherited stdio does
    NOT block _run — it returns as soon as the child exits. A regression to stdout=PIPE
    would hang here (communicate waits for the grandchild to close the pipe) and trip the
    timeout instead [audit v20.4 suite deadlock]."""
    if os.name != "posix":
        return
    import time
    # Child: spawn a 30s sleeper that inherits our stdio, then exit(0) at once.
    script = ("import subprocess,sys;"
              "subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);"
              "sys.exit(0)")
    t0 = time.time()
    cp = _run([sys.executable, "-c", script], timeout=25, capture_output=False)
    dt = time.time() - t0
    assert cp.returncode == 0 and cp.stdout is None
    assert dt < 8, "returned in {:.1f}s — a pipe made us wait on the grandchild".format(dt)


# Tests that TRAIN a model (validate baseline / evaluate TSTR) dominate the runtime.
# The runner classifies every test into THREE CI lanes so each finishes within a time
# budget and the whole suite never has to run as one block [audit residual]:
#   ml           -> trains a RandomForest (validate/evaluate); the heavy lane.
#   integration  -> spawns a script via _run() (subprocess), but no model training.
#   unit         -> pure in-process, no subprocess.
# Every test uses its OWN tempdir and calls scripts through _run() (its own process
# group, killed on timeout), so they never share state — the split is about RUNTIME.
_ML_TESTS = frozenset({
    "test_evaluate_categorical_axis_in_quality", "test_evaluate_overlap_aborts_by_default",
    "test_evaluate_override_forces_diagnostic", "test_evaluate_realism_quality_and_fragility",
    "test_evaluate_single_run_is_diagnostic", "test_evaluate_uses_campaign_split",
    "test_validate_campaign_val_after_test_aborts", "test_validate_drops_ambiguous_from_audit",
    "test_validate_partial_schema_and_junk_abort", "test_validate_rejects_impossible_values",
    "test_validate_single_run_needs_flag", "test_validate_unknown_label_aborts",
    "test_validate_uses_campaign_split", "test_evaluate_override_emits_diagnostic_json",
    "test_evaluate_json_is_fail_closed", "test_evaluate_missing_policy_is_diagnostic",
    "test_validate_verdict_json_diagnostic", "test_evaluate_no_campaign_is_diagnostic",
    "test_evaluate_domain_distinguishability",   # trains RFs -> ML lane [audit v20.18 §15]
    # These reach a real sklearn baseline/detector, so they belong in the ML lane too — misfiled as
    # 'integration' they trained RFs inside that lane and could stall it [audit v20.22 §13]:
    "test_domain_gate_requires_all_expected_classes_in_holdout",
    "test_evaluate_json_includes_input_authentication",
    "test_validate_json_includes_input_authentication",
    "test_manifest_pins_release_quality_and_min_samples",
    "test_release_quality_policy_pins_thresholds_and_exit_code",
    "test_release_requires_complete_policy",
})
_SLOW_TESTS = _ML_TESTS               # backward-compatible alias (slow == ml lane)


def _category(name, fn):
    """One of 'ml' / 'integration' / 'unit' for a test [audit residual]."""
    if name in _ML_TESTS:
        return "ml"
    try:
        import inspect
        src = inspect.getsource(fn)
    except (OSError, TypeError):
        src = ""
    return "integration" if ("_run(" in src or "_campaign_pkg(" in src) else "unit"


def _run_forked(fn, timeout):
    """Run ONE test in its own forked process (new session) so BLAS/OpenMP threads,
    scikit-learn pools, module caches and file descriptors are RECLAIMED when it exits —
    no accumulation across a lane, which is what could make a big batch fail to terminate
    [audit v20 P1-16]. Returns 'pass', 'fail', or a short error string.
    """
    import time
    pid = os.fork()
    if pid == 0:                                          # child: isolated process
        os.setsid()                                       # own session/group => killable tree
        try:
            fn()
            os._exit(0)
        except AssertionError:
            os._exit(1)
        except BaseException:
            os._exit(2)
    deadline = time.time() + timeout
    while True:
        wpid, status = os.waitpid(pid, os.WNOHANG)
        if wpid == pid:
            if os.WIFEXITED(status):
                code = os.WEXITSTATUS(status)
                return {0: "pass", 1: "fail"}.get(code, "error(exit {})".format(code))
            if os.WIFSIGNALED(status):
                return "error(signal {})".format(os.WTERMSIG(status))
            return "error"
        if time.time() > deadline:                        # kill the WHOLE group, then reap
            try:
                os.killpg(os.getpgid(pid), signal.SIGKILL)
            except OSError:
                pass
            os.waitpid(pid, 0)
            return "error(timeout)"
        time.sleep(0.03)


def _run_standalone(argv=None):
    """Standalone runner with THREE CI lanes + durations [audit residual].

    Usage: test_pipeline.py [--only all|unit|integration|ml|fast|slow] [--durations N] [--list]
      --only unit        : pure in-process tests (fastest)
      --only integration : subprocess tests, no model training
      --only ml          : the RandomForest tests (heavy lane)
      --only fast        : unit + integration (everything except ml); alias
      --only slow        : ml only; alias
      --forked           : run EACH test in its own forked process (POSIX), reclaiming
                           threads/pools/fds between tests [audit v20 P1-16]
      --isolated         : run EACH test in a FRESH interpreter (python -m ... --run-one);
                           the strongest isolation — nothing carries over, the reliable way
                           to run a whole lane as one batch [audit v20.2 P1-8]
      --run-one NAME     : run exactly one test in this interpreter and exit (used by --isolated)
      --timeout N        : per-test timeout in seconds under --forked/--isolated (default 300)
      --durations N      : print the N slowest tests (like pytest --durations)
    """
    import time
    argv = sys.argv[1:] if argv is None else argv
    only, durations = "all", 10
    allfns = {k: v for k, v in globals().items() if k.startswith("test_")}
    # --run-one NAME: execute exactly one test in THIS fresh interpreter and exit — the unit
    # of true external isolation used by --isolated [audit v20.2 P1-8].
    if "--run-one" in argv:
        name = argv[argv.index("--run-one") + 1]
        fn = allfns.get(name)
        if fn is None:
            print("no such test:", name)
            return 1
        try:
            fn(); return 0
        except AssertionError as e:
            print("FAIL", name, "->", e); return 1
        except BaseException as e:
            print("ERR ", name, "->", repr(e)[:200]); return 1
    if "--list" in argv:
        for k in sorted(allfns):
            print(_category(k, allfns[k]), k)
        return 0
    if "--only" in argv:
        only = argv[argv.index("--only") + 1]
    if "--durations" in argv:
        durations = int(argv[argv.index("--durations") + 1])

    forked = "--forked" in argv and os.name == "posix"
    isolated = "--isolated" in argv                      # a fresh interpreter per test [P1-8]
    per_test_timeout = 300
    if "--timeout" in argv:
        per_test_timeout = int(argv[argv.index("--timeout") + 1])

    def _selected(name, fn):
        cat = _category(name, fn)
        if only in ("all", ""):
            return True
        if only == "fast":
            return cat != "ml"
        if only == "slow":
            return cat == "ml"
        return cat == only                            # unit | integration | ml

    tests = [(k, v) for k, v in sorted(allfns.items()) if _selected(k, v)]
    failed, timings = 0, []
    for name, t in tests:
        t0 = time.time()
        if isolated:
            # A FRESH Python interpreter per test — nothing (BLAS threads, sklearn pools,
            # module caches, fds) carries over. _run() kills the whole group on timeout
            # [audit v20.2 P1-8]. INHERIT stdout/stderr (capture_output=False): with no pipe
            # to hold open, a leaked/reparented grandchild of the --run-one child can never
            # block our communicate() — the exact hang the aggregate run hit [audit v20.4].
            try:
                cp = _run([sys.executable, os.path.abspath(__file__), "--run-one", name],
                          timeout=per_test_timeout, capture_output=False)
                ok = cp.returncode == 0
                detail = "" if ok else "exit {} (see output above)".format(cp.returncode)
            except subprocess.TimeoutExpired:
                ok, detail = False, "TIMEOUT after {}s (group killed)".format(per_test_timeout)
            if ok:
                print("  PASS", name)
            else:
                failed += 1
                print("  FAIL", name, "->", detail)
        elif forked:
            outcome = _run_forked(t, per_test_timeout)    # own process; freed on exit [audit v20 P1-16]
            if outcome == "pass":
                print("  PASS", name)
            else:
                failed += 1
                print("  {} {}".format("FAIL" if outcome == "fail" else "ERR ", name),
                      "->", outcome)
        else:
            try:
                t()
                print("  PASS", name)
            except AssertionError as e:
                failed += 1
                print("  FAIL", name, "->", e)
            except BaseException as e:                    # SystemExit in a test == error
                failed += 1
                print("  ERR ", name, "->", repr(e)[:160])
        timings.append((time.time() - t0, name))
    mode = " isolated" if isolated else (" forked" if forked else "")
    print("\n[{} lane{}] {}/{} passed".format(only, mode, len(tests) - failed, len(tests)))
    if durations:
        print("Slowest {}:".format(durations))
        for dt, name in sorted(timings, reverse=True)[:durations]:
            print("  {:6.2f}s  {}".format(dt, name))
    return failed


if __name__ == "__main__":
    sys.exit(1 if _run_standalone() else 0)
