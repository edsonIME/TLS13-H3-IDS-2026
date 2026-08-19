#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
shortcut_audit.py — find label shortcuts in a split-ready CSV, before training anything.

WHY
---
Chasing overlap one feature at a time is endless: campaign v1 leaked through `ja3`
(bijective with the attacker host), then through `transport` (UDP => BENIGN with
precision 1.0), then through `alpn` (h3 <=> QUIC because TLS 1.3 encrypts ALPN over
TCP), then through `dst_port_class` (nmap emits one flow per scanned port). Enriching
the feature set with the flowmeter adds 74 more chances to leak — `fwd_init_window_size`
alone can identify nmap, whose SYN probes use a fixed window.

The question that matters is not "does feature X overlap" but "can a simple model
separate the classes at all". This answers that, and names the culprits.

WHAT IT REPORTS
---------------
  1. CONSTANT columns — zero information, should not ship as features
  2. CATEGORICAL PURITY — how well a categorical column alone predicts the label, plus
     any value that maps to exactly one class (a bijection like v1's ja3)
  3. SINGLE-SPLIT SEPARABILITY — for every numeric column, the best threshold and the
     balanced accuracy it achieves; this is the "one line of code separates them" test
  4. A DEPTH-LIMITED TREE over ALL features — if a 3-question model reaches ~1.0, the
     dataset is separable by shortcut regardless of which column you drop

NO DEPENDENCIES: pure standard library, so it runs on the sensor host as well as the
training host. Numeric features are quantile-binned (default 32 bins), which makes the
exhaustive split search cheap without changing the conclusions.

READ THE OUTPUT LIKE THIS
-------------------------
Balanced accuracy near 0.5 means the feature is uninformative on its own — GOOD here.
Near 1.0 means it alone separates the classes — that is a shortcut, not a result. A
depth-3 tree above ~0.98 means no feature selection will save the experiment; the fix is
in traffic generation, not in the model.

USAGE
  python3 shortcut_audit.py --csv run0_split_ready.csv
  python3 shortcut_audit.py --csv merged_train.csv --binary --top 15
"""

import argparse
import collections
import csv
import math
import sys

NON_FEATURES = {"run_id", "timestamp", "label"}
# Columns known to be categorical in this schema; anything else that fails to parse as a
# float is treated as categorical too.
KNOWN_CATEGORICAL = {"transport", "dst_port_class", "tls_version", "alpn", "ja3", "ja3s"}


def load(path, binary):
    """Read the CSV. Returns (rows, labels, numeric_cols, categorical_cols).

    Missing values stay as None rather than 0: the flowmeter writes NaN for measures that
    do not apply to a transport (TCP flags on a UDP flow), and turning that into 0 would
    invent data.
    """
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    if not rows:
        sys.exit("ABORT: empty CSV")
    if "label" not in rows[0]:
        sys.exit("ABORT: no `label` column")

    cols = [c for c in rows[0] if c not in NON_FEATURES]
    labels = [("ATTACK" if r["label"] != "BENIGN" else "BENIGN") if binary else r["label"]
              for r in rows]

    numeric, categorical = [], []
    for c in cols:
        if c in KNOWN_CATEGORICAL:
            categorical.append(c)
            continue
        vals = [r[c] for r in rows if r[c] not in ("", None)]
        try:
            for v in vals[:500]:
                float(v)
            numeric.append(c)
        except ValueError:
            categorical.append(c)

    data = {}
    for c in numeric:
        col = []
        for r in rows:
            v = r[c]
            try:
                col.append(float(v) if v not in ("", None) else None)
            except ValueError:
                col.append(None)
        data[c] = col
    for c in categorical:
        data[c] = [r[c] for r in rows]
    return data, labels, numeric, categorical


def balanced_accuracy(pred, labels, classes):
    """Mean per-class recall. Immune to the 84%-DoS imbalance that makes plain accuracy
    meaningless in this dataset."""
    hit = collections.Counter()
    tot = collections.Counter()
    for p, y in zip(pred, labels):
        tot[y] += 1
        if p == y:
            hit[y] += 1
    recalls = [hit[c] / tot[c] for c in classes if tot[c]]
    return sum(recalls) / len(recalls) if recalls else 0.0


# ------------------------------------------------------------------------ categorical

def categorical_report(data, labels, cols, classes, top):
    """Best-case accuracy of mapping each category value to its majority label, plus the
    fraction of rows sitting in values that are PURE (one label only) — v1's ja3 was
    100% pure, which is what made it a perfect label leak."""
    out = []
    n = len(labels)
    for c in cols:
        by = collections.defaultdict(collections.Counter)
        for v, y in zip(data[c], labels):
            by[v][y] += 1
        pred = [by[v].most_common(1)[0][0] for v in data[c]]
        pure_rows = sum(sum(cnt.values()) for cnt in by.values() if len(cnt) == 1)
        out.append((balanced_accuracy(pred, labels, classes), len(by), pure_rows / n, c))
    out.sort(reverse=True)
    print("\n=== CATEGORICAS (acuracia balanceada da coluna sozinha) ===")
    print("  bal.acc  valores  %linhas-puras  coluna")
    for acc, nvals, pure, c in out[:top]:
        flag = "  <== ATALHO" if acc >= 0.90 else ""
        print("  {:.3f}    {:>6}   {:>6.1%}        {}{}".format(acc, nvals, pure, c, flag))
    return out


# ---------------------------------------------------------------------------- numeric

def quantile_bins(col, nbins):
    """Bin edges at quantiles of the OBSERVED values. Quantiles (not equal width) keep the
    search meaningful for the heavy-tailed rate/IAT columns."""
    vals = sorted(v for v in col if v is not None)
    if len(vals) < 2:
        return []
    edges, step = [], max(len(vals) // nbins, 1)
    for i in range(step, len(vals), step):
        e = vals[i]
        if not edges or e > edges[-1]:
            edges.append(e)
    return edges[:nbins - 1]


def binize(col, edges):
    """Map values to bin indices; None (missing / not-applicable) gets its own bin -1.

    Missing is a bin ON PURPOSE: 'TCP flags are NaN' identifies UDP perfectly, and that
    is exactly the kind of shortcut this tool must be able to see.
    """
    out = []
    for v in col:
        if v is None:
            out.append(-1)
            continue
        lo, hi = 0, len(edges)
        while lo < hi:
            mid = (lo + hi) // 2
            if v <= edges[mid]:
                hi = mid
            else:
                lo = mid + 1
        out.append(lo)
    return out


def best_single_split(binned, labels, classes, nbins):
    """Best threshold on one binned column, by balanced accuracy of a two-leaf rule."""
    counts = collections.defaultdict(collections.Counter)
    for b, y in zip(binned, labels):
        counts[b][y] += 1
    bins = sorted(counts)
    total = collections.Counter(labels)
    best = (0.0, None)
    left = collections.Counter()
    for i, b in enumerate(bins[:-1]):
        left.update(counts[b])
        right = collections.Counter({c: total[c] - left[c] for c in classes})
        lmaj = max(classes, key=lambda c: left[c])
        rmaj = max(classes, key=lambda c: right[c])
        if lmaj == rmaj:
            continue
        recalls = []
        for c in classes:
            if not total[c]:
                continue
            hit = (left[c] if lmaj == c else 0) + (right[c] if rmaj == c else 0)
            recalls.append(hit / total[c])
        acc = sum(recalls) / len(recalls) if recalls else 0.0
        if acc > best[0]:
            best = (acc, b)
    return best


def numeric_report(data, labels, cols, classes, nbins, top):
    results, binned_all, edges_all = [], {}, {}
    for c in cols:
        edges = quantile_bins(data[c], nbins)
        edges_all[c] = edges
        binned_all[c] = binize(data[c], edges)
        acc, at = best_single_split(binned_all[c], labels, classes, nbins)
        thr = edges[at] if (at is not None and 0 <= at < len(edges)) else None
        results.append((acc, thr, c))
    results.sort(reverse=True)
    print("\n=== NUMERICAS (melhor corte unico) ===")
    print("  bal.acc  limiar          coluna")
    for acc, thr, c in results[:top]:
        flag = "  <== ATALHO" if acc >= 0.90 else ""
        t = "{:>12.4g}".format(thr) if thr is not None else "     (nulo)"
        print("  {:.3f}   {}    {}{}".format(acc, t, c, flag))
    return results, binned_all


# ------------------------------------------------------------------------------- tree

def gini(counter, n):
    return 1.0 - sum((v / n) ** 2 for v in counter.values()) if n else 0.0


def grow(idx, binned, labels, cols, depth, min_leaf):
    """Greedy CART on binned features. Returns a nested dict describing the tree."""
    counts = collections.Counter(labels[i] for i in idx)
    node = {"n": len(idx), "majority": counts.most_common(1)[0][0]}
    if depth == 0 or len(counts) == 1 or len(idx) < 2 * min_leaf:
        return node
    n = len(idx)
    parent = gini(counts, n)
    best = None
    for c in cols:
        col = binned[c]
        per_bin = collections.defaultdict(collections.Counter)
        for i in idx:
            per_bin[col[i]][labels[i]] += 1
        bins = sorted(per_bin)
        if len(bins) < 2:
            continue
        left = collections.Counter()
        for b in bins[:-1]:
            left.update(per_bin[b])
            nl = sum(left.values())
            nr = n - nl
            if nl < min_leaf or nr < min_leaf:
                continue
            right = collections.Counter({k: counts[k] - left[k] for k in counts})
            gain = parent - (nl / n) * gini(left, nl) - (nr / n) * gini(right, nr)
            if best is None or gain > best[0]:
                best = (gain, c, b)
    if best is None or best[0] <= 1e-9:
        return node
    _g, c, b = best
    node["feature"], node["bin"] = c, b
    lidx = [i for i in idx if binned[c][i] <= b]
    ridx = [i for i in idx if binned[c][i] > b]
    node["left"] = grow(lidx, binned, labels, cols, depth - 1, min_leaf)
    node["right"] = grow(ridx, binned, labels, cols, depth - 1, min_leaf)
    return node


def predict(node, binned, i):
    while "feature" in node:
        node = node["left"] if binned[node["feature"]][i] <= node["bin"] else node["right"]
    return node["majority"]


def show(node, prefix=""):
    if "feature" not in node:
        print("{}-> {} (n={})".format(prefix, node["majority"], node["n"]))
        return
    print("{}[{} <= bin {}]  n={}".format(prefix, node["feature"], node["bin"], node["n"]))
    show(node["left"], prefix + "   ")
    show(node["right"], prefix + "   ")


def main():
    ap = argparse.ArgumentParser(description="Detect label shortcuts in a split-ready CSV.")
    ap.add_argument("--csv", required=True)
    ap.add_argument("--binary", action="store_true",
                    help="collapse all attacks into ATTACK vs BENIGN")
    ap.add_argument("--bins", type=int, default=32)
    ap.add_argument("--depth", type=int, default=3)
    ap.add_argument("--min-leaf", type=int, default=20)
    ap.add_argument("--top", type=int, default=12)
    ap.add_argument("--shortcut-threshold", type=float, default=0.90,
                    help="balanced accuracy at or above which a single column is called "
                         "a shortcut")
    args = ap.parse_args()

    data, labels, numeric, categorical = load(args.csv, args.binary)
    classes = sorted(set(labels))
    dist = collections.Counter(labels)
    print("linhas: {} | features: {} numericas + {} categoricas".format(
        len(labels), len(numeric), len(categorical)))
    print("classes:", dict(dist))

    const = [c for c in numeric + categorical if len({str(v) for v in data[c]}) <= 1]
    print("\n=== CONSTANTES ({}) ===".format(len(const)))
    print("  " + (", ".join(const) if const else "(nenhuma)"))

    cat_res = categorical_report(data, labels, categorical, classes, args.top) if categorical else []
    num_res, binned = numeric_report(data, labels, numeric, classes, args.bins, args.top)

    # categorical columns join the tree as binned integers, so the tree sees everything
    for c in categorical:
        codes = {v: i for i, v in enumerate(sorted({str(x) for x in data[c]}))}
        binned[c] = [codes[str(v)] for v in data[c]]
    all_cols = numeric + categorical

    idx = list(range(len(labels)))
    tree = grow(idx, binned, labels, all_cols, args.depth, args.min_leaf)
    pred = [predict(tree, binned, i) for i in idx]
    acc = balanced_accuracy(pred, labels, classes)

    print("\n=== ARVORE (profundidade {}) ===".format(args.depth))
    show(tree)
    print("\nacuracia balanceada da arvore: {:.4f}".format(acc))

    print("\n=== VEREDITO ===")
    leaks = ([c for a, _n, _p, c in cat_res if a >= args.shortcut_threshold]
             + [c for a, _t, c in num_res if a >= args.shortcut_threshold])
    if leaks:
        print("  colunas que sozinhas separam as classes ({:.0%}+): {}".format(
            args.shortcut_threshold, ", ".join(leaks)))
    else:
        print("  nenhuma coluna isolada separa as classes acima de {:.0%}".format(
            args.shortcut_threshold))
    if acc >= 0.98:
        print("  a arvore de {} perguntas atinge {:.4f}: o dataset e separavel por atalho.".format(
            args.depth, acc))
        print("  Remover colunas NAO resolve — a correcao esta na GERACAO de trafego.")
    elif acc >= 0.90:
        print("  a arvore atinge {:.4f}: ainda ha estrutura trivial, mas nao total.".format(acc))
    else:
        print("  a arvore fica em {:.4f}: nenhum atalho trivial domina. BOM SINAL.".format(acc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
