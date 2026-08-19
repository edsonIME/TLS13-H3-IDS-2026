#!/usr/bin/env python3
"""
hash_sources.py -- deterministic, self-excluding SHA-256 manifests for the NIDS
dataset campaign, plus fail-fast cross-node verification.

WHY THIS EXISTS
    The roteiro's per-node hashing steps piped `Get-ChildItem | Get-FileHash |
    Export-Csv <manifest-inside-the-dir>` (and, on Linux, `find | sha256sum >
    <manifest-inside-the-dir>`). Because the manifest lives inside the directory
    being hashed, the tool tried to hash its OWN output: on Windows that raised
    "the file is being used by another process"; on Linux it silently recorded a
    self-referential (empty-file) hash that breaks later `-c` verification. This
    script removes that whole class of bug by ALWAYS excluding the manifest it
    writes, and it produces one identical manifest format on every node so the
    NB4 "received vs source" comparison is trivial and reliable.

DESIGN (maps to the five review requirements)
    1. Modular / testable: the work is done by small PURE functions -- sha256_file,
       iter_files, build_manifest, format_manifest, parse_manifest, compare -- with
       no I/O side effects beyond reading. The `cmd_*` orchestrators and `main`
       wire them together. Every pure function is unit-testable in isolation.
    2. Sanity checks: validate_* run BEFORE any hashing -- directory exists / is a
       directory / is readable, the output parent exists / is writable, and every
       file to be hashed is readable. On any problem the script fails explicitly
       (clear message, non-zero exit) before touching data.
    3. Fail-fast: verification returns a NON-ZERO exit code on the first class of
       problem (missing file or hash mismatch), so a calling pipeline can stop and
       never propagate corrupted data. Distinct exit codes below.
    4. Zero side effects: files are opened read-only in binary mode and closed
       immediately (no long-held handles, no locks); originals are never modified
       or moved. The ONLY write is the manifest, produced atomically (temp + os
       .replace) and excluded from its own hash. `verify` writes nothing at all.
    5. Traceability: the `logging` module records, at INFO/WARNING/ERROR, which
       files were evaluated, expected-vs-computed hashes during verification, and
       the final status. `--log-file` also persists the log next to the artifacts.

USAGE
    # Generate a source/received manifest (self-excluding). Read-only except the manifest.
    python hash_sources.py generate --root <DIR> --out <DIR>/<name>.sha256

    # Verify a target manifest against one or more reference manifests (fail-fast).
    python hash_sources.py verify --target <received>.sha256 \
        --reference <nb1_source>.sha256 <nb2_source>.sha256 <nb3_source>.sha256

MANIFEST FORMAT
    One line per file, sorted, `sha256sum`-compatible:  "<64-hex>  <relpath>"
    Paths are relative to --root and use forward slashes, so a file keeps the same
    key on every node (the roteiro forbids renaming), making comparison exact.
"""

import argparse
import hashlib
import logging
import os
import re
import sys
from pathlib import Path

# ---- exit codes (distinct so a pipeline can branch on the failure class) ----
EXIT_OK = 0             # success
EXIT_USAGE = 2          # argparse usage error (argparse raises SystemExit(2))
EXIT_SANITY = 3         # input validation failed (missing/unreadable/etc.)
EXIT_VERIFY_FAILED = 4  # a hash mismatch or a missing file was detected
EXIT_IO = 5             # unexpected I/O or manifest-parse error

_HASH_RE = re.compile(r"^([0-9a-fA-F]{64})[ \t]+\*?(.+)$")  # "<hash>  <path>" (opt. '*')

log = logging.getLogger("hash_sources")


class SanityError(Exception):
    """Raised by the validate_* checks when a precondition is not met."""


# --------------------------------------------------------------------------- #
# PURE FUNCTIONS (no side effects beyond reading files) -- unit-testable.
# --------------------------------------------------------------------------- #
def sha256_file(path, chunk_size=1 << 20):
    """Return the lowercase hex SHA-256 of a file.

    Reads in chunks with a short-lived read-only handle (opened and closed here),
    so no lock is held on the original artifact.
    """
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def iter_files(root, exclude_names):
    """Return a sorted list of (relpath_posix, abspath) for every regular file
    under `root`, skipping any file whose *name* is in `exclude_names`.

    Sorting makes the manifest deterministic; forward-slash relpaths make it
    comparable across Windows and Linux nodes.
    """
    root = Path(root)
    items = []
    for p in root.rglob("*"):
        if p.is_file() and p.name not in exclude_names:
            items.append((p.relative_to(root).as_posix(), str(p)))
    items.sort(key=lambda t: t[0])
    return items


def build_manifest(root, exclude_names):
    """Return {relpath: hash} for all files under `root` (pure, read-only)."""
    return {rel: sha256_file(ab) for rel, ab in iter_files(root, exclude_names)}


def format_manifest(manifest):
    """Render {relpath: hash} as sorted `sha256sum`-style text."""
    return "".join("{}  {}\n".format(manifest[k], k) for k in sorted(manifest))


def parse_manifest(text):
    """Parse `sha256sum`-style text into {relpath: hash}.

    Blank lines and '#' comment lines are ignored. A malformed data line raises
    ValueError (so a corrupt manifest fails loudly rather than silently).
    """
    out = {}
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = _HASH_RE.match(stripped)
        if not m:
            raise ValueError("malformed manifest line {}: {!r}".format(lineno, line))
        rel = m.group(2).strip().replace("\\", "/")
        out[rel] = m.group(1).lower()
    return out


def compare(reference, target):
    """Compare a reference manifest to a target manifest (both {relpath: hash}).

    Returns (missing, mismatched):
      * missing    -- relpaths present in reference but absent from target
      * mismatched -- (relpath, expected_hash, found_hash) where the hashes differ
    Files that are ONLY in target are intentionally NOT reported: the collector
    (NB4) legitimately holds more files (the PCAP, capture JSON, other nodes'
    manifests) than any single source node produced.
    """
    missing, mismatched = [], []
    for rel in sorted(reference):
        expected = reference[rel]
        if rel not in target:
            missing.append(rel)
        elif target[rel].lower() != expected.lower():
            mismatched.append((rel, expected, target[rel]))
    return missing, mismatched


# --------------------------------------------------------------------------- #
# SANITY CHECKS (run before any processing; raise SanityError on any problem).
# --------------------------------------------------------------------------- #
def validate_source_dir(root):
    """The directory to hash must exist, be a directory, and be readable."""
    p = Path(root)
    if not p.exists():
        raise SanityError("source directory does not exist: {}".format(root))
    if not p.is_dir():
        raise SanityError("source path is not a directory: {}".format(root))
    if not os.access(p, os.R_OK | os.X_OK):
        raise SanityError("source directory is not readable: {}".format(root))


def validate_output_path(out):
    """The manifest's parent must exist and be writable; the path must not be a dir."""
    p = Path(out)
    parent = p.parent if str(p.parent) else Path(".")
    if not parent.exists():
        raise SanityError("output directory does not exist: {}".format(parent))
    if not parent.is_dir():
        raise SanityError("output parent is not a directory: {}".format(parent))
    if not os.access(parent, os.W_OK):
        raise SanityError("output directory is not writable: {}".format(parent))
    if p.exists() and not p.is_file():
        raise SanityError("output path exists and is not a regular file: {}".format(out))


def validate_readable_file(path, label="file"):
    """A manifest (or any input file) must exist, be a file, and be readable."""
    p = Path(path)
    if not p.exists():
        raise SanityError("{} does not exist: {}".format(label, path))
    if not p.is_file():
        raise SanityError("{} is not a regular file: {}".format(label, path))
    if not os.access(p, os.R_OK):
        raise SanityError("{} is not readable: {}".format(label, path))


def assert_all_readable(files):
    """Fail fast if any file scheduled for hashing is not readable."""
    unreadable = [ab for _, ab in files if not os.access(ab, os.R_OK)]
    if unreadable:
        preview = ", ".join(unreadable[:5]) + (" ..." if len(unreadable) > 5 else "")
        raise SanityError("unreadable file(s) under source: {}".format(preview))


# --------------------------------------------------------------------------- #
# ORCHESTRATORS.
# --------------------------------------------------------------------------- #
def cmd_generate(args):
    """Hash every file under --root (excluding the manifest itself) and write --out."""
    validate_source_dir(args.root)
    validate_output_path(args.out)

    out_name = Path(args.out).name
    # Exclude the manifest we are about to write AND its atomic temp, so a re-run
    # never hashes stale output -- the root cause of the original bug.
    excluded = {out_name, out_name + ".tmp"} | set(args.exclude or [])
    files = iter_files(args.root, excluded)
    if not files:
        log.warning("no files to hash under %s (excluding %s)", args.root, sorted(excluded))
    assert_all_readable(files)

    log.info("hashing %d file(s) under %s (excluding self: %s)",
             len(files), args.root, out_name)
    manifest = {}
    for rel, ab in files:
        digest = sha256_file(ab)
        manifest[rel] = digest
        log.info("  hashed %s  %s", digest[:12], rel)

    # Atomic write: build the text, write to <out>.tmp, then os.replace onto <out>.
    # This never leaves a half-written manifest and never locks the originals.
    tmp = str(Path(args.out)) + ".tmp"
    Path(tmp).write_text(format_manifest(manifest), encoding="utf-8", newline="\n")
    os.replace(tmp, args.out)
    log.info("wrote manifest %s (%d entries)", args.out, len(manifest))
    return EXIT_OK


def cmd_verify(args):
    """Confirm every file in each reference manifest is present in the target with
    an identical hash. Purely analytical: reads manifests only, writes nothing."""
    validate_readable_file(args.target, "target manifest")
    for ref in args.reference:
        validate_readable_file(ref, "reference manifest")

    target = parse_manifest(Path(args.target).read_text(encoding="utf-8"))
    log.info("target manifest %s: %d entries", args.target, len(target))

    total_missing = total_mismatch = total_checked = 0
    for ref_path in args.reference:
        reference = parse_manifest(Path(ref_path).read_text(encoding="utf-8"))
        missing, mismatched = compare(reference, target)
        log.info("checking %d entr%s from %s against target",
                 len(reference), "y" if len(reference) == 1 else "ies", ref_path)
        for rel in sorted(reference):
            total_checked += 1
            if rel in target and target[rel] == reference[rel]:
                log.info("  OK       %s  %s", reference[rel][:12], rel)
        for rel in missing:
            log.error("  MISSING  expected %s  %s  (not found in target)",
                      reference[rel][:12], rel)
        for rel, exp, got in mismatched:
            log.error("  MISMATCH %s  expected %s  got %s", rel, exp[:12], got[:12])
        total_missing += len(missing)
        total_mismatch += len(mismatched)

    if total_missing or total_mismatch:
        log.error("VERIFY FAILED: %d missing, %d mismatched (of %d checked)",
                  total_missing, total_mismatch, total_checked)
        return EXIT_VERIFY_FAILED
    log.info("VERIFY OK: %d reference file(s) present in target with matching hashes",
             total_checked)
    return EXIT_OK


# --------------------------------------------------------------------------- #
# CLI + logging.
# --------------------------------------------------------------------------- #
def configure_logging(level, log_file):
    """Send timestamped, levelled logs to stderr (and optionally to a file)."""
    handlers = [logging.StreamHandler(sys.stderr)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    logging.basicConfig(level=getattr(logging, level),
                        format="%(asctime)s %(levelname)-7s %(message)s",
                        handlers=handlers)


def parse_args(argv=None):
    """Parse CLI arguments into a Namespace (kept separate so it can be tested)."""
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    common.add_argument("--log-file", default=None, help="also append logs here")

    ap = argparse.ArgumentParser(
        description="Self-excluding SHA-256 manifests + fail-fast verification.")
    sub = ap.add_subparsers(dest="command", required=True)

    g = sub.add_parser("generate", parents=[common],
                       help="hash a directory into a self-excluding manifest")
    g.add_argument("--root", required=True, help="directory to hash")
    g.add_argument("--out", required=True, help="manifest path to write")
    g.add_argument("--exclude", nargs="*", default=None,
                   help="extra file NAMES to exclude from hashing")

    v = sub.add_parser("verify", parents=[common],
                       help="check a target manifest against reference manifests")
    v.add_argument("--target", required=True, help="the manifest to check (e.g. received)")
    v.add_argument("--reference", required=True, nargs="+",
                   help="one or more source manifests every entry of which must "
                        "appear in the target with the same hash")
    return ap.parse_args(argv)


def main(argv=None):
    """Dispatch to the requested subcommand and translate failures into exit codes."""
    args = parse_args(argv)
    configure_logging(args.log_level, args.log_file)
    try:
        if args.command == "generate":
            return cmd_generate(args)
        if args.command == "verify":
            return cmd_verify(args)
        log.error("unknown command: %s", args.command)  # unreachable (required=True)
        return EXIT_USAGE
    except SanityError as exc:
        log.error("sanity check failed: %s", exc)
        return EXIT_SANITY
    except (OSError, ValueError) as exc:
        log.error("I/O or manifest error: %s", exc)
        return EXIT_IO


if __name__ == "__main__":
    sys.exit(main())
