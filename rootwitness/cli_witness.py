"""A small, local-only command line witness for one Root Witness log.

The command deliberately has no service dependency beyond the log URLs supplied
at ``init``.  Its state directory contains the witness private key, public log
key, and the most recently accepted checkpoint.  It sends neither telemetry nor
any data other than ordinary HTTP requests to that configured log.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives.asymmetric import ed25519

from rootwitness.checkpoint import CheckpointSigner
from rootwitness.checkpoint import verify as checkpoint_verify
from rootwitness.witness import FileWitnessStore, LogMonitor, Witness

DEFAULT_STATE_DIR = Path.home() / ".rootwitness"
CONFIG_FILE = "config.json"
PRIVATE_KEY_FILE = "witness-ed25519.key"


# Kept as a named helper so an operator can read every network call in this
# file, and so applications embedding the CLI can replace only this boundary.
def _urlopen(request: Request | str, timeout: float = 15.0):
    return urlopen(request, timeout=timeout)


def _state_dir(value: str | None) -> Path:
    return Path(value or os.environ.get("ROOTWITNESS_STATE_DIR", DEFAULT_STATE_DIR)).expanduser()


def _b64decode(value: str, what: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError(f"{what} is not valid base64") from exc


def _vkey(name: str, public_key: ed25519.Ed25519PublicKey) -> str:
    """The C2SP verifier-key spelling: ``name+base64(raw Ed25519 key)``."""
    return name + "+" + base64.b64encode(public_key.public_bytes_raw()).decode("ascii")


def _read_config(directory: Path) -> dict[str, Any]:
    path = directory / CONFIG_FILE
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"no witness configuration in {directory}; run init first") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    if not isinstance(config, dict):
        raise ValueError(f"{path} is not a configuration object")
    return config


def _write_private_key(path: Path, private_key: ed25519.Ed25519PrivateKey) -> None:
    """Write raw Ed25519 private material without ever making it world-readable."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(private_key.private_bytes_raw())
            fh.flush()
            os.fsync(fh.fileno())
    except BaseException:
        # Preserve no accidental, partially-written secret if writing fails.
        try:
            path.unlink()
        except OSError:
            pass
        raise
    os.chmod(path, 0o600)


def _load_components(directory: Path) -> tuple[dict[str, Any], CheckpointSigner, ed25519.Ed25519PublicKey]:
    config = _read_config(directory)
    try:
        origin = config["origin"]
        witness_name = config["witness_name"]
        log_key_bytes = _b64decode(config["log_key"], "stored log key")
        private_bytes = (directory / PRIVATE_KEY_FILE).read_bytes()
    except (KeyError, OSError, TypeError) as exc:
        raise ValueError(f"incomplete witness configuration in {directory}: {exc}") from exc
    if not isinstance(origin, str) or not isinstance(witness_name, str):
        raise ValueError("stored origin and witness name must be strings")
    if len(log_key_bytes) != 32 or len(private_bytes) != 32:
        raise ValueError("stored Ed25519 key has the wrong length")
    try:
        signer = CheckpointSigner(witness_name, ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes))
        log_key = ed25519.Ed25519PublicKey.from_public_bytes(log_key_bytes)
    except Exception as exc:
        raise ValueError(f"cannot load witness keys: {exc}") from exc
    return config, signer, log_key


def _read_response(response) -> bytes:
    try:
        data = response.read()
    finally:
        close = getattr(response, "close", None)
        if close is not None:
            close()
    return data


def _fetch_text(url: str) -> str:
    response = _urlopen(Request(url, headers={"Accept": "text/plain"}))
    return _read_response(response).decode("utf-8")


def _fetch_proof(base_url: str, old_size: int, new_size: int) -> list[bytes]:
    query = urlencode({"old": old_size, "new": new_size})
    response = _urlopen(Request(f"{base_url}/proof/consistency?{query}", headers={"Accept": "application/json"}))
    try:
        payload = json.loads(_read_response(response).decode("utf-8"))
        values = payload["proof"]
        if not isinstance(values, list):
            raise ValueError("proof is not a list")
        proof = [_b64decode(item, "proof hash") for item in values]
    except (KeyError, TypeError, json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise ValueError(f"invalid consistency proof response: {exc}") from exc
    if any(len(item) != 32 for item in proof):
        raise ValueError("consistency proof contains a non-32-byte hash")
    return proof


def _monitor(directory: Path) -> tuple[LogMonitor, dict[str, str]]:
    config, signer, log_key = _load_components(directory)
    origin = config["origin"]
    base_url = config["base_url"].rstrip("/")
    last_note: dict[str, str] = {}

    def checkpoint() -> str:
        note = _fetch_text(base_url + "/checkpoint")
        last_note["note"] = note
        return note

    witness = Witness(signer, FileWitnessStore(directory), {origin: log_key})
    return LogMonitor(witness, checkpoint, lambda old, new: _fetch_proof(base_url, old, new), origin), last_note


def _is_refusal(detail: str) -> bool:
    return detail.startswith("REFUSED TO COSIGN")


def _is_transport_failure(detail: str) -> bool:
    return detail.startswith("could not read log:") or detail.startswith("log would not provide")


def _write_evidence(directory: Path, monitor: LogMonitor, last_note: dict[str, str]) -> Path | None:
    """Persist BOTH signed notes: the one we accepted and the one we refused.

    A single signed checkpoint proves nothing -- of course the log signed its
    own current state. The case is the *pair*: two signatures from the same key
    over two different roots, one of which the log can no longer derive. Anyone
    holding this file can check it with the log's published public key and no
    cooperation from us, which is the point.
    """
    bad = monitor.witness.violations[-1].evidence if monitor.witness.violations else last_note.get("note")
    if not bad:
        return None
    held = monitor.witness.latest_note(monitor.origin)

    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    digest = hashlib.sha256(bad.encode("utf-8")).hexdigest()[:12]
    path = directory / f"REFUSED-{stamp}-{digest}.evidence"
    if path.exists():
        # Repeated polls keep alarming but must never overwrite the original.
        return path

    reason = monitor.witness.violations[-1].args[0] if monitor.witness.violations else "unknown"
    lines = [
        "ROOT WITNESS EVIDENCE",
        "",
        f"origin:      {monitor.origin}",
        f"detected_at: {stamp}",
        f"reason:      {reason}",
        "",
        "This file records that the log signed a checkpoint contradicting one it",
        "had already signed. Verify it yourself, without our help:",
        "",
        "  1. Fetch the log's public key from its /keys endpoint, or use the copy",
        "     you were given at signup.",
        "  2. Check the signature on each note below against that key.",
        "  3. Compare the two roots. If both signatures verify and the roots",
        "     differ at the same tree size, or no consistency proof exists between",
        "     them, the log's recorded history was altered after the fact.",
        "",
        "Keep this file unmodified. Its value is that it is signed by the log,",
        "not by the witness.",
        "",
        "=== NOTE A: previously accepted, signed by the log ===",
        "",
    ]
    if held:
        lines.append(held.rstrip("\n"))
    else:
        # Be explicit rather than silently shipping half a case.
        lines += [
            "(not retained -- this witness stored its state before note retention",
            " was added, so only the root hash was kept. Note B below is still",
            " signed and still checkable, but the contradicting pair is",
            " incomplete. State recorded after this upgrade retains both.)",
        ]
    lines += ["", "=== NOTE B: refused, signed by the log ===", "", bad.rstrip("\n"), ""]

    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
        fh.flush()
        os.fsync(fh.fileno())
    return path


def cmd_init(args: argparse.Namespace) -> int:
    directory = _state_dir(args.state_dir)
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    config_path = directory / CONFIG_FILE
    key_path = directory / PRIVATE_KEY_FILE
    if config_path.exists() or key_path.exists():
        print(f"refusing to overwrite existing witness state in {directory}", file=sys.stderr)
        return 1

    raw_log_key = args.log_key
    # Accept a bare BASE64 key as documented, while also accepting a copied
    # C2SP verifier key for convenience.  The checkpoint identity remains the
    # configured origin, never an untrusted value from the key spelling.
    # Order matters: the standard base64 alphabet CONTAINS "+", so splitting on
    # it first silently truncates a perfectly good bare key. Try the bare form
    # and only fall back to the name+base64 spelling if that fails.
    log_key = None
    try:
        candidate = _b64decode(raw_log_key, "--log-key")
        if len(candidate) == 32:
            log_key = candidate
    except ValueError:
        pass
    if log_key is None and "+" in raw_log_key:
        # First "+", not last: the name cannot contain "+", the base64 key can.
        _, _, tail = raw_log_key.partition("+")
        try:
            log_key = _b64decode(tail, "--log-key")
        except ValueError as exc:
            print(f"init: {exc}", file=sys.stderr)
            return 1
    if log_key is None:
        print("init: --log-key is not valid base64", file=sys.stderr)
        return 1
    if len(log_key) != 32:
        print("init: --log-key must decode to a 32-byte Ed25519 public key", file=sys.stderr)
        return 1

    parsed = urlsplit(args.origin)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        print("init: --origin must be an http(s) URL", file=sys.stderr)
        return 1
    base_url = args.origin.rstrip("/")
    # Signed-note key names cannot contain whitespace or '+'.  This derived
    # name is stable, human-readable, and independent of the log provider.
    host = parsed.netloc.replace("+", "_")
    witness_name = f"witness/{host}"
    private_key = ed25519.Ed25519PrivateKey.generate()
    try:
        _write_private_key(key_path, private_key)
        config = {
            "origin": base_url,
            "base_url": base_url,
            "log_key": base64.b64encode(log_key).decode("ascii"),
            "witness_name": witness_name,
        }
        tmp = config_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, config_path)
    except OSError as exc:
        print(f"init: could not write witness state: {exc}", file=sys.stderr)
        return 1

    print(_vkey(witness_name, private_key.public_key()))
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    directory = _state_dir(args.state_dir)
    try:
        monitor, last_note = _monitor(directory)
        result = monitor.check_once()
    except (OSError, ValueError, URLError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    if result.ok:
        print(f"OK: {result.detail}")
        return 0
    if _is_refusal(result.detail):
        # Write the evidence here too, not only in `watch`. The signed bad note
        # is the artifact a customer takes to their regulator or their lawyer;
        # detecting the violation and then dropping the proof would be the
        # single most expensive bug in this tool. Anyone wiring `check` into CI
        # gets the same evidence as someone running the daemon.
        evidence = _write_evidence(directory, monitor, last_note)
        suffix = f" Evidence: {evidence}" if evidence else ""
        print(f"REFUSED: {result.detail}.{suffix}", file=sys.stderr)
        return 2
    print(f"ERROR: {result.detail}", file=sys.stderr)
    return 1


def cmd_watch(args: argparse.Namespace) -> int:
    directory = _state_dir(args.state_dir)
    if args.interval <= 0:
        print("watch: --interval must be greater than zero", file=sys.stderr)
        return 1
    try:
        monitor, last_note = _monitor(directory)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    try:
        while True:
            result = monitor.check_once()
            if result.ok:
                print(f"OK: {result.detail}")
            elif _is_refusal(result.detail):
                evidence = _write_evidence(directory, monitor, last_note)
                suffix = f" Evidence: {evidence}" if evidence else ""
                print(f"ALARM: {result.detail}.{suffix}", file=sys.stderr)
            elif _is_transport_failure(result.detail):
                print(f"ERROR: {result.detail}", file=sys.stderr)
            else:
                print(f"ERROR: {result.detail}", file=sys.stderr)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 0


def cmd_status(args: argparse.Namespace) -> int:
    directory = _state_dir(args.state_dir)
    try:
        config, signer, log_key = _load_components(directory)
        witness = Witness(signer, FileWitnessStore(directory), {config["origin"]: log_key})
        checkpoint = witness.latest(config["origin"])
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    if checkpoint is None:
        print("No checkpoint remembered yet.")
    else:
        print(f"origin: {checkpoint.origin}")
        print(f"tree size: {checkpoint.tree_size}")
        print(f"root: {base64.b64encode(checkpoint.root_hash).decode('ascii')}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify a public log's signed checkpoint with no account and no state.

    This is deliberately the lowest-barrier command in the tool. Anyone can
    point it at any Root Witness log, including ours, and confirm that the checkpoint
    really is signed by the key the log publishes. It writes nothing to disk.

    What this proves: the operator signed this (origin, size, root) triple, so
    they cannot later deny it.

    What this does NOT prove: that the operator has never rewritten history.
    A single checkpoint is one statement at one moment. Catching a rewrite
    requires remembering an earlier checkpoint and demanding a consistency
    proof, which is what `init` plus `check` do. Do not mistake this command
    for ongoing monitoring.
    """
    origin = args.origin.rstrip("/")
    try:
        log_key = ed25519.Ed25519PublicKey.from_public_bytes(
            _b64decode(args.log_key, "log public key")
        )
    except Exception as exc:
        print(f"ERROR: unusable log public key: {exc}", file=sys.stderr)
        return 2

    try:
        note = _fetch_text(f"{origin}/checkpoint")
    except (URLError, OSError, ValueError) as exc:
        print(f"ERROR: could not fetch the checkpoint: {exc}", file=sys.stderr)
        return 2

    try:
        checkpoint = checkpoint_verify(note, origin, log_key)
    except Exception as exc:
        print(f"REFUSED: checkpoint did not verify: {exc}", file=sys.stderr)
        print(
            "\nThe log served a checkpoint that is not validly signed by the key\n"
            "you supplied. Either the key is wrong for this log, or the\n"
            "checkpoint was not produced by the holder of that key.",
            file=sys.stderr,
        )
        return 1

    print(f"OK: signed checkpoint verified for {checkpoint.origin}")
    print(f"tree size: {checkpoint.tree_size}")
    print(f"root: {base64.b64encode(checkpoint.root_hash).decode('ascii')}")
    print(
        "\nThis proves the operator signed this size and root, so they cannot\n"
        "later deny it. It does NOT prove they have never rewritten history --\n"
        "for that, run `rootwitness init` and then `check` on a schedule, so\n"
        "a stored earlier checkpoint forces them to produce a consistency proof."
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run your own append-only-log witness.")
    subcommands = parser.add_subparsers(dest="command", required=True)

    init = subcommands.add_parser("init", help="create a local witness identity")
    init.add_argument("--origin", required=True, help="log base URL and signed checkpoint origin")
    init.add_argument("--log-key", required=True, help="base64 Ed25519 public key for the log")
    init.add_argument(
        "--state-dir",
        help=f"directory for the witness key and state (default: {DEFAULT_STATE_DIR})",
    )
    init.set_defaults(handler=cmd_init)

    for name, help_text, handler in (
        ("check", "poll once and refuse inconsistent history", cmd_check),
        ("status", "show the last accepted checkpoint", cmd_status),
    ):
        command = subcommands.add_parser(name, help=help_text)
        command.add_argument("--state-dir", help="witness state directory (or ROOTWITNESS_STATE_DIR)")
        command.set_defaults(handler=handler)

    verify = subcommands.add_parser(
        "verify",
        help="one-shot: verify any public log's signed checkpoint (no account, no state)",
    )
    verify.add_argument("--origin", required=True, help="log base URL, e.g. https://example.com/acme")
    verify.add_argument("--log-key", required=True, help="base64 Ed25519 public key the log publishes")
    verify.set_defaults(handler=cmd_verify)

    watch = subcommands.add_parser("watch", help="poll continuously and alarm on refusal")
    watch.add_argument("--state-dir", help="witness state directory (or ROOTWITNESS_STATE_DIR)")
    watch.add_argument("--interval", type=float, default=60.0, help="seconds between polls (default: 60)")
    watch.set_defaults(handler=cmd_watch)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":  # pragma: no cover - console entry point
    raise SystemExit(main())
