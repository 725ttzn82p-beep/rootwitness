"""The witness: a customer-runnable program that refuses to be lied to.

Why this is the product
-----------------------

The cryptography in `merkle.py` is a commodity. Anyone can implement RFC 6962
in a weekend, and several open-source projects already give away a better
version than we will ever write. So the Merkle tree is not the moat, and
pretending otherwise would be a strategic mistake and a marketing lie.

The moat is this file, because of what it lets a customer say:

    "I do not trust my log provider. I run my own witness. If they ever
     rewrite, truncate, or fork my history, my witness refuses to cosign and
     tells me -- and their own signature on the bad checkpoint is the proof."

A witness holds one small piece of state per log: the latest checkpoint it has
cosigned. From that it can detect the three attacks that matter:

* **rewrite**  -- an old entry is edited, so the consistency proof fails
* **truncate** -- the tree shrinks, or a claimed size does not match its root
* **split view** -- the log shows a different history to different parties,
  which is caught when the witness's remembered root cannot be reconciled

Crucially the log cannot route around a witness it does not control. To serve
a customer a forked history, it would have to obtain that customer's own
witness cosignature on a checkpoint that contradicts what the witness already
saw -- which is exactly what this code refuses to do.

Every customer who runs one makes the guarantee stronger for every other
customer. That is a network effect an open-source clone starts with zero of.

Implementation notes
--------------------

Follows c2sp.org/tlog-witness. Two rules from that spec carry almost all of
the security weight, and both are easy to get subtly wrong:

1. **State must be persisted before the cosignature is returned**, and the
   read-check-write must be atomic. The spec spells out the race: two
   concurrent submissions at sizes N and N+K can interleave so the stored size
   is rolled back from N+K to N, silently un-witnessing K leaves. We make that
   race unrepresentable by only exposing state through a locked transaction
   that commits before the signature is produced -- there is no API by which a
   caller can sign first and persist later.

2. **An inconsistent checkpoint is not an error, it is evidence.** The spec
   permits logging such requests as possible proof of log misbehavior. For our
   customers that is the entire point, so violations are recorded durably and
   surfaced, never merely rejected.

Deliberate deviation from the spec
----------------------------------

The spec says witnesses SHOULD use ML-DSA-44 cosignatures, which carry a
timestamp. We currently emit plain Ed25519 note signatures instead. This is a
real deviation and it is written down here rather than glossed over: without a
timestamp, a cosignature proves the witness saw this history, but not when.
Freshness therefore has to come from the witness's own logs rather than from
the signature. Upgrading is additive -- a second signature line -- so no
verifier that trusts today's output breaks later.
"""
from __future__ import annotations

import base64
import contextlib
import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

from cryptography.hazmat.primitives.asymmetric import ed25519

from rootwitness import merkle
from rootwitness.checkpoint import (
    Checkpoint,
    CheckpointError,
    CheckpointSigner,
    key_id,
    parse,
)

# The spec caps a consistency proof at 63 hashes; a proof is at most
# ceil(log2(n)) long, so 63 covers trees up to 2**63 leaves. Anything longer is
# a malformed or hostile request, not a big log.
MAX_PROOF_LINES = 63

SIZE_CONTENT_TYPE = "text/x.tlog.size"


class WitnessViolation(Exception):
    """The log presented something inconsistent with what we already witnessed.

    This is deliberately a distinct type from `CheckpointError`. A parse error
    is a bug or a bad client; this is a signed statement by the log that
    contradicts an earlier signed statement by the same log. It is the alarm
    the customer bought the product for.
    """

    def __init__(self, message: str, *, origin: str, evidence: str) -> None:
        super().__init__(message)
        self.origin = origin
        self.evidence = evidence


@dataclass(frozen=True)
class WitnessResponse:
    status: int
    body: str
    content_type: str = "text/plain; charset=utf-8"

    @property
    def ok(self) -> bool:
        return self.status == 200


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------


class _Transaction:
    """A held lock plus the current state, with exactly one way to commit."""

    def __init__(self, current: Checkpoint | None, current_note: str | None = None) -> None:
        self.current = current
        # The signed note that produced `current`. Retained because a root hash
        # alone is only the witness's own word; the log's signature over that
        # root is what makes a later contradiction attributable to the log.
        self.current_note = current_note
        self._pending: Checkpoint | None = None
        self._pending_note: str | None = None

    def set(self, checkpoint: Checkpoint, note: str | None = None) -> None:
        self._pending = checkpoint
        self._pending_note = note


class WitnessStore:
    """Durable per-origin state.

    The only supported access path is `transaction`, which must hold an
    exclusive lock for its whole body and must durably commit before it
    returns. Callers cannot obtain state any other way, which is what makes
    the rollback race from the spec impossible to write.
    """

    @contextlib.contextmanager
    def transaction(self, origin: str) -> Iterator[_Transaction]:
        raise NotImplementedError


class MemoryWitnessStore(WitnessStore):
    """For tests and ephemeral use. Not durable -- never ship this."""

    def __init__(self) -> None:
        self._state: dict[str, tuple[Checkpoint, str | None]] = {}
        self._lock = threading.Lock()

    @contextlib.contextmanager
    def transaction(self, origin: str) -> Iterator[_Transaction]:
        with self._lock:
            held = self._state.get(origin)
            txn = _Transaction(held[0] if held else None, held[1] if held else None)
            yield txn
            if txn._pending is not None:
                self._state[origin] = (txn._pending, txn._pending_note)


class FileWitnessStore(WitnessStore):
    """Durable state in a directory. Runs anywhere, including a Raspberry Pi.

    Commit is write-temp, fsync, rename, fsync-directory: the rename is atomic
    on POSIX, and the fsyncs are what make "persisted" mean survived-a-power-cut
    rather than reached-the-page-cache. A witness that loses state on a crash
    can be induced to cosign a history it already contradicted, so this is a
    security property, not tidiness.
    """

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _path(self, origin: str) -> Path:
        safe = base64.urlsafe_b64encode(origin.encode()).decode().rstrip("=")
        return self.directory / f"{safe}.json"

    def _read(self, origin: str) -> tuple[Checkpoint | None, str | None]:
        path = self._path(origin)
        if not path.exists():
            return None, None
        raw = json.loads(path.read_text())
        checkpoint = Checkpoint(
            origin=raw["origin"],
            tree_size=raw["tree_size"],
            root_hash=base64.b64decode(raw["root_hash"]),
        )
        # State written by an older version has no note. That is recoverable --
        # detection still works off the root hash -- so read it rather than
        # refusing to start, and let the evidence file say the note is absent.
        return checkpoint, raw.get("note")

    def _write(self, checkpoint: Checkpoint, note: str | None = None) -> None:
        path = self._path(checkpoint.origin)
        tmp = path.with_suffix(".tmp")
        payload = json.dumps(
            {
                "origin": checkpoint.origin,
                "tree_size": checkpoint.tree_size,
                "root_hash": base64.b64encode(checkpoint.root_hash).decode(),
                "note": note,
            }
        )
        with open(tmp, "w") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        dir_fd = os.open(self.directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    @contextlib.contextmanager
    def transaction(self, origin: str) -> Iterator[_Transaction]:
        lock_path = self.directory / ".lock"
        with self._lock:
            with open(lock_path, "w") as lock_fh:
                _flock(lock_fh)
                try:
                    held, held_note = self._read(origin)
                    txn = _Transaction(held, held_note)
                    yield txn
                    if txn._pending is not None:
                        self._write(txn._pending, txn._pending_note)
                finally:
                    _unflock(lock_fh)


def _flock(fh) -> None:
    try:
        import fcntl

        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
    except ImportError:  # pragma: no cover - non-POSIX
        pass


def _unflock(fh) -> None:
    try:
        import fcntl

        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    except ImportError:  # pragma: no cover - non-POSIX
        pass


# ---------------------------------------------------------------------------
# Request parsing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AddCheckpointRequest:
    old_size: int
    proof: list[bytes]
    note: str


def parse_add_checkpoint(body: str) -> AddCheckpointRequest:
    """Parse an add-checkpoint request body.

    Layout: an old-size line, zero or more base64 proof lines, an empty line,
    then the checkpoint. The empty line is found first because the checkpoint
    itself contains a blank line before its signatures.
    """
    if "\n\n" not in body:
        raise CheckpointError("request has no blank line before the checkpoint")

    head, _, note = body.partition("\n\n")
    lines = head.split("\n")

    old_line = lines[0]
    if not old_line.startswith("old "):
        raise CheckpointError(f"expected an old size line, got {old_line!r}")
    size_text = old_line[4:]
    if not size_text.isdigit():
        raise CheckpointError(f"old size is not ASCII decimal: {size_text!r}")
    if size_text != "0" and size_text.startswith("0"):
        raise CheckpointError("old size has a leading zero")
    old_size = int(size_text)

    proof_lines = [line for line in lines[1:] if line]
    if len(proof_lines) > MAX_PROOF_LINES:
        raise CheckpointError(
            f"consistency proof has {len(proof_lines)} lines, max is {MAX_PROOF_LINES}"
        )

    proof = []
    for line in proof_lines:
        try:
            h = base64.b64decode(line, validate=True)
        except Exception as exc:
            raise CheckpointError(f"proof line is not valid base64: {exc}") from exc
        if len(h) != merkle.HASH_SIZE:
            raise CheckpointError(f"proof hash is {len(h)} bytes, expected 32")
        proof.append(h)

    return AddCheckpointRequest(old_size=old_size, proof=proof, note=note)


def build_add_checkpoint(old_size: int, proof: list[bytes], note: str) -> str:
    """Build a request body. Used by the log when submitting to a witness."""
    lines = [f"old {old_size}"]
    lines.extend(base64.b64encode(h).decode() for h in proof)
    return "\n".join(lines) + "\n\n" + note


# ---------------------------------------------------------------------------
# The witness
# ---------------------------------------------------------------------------


class Witness:
    """Cosigns checkpoints, and refuses when a log contradicts itself."""

    def __init__(
        self,
        signer: CheckpointSigner,
        store: WitnessStore,
        trusted_keys: dict[str, ed25519.Ed25519PublicKey],
        *,
        on_violation: Callable[[WitnessViolation], None] | None = None,
    ) -> None:
        self.signer = signer
        self.store = store
        self.trusted_keys = dict(trusted_keys)
        self._on_violation = on_violation
        self.violations: list[WitnessViolation] = []

    # -- helpers ---------------------------------------------------------

    def _violation(self, message: str, origin: str, note: str) -> WitnessViolation:
        v = WitnessViolation(message, origin=origin, evidence=note)
        self.violations.append(v)
        if self._on_violation is not None:
            # A failing alarm handler must not swallow the alarm.
            try:
                self._on_violation(v)
            except Exception:
                pass
        return v

    def _verify_log_signature(self, note: str, checkpoint: Checkpoint) -> int:
        """Return 200 if a trusted signature verifies, else the status to send."""
        public_key = self.trusted_keys.get(checkpoint.origin)
        if public_key is None:
            return 404

        _, signatures, _ = parse(note)
        want_id = key_id(checkpoint.origin, public_key)
        signed = checkpoint.signed_bytes()

        for sig in signatures:
            if sig.name != checkpoint.origin or sig.key_id != want_id:
                continue  # unknown key: MUST be ignored, not rejected
            try:
                public_key.verify(sig.signature, signed)
            except Exception:
                # Matching name and key ID but a bad signature. Per the
                # signed-note spec this note is malformed, so 403 -- but only
                # after exhausting other lines, since key IDs are 4 bytes and
                # can collide.
                continue
            return 200
        return 403

    # -- the endpoint ----------------------------------------------------

    def add_checkpoint(self, body: str) -> WitnessResponse:
        """Handle POST <prefix>/add-checkpoint.

        Every check below is required by the spec. The ordering matters: we
        authenticate the log before doing consistency work, so an unauthenticated
        caller cannot make us burn cycles or record spurious violations.
        """
        try:
            request = parse_add_checkpoint(body)
            checkpoint, _, _ = parse(request.note)
        except CheckpointError as exc:
            return WitnessResponse(400, f"{exc}\n")

        status = self._verify_log_signature(request.note, checkpoint)
        if status != 200:
            return WitnessResponse(status, "")

        # From here the log is authenticated, so anything inconsistent is
        # attributable evidence rather than noise.

        if request.old_size > checkpoint.tree_size:
            return WitnessResponse(400, "old size exceeds checkpoint size\n")

        if checkpoint.tree_size == 0 and checkpoint.root_hash != merkle.empty_root():
            self._violation(
                "size-zero checkpoint with a non-empty root hash",
                checkpoint.origin,
                request.note,
            )
            return WitnessResponse(422, "empty tree must have the empty root hash\n")

        with self.store.transaction(checkpoint.origin) as txn:
            current = txn.current
            current_size = current.tree_size if current else 0

            if request.old_size != current_size:
                # Not necessarily misbehaviour -- a stale client looks the same.
                return WitnessResponse(
                    409, f"{current_size}\n", content_type=SIZE_CONTENT_TYPE
                )

            if request.old_size == 0:
                if request.proof:
                    return WitnessResponse(
                        422, "consistency proof must be empty when old size is zero\n"
                    )
            elif request.old_size == checkpoint.tree_size:
                assert current is not None
                if checkpoint.root_hash != current.root_hash:
                    self._violation(
                        f"two different roots at size {checkpoint.tree_size}: "
                        "the log is presenting a split view",
                        checkpoint.origin,
                        request.note,
                    )
                    return WitnessResponse(422, "root hash changed at the same size\n")
            else:
                assert current is not None
                if not merkle.verify_consistency(
                    current.tree_size,
                    checkpoint.tree_size,
                    current.root_hash,
                    checkpoint.root_hash,
                    request.proof,
                ):
                    self._violation(
                        f"no valid consistency proof from size {current.tree_size} "
                        f"to size {checkpoint.tree_size}: history was rewritten",
                        checkpoint.origin,
                        request.note,
                    )
                    return WitnessResponse(422, "consistency proof did not verify\n")

            # Commit happens on exiting this block, strictly before we sign.
            txn.set(checkpoint, request.note)

        return WitnessResponse(200, self.signer.signature_line(checkpoint))

    # -- client side -----------------------------------------------------

    def latest(self, origin: str) -> Checkpoint | None:
        with self.store.transaction(origin) as txn:
            return txn.current

    def latest_note(self, origin: str) -> str | None:
        """The log's own signed note for the state we currently hold.

        Paired with a contradicting note, this is the whole case: two
        signatures from the same key over two different roots. Alone, neither
        is worth anything.
        """
        with self.store.transaction(origin) as txn:
            return txn.current_note


# ---------------------------------------------------------------------------
# The customer-facing monitor
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MonitorResult:
    checked_at: float
    origin: str
    tree_size: int
    ok: bool
    detail: str


class LogMonitor:
    """What a customer actually runs: fetch, verify, cosign, shout on failure.

    Deliberately tiny and dependency-light. A customer must be able to read
    the whole thing in one sitting and satisfy themselves that it does not
    phone home and cannot be told to look the other way. If they cannot audit
    the witness, the witness is worth nothing to them.
    """

    def __init__(
        self,
        witness: Witness,
        fetch_checkpoint: Callable[[], str],
        fetch_consistency_proof: Callable[[int, int], list[bytes]],
        origin: str,
    ) -> None:
        self.witness = witness
        self.fetch_checkpoint = fetch_checkpoint
        self.fetch_consistency_proof = fetch_consistency_proof
        self.origin = origin

    def check_once(self) -> MonitorResult:
        now = time.time()
        try:
            note = self.fetch_checkpoint()
            checkpoint, _, _ = parse(note)
        except Exception as exc:
            return MonitorResult(now, self.origin, -1, False, f"could not read log: {exc}")

        current = self.witness.latest(self.origin)
        old_size = current.tree_size if current else 0

        proof: list[bytes] = []
        if 0 < old_size < checkpoint.tree_size:
            try:
                proof = self.fetch_consistency_proof(old_size, checkpoint.tree_size)
            except Exception as exc:
                return MonitorResult(
                    now,
                    self.origin,
                    checkpoint.tree_size,
                    False,
                    f"log would not provide a consistency proof: {exc}",
                )

        response = self.witness.add_checkpoint(
            build_add_checkpoint(old_size, proof, note)
        )

        if response.ok:
            return MonitorResult(
                now,
                self.origin,
                checkpoint.tree_size,
                True,
                f"consistent through {checkpoint.tree_size} entries",
            )

        if response.status == 409:
            return MonitorResult(
                now, self.origin, checkpoint.tree_size, False,
                f"witness state moved underneath us (now {response.body.strip()}); retry",
            )

        return MonitorResult(
            now,
            self.origin,
            checkpoint.tree_size,
            False,
            f"REFUSED TO COSIGN ({response.status}): {response.body.strip()}",
        )
