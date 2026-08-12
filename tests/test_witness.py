"""Witness tests, written around the attacks rather than the API surface.

The interesting question is never "does add_checkpoint return 200 on a good
input". It is "what happens when the log lies", so most of this file plays the
role of a dishonest log operator and checks that the witness refuses.
"""
from __future__ import annotations

import base64
import threading

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from rootwitness import merkle
from rootwitness import witness as W
from rootwitness.checkpoint import Checkpoint, CheckpointSigner, parse

ORIGIN = "api.rootwitness.com/log0"


class FakeLog:
    """A log we control, so we can make it misbehave on demand."""

    def __init__(self, origin: str = ORIGIN) -> None:
        key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.signer = CheckpointSigner(origin, key)
        self.origin = origin
        self.leaves: list[bytes] = []

    def append(self, data: bytes) -> None:
        self.leaves.append(merkle.leaf_hash(data))

    def checkpoint(self) -> Checkpoint:
        return Checkpoint(
            origin=self.origin,
            tree_size=len(self.leaves),
            root_hash=merkle.root_from_leaf_hashes(self.leaves),
        )

    def note(self) -> str:
        return self.signer.sign(self.checkpoint())

    def proof(self, old_size: int) -> list[bytes]:
        if old_size == 0 or old_size == len(self.leaves):
            return []
        return merkle.consistency_proof(old_size, self.leaves)

    def submit(self, wit: W.Witness, old_size: int | None = None) -> W.WitnessResponse:
        if old_size is None:
            current = wit.latest(self.origin)
            old_size = current.tree_size if current else 0
        return wit.add_checkpoint(
            W.build_add_checkpoint(old_size, self.proof(old_size), self.note())
        )


@pytest.fixture
def log() -> FakeLog:
    return FakeLog()


@pytest.fixture
def wit(log: FakeLog) -> W.Witness:
    return W.Witness(
        signer=CheckpointSigner.generate("witness.customer.example/w1"),
        store=W.MemoryWitnessStore(),
        trusted_keys={ORIGIN: log.signer.public_key},
    )


def grow(log: FakeLog, n: int) -> None:
    start = len(log.leaves)
    for i in range(start, start + n):
        log.append(f"record-{i}".encode())


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_cosigns_a_growing_honest_log(log, wit):
    for _ in range(12):
        grow(log, 3)
        response = log.submit(wit)
        assert response.ok, response.body
    assert wit.latest(ORIGIN).tree_size == 36
    assert wit.violations == []


def test_cosignature_verifies_and_attaches_to_the_note(log, wit):
    grow(log, 9)
    note = log.note()
    response = wit.add_checkpoint(W.build_add_checkpoint(0, [], note))
    assert response.ok

    cosigned = note + response.body
    from rootwitness import checkpoint as cp

    assert cp.verify(cosigned, ORIGIN, log.signer.public_key).tree_size == 9
    assert cp.verify(cosigned, wit.signer.name, wit.signer.public_key).tree_size == 9


def test_empty_log_is_witnessable(log, wit):
    response = log.submit(wit)
    assert response.ok
    assert wit.latest(ORIGIN).tree_size == 0


def test_resubmitting_the_same_checkpoint_is_accepted(log, wit):
    grow(log, 7)
    assert log.submit(wit).ok
    again = wit.add_checkpoint(W.build_add_checkpoint(7, [], log.note()))
    assert again.ok


# ---------------------------------------------------------------------------
# The three attacks
# ---------------------------------------------------------------------------


def test_detects_a_rewritten_entry(log, wit):
    """Operator edits history and rebuilds a perfectly valid tree around it."""
    grow(log, 20)
    assert log.submit(wit).ok

    log.leaves[4] = merkle.leaf_hash(b"the trade we wish we had logged")
    grow(log, 5)

    response = log.submit(wit)
    assert response.status == 422
    assert wit.violations
    assert "rewritten" in str(wit.violations[-1])
    # State must not advance past a checkpoint we refused.
    assert wit.latest(ORIGIN).tree_size == 20


def test_detects_truncation(log, wit):
    grow(log, 30)
    assert log.submit(wit).ok

    del log.leaves[25:]
    # A shrinking log cannot even name a matching old size, so it is caught
    # at the 409 stage rather than by the proof.
    response = wit.add_checkpoint(W.build_add_checkpoint(30, [], log.note()))
    assert response.status == 400  # old size 30 exceeds new size 25
    assert wit.latest(ORIGIN).tree_size == 30


def test_detects_a_deleted_entry_in_the_middle(log, wit):
    grow(log, 20)
    assert log.submit(wit).ok
    del log.leaves[9]
    grow(log, 10)
    response = log.submit(wit)
    assert response.status == 422
    assert wit.violations


def test_detects_a_split_view(log, wit):
    """Two different roots at one size: the classic equivocation."""
    grow(log, 16)
    assert log.submit(wit).ok

    forked = FakeLog()
    for i in range(15):
        forked.append(f"record-{i}".encode())
    forked.append(b"a different sixteenth record")

    response = wit.add_checkpoint(W.build_add_checkpoint(16, [], forked.note()))
    assert response.status == 422
    assert "split view" in str(wit.violations[-1])


def test_refuses_a_forged_consistency_proof(log, wit):
    grow(log, 12)
    assert log.submit(wit).ok
    grow(log, 8)
    bogus = [b"\xab" * 32 for _ in range(4)]
    response = wit.add_checkpoint(
        W.build_add_checkpoint(12, bogus, log.note())
    )
    assert response.status == 422


def test_violation_carries_the_signed_evidence(log, wit):
    grow(log, 10)
    log.submit(wit)
    log.leaves[2] = merkle.leaf_hash(b"tampered")
    grow(log, 4)
    log.submit(wit)

    violation = wit.violations[-1]
    assert violation.origin == ORIGIN
    # The evidence is the log's own signed note, so it stands on its own.
    from rootwitness import checkpoint as cp

    assert cp.verify(violation.evidence, ORIGIN, log.signer.public_key)


def test_violation_callback_fires_and_a_broken_handler_does_not_swallow_it(log):
    fired = []

    def boom(v):
        fired.append(v)
        raise RuntimeError("the customer's pager is broken")

    wit = W.Witness(
        signer=CheckpointSigner.generate("w.example/1"),
        store=W.MemoryWitnessStore(),
        trusted_keys={ORIGIN: log.signer.public_key},
        on_violation=boom,
    )
    grow(log, 8)
    log.submit(wit)
    log.leaves[1] = merkle.leaf_hash(b"tampered")
    grow(log, 2)
    response = log.submit(wit)

    assert response.status == 422
    assert len(fired) == 1
    assert wit.violations  # recorded even though the handler blew up


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


def test_unknown_origin_is_404(wit):
    other = FakeLog(origin="stranger.example/log")
    other.append(b"x")
    response = wit.add_checkpoint(W.build_add_checkpoint(0, [], other.note()))
    assert response.status == 404


def test_untrusted_key_for_a_known_origin_is_403(log, wit):
    impostor = FakeLog()
    impostor.signer = CheckpointSigner(ORIGIN, ed25519.Ed25519PrivateKey.generate())
    impostor.append(b"x")
    response = wit.add_checkpoint(W.build_add_checkpoint(0, [], impostor.note()))
    assert response.status == 403


def test_corrupted_signature_is_403(log, wit):
    grow(log, 4)
    note = log.note()
    _, sigs, _ = parse(note)
    good = base64.b64encode(sigs[0].key_id + sigs[0].signature).decode()
    bad = base64.b64encode(sigs[0].key_id + b"\x00" * 64).decode()
    response = wit.add_checkpoint(
        W.build_add_checkpoint(0, [], note.replace(good, bad))
    )
    assert response.status == 403


def test_authentication_happens_before_consistency_work(log, wit):
    """An unauthenticated caller must not be able to plant violations."""
    grow(log, 10)
    log.submit(wit)

    impostor = FakeLog()
    impostor.signer = CheckpointSigner(ORIGIN, ed25519.Ed25519PrivateKey.generate())
    for i in range(20):
        impostor.append(f"garbage-{i}".encode())
    response = wit.add_checkpoint(
        W.build_add_checkpoint(10, [b"\x00" * 32], impostor.note())
    )
    assert response.status == 403
    assert wit.violations == []  # no spurious alarm


# ---------------------------------------------------------------------------
# Spec-mandated status codes
# ---------------------------------------------------------------------------


def test_stale_old_size_gets_409_with_the_real_size(log, wit):
    grow(log, 14)
    log.submit(wit)
    grow(log, 3)
    response = wit.add_checkpoint(W.build_add_checkpoint(9, log.proof(9), log.note()))
    assert response.status == 409
    assert response.body == "14\n"
    assert response.content_type == W.SIZE_CONTENT_TYPE


def test_zero_old_size_probe_reveals_the_recorded_size(log, wit):
    grow(log, 22)
    log.submit(wit)
    grow(log, 1)
    response = wit.add_checkpoint(W.build_add_checkpoint(0, [], log.note()))
    assert response.status == 409
    assert response.body == "22\n"


def test_old_size_greater_than_checkpoint_size_is_400(log, wit):
    grow(log, 5)
    response = wit.add_checkpoint(W.build_add_checkpoint(9, [], log.note()))
    assert response.status == 400


def test_nonempty_proof_with_zero_old_size_is_422(log, wit):
    grow(log, 5)
    response = wit.add_checkpoint(
        W.build_add_checkpoint(0, [b"\x11" * 32], log.note())
    )
    assert response.status == 422


def test_zero_size_checkpoint_with_wrong_root_is_422(log, wit):
    forged = Checkpoint(origin=ORIGIN, tree_size=0, root_hash=b"\x42" * 32)
    note = log.signer.sign(forged)
    response = wit.add_checkpoint(W.build_add_checkpoint(0, [], note))
    assert response.status == 422
    assert wit.violations


def test_oversized_proof_is_rejected(log, wit):
    grow(log, 5)
    response = wit.add_checkpoint(
        W.build_add_checkpoint(1, [b"\x00" * 32] * 64, log.note())
    )
    assert response.status == 400


@pytest.mark.parametrize(
    "body",
    [
        "no old line\n\ncheckpoint\n",
        "old x\n\nnote\n",
        "old 01\n\nnote\n",
        "old 1\n",  # no blank line
        "old 1\nnot-base64!!\n\nnote\n",
    ],
)
def test_malformed_requests_are_400(wit, body):
    assert wit.add_checkpoint(body).status == 400


def test_proof_hash_of_wrong_length_is_rejected(log, wit):
    short = base64.b64encode(b"\x00" * 16).decode()
    body = f"old 1\n{short}\n\n" + log.note()
    assert wit.add_checkpoint(body).status == 400


# ---------------------------------------------------------------------------
# The atomicity requirement
# ---------------------------------------------------------------------------


def test_state_is_persisted_before_the_signature_is_returned(log):
    """The spec's rule, checked by observation rather than by reading the code.

    We wrap the store so it records the order of commit versus signing. If a
    future refactor ever signs first, this fails.
    """
    events: list[str] = []
    inner = W.MemoryWitnessStore()

    class Recording(W.WitnessStore):
        def transaction(self, origin):
            import contextlib

            @contextlib.contextmanager
            def cm():
                with inner.transaction(origin) as txn:
                    yield txn
                    wrote = txn._pending is not None
                if wrote:
                    events.append("committed")

            return cm()

    class RecordingSigner(CheckpointSigner):
        def signature_line(self, checkpoint):
            events.append("signed")
            return super().signature_line(checkpoint)

    wit = W.Witness(
        signer=RecordingSigner.generate("w.example/1"),
        store=Recording(),
        trusted_keys={ORIGIN: log.signer.public_key},
    )
    grow(log, 6)
    assert log.submit(wit).ok
    assert events == ["committed", "signed"]


def test_concurrent_submissions_never_roll_state_backwards(log):
    """The exact race the spec warns about, run for real.

    Interleaved submissions at many sizes must never leave the witness
    remembering a smaller tree than one it already cosigned.
    """
    grow(log, 200)
    wit = W.Witness(
        signer=CheckpointSigner.generate("w.example/1"),
        store=W.MemoryWitnessStore(),
        trusted_keys={ORIGIN: log.signer.public_key},
    )

    sizes = list(range(1, 200))
    observed: list[int] = []
    lock = threading.Lock()

    def submit(size: int) -> None:
        snapshot = FakeLog()
        snapshot.signer = log.signer
        snapshot.leaves = log.leaves[:size]
        current = wit.latest(ORIGIN)
        old = current.tree_size if current else 0
        if old > size:
            return
        response = wit.add_checkpoint(
            W.build_add_checkpoint(old, snapshot.proof(old), snapshot.note())
        )
        if response.ok:
            with lock:
                observed.append(size)

    threads = [threading.Thread(target=submit, args=(s,)) for s in sizes]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert wit.latest(ORIGIN).tree_size == max(observed)
    assert wit.violations == []


def test_file_store_survives_a_restart(tmp_path, log):
    store_dir = tmp_path / "witness-state"

    def make_witness():
        return W.Witness(
            signer=CheckpointSigner.generate("w.example/1"),
            store=W.FileWitnessStore(store_dir),
            trusted_keys={ORIGIN: log.signer.public_key},
        )

    first = make_witness()
    grow(log, 25)
    assert log.submit(first).ok

    # Restart: brand new process-equivalent, same directory.
    second = make_witness()
    assert second.latest(ORIGIN).tree_size == 25

    # And it still refuses a rewrite it only knows about from disk.
    log.leaves[3] = merkle.leaf_hash(b"tampered after the restart")
    grow(log, 5)
    assert log.submit(second).status == 422


def test_file_store_keeps_logs_separate(tmp_path):
    a, b = FakeLog("a.example/log"), FakeLog("b.example/log")
    store = W.FileWitnessStore(tmp_path)
    wit = W.Witness(
        signer=CheckpointSigner.generate("w.example/1"),
        store=store,
        trusted_keys={
            "a.example/log": a.signer.public_key,
            "b.example/log": b.signer.public_key,
        },
    )
    grow(a, 5)
    grow(b, 11)
    assert a.submit(wit).ok
    assert b.submit(wit).ok
    assert wit.latest("a.example/log").tree_size == 5
    assert wit.latest("b.example/log").tree_size == 11


# ---------------------------------------------------------------------------
# The monitor a customer runs
# ---------------------------------------------------------------------------


def test_monitor_reports_healthy_growth(log, wit):
    monitor = W.LogMonitor(
        wit, log.note, lambda old, new: log.proof(old), ORIGIN
    )
    grow(log, 10)
    first = monitor.check_once()
    assert first.ok and first.tree_size == 10

    grow(log, 15)
    second = monitor.check_once()
    assert second.ok and second.tree_size == 25
    assert "consistent through 25" in second.detail


def test_monitor_reports_tampering_loudly(log, wit):
    monitor = W.LogMonitor(wit, log.note, lambda old, new: log.proof(old), ORIGIN)
    grow(log, 12)
    assert monitor.check_once().ok

    log.leaves[6] = merkle.leaf_hash(b"tampered")
    grow(log, 3)
    result = monitor.check_once()
    assert not result.ok
    assert "REFUSED TO COSIGN" in result.detail


def test_monitor_reports_an_unreachable_log(wit):
    def down() -> str:
        raise ConnectionError("connection refused")

    monitor = W.LogMonitor(wit, down, lambda old, new: [], ORIGIN)
    result = monitor.check_once()
    assert not result.ok
    assert "could not read log" in result.detail


def test_monitor_reports_a_log_that_withholds_proofs(log, wit):
    """Refusing to produce a proof is itself a red flag worth surfacing."""
    monitor = W.LogMonitor(wit, log.note, lambda old, new: log.proof(old), ORIGIN)
    grow(log, 10)
    assert monitor.check_once().ok

    def refuse(old: int, new: int):
        raise RuntimeError("500 Internal Server Error")

    monitor.fetch_consistency_proof = refuse
    grow(log, 5)
    result = monitor.check_once()
    assert not result.ok
    assert "would not provide a consistency proof" in result.detail


def test_evidence_retains_the_note_that_justified_the_accepted_state():
    """The pair is the case. A root hash alone is only the witness's own word."""
    from rootwitness.witness import FileWitnessStore
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        store = FileWitnessStore(d)
        cp = Checkpoint(origin="rootwitness.test/acme", tree_size=4, root_hash=b"\x11" * 32)
        with store.transaction(cp.origin) as txn:
            txn.set(cp, "rootwitness.test/acme\n4\nEREREREREQ==\n\n\u2014 rootwitness.test/acme AAAA\n")
        with store.transaction(cp.origin) as txn:
            assert txn.current is not None
            assert txn.current.tree_size == 4
            assert txn.current_note is not None
            assert "rootwitness.test/acme" in txn.current_note


def test_state_written_before_note_retention_still_loads():
    """An older state file must not brick the witness; detection still works
    off the root hash, and the evidence file says the note is missing."""
    import base64 as b64
    import json as js
    import tempfile
    from pathlib import Path

    from rootwitness.witness import FileWitnessStore

    with tempfile.TemporaryDirectory() as d:
        store = FileWitnessStore(d)
        origin = "rootwitness.test/acme"
        safe = b64.urlsafe_b64encode(origin.encode()).decode().rstrip("=")
        Path(d, f"{safe}.json").write_text(
            js.dumps({"origin": origin, "tree_size": 7, "root_hash": b64.b64encode(b"\x22" * 32).decode()})
        )
        with store.transaction(origin) as txn:
            assert txn.current is not None and txn.current.tree_size == 7
            assert txn.current_note is None
