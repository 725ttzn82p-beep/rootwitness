"""Checkpoint tests, weighted toward the bugs that break interoperability.

Two classes of failure matter here and neither shows up in casual use:

1. **Signing the wrong bytes.** Off by one newline and every signature
   verifies against our own verifier and fails against every other
   implementation of the spec. Pinned explicitly.
2. **Signing an inconsistent checkpoint.** This is the one that destroys the
   product rather than the build, so it gets adversarial cases rather than
   a happy path.
"""
from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from rootwitness import checkpoint as cp
from rootwitness import merkle

ORIGIN = "api.rootwitness.com/log0"


def leaf_hashes(n: int) -> list[bytes]:
    return [merkle.leaf_hash(f"record-{i}".encode()) for i in range(n)]


def make(n: int, origin: str = ORIGIN) -> cp.Checkpoint:
    return cp.Checkpoint(
        origin=origin,
        tree_size=n,
        root_hash=merkle.root_from_leaf_hashes(leaf_hashes(n)),
    )


@pytest.fixture
def signer() -> cp.CheckpointSigner:
    # Deterministic key so failures are reproducible.
    key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    return cp.CheckpointSigner(ORIGIN, key)


# ---------------------------------------------------------------------------
# Body format
# ---------------------------------------------------------------------------


def test_body_is_three_lines_ending_in_newline():
    body = make(20).body()
    assert body.endswith("\n")
    lines = body.split("\n")
    assert lines[-1] == ""  # nothing after the final newline
    assert len(lines) == 4  # origin, size, root, and the empty tail
    assert lines[0] == ORIGIN
    assert lines[1] == "20"
    assert base64.b64decode(lines[2]) == make(20).root_hash


def test_body_matches_the_spec_example_shape():
    """Spec example: origin, decimal size, standard base64 root, in that order."""
    body = cp.Checkpoint(
        origin="example.com/behind-the-sofa",
        tree_size=20852163,
        root_hash=base64.b64decode("CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I="),
    ).body()
    assert body == (
        "example.com/behind-the-sofa\n"
        "20852163\n"
        "CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n"
    )


def test_tree_size_has_no_leading_zeroes_and_empty_tree_is_zero():
    assert make(0).body().split("\n")[1] == "0"
    assert make(7).body().split("\n")[1] == "7"


def test_empty_tree_root_is_the_rfc_empty_root():
    assert make(0).root_hash == merkle.empty_root()


def test_checkpoint_is_frozen():
    c = make(5)
    with pytest.raises(Exception):
        c.tree_size = 6  # type: ignore[misc]


def test_origin_validation():
    for bad in ("", "has space", "has+plus"):
        with pytest.raises(cp.CheckpointError):
            cp.Checkpoint(origin=bad, tree_size=1, root_hash=b"\x00" * 32)


def test_root_hash_length_validated():
    with pytest.raises(cp.CheckpointError):
        cp.Checkpoint(origin=ORIGIN, tree_size=1, root_hash=b"\x00" * 31)


def test_negative_tree_size_rejected():
    with pytest.raises(cp.CheckpointError):
        cp.Checkpoint(origin=ORIGIN, tree_size=-1, root_hash=b"\x00" * 32)


# ---------------------------------------------------------------------------
# What exactly gets signed -- the interoperability trap
# ---------------------------------------------------------------------------


def test_signed_bytes_include_final_newline_but_not_the_blank_line(signer):
    c = make(20)
    signed = c.signed_bytes()
    assert signed.endswith(b"\n")
    assert not signed.endswith(b"\n\n")
    note = signer.sign(c)
    # The note itself has the blank separator; the signed bytes do not.
    assert note.startswith(signed.decode() + "\n\u2014 ")


def test_signature_verifies_against_body_bytes_exactly(signer):
    """Verify with raw cryptography, bypassing our own verifier.

    If our signer and verifier share a mistake about which bytes are covered,
    a round-trip test passes and interoperability still fails. This checks the
    signature against independently constructed bytes.
    """
    c = make(13)
    note = signer.sign(c)
    _, sigs, _ = cp.parse(note)
    expected = f"{ORIGIN}\n13\n{base64.b64encode(c.root_hash).decode()}\n".encode()
    signer.public_key.verify(sigs[0].signature, expected)


def test_key_id_is_first_four_bytes_of_the_specified_hash(signer):
    import hashlib

    raw = signer.public_key.public_bytes_raw()
    expected = hashlib.sha256(ORIGIN.encode() + b"\x0a" + b"\x01" + raw).digest()[:4]
    assert signer.key_id == expected
    assert len(signer.key_id) == 4


def test_signature_line_grammar(signer):
    line = signer.signature_line(make(4))
    assert line.startswith("\u2014 ")  # em dash then one space
    assert line.endswith("\n")
    body = line[2:-1]
    name, space, encoded = body.partition(" ")
    assert name == ORIGIN
    assert space == " "
    blob = base64.b64decode(encoded, validate=True)
    assert len(blob) == 4 + 64  # key ID plus Ed25519 signature
    assert blob[:4] == signer.key_id


# ---------------------------------------------------------------------------
# Round trip and verification
# ---------------------------------------------------------------------------


def test_sign_parse_verify_round_trip(signer):
    c = make(41)
    note = signer.sign(c)
    got = cp.verify(note, ORIGIN, signer.public_key)
    assert got == c
    assert got.tree_size == 41


def test_verify_rejects_wrong_key(signer):
    note = signer.sign(make(9))
    other = ed25519.Ed25519PrivateKey.generate().public_key()
    with pytest.raises(cp.CheckpointError):
        cp.verify(note, ORIGIN, other)


def test_verify_rejects_tampered_tree_size(signer):
    """The attack the whole module exists to stop.

    Changing the size in a signed note must invalidate it, because the size is
    inside the signed bytes. Without this the inclusion-proof size ambiguity
    documented in test_merkle.py would become exploitable.
    """
    note = signer.sign(make(20))
    tampered = note.replace("\n20\n", "\n19\n", 1)
    assert tampered != note
    with pytest.raises(cp.CheckpointError):
        cp.verify(tampered, ORIGIN, signer.public_key)


def test_verify_rejects_tampered_root(signer):
    c = make(20)
    note = signer.sign(c)
    other_root = base64.b64encode(merkle.root_from_leaf_hashes(leaf_hashes(21)))
    tampered = note.replace(
        base64.b64encode(c.root_hash).decode(), other_root.decode(), 1
    )
    with pytest.raises(cp.CheckpointError):
        cp.verify(tampered, ORIGIN, signer.public_key)


def test_verify_rejects_tampered_origin(signer):
    note = signer.sign(make(6))
    with pytest.raises(cp.CheckpointError):
        cp.verify(note.replace(ORIGIN, "evil.example/log0", 1), ORIGIN, signer.public_key)


# ---------------------------------------------------------------------------
# Parsing hostile input
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "note",
    [
        "no blank line\n1\nAAAA\n",
        "origin\n1\n",  # too few lines
        "origin\nnotanumber\nAAAA\n\n\u2014 n AAAA\n",
        "origin\n007\nAAAA\n\n\u2014 n AAAA\n",  # leading zero
        "origin\n1\n!!!notbase64!!!\n\n\u2014 n AAAA\n",
        "origin\n1\nAAAA\n\nno em dash here\n",
        "origin\n1\nAAAA\n\n\u2014 nospaceafterthename\n",
    ],
)
def test_parse_rejects_malformed_notes(note):
    with pytest.raises(cp.CheckpointError):
        cp.parse(note)


def test_parse_rejects_note_with_no_signatures():
    root = base64.b64encode(b"\x00" * 32).decode()
    with pytest.raises(cp.CheckpointError):
        cp.parse(f"{ORIGIN}\n1\n{root}\n\n")


def test_parse_rejects_control_characters():
    root = base64.b64encode(b"\x00" * 32).decode()
    with pytest.raises(cp.CheckpointError):
        cp.parse(f"{ORIGIN}\n1\n{root}\n\x07\n\n\u2014 n AAAAAA==\n")


def test_parse_rejects_short_signature_blob():
    root = base64.b64encode(b"\x00" * 32).decode()
    tiny = base64.b64encode(b"\x01\x02").decode()
    with pytest.raises(cp.CheckpointError):
        cp.parse(f"{ORIGIN}\n1\n{root}\n\n\u2014 {ORIGIN} {tiny}\n")


# ---------------------------------------------------------------------------
# Witness cosigning
# ---------------------------------------------------------------------------


def test_witness_can_cosign_without_breaking_the_log_signature(signer):
    """The mechanism the entire moat rests on."""
    witness = cp.CheckpointSigner.generate("witness-alpha.example/w1")
    note = signer.sign(make(30))
    cosigned = cp.add_signature(note, witness)

    # Both identities verify against the same note.
    assert cp.verify(cosigned, ORIGIN, signer.public_key).tree_size == 30
    assert cp.verify(cosigned, witness.name, witness.public_key).tree_size == 30


def test_multiple_witnesses_accumulate(signer):
    note = signer.sign(make(12))
    witnesses = [cp.CheckpointSigner.generate(f"w{i}.example/w") for i in range(3)]
    for w in witnesses:
        note = cp.add_signature(note, w)
    _, sigs, _ = cp.parse(note)
    assert len(sigs) == 4
    for w in witnesses:
        assert cp.verify(note, w.name, w.public_key).tree_size == 12


def test_unknown_signatures_are_ignored_not_rejected(signer):
    """Spec: clients MUST ignore unknown signatures. Enables rotation."""
    stranger = cp.CheckpointSigner.generate("stranger.example/x")
    note = cp.add_signature(signer.sign(make(8)), stranger)
    # Verifying as the log still works despite an unrecognised signature line.
    assert cp.verify(note, ORIGIN, signer.public_key).tree_size == 8


def test_cosigning_preserves_note_text_byte_for_byte(signer):
    note = signer.sign(make(15))
    text = note.split("\n\n")[0]
    cosigned = cp.add_signature(note, cp.CheckpointSigner.generate("w.example/1"))
    assert cosigned.split("\n\n")[0] == text
    assert cosigned.startswith(note)


# ---------------------------------------------------------------------------
# The rule that protects the product
# ---------------------------------------------------------------------------


def test_consistent_growth_is_allowed():
    hashes = leaf_hashes(40)
    prev = None
    for size in range(1, 41):
        new = cp.Checkpoint(
            origin=ORIGIN,
            tree_size=size,
            root_hash=merkle.root_from_leaf_hashes(hashes[:size]),
        )
        proof = (
            merkle.consistency_proof(prev.tree_size, hashes[:size]) if prev else []
        )
        cp.assert_consistent_with_previous(prev, new, proof)
        prev = new


def test_first_checkpoint_needs_no_proof():
    cp.assert_consistent_with_previous(None, make(5), [])


def test_refuses_to_shrink():
    with pytest.raises(cp.CheckpointError, match="shrank"):
        cp.assert_consistent_with_previous(make(20), make(10), [])


def test_refuses_same_size_with_different_root():
    a = make(20)
    b = cp.Checkpoint(origin=ORIGIN, tree_size=20, root_hash=b"\xff" * 32)
    with pytest.raises(cp.CheckpointError, match="rewritten"):
        cp.assert_consistent_with_previous(a, b, [])


def test_same_size_same_root_is_fine():
    cp.assert_consistent_with_previous(make(20), make(20), [])


def test_refuses_origin_change():
    with pytest.raises(cp.CheckpointError, match="origin changed"):
        cp.assert_consistent_with_previous(make(5), make(9, origin="other.example/l"), [])


def test_refuses_rewritten_history_even_with_a_valid_looking_proof():
    """The operator-tampering scenario, end to end.

    An operator edits entry 3, recomputes the whole tree so it is internally
    perfect, and generates a consistency proof from their new tree. It must
    still be refused, because the earlier checkpoint pinned the old root.
    """
    honest = leaf_hashes(30)
    previous = cp.Checkpoint(
        origin=ORIGIN,
        tree_size=12,
        root_hash=merkle.root_from_leaf_hashes(honest[:12]),
    )

    rewritten = list(honest)
    rewritten[3] = merkle.leaf_hash(b"the record we wish we had written")
    forged = cp.Checkpoint(
        origin=ORIGIN,
        tree_size=30,
        root_hash=merkle.root_from_leaf_hashes(rewritten),
    )
    forged_proof = merkle.consistency_proof(12, rewritten)

    with pytest.raises(cp.CheckpointError, match="rewritten"):
        cp.assert_consistent_with_previous(previous, forged, forged_proof)


def test_refuses_deleted_entry():
    honest = leaf_hashes(30)
    previous = cp.Checkpoint(
        origin=ORIGIN,
        tree_size=12,
        root_hash=merkle.root_from_leaf_hashes(honest[:12]),
    )
    truncated = honest[:5] + honest[6:]
    new = cp.Checkpoint(
        origin=ORIGIN,
        tree_size=len(truncated),
        root_hash=merkle.root_from_leaf_hashes(truncated),
    )
    with pytest.raises(cp.CheckpointError):
        cp.assert_consistent_with_previous(
            previous, new, merkle.consistency_proof(12, truncated)
        )


def test_refuses_growth_with_an_empty_proof():
    with pytest.raises(cp.CheckpointError):
        cp.assert_consistent_with_previous(make(12), make(30), [])


def test_there_is_no_force_override():
    """Guards against a future 'just this once' parameter.

    If someone adds a bypass flag this fails, which is the point.
    """
    import inspect

    params = set(inspect.signature(cp.assert_consistent_with_previous).parameters)
    assert params == {"previous", "new", "consistency_proof"}
