"""Exhaustive cross-verification of the Merkle implementation.

The strategy: the RFC states its algorithms as recursive definitions that are
obviously correct and hopelessly slow. `merkle.py` also ships fast iterative
versions. These tests assert the two agree for *every* tree size in a range
and *every* leaf index within each size, then assert the verifiers accept
every honest proof and reject a catalogue of dishonest ones.

That is deliberately stronger than checking a handful of published vectors.
Published vectors catch transcription errors. Exhaustive cross-checking plus
negative cases catches the off-by-one in the odd-node promotion, which is the
bug that actually ships in Merkle code and which no small vector set exercises.
"""
from __future__ import annotations

import hashlib

import pytest

from notary_witness import merkle

MAX_N = 65  # crosses several powers of two, including 32 and 64


def leaves(n: int) -> list[bytes]:
    """Distinguishable leaf data. Content is irrelevant; distinctness is not."""
    return [f"leaf-{i}".encode() for i in range(n)]


def leaf_hashes(n: int) -> list[bytes]:
    return [merkle.leaf_hash(d) for d in leaves(n)]


# ---------------------------------------------------------------------------
# Hashing primitives
# ---------------------------------------------------------------------------


def test_empty_root_is_sha256_of_empty_string():
    assert merkle.empty_root() == hashlib.sha256(b"").digest()


def test_leaf_hash_uses_zero_prefix():
    assert merkle.leaf_hash(b"abc") == hashlib.sha256(b"\x00abc").digest()


def test_node_hash_uses_one_prefix():
    left = b"\x11" * 32
    right = b"\x22" * 32
    assert merkle.node_hash(left, right) == hashlib.sha256(
        b"\x01" + left + right
    ).digest()


def test_node_hash_rejects_wrong_length():
    with pytest.raises(ValueError):
        merkle.node_hash(b"short", b"\x00" * 32)


def test_leaf_and_node_domains_are_separated():
    """A 32-byte leaf must not collide with the interior node of the same bytes.

    This is the attack the prefixes exist to stop: without them, an interior
    node could be replayed as a leaf and inclusion proven for data that was
    never submitted.
    """
    payload = b"\x33" * 64
    assert merkle.leaf_hash(payload) != hashlib.sha256(b"\x01" + payload).digest()


def test_single_leaf_root_is_its_leaf_hash():
    assert merkle.root_from_leaf_hashes([merkle.leaf_hash(b"x")]) == merkle.leaf_hash(
        b"x"
    )


def test_k_is_largest_power_of_two_strictly_below_n():
    cases = {2: 1, 3: 2, 4: 2, 5: 4, 7: 4, 8: 4, 9: 8, 16: 8, 17: 16}
    for n, expected in cases.items():
        assert merkle._largest_power_of_two_below(n) == expected, n


def test_k_undefined_below_two():
    for n in (0, 1):
        with pytest.raises(ValueError):
            merkle._largest_power_of_two_below(n)


# ---------------------------------------------------------------------------
# Root: fast path must equal the RFC recursion
# ---------------------------------------------------------------------------


def test_root_matches_spec_recursion_for_all_sizes():
    for n in range(0, MAX_N):
        expected = merkle._spec_root(leaves(n))
        actual = merkle.root_from_leaf_hashes(leaf_hashes(n))
        assert actual == expected, f"root mismatch at n={n}"


def test_root_changes_when_any_leaf_changes():
    n = 17
    base = leaf_hashes(n)
    baseline = merkle.root_from_leaf_hashes(base)
    for i in range(n):
        mutated = list(base)
        mutated[i] = merkle.leaf_hash(b"tampered")
        assert merkle.root_from_leaf_hashes(mutated) != baseline, i


def test_root_changes_when_two_leaves_are_swapped():
    """Reordering must be visible, or 'append-only' means nothing."""
    base = leaf_hashes(9)
    baseline = merkle.root_from_leaf_hashes(base)
    swapped = list(base)
    swapped[2], swapped[6] = swapped[6], swapped[2]
    assert merkle.root_from_leaf_hashes(swapped) != baseline


# ---------------------------------------------------------------------------
# Inclusion proofs
# ---------------------------------------------------------------------------


def test_inclusion_path_matches_spec_for_every_size_and_index():
    for n in range(1, MAX_N):
        data = leaves(n)
        hashes = leaf_hashes(n)
        for i in range(n):
            expected = merkle._spec_inclusion_path(i, data)
            actual = merkle.inclusion_proof(i, hashes)
            assert actual == expected, f"path mismatch at n={n} i={i}"


def test_inclusion_proof_length_is_logarithmic():
    for n in range(1, MAX_N):
        for i in range(n):
            proof = merkle.inclusion_proof(i, leaf_hashes(n))
            assert len(proof) <= (n - 1).bit_length(), (n, i, len(proof))


def test_every_honest_inclusion_proof_verifies():
    for n in range(1, MAX_N):
        hashes = leaf_hashes(n)
        root = merkle.root_from_leaf_hashes(hashes)
        for i in range(n):
            proof = merkle.inclusion_proof(i, hashes)
            assert merkle.verify_inclusion(i, n, hashes[i], proof, root), (n, i)


def test_inclusion_rejects_wrong_leaf():
    n = 20
    hashes = leaf_hashes(n)
    root = merkle.root_from_leaf_hashes(hashes)
    proof = merkle.inclusion_proof(7, hashes)
    forged = merkle.leaf_hash(b"never submitted")
    assert not merkle.verify_inclusion(7, n, forged, proof, root)


def test_inclusion_rejects_wrong_index():
    n = 20
    hashes = leaf_hashes(n)
    root = merkle.root_from_leaf_hashes(hashes)
    proof = merkle.inclusion_proof(7, hashes)
    assert not merkle.verify_inclusion(8, n, hashes[7], proof, root)


def test_inclusion_rejects_wrong_root():
    n = 20
    hashes = leaf_hashes(n)
    proof = merkle.inclusion_proof(7, hashes)
    assert not merkle.verify_inclusion(7, n, hashes[7], proof, b"\x00" * 32)


def test_inclusion_rejects_tampered_proof_node():
    n = 20
    hashes = leaf_hashes(n)
    root = merkle.root_from_leaf_hashes(hashes)
    proof = merkle.inclusion_proof(7, hashes)
    for j in range(len(proof)):
        bad = list(proof)
        bad[j] = b"\xff" * 32
        assert not merkle.verify_inclusion(7, n, hashes[7], bad, root), j


def test_inclusion_rejects_truncated_and_extended_proof():
    n = 20
    hashes = leaf_hashes(n)
    root = merkle.root_from_leaf_hashes(hashes)
    proof = merkle.inclusion_proof(7, hashes)
    assert not merkle.verify_inclusion(7, n, hashes[7], proof[:-1], root)
    assert not merkle.verify_inclusion(
        7, n, hashes[7], proof + [b"\xab" * 32], root
    )


def test_inclusion_rejects_index_at_or_beyond_tree_size():
    hashes = leaf_hashes(8)
    root = merkle.root_from_leaf_hashes(hashes)
    assert not merkle.verify_inclusion(8, 8, hashes[0], [], root)
    assert not merkle.verify_inclusion(-1, 8, hashes[0], [], root)


def test_inclusion_proof_binds_to_the_root_not_to_the_claimed_size():
    """What the inclusion proof does and does not pin down.

    A first draft of this test asserted that a proof valid at tree_size=20
    would fail against a claimed tree_size of 19 or 21. It does not, and that
    is not a bug -- it is a property of the RFC 9162 verification algorithm.
    The fn/sn walk only uses tree_size to decide the tree *shape*, and many
    nearby sizes share the same shape for a given leaf index. For leaf 7 in a
    size-20 tree, every claimed size from 17 to 32 walks identically.

    What the proof genuinely binds is the leaf to a specific **root**. An
    attacker who lies about the size gains nothing, because the real root of
    a tree of that size differs from the root they had to present. This test
    asserts exactly that, and no more.

    The consequence for the rest of the system, which is why this is written
    up rather than quietly deleted: **tree_size is only authenticated because
    the signed checkpoint covers it together with the root.** Serving a bare
    root without a signed size would make truncation undetectable. That is a
    hard requirement on the checkpoint format, discovered here.
    """
    true_size = 20
    hashes = leaf_hashes(true_size)
    root = merkle.root_from_leaf_hashes(hashes)
    proof = merkle.inclusion_proof(7, hashes)

    accepted_sizes = [
        n for n in range(1, 40) if merkle.verify_inclusion(7, n, hashes[7], proof, root)
    ]
    # Shape-compatible sizes are accepted; that is expected, not a finding.
    assert true_size in accepted_sizes
    assert len(accepted_sizes) > 1, "if this narrows, the note above is stale"

    # The security property: of every size the walk accepts, only the true one
    # has a real tree whose root is the root that was presented.
    matching = [
        n
        for n in accepted_sizes
        if merkle.root_from_leaf_hashes(leaf_hashes(n)) == root
    ]
    assert matching == [true_size], matching


def test_inclusion_fails_against_the_real_root_of_any_other_size():
    """The lie has to survive contact with a genuine root, and it does not."""
    hashes = leaf_hashes(20)
    proof = merkle.inclusion_proof(7, hashes)
    for n in (17, 18, 19, 21, 24, 32):
        other_root = merkle.root_from_leaf_hashes(leaf_hashes(n))
        assert not merkle.verify_inclusion(7, n, hashes[7], proof, other_root), n


def test_inclusion_proof_index_out_of_range_raises():
    with pytest.raises(IndexError):
        merkle.inclusion_proof(5, leaf_hashes(5))


# ---------------------------------------------------------------------------
# Consistency proofs -- the ones implementations get wrong
# ---------------------------------------------------------------------------


def test_consistency_path_matches_spec_for_every_pair():
    for n in range(1, 40):
        data = leaves(n)
        hashes = leaf_hashes(n)
        for m in range(1, n + 1):
            expected = merkle._spec_consistency_path(m, data)
            actual = merkle.consistency_proof(m, hashes)
            assert actual == expected, f"consistency mismatch m={m} n={n}"


def test_every_honest_consistency_proof_verifies():
    for n in range(1, 40):
        hashes = leaf_hashes(n)
        second_root = merkle.root_from_leaf_hashes(hashes)
        for m in range(1, n + 1):
            first_root = merkle.root_from_leaf_hashes(hashes[:m])
            proof = merkle.consistency_proof(m, hashes)
            assert merkle.verify_consistency(
                m, n, first_root, second_root, proof
            ), f"m={m} n={n}"


def test_consistency_detects_edited_history():
    """The point of the whole exercise.

    An operator who rewrites entry 3 and recomputes everything produces a
    tree that is internally perfect. It still cannot satisfy a consistency
    proof against a root a witness recorded beforehand.
    """
    honest = leaf_hashes(30)
    witnessed_size = 12
    witnessed_root = merkle.root_from_leaf_hashes(honest[:witnessed_size])

    rewritten = list(honest)
    rewritten[3] = merkle.leaf_hash(b"the record we wish we had written")
    rewritten_root = merkle.root_from_leaf_hashes(rewritten)
    forged_proof = merkle.consistency_proof(witnessed_size, rewritten)

    assert not merkle.verify_consistency(
        witnessed_size, 30, witnessed_root, rewritten_root, forged_proof
    )


def test_consistency_detects_deleted_entry():
    honest = leaf_hashes(30)
    witnessed_root = merkle.root_from_leaf_hashes(honest[:12])
    truncated = honest[:5] + honest[6:]  # entry 5 removed
    assert not merkle.verify_consistency(
        12,
        len(truncated),
        witnessed_root,
        merkle.root_from_leaf_hashes(truncated),
        merkle.consistency_proof(12, truncated),
    )


def test_consistency_rejects_shrinking_tree():
    hashes = leaf_hashes(20)
    big = merkle.root_from_leaf_hashes(hashes)
    small = merkle.root_from_leaf_hashes(hashes[:10])
    # Claiming the size-20 tree is a prefix of the size-10 tree.
    assert not merkle.verify_consistency(20, 10, big, small, [])


def test_consistency_equal_sizes_requires_empty_proof_and_matching_roots():
    hashes = leaf_hashes(16)
    root = merkle.root_from_leaf_hashes(hashes)
    assert merkle.verify_consistency(16, 16, root, root, [])
    assert not merkle.verify_consistency(16, 16, root, b"\x00" * 32, [])
    assert not merkle.verify_consistency(16, 16, root, root, [b"\x00" * 32])


def test_consistency_rejects_tampered_proof_node():
    hashes = leaf_hashes(30)
    second_root = merkle.root_from_leaf_hashes(hashes)
    first_root = merkle.root_from_leaf_hashes(hashes[:12])
    proof = merkle.consistency_proof(12, hashes)
    for j in range(len(proof)):
        bad = list(proof)
        bad[j] = b"\xff" * 32
        assert not merkle.verify_consistency(
            12, 30, first_root, second_root, bad
        ), j


def test_consistency_rejects_nonsense_sizes():
    hashes = leaf_hashes(10)
    root = merkle.root_from_leaf_hashes(hashes)
    assert not merkle.verify_consistency(0, 10, root, root, [])
    assert not merkle.verify_consistency(-1, 10, root, root, [])


def test_consistency_proof_first_out_of_range_raises():
    with pytest.raises(ValueError):
        merkle.consistency_proof(0, leaf_hashes(5))
    with pytest.raises(ValueError):
        merkle.consistency_proof(6, leaf_hashes(5))


def test_power_of_two_first_size_omits_first_root_from_path():
    """RFC step 1: when `first` is a power of two the log omits that node.

    Verified behaviourally -- the proof the log emits is shorter than the
    path the verifier reconstructs, and verification still succeeds.
    """
    hashes = leaf_hashes(30)
    second_root = merkle.root_from_leaf_hashes(hashes)
    for m in (1, 2, 4, 8, 16):
        first_root = merkle.root_from_leaf_hashes(hashes[:m])
        proof = merkle.consistency_proof(m, hashes)
        assert first_root not in proof, m
        assert merkle.verify_consistency(m, 30, first_root, second_root, proof), m


# ---------------------------------------------------------------------------
# The property a customer actually cares about
# ---------------------------------------------------------------------------


def test_append_only_growth_is_continuously_verifiable():
    """Simulate a witness that keeps only the latest root, 1 to 40 entries.

    At each step it holds 32 bytes from the previous step and demands a
    consistency proof. This is the entire operational model, and it must
    hold at every size, not just convenient ones.
    """
    hashes = leaf_hashes(40)
    prev_size = 1
    prev_root = merkle.root_from_leaf_hashes(hashes[:1])

    for size in range(2, 41):
        root = merkle.root_from_leaf_hashes(hashes[:size])
        proof = merkle.consistency_proof(prev_size, hashes[:size])
        assert merkle.verify_consistency(
            prev_size, size, prev_root, root, proof
        ), f"{prev_size} -> {size}"
        prev_size, prev_root = size, root
