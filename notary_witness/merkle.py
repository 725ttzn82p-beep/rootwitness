"""RFC 6962 Merkle Hash Tree, with inclusion and consistency proofs.

Why this exists at all
----------------------

The existing audit ledger is a linear hash chain: each row commits to its
predecessor. That detects tampering *if you have the whole chain*, which
means the only party who can check it is the party who holds the database --
us. That is the wrong party. A customer asking "prove my record is in your
log, and prove you haven't rewritten the log since" cannot be answered by a
hash chain without shipping them the entire history and asking them to trust
that what we shipped is what we have.

A Merkle tree answers both questions with about 32 bytes per level:

  * An **inclusion proof** lets a holder of one receipt verify that their
    record is in a tree of size n, given only the root. ceil(log2(n)) + 1
    hashes. They verify it offline, with code they wrote, against a root they
    got from somewhere that isn't us.

  * A **consistency proof** lets someone who saw the root at size m verify
    that the tree at size n > m still contains the size-m tree as a prefix.
    This is the one that matters, because it is what makes deletion and
    reordering provable by a party who kept only 32 bytes and threw away
    everything else.

Hashing follows RFC 6962 section 2.1 exactly:

    MTH({})       = SHA-256()
    MTH({d0})     = SHA-256(0x00 || d0)
    MTH(D[n])     = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))

where k is the largest power of two strictly less than n. The domain
separation prefixes (0x00 for leaves, 0x01 for interior nodes) are not
decoration: without them an attacker can present an interior node as a leaf
and prove inclusion of something that was never submitted.

We implement each algorithm twice on purpose. The `_spec_*` functions are
transcribed directly from the RFC's recursive definitions -- obviously
correct, uselessly slow. The public functions are the incremental versions
we actually ship. The test suite asserts the two agree for every tree size
and every leaf index in a range. That is a stronger guarantee than matching
a handful of published vectors, and it is how we catch the consistency-proof
edge cases that everyone gets wrong.

Nothing in this module does I/O, holds state, or knows what a record is. It
takes bytes and returns bytes, which makes it the one part of the system a
sceptical customer can audit in an afternoon.
"""
from __future__ import annotations

import hashlib

# Domain separation prefixes from RFC 6962 section 2.1.
LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"

HASH_SIZE = 32


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def empty_root() -> bytes:
    """MTH({}) = SHA-256() -- the hash of the empty string.

    Spelled out rather than inlined because an empty log is a real state we
    serve checkpoints for, and a reader should not have to wonder whether we
    got it right.
    """
    return _sha256(b"")


def leaf_hash(data: bytes) -> bytes:
    """MTH({d}) = SHA-256(0x00 || d)."""
    return _sha256(LEAF_PREFIX + data)


def node_hash(left: bytes, right: bytes) -> bytes:
    """Interior node: SHA-256(0x01 || left || right)."""
    if len(left) != HASH_SIZE or len(right) != HASH_SIZE:
        raise ValueError("node_hash requires two 32-byte hashes")
    return _sha256(NODE_PREFIX + left + right)


def _largest_power_of_two_below(n: int) -> int:
    """The k from the RFC: largest power of 2 strictly less than n.

    Requires n >= 2. For n == 2 this is 1.
    """
    if n < 2:
        raise ValueError("k is only defined for n >= 2")
    return 1 << (n.bit_length() - 1) if (n & (n - 1)) else n >> 1


# ---------------------------------------------------------------------------
# Reference implementations, straight from the RFC's recursive definitions.
# Exponential in the worst case if you are careless; used only by tests and
# as the readable statement of what the fast paths must reproduce.
# ---------------------------------------------------------------------------


def _spec_root(leaves: list[bytes]) -> bytes:
    """MTH(D[n]) by direct recursion on the RFC definition."""
    n = len(leaves)
    if n == 0:
        return empty_root()
    if n == 1:
        return leaf_hash(leaves[0])
    k = _largest_power_of_two_below(n)
    return node_hash(_spec_root(leaves[:k]), _spec_root(leaves[k:]))


def _spec_inclusion_path(index: int, leaves: list[bytes]) -> list[bytes]:
    """PATH(m, D[n]) from RFC 6962 section 2.1.1."""
    n = len(leaves)
    if n == 1:
        if index != 0:
            raise IndexError("index out of range for single-leaf tree")
        return []
    k = _largest_power_of_two_below(n)
    if index < k:
        return _spec_inclusion_path(index, leaves[:k]) + [_spec_root(leaves[k:])]
    return _spec_inclusion_path(index - k, leaves[k:]) + [_spec_root(leaves[:k])]


def _spec_consistency_path(first: int, leaves: list[bytes]) -> list[bytes]:
    """PROOF(m, D[n]) from RFC 6962 section 2.1.2."""
    return _spec_subproof(first, leaves, True)


def _spec_subproof(m: int, leaves: list[bytes], b: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        # SUBPROOF(m, D[m], true) = {}; SUBPROOF(m, D[m], false) = {MTH(D[m])}
        return [] if b else [_spec_root(leaves)]
    k = _largest_power_of_two_below(n)
    if m <= k:
        return _spec_subproof(m, leaves[:k], b) + [_spec_root(leaves[k:])]
    return _spec_subproof(m - k, leaves[k:], False) + [_spec_root(leaves[:k])]


# ---------------------------------------------------------------------------
# The implementations we ship.
# ---------------------------------------------------------------------------


def root_from_leaf_hashes(leaf_hashes: list[bytes]) -> bytes:
    """Compute the tree root from already-hashed leaves, iteratively.

    Takes leaf *hashes* rather than leaf data because callers who store
    hashes (which is all of them) should not have to keep the originals to
    recompute a root.
    """
    n = len(leaf_hashes)
    if n == 0:
        return empty_root()
    level = list(leaf_hashes)
    while len(level) > 1:
        nxt = []
        # Pair left to right; a trailing odd node is promoted unchanged.
        # This reproduces the RFC's k-split because k is the largest power
        # of two below n, which is exactly what "promote the odd tail"
        # yields when applied bottom-up.
        for i in range(0, len(level) - 1, 2):
            nxt.append(node_hash(level[i], level[i + 1]))
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def inclusion_proof(index: int, leaf_hashes: list[bytes]) -> list[bytes]:
    """The audit path for `index` in a tree of the given leaf hashes."""
    n = len(leaf_hashes)
    if not 0 <= index < n:
        raise IndexError(f"leaf index {index} out of range for tree size {n}")
    proof: list[bytes] = []
    level = list(leaf_hashes)
    i = index
    while len(level) > 1:
        if i % 2:
            proof.append(level[i - 1])
        elif i + 1 < len(level):
            proof.append(level[i + 1])
        # else: odd node at the end of an odd-length level has no sibling and
        # is promoted, contributing nothing to the path.
        nxt = []
        for j in range(0, len(level) - 1, 2):
            nxt.append(node_hash(level[j], level[j + 1]))
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
        i //= 2
    return proof


def consistency_proof(first: int, leaf_hashes: list[bytes]) -> list[bytes]:
    """Proof that the tree of size `first` is a prefix of this tree.

    Delegates to the spec recursion. The recursion is O(n) in practice for
    our shapes and this is not a hot path -- consistency proofs are served
    to witnesses on a schedule, not per request. Correctness here is worth
    more than speed, and this is the algorithm implementations get wrong.
    """
    n = len(leaf_hashes)
    if not 0 < first <= n:
        raise ValueError(f"first={first} must satisfy 0 < first <= {n}")
    if first == n:
        return []
    return _spec_subproof_hashed(first, leaf_hashes, True)


def _spec_subproof_hashed(m: int, leaf_hashes: list[bytes], b: bool) -> list[bytes]:
    n = len(leaf_hashes)
    if m == n:
        return [] if b else [root_from_leaf_hashes(leaf_hashes)]
    k = _largest_power_of_two_below(n)
    if m <= k:
        return _spec_subproof_hashed(m, leaf_hashes[:k], b) + [
            root_from_leaf_hashes(leaf_hashes[k:])
        ]
    return _spec_subproof_hashed(m - k, leaf_hashes[k:], False) + [
        root_from_leaf_hashes(leaf_hashes[:k])
    ]


# ---------------------------------------------------------------------------
# Verifiers. These are the functions a customer reimplements, so they are
# written to be transcribed rather than imported.
# ---------------------------------------------------------------------------


def verify_inclusion(
    leaf_index: int,
    tree_size: int,
    leaf_hash_value: bytes,
    proof: list[bytes],
    root: bytes,
) -> bool:
    """RFC 9162 section 2.1.3.2 inclusion-proof verification.

    Returns True only if `proof` demonstrates that `leaf_hash_value` sits at
    `leaf_index` in a tree of exactly `tree_size` leaves whose root is
    `root`. Binding the proof to tree_size is what stops a log from
    presenting a proof against a tree it has since truncated.
    """
    if leaf_index >= tree_size or leaf_index < 0 or tree_size <= 0:
        return False

    fn = leaf_index
    sn = tree_size - 1
    r = leaf_hash_value

    for p in proof:
        if sn == 0:
            return False
        if (fn & 1) or fn == sn:
            r = node_hash(p, r)
            if not (fn & 1):
                # Climb past the promoted-odd-node levels.
                while True:
                    fn >>= 1
                    sn >>= 1
                    if (fn & 1) or fn == 0:
                        break
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1

    return sn == 0 and r == root


def verify_consistency(
    first: int,
    second: int,
    first_root: bytes,
    second_root: bytes,
    proof: list[bytes],
) -> bool:
    """RFC 9162 section 2.1.4.2 consistency-proof verification.

    Returns True only if the size-`first` tree with root `first_root` is a
    prefix of the size-`second` tree with root `second_root`. A log that has
    deleted, edited, or reordered any of its first `first` entries cannot
    produce a proof that satisfies this.
    """
    if first > second or first <= 0 or second <= 0:
        return False
    if first == second:
        # Nothing to prove beyond the roots agreeing, and RFC requires the
        # proof be empty in this case.
        return not proof and first_root == second_root

    path = list(proof)
    # Step 1: if first is an exact power of two, first_root is a node the
    # verifier already holds, and the log omits it from the path.
    if first & (first - 1) == 0:
        path.insert(0, first_root)

    if not path:
        return False

    fn = first - 1
    sn = second - 1

    # Step 3: skip the levels where the first tree's frontier is a left child.
    while fn & 1:
        fn >>= 1
        sn >>= 1

    fr = path[0]
    sr = path[0]

    for c in path[1:]:
        if sn == 0:
            return False
        if (fn & 1) or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not (fn & 1):
                while True:
                    fn >>= 1
                    sn >>= 1
                    if (fn & 1) or fn == 0:
                        break
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1

    return sn == 0 and fr == first_root and sr == second_root
