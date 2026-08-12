"""C2SP signed-note checkpoints: the thing that makes tree size trustworthy.

Why this module carries more weight than it looks like it should
----------------------------------------------------------------

A test in `test_merkle.py` established that an inclusion proof binds a leaf to
a **root hash**, and not to a tree size. The verification walk uses tree size
only to choose the tree's shape, and many nearby sizes share a shape. For leaf
7 in a size-20 tree, every claimed size from 17 to 32 walks identically.

That is harmless *provided* the size and the root always travel together under
one signature. It is fatal if they can be separated, because a log that serves
a bare root can shrink and nobody can prove it did. So this module exists to
make separation impossible: the signed bytes are origin, size, and root as a
single unit, and there is no code path that signs a root without a size.

Format
------

Per c2sp.org/tlog-checkpoint and c2sp.org/signed-note@v1.0.0. The note text is
at least three non-empty newline-separated lines:

    <origin>
    <tree size, ASCII decimal, no leading zeroes>
    <base64 of the RFC 6962 root hash>

followed by a blank line, then one or more signature lines:

    — <key name> <base64(4-byte big-endian key ID || signature)>

The note text **includes its final newline** and the blank separator line is
**not** part of it. That distinction is the classic implementation bug: sign
the wrong byte count and every signature verifies locally and fails against
every other implementation. Both are pinned by tests.

Key IDs are `SHA-256(name || 0x0A || 0x01 || pubkey)[:4]` for Ed25519, where
`0x01` is the signature type identifier.

Extension lines are supported for parsing but we do not emit them: the spec
says their use is NOT RECOMMENDED because monitors cannot audit them, and the
ML-DSA cosignature format does not sign them.

Cosigning
---------

The spec requires clients to ignore signatures they cannot verify, which is
precisely what allows a witness to append its own signature line to a
checkpoint the log signed. `add_signature` therefore appends without touching
the note text, because rewriting the text would invalidate every signature
already on it -- including our own.

The rule this module cannot enforce alone
-----------------------------------------

    "A log MUST not sign any checkpoint which is inconsistent with any
    checkpoint it previously signed."

Signing is stateless; that rule is stateful. `assert_consistent_with_previous`
is provided so the storage layer has one obvious place to enforce it, and the
service must call it before every signature. A log that violates this has
published cryptographic proof of its own misbehaviour, which is the whole
mechanism by which split views are caught.
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ed25519

from rootwitness import merkle

# U+2014 followed by U+0020, per the signed-note grammar. Written as an escape
# rather than a literal so it survives any editor that helpfully "fixes"
# dashes -- an em dash silently replaced with a hyphen would break every
# signature line we emit, in a way that is invisible in a diff.
SIG_PREFIX = "\u2014 "

ED25519_SIG_TYPE = b"\x01"
KEY_ID_LEN = 4


def _b64(data: bytes) -> str:
    """Standard RFC 4648 section 4 encoding, with padding."""
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def key_id(name: str, public_key: ed25519.Ed25519PublicKey) -> bytes:
    """SHA-256(name || 0x0A || 0x01 || pubkey)[:4]."""
    raw = public_key.public_bytes_raw()
    digest = hashlib.sha256(name.encode("utf-8") + b"\x0a" + ED25519_SIG_TYPE + raw)
    return digest.digest()[:KEY_ID_LEN]


class CheckpointError(Exception):
    """A checkpoint could not be parsed, verified, or safely signed."""


@dataclass(frozen=True)
class Checkpoint:
    """A log's commitment to its entire history at one size.

    Frozen because a checkpoint that can be mutated after signing is a
    checkpoint whose signature means nothing.
    """

    origin: str
    tree_size: int
    root_hash: bytes

    def __post_init__(self) -> None:
        if not self.origin:
            raise CheckpointError("origin MUST be non-empty")
        if any(c.isspace() for c in self.origin) or "+" in self.origin:
            raise CheckpointError("origin must contain no spaces or plus signs")
        if self.tree_size < 0:
            raise CheckpointError("tree size cannot be negative")
        if len(self.root_hash) != merkle.HASH_SIZE:
            raise CheckpointError(
                f"root hash must be {merkle.HASH_SIZE} bytes, got {len(self.root_hash)}"
            )

    def body(self) -> str:
        """The note text, including its final newline.

        These exact bytes are what gets signed. Nothing else.
        """
        return f"{self.origin}\n{self.tree_size}\n{_b64(self.root_hash)}\n"

    def signed_bytes(self) -> bytes:
        return self.body().encode("utf-8")


class CheckpointSigner:
    """An Ed25519 signing identity for checkpoints."""

    def __init__(self, name: str, private_key: ed25519.Ed25519PrivateKey) -> None:
        if not name or any(c.isspace() for c in name) or "+" in name:
            raise CheckpointError("key name must be non-empty, no spaces or plus")
        self.name = name
        self._private_key = private_key
        self.public_key = private_key.public_key()
        self.key_id = key_id(name, self.public_key)

    @classmethod
    def generate(cls, name: str) -> "CheckpointSigner":
        return cls(name, ed25519.Ed25519PrivateKey.generate())

    def signature_line(self, checkpoint: Checkpoint) -> str:
        sig = self._private_key.sign(checkpoint.signed_bytes())
        return f"{SIG_PREFIX}{self.name} {_b64(self.key_id + sig)}\n"

    def sign(self, checkpoint: Checkpoint) -> str:
        """Produce a complete signed note carrying exactly one signature."""
        return checkpoint.body() + "\n" + self.signature_line(checkpoint)


@dataclass(frozen=True)
class Signature:
    name: str
    key_id: bytes
    signature: bytes


def parse(note: str) -> tuple[Checkpoint, list[Signature], list[str]]:
    """Parse a signed note into checkpoint, signatures, and extension lines.

    Rejects malformed input loudly rather than guessing. A checkpoint parser
    that is generous with malformed input is a parser an attacker can use to
    make two parties disagree about what a log said.
    """
    if "\n\n" not in note:
        raise CheckpointError("no blank line separating text from signatures")
    if any(ord(c) < 0x20 and c != "\n" for c in note):
        raise CheckpointError("note contains ASCII control characters")

    # The text is separated from the signatures by the LAST empty line, since
    # the text itself may legally contain empty lines.
    text, _, sig_block = note.rpartition("\n\n")
    body = text + "\n"

    lines = body.split("\n")[:-1]
    if len(lines) < 3:
        raise CheckpointError("note text must have at least three lines")
    if any(not line for line in lines):
        raise CheckpointError("note text lines MUST be non-empty")

    origin, size_line, root_line = lines[0], lines[1], lines[2]
    extensions = lines[3:]

    if not size_line.isdigit():
        raise CheckpointError(f"tree size is not ASCII decimal: {size_line!r}")
    if size_line != "0" and size_line.startswith("0"):
        raise CheckpointError("tree size has a leading zero")
    tree_size = int(size_line)

    try:
        root_hash = _unb64(root_line)
    except Exception as exc:
        raise CheckpointError(f"root hash is not valid base64: {exc}") from exc

    checkpoint = Checkpoint(origin=origin, tree_size=tree_size, root_hash=root_hash)

    signatures = []
    for line in sig_block.split("\n"):
        if not line:
            continue
        if not line.startswith(SIG_PREFIX):
            raise CheckpointError(f"malformed signature line: {line!r}")
        rest = line[len(SIG_PREFIX) :]
        name, sep, encoded = rest.partition(" ")
        if not sep or not name:
            raise CheckpointError(f"malformed signature line: {line!r}")
        try:
            blob = _unb64(encoded)
        except Exception as exc:
            raise CheckpointError(f"signature is not valid base64: {exc}") from exc
        if len(blob) <= KEY_ID_LEN:
            raise CheckpointError("signature too short to contain a key ID")
        signatures.append(
            Signature(
                name=name,
                key_id=blob[:KEY_ID_LEN],
                signature=blob[KEY_ID_LEN:],
            )
        )

    if not signatures:
        raise CheckpointError("note carries no signature lines")

    return checkpoint, signatures, extensions


def verify(
    note: str,
    name: str,
    public_key: ed25519.Ed25519PublicKey,
) -> Checkpoint:
    """Verify that `note` carries a good signature from `name`.

    Returns the checkpoint. Raises if no signature from that identity
    verifies. Per the spec, signatures from other identities are ignored
    rather than rejected -- that is what makes witness cosigning work.
    """
    checkpoint, signatures, _ = parse(note)
    want_id = key_id(name, public_key)
    signed = checkpoint.signed_bytes()

    for sig in signatures:
        if sig.name != name or sig.key_id != want_id:
            continue
        try:
            public_key.verify(sig.signature, signed)
        except Exception:
            # Right key ID, bad signature. Keep looking: key IDs are only four
            # bytes, so a collision is possible and must not be fatal.
            continue
        return checkpoint

    raise CheckpointError(f"no valid signature from {name!r}")


def add_signature(note: str, signer: CheckpointSigner) -> str:
    """Append a cosignature without disturbing the note text.

    The text is deliberately re-emitted byte for byte rather than rebuilt from
    the parsed checkpoint. Rebuilding would drop extension lines and could
    normalise something subtly, invalidating every signature already present.
    """
    if not note.endswith("\n"):
        raise CheckpointError("note must end with a newline")
    checkpoint, _, _ = parse(note)
    return note + signer.signature_line(checkpoint)


def assert_consistent_with_previous(
    previous: Checkpoint | None,
    new: Checkpoint,
    consistency_proof: list[bytes],
) -> None:
    """Refuse to sign a checkpoint that contradicts one already signed.

    The spec's requirement -- "A log MUST not sign any checkpoint which is
    inconsistent with any checkpoint it previously signed" -- is the single
    rule whose violation turns this product into a database with marketing.
    Call this immediately before signing, every time, with no exceptions and
    no override flag. There is deliberately no `force` parameter.
    """
    if previous is None:
        return

    if new.origin != previous.origin:
        raise CheckpointError(
            f"origin changed from {previous.origin!r} to {new.origin!r}"
        )

    if new.tree_size < previous.tree_size:
        raise CheckpointError(
            f"tree shrank from {previous.tree_size} to {new.tree_size}"
        )

    if new.tree_size == previous.tree_size:
        if new.root_hash != previous.root_hash:
            raise CheckpointError(
                "same tree size with a different root: history was rewritten"
            )
        return

    if previous.tree_size == 0:
        # Nothing to be consistent with; any tree extends the empty tree.
        return

    if not merkle.verify_consistency(
        previous.tree_size,
        new.tree_size,
        previous.root_hash,
        new.root_hash,
        consistency_proof,
    ):
        raise CheckpointError(
            f"no valid consistency proof from size {previous.tree_size} "
            f"to size {new.tree_size}: history was rewritten"
        )
