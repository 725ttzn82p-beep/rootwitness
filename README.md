# rootwitness

Verify an append-only log yourself, instead of believing the company that runs it.

This is the verifier for [Root Witness](https://api.rootwitness.com), a
transparency log for AI agent actions. You do not need an account, an API key, or
our permission to use it. That is the entire point: if checking us required a
credential from us, we would control who is allowed to catch us.

It is also useful on its own. Any log that publishes
[RFC 6962](https://datatracker.ietf.org/doc/html/rfc6962) checkpoints in the
[C2SP signed-note](https://github.com/C2SP/C2SP/blob/main/signed-note.md) format
can be checked with it.

## Try it in ten seconds

```bash
pip install git+https://github.com/725ttzn82p-beep/rootwitness

rootwitness verify \
  --origin https://api.rootwitness.com/demo \
  --log-key JC+94YSo0xpxjaUerN2HRKJtTBcXdyoXS6o2M7uX3EU=
```

```
OK: signed checkpoint verified for https://api.rootwitness.com/demo
tree size: 10
root: oDZuwpv/pjPlANNsUC1Ramy4dMzhR4XUqFVrWq1ZIic=
```

Change one character of the key and it exits non-zero. Nothing is written to disk.

## What that command does and does not prove

It proves the operator signed that exact `(origin, tree size, root hash)` triple,
so they cannot later deny it.

It does **not** prove they have never rewritten history. One checkpoint is one
statement at one moment. To catch a rewrite you have to remember an earlier
checkpoint and force the operator to prove the new tree still contains it.

That is what a witness does.

## Running a real witness

```bash
rootwitness init \
  --origin https://api.rootwitness.com/demo \
  --log-key JC+94YSo0xpxjaUerN2HRKJtTBcXdyoXS6o2M7uX3EU=

rootwitness check     # run this on a schedule
```

`init` generates your own signing key and stores it, with the log's current
checkpoint, in `~/.rootwitness` (override with `--state-dir` or
`ROOTWITNESS_STATE_DIR`).

Every `check` fetches the newest checkpoint and demands a consistency proof from
the size it already remembers. If the proof verifies, it accepts, cosigns, and
advances. If it does not, it **refuses**, exits non-zero, and writes an evidence
file.

```
OK: consistent through 10 entries
```

Use `rootwitness watch --interval 300` to poll continuously.

## What a refusal gives you

A refusal is not just an alert. The witness writes
`REFUSED-<timestamp>-<digest>.evidence` into its state directory containing:

- the checkpoint it previously accepted, **signed by the log**
- the checkpoint it just refused, **also signed by the log**
- what specifically contradicts, and instructions a third party can follow

Two signed statements from the same key that cannot both be true is the useful
artifact. It is checkable by someone who has never heard of you, has no account,
and does not have to take your word for anything — which is exactly what an
audit trail needs to be and what a database row is not.

## What this cannot do

Being direct about the limits, because a verification tool that oversells itself
is worse than none:

- **It cannot prevent tampering.** Nothing here stops an operator from editing
  their database. It makes the edit *detectable* and, once detected, *provable*.
  This is tamper-evidence, not tamper-prevention.
- **It cannot detect anything while it is not running.** A witness that checked
  once, six months ago, proves almost nothing. The value comes from checking on a
  schedule and keeping the state directory.
- **It cannot tell you an entry is true.** It proves an entry was in the log at a
  given size and has not been altered since. Whether the logged claim was
  accurate when written is outside what any log can establish.
- **It cannot prove *when* something was logged.** Ed25519 signatures carry no
  trustworthy timestamp. Ordering and inclusion, yes; wall-clock time, no,
  unless the log anchors its checkpoints to an external timechain.
- **It cannot help if you lose the state directory.** Your remembered checkpoint
  is the leverage. Back it up; it contains no secrets you need to hide, only a
  key that identifies your witness.
- **It does not protect the log's contents from disclosure.** Checkpoints and
  consistency proofs are public data by design.

## Verification without this tool

The checks are deliberately simple enough to reimplement:

```
GET  {origin}/checkpoint                       -> signed note, text
GET  {origin}/proof/consistency?old=N&new=M    -> {"proof": [base64, ...]}
GET  {host}/.well-known/rootwitness-keys            -> public keys
```

Hashes on the wire are base64. Merkle hashing follows RFC 6962: leaves are
`SHA-256(0x00 || entry)`, internal nodes are `SHA-256(0x01 || left || right)`.

The whole verifier is four files and about 1,600 lines, with one dependency
(`cryptography`, for Ed25519 alone). Everything else is the standard library, so
you can read it end to end:

| File | Purpose |
|---|---|
| `rootwitness/merkle.py` | RFC 6962 hashing, inclusion and consistency proofs |
| `rootwitness/checkpoint.py` | signed-note parsing, signing, verification |
| `rootwitness/witness.py` | the refusal logic and state store |
| `rootwitness/cli_witness.py` | the command line interface |

## Tests

```bash
pip install -e ".[dev]"
pytest -q
```

The interesting ones assert that the witness *refuses*: split-view histories,
roots that changed at a fixed size, shrinking trees, missing proofs, and replayed
old checkpoints.

## Licence

Apache 2.0.
