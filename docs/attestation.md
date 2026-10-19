# Proof-Carrying Finding Attestation

> Status: implemented. `CaseAttest` emits a canonical, hash-chained, optionally
> Ed25519-signed manifest for a CONFIRMED case; `xpi-verify` checks it with
> zero project dependencies.

## 1. Why

XPI's whole confirmation gate exists to make a finding real by machine, not by
prose: nonce-bound evidence hashes, a DNS-pinned differential replay with a
conclusive `target_only` verdict, and a main-agent `ConfirmFinding` (see
[poc-trust-model.md](poc-trust-model.md)). But that trust stops at the workspace
boundary. The moment a finding leaves as a report, it collapses back into
markdown that says "Confirmed — trust me." The triager at the bounty program,
the customer, or the next agent resuming the case cannot verify any of it.

The internal invariant is **"zero exit is never proof."** The external twin is
**"prose is never proof."** An attestation enforces the second: it serializes
the gate's own outputs into one tamper-evident file a third party can check
without trusting the researcher and without re-running anything live.

## 2. What an attestation certifies — and what it does not

It **certifies** that, at `confirmed_at`, the pi-casefile gate executed and
produced a conclusive **target-only** differential for the referenced finding,
and that the recorded hashes (PoC script, evidence artifacts, response bodies,
canary token) are exactly what the gate saw. Any later edit to any committed
field breaks the chain root, and — if signed — the signature.

It does **not** re-test the target. An attestation is an integrity proof over a
past gate run, not a live vulnerability claim; a target may since have been
patched. `xpi-verify` says "this gate ran and produced this verdict," never
"the target is vulnerable now." The manifest carries this scope in its
`disclaimer` leaf so it travels with the file.

It also cannot manufacture confirmation. `CaseAttest` refuses any case that is
not `confirmed` with a `CONFIRMED` main-agent verdict, a `target_only`
differential, and a harness-owned phase-2 replay bound to that verdict.

## 3. Manifest shape (`xpi-attestation/v1`)

```jsonc
{
  "schema": "xpi-attestation/v1",
  "generated_at": "...",
  "generator": "pi-casefile X.Y.Z",
  "content": {
    "case":         { "id", "title", "status", "severity?", "bug_class?", "target_host?", "endpoint?" },
    "confirmation": { "mode", "poc_sha256", "reviewer", "verdict", "differential",
                      "proof_strength?", "confirmed_at", "model?" },
    "machine_gate": {
      "phase1?": { "attempted", "pass?", "differential", "proof_strength?",
                   "target_body_sha256?", "control_body_sha256?", "canary_token_sha256?" },
      "phase2":  { ...same shape — the fresh ConfirmFinding replay }
    },
    "evidence":   [ { "role", "artifact_sha256?", "summary_sha256" } ],
    "coverage?":  [ { "asset", "class", "scope", "backed" } ],
    "disclaimer": "..."
  },
  "leaves":     [ { "key", "sha256" } ],   // ordered, one per content region
  "chain_root": "<sha256>",
  "signature?": { "alg": "ed25519", "public_key", "chain_root_signature", "public_key_fingerprint" }
}
```

Only **hashes** cross the boundary — never response bodies, never the raw
canary token (consistent with the gate's never-persist-the-secret rule), and
only the **host** of the target, never full URLs or local paths.

### Chain construction

Each content region is canonicalized (recursively key-sorted JSON, `undefined`
dropped, non-finite numbers rejected) and hashed into a leaf. The leaves are
folded in a fixed order, seeded with the schema id:

```
root₀ = sha256("xpi-attestation/v1")
rootᵢ = sha256(rootᵢ₋₁ + ":" + keyᵢ + ":" + leaf_sha256ᵢ)
chain_root = rootₙ
```

Reordering, adding, dropping, or editing any leaf changes the root. The
signature covers the root alone, so it transitively covers all content.

## 4. Verification

`xpi-verify` recomputes every leaf **from `content`** (it never trusts the
manifest's own `leaves`/`chain_root` except to localize a mismatch),
recomputes the root, and verifies the signature:

```bash
xpi-verify path/to/report/<slug>-<case>.attestation.json
# pin the signer to a key you already trust (e.g. from the program's security.txt):
xpi-verify att.json --key-fingerprint 9919b2b6...b77ab2
xpi-verify att.json --json        # machine-readable VerifyResult
```

Exit `0` = verified, `1` = verification failed (tamper, bad signature, wrong
key), `2` = usage/read error. `ok` is true only when schema, every leaf, the
root, and any signature all hold; `--key-fingerprint` additionally requires the
embedded key to match.

The verifier depends only on `node:crypto`. Run it with modern Node (TS types
strip) or `bun bin/xpi-verify.ts`.

## 5. Signing keys

Signing is optional — an unsigned attestation is still integrity-checkable, it
is just not authenticated to a researcher identity. To sign, configure one of:

| Variable | Meaning |
|----------|---------|
| `PI_ATTEST_KEY` | Path to an Ed25519 private key in PKCS#8 PEM |
| `PI_ATTEST_KEY_PEM` | The PEM inline (takes precedence) |

Generate a keypair:

```bash
openssl genpkey -algorithm ed25519 -out xpi-attest.key
openssl pkey -in xpi-attest.key -pubout -out xpi-attest.pub   # publish this
```

Publish the **public key fingerprint** (the `public_key_fingerprint` field, or
`sha256` of the DER SPKI public key) wherever triagers can pin it — a bounty
profile, `security.txt`, a report footer — so a verified signature means "the
holder of that key attested this," not merely "some key did."

## 6. Workflow

```
PromoteFinding → ConfirmFinding (CONFIRMED, target_only)
  → CaseAttest(id)                      # writes <slug>-<case>.attestation.json next to the report
  → attach the attestation.json to the report; include the verify command + key fingerprint
```

`CaseAttest` is main-agent-only — the same boundary that owns `ConfirmFinding`.
It self-verifies before writing: an attestation that fails its own
`verifyAttestation` is never emitted.
