/**
 * Proof-carrying finding attestation.
 *
 * XPI's confirmation gate computes, but never exports, the trust it establishes:
 * nonce-bound evidence hashes, a DNS-pinned differential replay with a conclusive
 * `target_only` verdict, and a main-agent `ConfirmFinding`. The moment a finding
 * leaves the workspace as a report, all of that collapses into prose that says
 * "Confirmed — trust me." A triager, customer, or resuming agent cannot check it.
 *
 * `buildAttestation` serializes the gate's own outputs into a single, canonical,
 * hash-chained manifest and (optionally) signs its root with Ed25519. A third
 * party runs `verifyAttestation` — or the standalone `xpi-verify` CLI — to
 * recompute every leaf from the content, confirm the chain root, and check the
 * signature, WITHOUT trusting the researcher and without re-running anything live.
 *
 * Honesty scope: an attestation certifies that the gate ran and produced a
 * conclusive target-only differential for the referenced finding at
 * `confirmed_at`. It proves gate integrity and the reproducibility of the
 * recorded hashes — it is NOT a live re-validation and makes no claim that the
 * target is still vulnerable at verification time. This mirrors the internal
 * invariant "zero exit is never proof": here, "prose is never proof."
 *
 * This module imports only `node:crypto` so the verifier stays dependency-free
 * and the canonicalization cannot drift from any other package module.
 */

import { createHash, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import type { CaseRecord } from "./ledger.ts";

export const ATTESTATION_SCHEMA = "xpi-attestation/v1";

export const ATTESTATION_DISCLAIMER =
  "This attestation certifies that the pi-casefile confirmation gate executed and " +
  "produced a conclusive target-only differential for the referenced finding at " +
  "confirmed_at. It proves gate integrity and the reproducibility of the recorded " +
  "evidence hashes — NOT that the target remains vulnerable at verification time.";

// ── Canonical JSON + hashing ────────────────────────────────────────

/**
 * Deterministic JSON: object keys sorted recursively, arrays left in order,
 * `undefined` object members dropped, non-finite numbers rejected. Two callers
 * (build + verify, in any language) that follow this spec hash identical bytes.
 */
export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("canonicalize: non-finite numbers are not representable");
    }
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalize(v === undefined ? null : v)).join(",")}]`;
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalize(v)}`).join(",")}}`;
  }
  throw new Error(`canonicalize: unsupported value of type ${typeof value}`);
}

export function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

// ── Manifest shape ──────────────────────────────────────────────────

export type AttestationLeaf = { key: string; sha256: string };

export type HarnessGateSummary = {
  attempted: boolean;
  pass?: boolean;
  differential?: string;
  proof_strength?: string;
  /** SHA-256 the harness recorded for each side's response body (never the body). */
  target_body_sha256?: string;
  control_body_sha256?: string;
  /** SHA-256 of the harness-generated reflection canary, when one was used. */
  canary_token_sha256?: string;
};

export type AttestationContent = {
  case: {
    id: string;
    title: string;
    status: string;
    severity?: string;
    bug_class?: string;
    /** Host only — full target URLs/paths are never embedded in a shareable artifact. */
    target_host?: string;
    endpoint?: string;
  };
  confirmation: {
    mode: string;
    poc_sha256: string;
    reviewer: "main_agent";
    verdict: "CONFIRMED";
    differential: string;
    proof_strength?: string;
    confirmed_at: string;
    model?: string;
  };
  machine_gate: {
    phase1?: HarnessGateSummary;
    phase2: HarnessGateSummary;
  };
  evidence: Array<{
    role: string;
    /** SHA-256 of the backing artifact file (absent = unbacked evidence item). */
    artifact_sha256?: string;
    summary_sha256: string;
  }>;
  coverage?: Array<{
    asset: string;
    class: string;
    scope: string;
    /** true = backed by an artifact-backed evidence item. */
    backed: boolean;
  }>;
  disclaimer: string;
};

export type AttestationSignature = {
  alg: "ed25519";
  /** PEM SPKI public key — the verifier needs no other input to check the signature. */
  public_key: string;
  /** base64 Ed25519 signature over the chain_root hex string (UTF-8 bytes). */
  chain_root_signature: string;
  /** SHA-256 of the DER SPKI public key — a short fingerprint to pin against security.txt. */
  public_key_fingerprint: string;
};

export type Attestation = {
  schema: typeof ATTESTATION_SCHEMA;
  generated_at: string;
  generator: string;
  content: AttestationContent;
  leaves: AttestationLeaf[];
  chain_root: string;
  signature?: AttestationSignature;
};

// ── Leaf + chain computation (shared by build and verify) ───────────

/**
 * The ordered leaves committed by the chain. Computed identically on build and
 * verify, so the verifier recomputes these from `content` and never trusts the
 * manifest's own `leaves` array except to localize a mismatch.
 */
export function computeLeaves(content: AttestationContent): AttestationLeaf[] {
  const leaves: AttestationLeaf[] = [
    { key: "case", sha256: sha256Hex(canonicalize(content.case)) },
    { key: "confirmation", sha256: sha256Hex(canonicalize(content.confirmation)) },
  ];
  if (content.machine_gate.phase1 !== undefined) {
    leaves.push({
      key: "machine_gate.phase1",
      sha256: sha256Hex(canonicalize(content.machine_gate.phase1)),
    });
  }
  leaves.push({
    key: "machine_gate.phase2",
    sha256: sha256Hex(canonicalize(content.machine_gate.phase2)),
  });
  content.evidence.forEach((item, i) => {
    leaves.push({ key: `evidence[${i}]`, sha256: sha256Hex(canonicalize(item)) });
  });
  if (content.coverage !== undefined) {
    leaves.push({ key: "coverage", sha256: sha256Hex(canonicalize(content.coverage)) });
  }
  leaves.push({ key: "disclaimer", sha256: sha256Hex(canonicalize(content.disclaimer)) });
  return leaves;
}

/**
 * An order-committing hash fold over the leaves, seeded with the schema id.
 * Reordering, adding, or dropping any leaf — or changing any leaf hash —
 * changes the root. The root is the single value the signature covers.
 */
export function computeChainRoot(leaves: AttestationLeaf[]): string {
  let acc = sha256Hex(ATTESTATION_SCHEMA);
  for (const leaf of leaves) {
    acc = sha256Hex(`${acc}:${leaf.key}:${leaf.sha256}`);
  }
  return acc;
}

// ── Build ───────────────────────────────────────────────────────────

function hostOf(target: string | undefined): string | undefined {
  if (!target) return undefined;
  try {
    return new URL(target).host || undefined;
  } catch {
    // Not a URL (e.g. a bare host or app name) — keep a bounded raw value.
    return target.slice(0, 256);
  }
}

function summarizeGate(h: {
  attempted?: boolean;
  pass?: boolean;
  differential?: string;
  proofStrength?: string;
  target?: { bodySha256?: string };
  control?: { bodySha256?: string };
  canary?: { tokenSha256?: string };
}): HarnessGateSummary {
  return {
    attempted: h.attempted ?? false,
    pass: h.pass,
    differential: h.differential,
    proof_strength: h.proofStrength,
    target_body_sha256: h.target?.bodySha256,
    control_body_sha256: h.control?.bodySha256,
    canary_token_sha256: h.canary?.tokenSha256,
  };
}

export type BuildAttestationOptions = {
  /** Recorded in `generator`, e.g. `pi-casefile 0.9.4`. */
  generator?: string;
  /** Include the (asset × class) coverage matrix as a committed leaf. */
  includeCoverage?: boolean;
  /** Override the generation timestamp (tests). */
  now?: string;
};

/**
 * Build an unsigned attestation from a CONFIRMED case record. Throws unless the
 * case genuinely passed the full gate — an attestation can never certify a
 * finding the gate did not confirm with a conclusive target-only differential.
 */
export function buildAttestation(
  record: CaseRecord,
  opts: BuildAttestationOptions = {},
): Attestation {
  if (record.status !== "confirmed") {
    throw new Error(
      `CaseAttest requires a confirmed case; ${record.id} is "${record.status}". Promote + ConfirmFinding first.`,
    );
  }
  const cv = record.confirmerVerdict;
  if (!cv || cv.verdict !== "CONFIRMED") {
    throw new Error("CaseAttest requires a main-agent CONFIRMED verdict (ConfirmFinding).");
  }
  if (cv.differential !== "target_only") {
    throw new Error(
      `CaseAttest requires a target-only differential; verdict recorded "${cv.differential}".`,
    );
  }
  const phase2 = cv.phase2Verification?.result;
  if (!phase2) {
    throw new Error(
      "CaseAttest requires a harness-owned phase-2 replay bound to the verdict (re-run ConfirmFinding).",
    );
  }
  if (phase2.differential !== "target_only") {
    throw new Error(
      `CaseAttest requires the phase-2 replay to be target-only; harness recorded "${phase2.differential}".`,
    );
  }
  const bundle = record.pendingConfirmation;
  if (!bundle) {
    throw new Error("CaseAttest requires the PromoteFinding bundle (poc hash + phase-1 replay).");
  }

  const evidence = [...record.evidenceItems]
    .sort((a, b) =>
      a.role !== b.role
        ? a.role < b.role
          ? -1
          : 1
        : a.createdAt !== b.createdAt
          ? a.createdAt < b.createdAt
            ? -1
            : 1
          : a.id < b.id
            ? -1
            : a.id > b.id
              ? 1
              : 0,
    )
    .map((e) => ({
      role: e.role,
      artifact_sha256: e.sha256,
      summary_sha256: sha256Hex(e.summary),
    }));

  const content: AttestationContent = {
    case: {
      id: record.id,
      title: record.title,
      status: record.status,
      severity: record.severity,
      bug_class: record.bugClass,
      target_host: hostOf(record.target),
      endpoint: record.endpoint,
    },
    confirmation: {
      mode: bundle.mode ?? "inter_host",
      poc_sha256: bundle.pocSha256,
      reviewer: "main_agent",
      verdict: "CONFIRMED",
      differential: cv.differential,
      proof_strength: cv.proofStrength ?? phase2.proofStrength,
      confirmed_at: cv.at,
      model: cv.model,
    },
    machine_gate: {
      phase1: bundle.harnessVerified ? summarizeGate(bundle.harnessVerified) : undefined,
      phase2: summarizeGate(phase2),
    },
    evidence,
    coverage:
      opts.includeCoverage && record.coverageItems.length > 0
        ? [...record.coverageItems]
            .sort((a, b) => {
              const ka = `${a.asset}\u0000${a.class}\u0000${a.scope}`;
              const kb = `${b.asset}\u0000${b.class}\u0000${b.scope}`;
              return ka < kb ? -1 : ka > kb ? 1 : 0;
            })
            .map((c) => ({
              asset: c.asset,
              class: c.class,
              scope: c.scope,
              backed: Boolean(c.evidenceItemId),
            }))
        : undefined,
    disclaimer: ATTESTATION_DISCLAIMER,
  };

  const leaves = computeLeaves(content);
  return {
    schema: ATTESTATION_SCHEMA,
    generated_at: opts.now ?? new Date().toISOString(),
    generator: opts.generator ?? "pi-casefile",
    content,
    leaves,
    chain_root: computeChainRoot(leaves),
  };
}

// ── Signing ─────────────────────────────────────────────────────────

export function publicKeyFingerprint(publicKeyPem: string): string {
  const der = createPublicKey(publicKeyPem).export({ type: "spki", format: "der" });
  return createHash("sha256").update(der).digest("hex");
}

/** Generate an Ed25519 keypair as PEM strings (for key setup + tests). */
export function generateAttestationKeypair(): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKey: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

/** Sign (or re-sign) an attestation's chain root with an Ed25519 private key (PEM). */
export function signAttestation(attestation: Attestation, privateKeyPem: string): Attestation {
  const publicKey = createPublicKey(privateKeyPem)
    .export({ type: "spki", format: "pem" })
    .toString();
  const signature = sign(null, Buffer.from(attestation.chain_root, "utf8"), privateKeyPem);
  return {
    ...attestation,
    signature: {
      alg: "ed25519",
      public_key: publicKey,
      chain_root_signature: signature.toString("base64"),
      public_key_fingerprint: publicKeyFingerprint(publicKey),
    },
  };
}

// ── Verify ──────────────────────────────────────────────────────────

export type VerifyLeafResult = { key: string; ok: boolean; expected: string; recomputed: string };

export type VerifyResult = {
  ok: boolean;
  schemaOk: boolean;
  chainRootOk: boolean;
  leaves: VerifyLeafResult[];
  signature: {
    present: boolean;
    valid?: boolean;
    /** Fingerprint of the embedded key, so the caller can pin it to a known identity. */
    fingerprint?: string;
  };
  errors: string[];
};

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Recompute every leaf from `content`, recompute the chain root from those
 * leaves, and (if present) verify the Ed25519 signature over the root. Trusts
 * nothing in the manifest but `content` and the embedded public key; `ok` is
 * true only when structure, every leaf, the root, and any signature all hold.
 *
 * `expectedFingerprint`, when given, additionally requires the signing key to
 * match — this is how a program pins an attestation to a known researcher key.
 */
export function verifyAttestation(raw: unknown, expectedFingerprint?: string): VerifyResult {
  const errors: string[] = [];
  const result: VerifyResult = {
    ok: false,
    schemaOk: false,
    chainRootOk: false,
    leaves: [],
    signature: { present: false },
    errors,
  };

  if (!isRecord(raw)) {
    errors.push("attestation must be a JSON object");
    return result;
  }
  if (raw.schema !== ATTESTATION_SCHEMA) {
    errors.push(
      `unknown schema: expected "${ATTESTATION_SCHEMA}", got ${JSON.stringify(raw.schema)}`,
    );
    return result;
  }
  result.schemaOk = true;
  if (!isRecord(raw.content)) {
    errors.push("attestation.content is missing or not an object");
    return result;
  }

  let recomputedLeaves: AttestationLeaf[];
  try {
    recomputedLeaves = computeLeaves(raw.content as unknown as AttestationContent);
  } catch (err) {
    errors.push(`could not recompute leaves from content: ${(err as Error).message}`);
    return result;
  }

  const claimedLeaves: AttestationLeaf[] = Array.isArray(raw.leaves)
    ? (raw.leaves as AttestationLeaf[])
    : [];
  const claimedByKey = new Map(claimedLeaves.map((l) => [l.key, l.sha256] as const));
  let allLeavesOk = recomputedLeaves.length === claimedLeaves.length;
  for (const leaf of recomputedLeaves) {
    const claimed = claimedByKey.get(leaf.key);
    const ok = claimed === leaf.sha256;
    if (!ok) allLeavesOk = false;
    result.leaves.push({
      key: leaf.key,
      ok,
      expected: claimed ?? "(absent)",
      recomputed: leaf.sha256,
    });
  }
  if (recomputedLeaves.length !== claimedLeaves.length) {
    errors.push(
      `leaf count mismatch: content yields ${recomputedLeaves.length}, manifest lists ${claimedLeaves.length}`,
    );
  }
  if (!allLeavesOk) errors.push("one or more leaves do not match the content (tampering)");

  const recomputedRoot = computeChainRoot(recomputedLeaves);
  result.chainRootOk = recomputedRoot === raw.chain_root;
  if (!result.chainRootOk) {
    errors.push(
      `chain_root mismatch: recomputed ${recomputedRoot}, manifest claims ${JSON.stringify(raw.chain_root)}`,
    );
  }

  if (raw.signature !== undefined) {
    result.signature.present = true;
    const sig = raw.signature;
    if (
      !isRecord(sig) ||
      sig.alg !== "ed25519" ||
      typeof sig.public_key !== "string" ||
      typeof sig.chain_root_signature !== "string"
    ) {
      result.signature.valid = false;
      errors.push(
        "signature block is malformed (need alg ed25519, public_key, chain_root_signature)",
      );
    } else {
      try {
        const fingerprint = publicKeyFingerprint(sig.public_key);
        result.signature.fingerprint = fingerprint;
        const valid = verify(
          null,
          Buffer.from(String(raw.chain_root), "utf8"),
          createPublicKey(sig.public_key),
          Buffer.from(sig.chain_root_signature, "base64"),
        );
        result.signature.valid = valid;
        if (!valid) errors.push("Ed25519 signature does not verify against chain_root");
        if (expectedFingerprint && fingerprint !== expectedFingerprint) {
          result.signature.valid = false;
          errors.push(
            `signing key fingerprint ${fingerprint} does not match expected ${expectedFingerprint}`,
          );
        }
      } catch (err) {
        result.signature.valid = false;
        errors.push(`signature verification error: ${(err as Error).message}`);
      }
    }
  } else if (expectedFingerprint) {
    errors.push("a key fingerprint was required but the attestation is unsigned");
  }

  result.ok =
    result.schemaOk &&
    allLeavesOk &&
    result.chainRootOk &&
    (!result.signature.present || result.signature.valid === true) &&
    (!expectedFingerprint || result.signature.valid === true);
  return result;
}
