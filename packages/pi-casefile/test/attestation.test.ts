import assert from "node:assert";
import { describe, it } from "node:test";
import {
  ATTESTATION_SCHEMA,
  type Attestation,
  buildAttestation,
  canonicalize,
  computeChainRoot,
  computeLeaves,
  generateAttestationKeypair,
  signAttestation,
  verifyAttestation,
} from "../src/attestation.ts";
import type { CaseRecord } from "../src/ledger.ts";

/** A fully-gated, CONFIRMED case record: the only input that may be attested. */
function confirmedCase(overrides: Partial<CaseRecord> = {}): CaseRecord {
  const base: CaseRecord = {
    id: "case_abc123",
    title: "SQL injection in /api/report",
    status: "confirmed",
    everAdvanced: true,
    confidence: "high",
    severity: "high",
    bugClass: "sql-injection",
    target: "https://app.example.com/api/report?id=1",
    endpoint: "/api/report",
    pendingConfirmation: {
      caseId: "case_abc123",
      ranAt: "2026-01-01T00:00:00.000Z",
      pocPath: "poc.sh",
      pocSha256: "a".repeat(64),
      mode: "inter_host",
      controlTarget: "https://patched.example.com",
      targetRuns: [
        {
          mode: "poc",
          target: "https://app.example.com",
          nonce: "n1",
          ranAt: "2026-01-01T00:00:00.000Z",
          exitCode: 0,
          sandbox: false,
          completed: true,
          outputComplete: true,
          output: "ok",
          evidence: {
            nonce: "n1",
            claim: "read admin row",
            verify: {
              method: "GET",
              url: "https://app.example.com/api/report?id=1",
              expect: { body_contains: ["is_admin"] },
            },
            observations: [],
          },
          evidenceSha256: "b".repeat(64),
        },
        {
          mode: "poc",
          target: "https://app.example.com",
          nonce: "n2",
          ranAt: "2026-01-01T00:00:01.000Z",
          exitCode: 0,
          sandbox: false,
          completed: true,
          outputComplete: true,
          output: "ok",
          evidence: {
            nonce: "n2",
            claim: "read admin row",
            verify: {
              method: "GET",
              url: "https://app.example.com/api/report?id=1",
              expect: { body_contains: ["is_admin"] },
            },
            observations: [],
          },
          evidenceSha256: "c".repeat(64),
        },
      ],
      harnessVerified: {
        attempted: true,
        pass: true,
        differential: "target_only",
        proofStrength: "predicate_differential",
        target: {
          attempted: true,
          matched: true,
          url: "https://app.example.com",
          bodySha256: "d".repeat(64),
          note: "",
        },
        control: {
          attempted: true,
          matched: false,
          url: "https://patched.example.com",
          bodySha256: "e".repeat(64),
          note: "",
        },
        note: "",
      },
    },
    confirmerVerdict: {
      verdict: "CONFIRMED",
      reasoning: "target-only differential confirmed",
      evidence_reviewed: ["poc.sh", "evidence.json"],
      re_execution_note: "replayed, admin row only on target",
      differential: "target_only",
      disconfirmation_attempt: "tried baseline user; no admin row",
      canary_assessment: "not_applicable",
      canary_reason: "no reflection oracle for this class",
      at: "2026-01-01T00:05:00.000Z",
      reviewer: "main_agent",
      proofStrength: "predicate_differential",
      phase2Verification: {
        at: "2026-01-01T00:05:00.000Z",
        result: {
          attempted: true,
          pass: true,
          differential: "target_only",
          proofStrength: "predicate_differential",
          target: {
            attempted: true,
            matched: true,
            url: "https://app.example.com",
            bodySha256: "f".repeat(64),
            note: "",
          },
          control: {
            attempted: true,
            matched: false,
            url: "https://patched.example.com",
            bodySha256: "0".repeat(64),
            note: "",
          },
          note: "",
        },
      },
    },
    evidenceItems: [
      {
        id: "ev_2",
        caseId: "case_abc123",
        role: "reproduction",
        artifactPath: "evidence.json",
        sha256: "1".repeat(64),
        summary: "nonce-bound evidence.json",
        createdAt: "2026-01-01T00:02:00.000Z",
      },
      {
        id: "ev_1",
        caseId: "case_abc123",
        role: "observation",
        artifactPath: "resp.txt",
        sha256: "2".repeat(64),
        summary: "admin row in response",
        createdAt: "2026-01-01T00:01:00.000Z",
      },
    ],
    coverageItems: [
      {
        id: "cov_1",
        caseId: "case_abc123",
        asset: "/api/report",
        class: "sql-injection",
        scope: "local",
        note: "sqlmap + manual · found",
        evidenceItemId: "ev_1",
        createdAt: "2026-01-01T00:03:00.000Z",
      },
    ],
    linkedCases: [],
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-01T00:05:00.000Z",
  };
  return { ...base, ...overrides };
}

const BUILD_OPTS = { now: "2026-01-02T00:00:00.000Z", generator: "pi-casefile test" };

describe("attestation: canonicalize", () => {
  it("sorts object keys and drops undefined members deterministically", () => {
    assert.equal(canonicalize({ b: 1, a: 2 }), '{"a":2,"b":1}');
    assert.equal(canonicalize({ a: undefined, b: 1 }), '{"b":1}');
    assert.equal(canonicalize([{ y: 1, x: 2 }]), '[{"x":2,"y":1}]');
  });

  it("preserves array order", () => {
    assert.equal(canonicalize([3, 1, 2]), "[3,1,2]");
  });

  it("rejects non-finite numbers", () => {
    assert.throws(() => canonicalize(Number.NaN));
    assert.throws(() => canonicalize(Number.POSITIVE_INFINITY));
  });
});

describe("attestation: build guardrails", () => {
  it("builds from a fully-gated confirmed case", () => {
    const a = buildAttestation(confirmedCase(), BUILD_OPTS);
    assert.equal(a.schema, ATTESTATION_SCHEMA);
    assert.equal(a.content.confirmation.verdict, "CONFIRMED");
    assert.equal(a.content.confirmation.differential, "target_only");
    assert.equal(a.content.case.target_host, "app.example.com"); // host only, no path/query
    assert.equal(a.content.confirmation.poc_sha256, "a".repeat(64));
    assert.ok(a.chain_root.length === 64);
  });

  it("refuses a non-confirmed case", () => {
    assert.throws(
      () => buildAttestation(confirmedCase({ status: "investigating" }), BUILD_OPTS),
      /confirmed/,
    );
  });

  it("refuses when the verdict is not CONFIRMED", () => {
    const rec = confirmedCase();
    rec.confirmerVerdict = { ...rec.confirmerVerdict!, verdict: "NOT_CONFIRMED" };
    assert.throws(() => buildAttestation(rec, BUILD_OPTS), /CONFIRMED verdict/);
  });

  it("refuses when the phase-2 replay is not target_only", () => {
    const rec = confirmedCase();
    rec.confirmerVerdict!.phase2Verification!.result.differential = "both";
    assert.throws(() => buildAttestation(rec, BUILD_OPTS), /phase-2 replay to be target-only/);
  });

  it("refuses when there is no phase-2 replay bound to the verdict", () => {
    const rec = confirmedCase();
    rec.confirmerVerdict!.phase2Verification = undefined;
    assert.throws(() => buildAttestation(rec, BUILD_OPTS), /phase-2 replay/);
  });
});

describe("attestation: evidence + coverage", () => {
  it("sorts evidence by role deterministically regardless of input order", () => {
    const a = buildAttestation(confirmedCase(), BUILD_OPTS);
    assert.deepEqual(
      a.content.evidence.map((e) => e.role),
      ["observation", "reproduction"],
    );
  });

  it("includes coverage with backed flags when requested, omits it otherwise", () => {
    const withCov = buildAttestation(confirmedCase(), { ...BUILD_OPTS, includeCoverage: true });
    assert.equal(withCov.content.coverage?.[0]?.backed, true);
    const withoutCov = buildAttestation(confirmedCase(), { ...BUILD_OPTS, includeCoverage: false });
    assert.equal(withoutCov.content.coverage, undefined);
  });
});

describe("attestation: verify (unsigned integrity)", () => {
  it("verifies a freshly built unsigned attestation", () => {
    const a = buildAttestation(confirmedCase(), BUILD_OPTS);
    const r = verifyAttestation(a);
    assert.equal(r.ok, true);
    assert.equal(r.chainRootOk, true);
    assert.equal(r.signature.present, false);
    assert.ok(r.leaves.every((l) => l.ok));
  });

  it("is deterministic — same input yields the same chain root", () => {
    const a1 = buildAttestation(confirmedCase(), BUILD_OPTS);
    const a2 = buildAttestation(confirmedCase(), BUILD_OPTS);
    assert.equal(a1.chain_root, a2.chain_root);
  });

  it("detects tampering with a content field (leaf + root fail)", () => {
    const a = buildAttestation(confirmedCase(), BUILD_OPTS);
    a.content.case.severity = "critical"; // inflate severity after the fact
    const r = verifyAttestation(a);
    assert.equal(r.ok, false);
    assert.equal(r.leaves.find((l) => l.key === "case")?.ok, false);
    assert.equal(r.chainRootOk, false);
  });

  it("detects tampering with the confirmation differential", () => {
    const a = buildAttestation(confirmedCase(), BUILD_OPTS);
    a.content.confirmation.differential = "both";
    const r = verifyAttestation(a);
    assert.equal(r.ok, false);
    assert.equal(r.leaves.find((l) => l.key === "confirmation")?.ok, false);
  });

  it("detects a swapped chain_root even when leaves are internally consistent", () => {
    const a = buildAttestation(confirmedCase(), BUILD_OPTS);
    a.chain_root = computeChainRoot(computeLeaves(a.content)).replace(/.$/, "0");
    const r = verifyAttestation(a);
    assert.equal(r.chainRootOk, false);
    assert.equal(r.ok, false);
  });

  it("detects an added/removed leaf (count mismatch)", () => {
    const a = buildAttestation(confirmedCase(), BUILD_OPTS);
    a.leaves.push({ key: "evidence[99]", sha256: "9".repeat(64) });
    const r = verifyAttestation(a);
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => /count mismatch/.test(e)));
  });

  it("rejects an unknown schema", () => {
    const a = buildAttestation(confirmedCase(), BUILD_OPTS) as unknown as Record<string, unknown>;
    a.schema = "xpi-attestation/v99";
    const r = verifyAttestation(a);
    assert.equal(r.schemaOk, false);
    assert.equal(r.ok, false);
  });
});

describe("attestation: sign + verify (Ed25519)", () => {
  it("round-trips a signature and reports the fingerprint", () => {
    const { privateKey } = generateAttestationKeypair();
    const signed = signAttestation(buildAttestation(confirmedCase(), BUILD_OPTS), privateKey);
    assert.equal(signed.signature?.alg, "ed25519");
    const r = verifyAttestation(signed);
    assert.equal(r.ok, true);
    assert.equal(r.signature.present, true);
    assert.equal(r.signature.valid, true);
    assert.equal(r.signature.fingerprint, signed.signature?.public_key_fingerprint);
  });

  it("fails signature verification when the signed content is tampered", () => {
    const { privateKey } = generateAttestationKeypair();
    const signed = signAttestation(buildAttestation(confirmedCase(), BUILD_OPTS), privateKey);
    signed.content.case.severity = "critical";
    signed.leaves = computeLeaves(signed.content);
    signed.chain_root = computeChainRoot(signed.leaves); // re-fit leaves+root to the forged content
    const r = verifyAttestation(signed);
    // Leaves + root now self-consistent, but the signature was over the ORIGINAL root.
    assert.equal(r.chainRootOk, true);
    assert.equal(r.signature.valid, false);
    assert.equal(r.ok, false);
  });

  it("enforces an expected key fingerprint (key pinning)", () => {
    const { privateKey } = generateAttestationKeypair();
    const other = generateAttestationKeypair();
    const signed: Attestation = signAttestation(
      buildAttestation(confirmedCase(), BUILD_OPTS),
      privateKey,
    );
    const good = verifyAttestation(signed, signed.signature?.public_key_fingerprint);
    assert.equal(good.ok, true);
    const bad = verifyAttestation(
      signed,
      verifyAttestation(
        signAttestation(buildAttestation(confirmedCase(), BUILD_OPTS), other.privateKey),
      ).signature.fingerprint,
    );
    assert.equal(bad.ok, false);
  });

  it("requires a signature when a fingerprint is demanded of an unsigned attestation", () => {
    const a = buildAttestation(confirmedCase(), BUILD_OPTS);
    const r = verifyAttestation(a, "a".repeat(64));
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => /unsigned/.test(e)));
  });
});
