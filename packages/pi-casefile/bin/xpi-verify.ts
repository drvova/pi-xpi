#!/usr/bin/env node
/**
 * xpi-verify — independently verify an XPI finding attestation.
 *
 * A third party (a bug-bounty triager, a customer, a resuming agent) runs this
 * against an `attestation.json` to confirm, WITHOUT trusting the researcher and
 * without re-running anything live, that:
 *   1. every content leaf hashes to the value the manifest claims,
 *   2. the order-committing chain root is consistent with those leaves, and
 *   3. the Ed25519 signature (if present) verifies over that root — optionally
 *      pinned to an expected public-key fingerprint.
 *
 * It depends only on `node:crypto` (via attestation.ts). Run it with Node (its
 * TS types strip under modern Node) or with `bun bin/xpi-verify.ts`.
 *
 * Usage:
 *   xpi-verify <attestation.json> [--key-fingerprint <sha256-hex>] [--json] [--quiet]
 *
 * Exit codes: 0 = verified, 1 = verification failed, 2 = usage/read error.
 */

import { readFileSync } from "node:fs";
import { verifyAttestation } from "../src/attestation.ts";

function usage(): never {
  process.stderr.write(
    "Usage: xpi-verify <attestation.json> [--key-fingerprint <sha256-hex>] [--json] [--quiet]\n",
  );
  process.exit(2);
}

function main(argv: string[]): number {
  const args = argv.slice(2);
  let file: string | undefined;
  let expectedFingerprint: string | undefined;
  let asJson = false;
  let quiet = false;

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--json") asJson = true;
    else if (a === "--quiet" || a === "-q") quiet = true;
    else if (a === "--key-fingerprint") {
      expectedFingerprint = args[++i];
      if (!expectedFingerprint) usage();
    } else if (a === "-h" || a === "--help") usage();
    else if (a.startsWith("-")) usage();
    else if (file === undefined) file = a;
    else usage();
  }
  if (!file) usage();

  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(file, "utf8"));
  } catch (err) {
    process.stderr.write(`cannot read ${file}: ${(err as Error).message}\n`);
    return 2;
  }

  const result = verifyAttestation(raw, expectedFingerprint);

  if (asJson) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return result.ok ? 0 : 1;
  }

  if (!quiet) {
    const manifest = raw as Record<string, unknown>;
    const content = (manifest.content ?? {}) as Record<string, unknown>;
    const caseInfo = (content.case ?? {}) as Record<string, unknown>;
    const confirmation = (content.confirmation ?? {}) as Record<string, unknown>;
    const mark = (ok: boolean) => (ok ? "✓" : "✗");

    process.stdout.write(`attestation: ${file}\n`);
    if (caseInfo.title) process.stdout.write(`  finding:    ${caseInfo.title}\n`);
    if (caseInfo.severity) process.stdout.write(`  severity:   ${caseInfo.severity}\n`);
    if (confirmation.mode) {
      process.stdout.write(
        `  gate:       ${confirmation.mode} · ${confirmation.differential ?? "?"} · ${
          confirmation.proof_strength ?? "?"
        }\n`,
      );
    }
    process.stdout.write(`  schema:     ${mark(result.schemaOk)}\n`);
    const leafOk = result.leaves.every((l) => l.ok);
    process.stdout.write(`  leaves:     ${mark(leafOk)} (${result.leaves.length} committed)\n`);
    for (const leaf of result.leaves.filter((l) => !l.ok)) {
      process.stdout.write(
        `                ✗ ${leaf.key}: expected ${leaf.expected}, got ${leaf.recomputed}\n`,
      );
    }
    process.stdout.write(`  chain_root: ${mark(result.chainRootOk)}\n`);
    if (result.signature.present) {
      process.stdout.write(
        `  signature:  ${mark(result.signature.valid === true)}${
          result.signature.fingerprint ? ` (key ${result.signature.fingerprint})` : ""
        }\n`,
      );
    } else {
      process.stdout.write("  signature:  (unsigned — integrity only, not authenticated)\n");
    }
    for (const e of result.errors) process.stdout.write(`  ! ${e}\n`);
    process.stdout.write(result.ok ? "\nVERIFIED\n" : "\nFAILED\n");
  }

  return result.ok ? 0 : 1;
}

process.exit(main(process.argv));
