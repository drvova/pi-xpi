import assert from "node:assert";
import { describe, it } from "node:test";
import {
  type OmpToolMetadata,
  type ToolApprovalTier,
  type ToolLoadModeTier,
  withOmpMetadata,
} from "../src/omp-tool.ts";

describe("omp-tool: withOmpMetadata", () => {
  it("attaches OMP-native metadata onto a tool definition at runtime", () => {
    const base = { name: "CaseGet", label: "Get Case", description: "..." };
    const out = withOmpMetadata(base, { approval: "read" });
    assert.equal((out as typeof base & OmpToolMetadata).approval, "read");
    // Original fields are preserved.
    assert.equal(out.name, "CaseGet");
    assert.equal(out.description, "...");
  });

  it("carries every supported field and does not mutate the input", () => {
    const base = { name: "PromoteFinding" };
    const meta: OmpToolMetadata = { approval: "exec", loadMode: "essential", readsSkillUris: true };
    const out = withOmpMetadata(base, meta) as typeof base & OmpToolMetadata;
    assert.equal(out.approval, "exec");
    assert.equal(out.loadMode, "essential");
    assert.equal(out.readsSkillUris, true);
    assert.deepEqual(base, { name: "PromoteFinding" }, "input is not mutated");
  });

  it("later metadata keys win over any same-named keys already on the def", () => {
    const base = { name: "x", approval: "read" as ToolApprovalTier };
    const out = withOmpMetadata(base, { approval: "write" });
    assert.equal((out as typeof base).approval, "write");
  });

  it("pins the approval + loadMode tiers to the OMP contract", () => {
    // These unions mirror @oh-my-pi/pi-coding-agent's ToolDefinition. If OMP
    // changes them, this and the type will need updating together.
    const approvals: ToolApprovalTier[] = ["read", "write", "exec"];
    const loadModes: ToolLoadModeTier[] = ["essential", "discoverable"];
    assert.deepEqual(approvals, ["read", "write", "exec"]);
    assert.deepEqual(loadModes, ["essential", "discoverable"]);
  });
});
