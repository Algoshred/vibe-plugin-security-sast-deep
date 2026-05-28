import { describe, expect, test } from "bun:test";

import { SemgrepOsvScannerProvider } from "../src/provider.js";
import { OSV_SCANNER_VERSION, SEMGREP_VERSION } from "../src/tools-manifest.js";

describe("SemgrepOsvScannerProvider", () => {
  test("provider name + stage are stable identifiers", () => {
    const p = new SemgrepOsvScannerProvider();
    expect(p.name).toBe("semgrep-osv-scanner");
    expect(p.stage).toBe("pull_request.deep");
  });

  test("metadata() reports stage + supported profiles + tool version", () => {
    const p = new SemgrepOsvScannerProvider();
    const meta = p.metadata();
    expect(meta.stage).toBe("pull_request.deep");
    expect(meta.supportedProfiles).toContain("backend");
    expect(meta.supportedProfiles).toContain("frontend");
    expect(meta.toolVersion).toBe(`semgrep@${SEMGREP_VERSION}+osv-scanner@${OSV_SCANNER_VERSION}`);
    expect(p.toolVersion).toBe(`semgrep@${SEMGREP_VERSION}+osv-scanner@${OSV_SCANNER_VERSION}`);
  });

  test("cancel() on an unknown run is a no-op", async () => {
    const p = new SemgrepOsvScannerProvider();
    await expect(p.cancel("nonexistent")).resolves.toBeUndefined();
  });
});
