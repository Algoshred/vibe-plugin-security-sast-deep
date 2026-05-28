import { beforeAll, afterAll, describe, expect, test } from "bun:test";
import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { SemgrepOsvScannerProvider } from "../src/provider.js";
import { OSV_SCANNER_VERSION, SEMGREP_VERSION } from "../src/tools-manifest.js";

const SAMPLE_SEMGREP_SARIF = JSON.stringify({
  $schema: "https://json.schemastore.org/sarif-2.1.0.json",
  version: "2.1.0",
  runs: [
    {
      tool: { driver: { name: "semgrep", version: SEMGREP_VERSION } },
      results: [
        {
          ruleId: "javascript.lang.security.audit.weak-rand",
          level: "warning",
          message: { text: "Use of weak PRNG detected" },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "src/foo.js" },
                region: { startLine: 12 },
              },
            },
          ],
        },
      ],
    },
  ],
});

const SAMPLE_OSV_SARIF = JSON.stringify({
  $schema: "https://json.schemastore.org/sarif-2.1.0.json",
  version: "2.1.0",
  runs: [
    {
      tool: { driver: { name: "osv-scanner", version: OSV_SCANNER_VERSION } },
      results: [
        {
          ruleId: "GHSA-aaaa-bbbb-cccc",
          level: "error",
          message: { text: "Vulnerable dependency lodash@4.17.0" },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "package.json" },
                region: { startLine: 1 },
              },
            },
          ],
        },
      ],
    },
  ],
});

describe("SemgrepOsvScannerProvider (static metadata)", () => {
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

describe("SemgrepOsvScannerProvider (fixture run)", () => {
  let tmpRoot: string;
  let fakeBinDir: string;
  let originalPath: string | undefined;

  beforeAll(async () => {
    tmpRoot = await fs.mkdtemp(path.join(os.tmpdir(), "sast-deep-test-"));
    fakeBinDir = path.join(tmpRoot, "bin");
    await fs.mkdir(fakeBinDir, { recursive: true });

    // Write SARIF outputs that the fakes will copy to the workdir.
    const semgrepFixture = path.join(tmpRoot, "semgrep.sarif.fixture");
    const osvFixture = path.join(tmpRoot, "osv.sarif.fixture");
    await fs.writeFile(semgrepFixture, SAMPLE_SEMGREP_SARIF);
    await fs.writeFile(osvFixture, SAMPLE_OSV_SARIF);

    // Fake semgrep shell script that emits the fixture SARIF to its --output path.
    const fakeSemgrep = path.join(fakeBinDir, "semgrep");
    await fs.writeFile(
      fakeSemgrep,
      `#!/usr/bin/env bash
set -e
out=""
i=0
args=("$@")
while [ $i -lt \${#args[@]} ]; do
  if [ "\${args[$i]}" = "--output" ]; then
    j=$((i+1))
    out="\${args[$j]}"
    break
  fi
  if [ "\${args[$i]}" = "--version" ]; then
    echo "${SEMGREP_VERSION}"
    exit 0
  fi
  i=$((i+1))
done
if [ -n "$out" ]; then
  cp "${semgrepFixture}" "$out"
fi
exit 0
`,
    );
    await fs.chmod(fakeSemgrep, 0o755);

    // Fake osv-scanner shell script with same SARIF-emitting behaviour.
    const fakeOsv = path.join(fakeBinDir, "osv-scanner");
    await fs.writeFile(
      fakeOsv,
      `#!/usr/bin/env bash
set -e
out=""
i=0
args=("$@")
while [ $i -lt \${#args[@]} ]; do
  if [ "\${args[$i]}" = "--output" ]; then
    j=$((i+1))
    out="\${args[$j]}"
    break
  fi
  if [ "\${args[$i]}" = "--version" ]; then
    echo "${OSV_SCANNER_VERSION}"
    exit 0
  fi
  i=$((i+1))
done
if [ -n "$out" ]; then
  cp "${osvFixture}" "$out"
fi
exit 0
`,
    );
    await fs.chmod(fakeOsv, 0o755);

    originalPath = process.env.PATH;
    process.env.PATH = `${fakeBinDir}:${originalPath ?? ""}`;
  });

  afterAll(async () => {
    if (originalPath !== undefined) process.env.PATH = originalPath;
    await fs.rm(tmpRoot, { recursive: true, force: true });
  });

  test("run() merges findings from semgrep + osv-scanner SARIF outputs", async () => {
    const provider = new SemgrepOsvScannerProvider();

    // Provide a fake host with getDataDir() pointing into tmp so the
    // installer caches under our fixture root.
    const dataDir = path.join(tmpRoot, "agent-data");
    await fs.mkdir(dataDir, { recursive: true });
    await provider.init({
      getDataDir: () => dataDir,
      logger: {
        info: () => {},
        warn: () => {},
        error: () => {},
      },
    } as unknown as Parameters<SemgrepOsvScannerProvider["init"]>[0]);

    // Pre-stage the osv-scanner cache pointing at the fake script so
    // resolveToolPath returns it without a network download. We mimic
    // the installer's <dataDir>/tools/<tool>/<ver>/<bin> layout.
    const osvCache = path.join(dataDir, "tools", "osv-scanner", OSV_SCANNER_VERSION);
    await fs.mkdir(osvCache, { recursive: true });
    // Point the cache file at our fake by copying — but cache content
    // must match sha for the installer to accept; easier: let the
    // installer fall back to PATH probe by giving the fake a matching
    // --version output.
    // The installer first checks sha256 of the cached binary against the
    // manifest entry. We don't have a matching sha for the fake, so we
    // rely on PATH probe: installer calls `which osv-scanner` which finds
    // our fake; then versionMatches() runs `--version` and the regex
    // (escaped 1.9.2) matches the fake's "1.9.2" output.

    const workdir = path.join(tmpRoot, "scan-work");
    await fs.mkdir(workdir, { recursive: true });

    const result = await provider.run({
      runId: "test-run-1",
      vibeId: "vibe-1",
      workspaceId: "ws-1",
      repoUrl: "git://example.com/repo.git",
      repoLocalPath: tmpRoot,
      commit: "deadbeef",
      stage: "pull_request.deep",
      profile: { kind: "backend", languages: [], runtimes: [] },
      policyLevel: "advisory",
      config: { semgrepConfig: "p/default" },
      workdir,
    });

    expect(result.status).toBe("succeeded");
    expect(result.findings.length).toBe(2);
    const ruleIds = result.findings.map((f) => f.ruleId);
    expect(ruleIds).toContain("javascript.lang.security.audit.weak-rand");
    expect(ruleIds).toContain("GHSA-aaaa-bbbb-cccc");

    const categories = new Set(result.findings.map((f) => f.category));
    expect(categories.has("sast")).toBe(true);
    expect(categories.has("vuln")).toBe(true);

    expect(result.evidence.length).toBe(2);
    for (const ev of result.evidence) {
      expect(ev.type).toBe("sarif");
      expect(ev.sha256).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  test("ensureToolInstalled() throws clearly when semgrep + pipx + python3 all absent", async () => {
    // Construct a tightly scoped PATH where `which` itself is the only
    // resolvable tool (other than osv-scanner which is required for the
    // earlier installer step). semgrep / pipx / python3 are deliberately
    // shadowed by absent-from-disk entries in an isolated dir.
    const isoDir = await fs.mkdtemp(path.join(os.tmpdir(), "sast-deep-iso-"));
    // Symlink only `which` from /usr/bin so PATH lookups for it work.
    try {
      await fs.symlink("/usr/bin/which", path.join(isoDir, "which"));
    } catch {
      // If /usr/bin/which doesn't exist, find it programmatically.
      const out = await new Promise<string>((resolve) => {
        const child = spawn("which", ["which"], { stdio: ["ignore", "pipe", "ignore"] });
        let o = "";
        child.stdout?.on("data", (b: Buffer) => (o += b.toString()));
        child.on("close", () => resolve(o.trim()));
        child.on("error", () => resolve(""));
      });
      if (out) await fs.symlink(out, path.join(isoDir, "which"));
    }
    // Also symlink osv-scanner (the fake from fakeBinDir) so that step
    // succeeds and the semgrep step is the one that fails.
    await fs.symlink(path.join(fakeBinDir, "osv-scanner"), path.join(isoDir, "osv-scanner"));

    const previousPath = process.env.PATH;
    process.env.PATH = isoDir;

    try {
      const p = new SemgrepOsvScannerProvider();
      await p.init({
        getDataDir: () => path.join(isoDir, "agent-data"),
        logger: { info: () => {}, warn: () => {}, error: () => {} },
      } as unknown as Parameters<SemgrepOsvScannerProvider["init"]>[0]);
      await expect(p.ensureToolInstalled()).rejects.toThrow(/semgrep not installed/);
    } finally {
      process.env.PATH = previousPath;
      await fs.rm(isoDir, { recursive: true, force: true });
    }
  });
});
