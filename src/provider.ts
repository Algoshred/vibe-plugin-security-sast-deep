/**
 * SemgrepOsvScannerProvider — implements SecurityProvider for stage
 * `pull_request.deep`. Runs Semgrep with the full ruleset (`--config
 * auto`) for SAST plus osv-scanner against package manifests for SCA.
 *
 * TODO: Wave 2 scaffold — real Semgrep + osv-scanner integration is
 * pending. This v1 verifies tool paths resolve and returns a single
 * info finding describing what a real scan would do.
 */
import { createHash } from "node:crypto";
import * as path from "node:path";

import type { HostServices } from "@vibecontrols/plugin-sdk/contract";
import { resolveToolPath } from "@vibecontrols/vibe-plugin-security/tool-installer";
import type {
  NormalizedFinding,
  SecurityProvider,
  SecurityProviderMetadata,
  SecurityScanInput,
  SecurityScanResult,
  SecurityScanSummary,
  SecurityStage,
} from "@vibecontrols/vibe-plugin-security/types";

import { OSV_SCANNER_VERSION, SEMGREP_VERSION, TOOLS_MANIFEST } from "./tools-manifest.js";

export class SemgrepOsvScannerProvider implements SecurityProvider {
  readonly name = "semgrep-osv-scanner";
  readonly stage: SecurityStage = "pull_request.deep";
  readonly toolVersion = `semgrep@${SEMGREP_VERSION}+osv-scanner@${OSV_SCANNER_VERSION}`;

  private host?: HostServices;
  private semgrepPath?: string;
  private osvScannerPath?: string;

  async init(host: HostServices): Promise<void> {
    this.host = host;
  }

  async ensureToolInstalled(): Promise<void> {
    const dataDir =
      this.host?.getDataDir?.() ?? path.join(process.env.HOME ?? ".", ".boff/vibecontrols");
    const ctx = {
      dataDir,
      log: {
        info: (m: string) => this.host?.logger?.info?.("semgrep-osv-scanner-provider", m),
        warn: (m: string) => this.host?.logger?.warn?.("semgrep-osv-scanner-provider", m),
        error: (m: string) => this.host?.logger?.error?.("semgrep-osv-scanner-provider", m),
      },
    };
    // Resolve both binaries up front so we surface manifest mismatches
    // early. Semgrep PATH fallback is expected on darwin/windows where
    // we don't ship a prebuilt binary; the tool-installer handles that.
    this.semgrepPath = await resolveToolPath(ctx, "semgrep", TOOLS_MANIFEST.semgrep);
    this.osvScannerPath = await resolveToolPath(ctx, "osv-scanner", TOOLS_MANIFEST["osv-scanner"]);
  }

  async run(input: SecurityScanInput): Promise<SecurityScanResult> {
    const startedAt = Date.now();
    input.onProgress?.({ pct: 10, message: "Verifying semgrep + osv-scanner tool paths" });

    try {
      if (!this.semgrepPath || !this.osvScannerPath) {
        await this.ensureToolInstalled();
      }
    } catch (err) {
      return {
        runId: input.runId,
        status: "errored",
        findings: [],
        evidence: [],
        durationMs: Date.now() - startedAt,
        summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        errorReason: `semgrep-osv-scanner: tool resolution failed: ${String(err)}`,
      };
    }

    input.onProgress?.({ pct: 100, message: "Stub finding emitted" });

    const fingerprint = createHash("sha256").update(`${this.name}:${input.runId}`).digest("hex");

    const finding: NormalizedFinding = {
      fingerprint,
      ruleId: `${this.name}.stub`,
      title: "pull_request.deep: semgrep-osv-scanner scaffolded — real scanner integration pending",
      severity: "info",
      category: "sast",
      description:
        "Wave 2 scaffold: when integrated, this provider will run `semgrep --config auto --sarif` for full-ruleset SAST and `osv-scanner --recursive` against package manifests (package.json, go.mod, Cargo.toml, requirements.txt, Gemfile.lock, etc.) for SCA. Findings will be normalized into NormalizedFinding[] with category `sast` for Semgrep rules and `vuln` for osv-scanner CVEs. See src/provider.ts TODO.",
      rawProviderRef: JSON.stringify({
        stub: true,
        message: `Real semgrep + osv-scanner integration pending; semgrep path resolves to ${
          this.semgrepPath ?? "<unresolved>"
        }, osv-scanner path resolves to ${this.osvScannerPath ?? "<unresolved>"}.`,
        semgrepVersion: SEMGREP_VERSION,
        osvScannerVersion: OSV_SCANNER_VERSION,
      }),
    };

    const summary: SecurityScanSummary = { critical: 0, high: 0, medium: 0, low: 0, info: 1 };

    return {
      runId: input.runId,
      status: "succeeded",
      findings: [finding],
      evidence: [],
      durationMs: Date.now() - startedAt,
      summary,
    };
  }

  async cancel(_runId: string): Promise<void> {
    // Stub provider has no in-flight subprocesses to cancel.
  }

  metadata(): SecurityProviderMetadata {
    return {
      stage: this.stage,
      supportedProfiles: [
        "backend",
        "frontend",
        "cli",
        "sdk",
        "mcp",
        "chrome-extension",
        "vscode-extension",
      ],
      toolVersion: this.toolVersion,
      description: "Semgrep (full ruleset) + osv-scanner for pull_request.deep",
    };
  }
}
