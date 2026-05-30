/**
 * SemgrepOsvScannerProvider — implements SecurityProvider for stage
 * `pull_request.deep`. Runs Semgrep with a sensible default ruleset
 * (`--config p/default`) for SAST plus osv-scanner against package
 * manifests for SCA. Both tools run sequentially and have a per-tool
 * wall-clock cap.
 *
 * Tool resolution:
 *   - osv-scanner is resolved via the shared tool-installer with a
 *     pinned binary + sha256.
 *   - Semgrep has no upstream prebuilt binary; the installer's PATH
 *     probe finds it if available. If neither PATH nor a previous
 *     install is present, ensureToolInstalled() auto-installs via
 *     `pipx install semgrep==<ver>` (preferred) or
 *     `python3 -m pip install --user semgrep==<ver>` (fallback).
 */
import { spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import type { HostServices } from "@vibecontrols/plugin-sdk/contract";
import { normalizeSarif } from "@vibecontrols/vibe-plugin-security/normalizer";
import { resolveToolPath } from "@vibecontrols/vibe-plugin-security/tool-installer";
import type {
  NormalizedFinding,
  ScanEvidenceArtifact,
  SecurityProvider,
  SecurityProviderMetadata,
  SecurityScanInput,
  SecurityScanResult,
  SecurityScanSummary,
  SecurityStage,
} from "@vibecontrols/vibe-plugin-security/types";

import { OSV_SCANNER_VERSION, SEMGREP_VERSION, TOOLS_MANIFEST } from "./tools-manifest.js";

interface SastDeepConfig {
  semgrepConfig?: string;
  extraSemgrepArgs?: string[];
  extraOsvScannerArgs?: string[];
  toolTimeoutMs?: number;
}

const DEFAULT_TOOL_TIMEOUT_MS = 10 * 60 * 1000;
const LOG_NAMESPACE = "semgrep-osv-scanner-provider";

export class SemgrepOsvScannerProvider implements SecurityProvider {
  readonly name = "semgrep-osv-scanner";
  readonly stage: SecurityStage = "pull_request.deep";
  readonly toolVersion = `semgrep@${SEMGREP_VERSION}+osv-scanner@${OSV_SCANNER_VERSION}`;

  private host?: HostServices;
  private semgrepPath?: string;
  private osvScannerPath?: string;
  private active = new Map<string, ChildProcess>();

  async init(host: HostServices): Promise<void> {
    this.host = host;
  }

  async ensureToolInstalled(): Promise<void> {
    const dataDir = this.host?.getDataDir?.() ?? path.join(os.homedir(), ".boff/vibecontrols");
    const ctx = {
      dataDir,
      log: {
        info: (m: string) => this.host?.logger?.info?.(LOG_NAMESPACE, m),
        warn: (m: string) => this.host?.logger?.warn?.(LOG_NAMESPACE, m),
        error: (m: string) => this.host?.logger?.error?.(LOG_NAMESPACE, m),
      },
    };

    // osv-scanner: shipped as a pinned binary + sha256. Pure download path.
    this.osvScannerPath = await resolveToolPath(ctx, "osv-scanner", TOOLS_MANIFEST["osv-scanner"]);

    // semgrep: PATH first; if not present, attempt pipx then pip --user.
    this.semgrepPath = await this.resolveSemgrep(ctx.log);
  }

  async run(input: SecurityScanInput): Promise<SecurityScanResult> {
    const startedAt = Date.now();
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

    const cfg = (input.config as SastDeepConfig) ?? {};
    const timeoutMs =
      typeof cfg.toolTimeoutMs === "number" && cfg.toolTimeoutMs > 0
        ? cfg.toolTimeoutMs
        : DEFAULT_TOOL_TIMEOUT_MS;
    const findings: NormalizedFinding[] = [];
    const evidence: ScanEvidenceArtifact[] = [];
    let lastError: string | undefined;

    input.onProgress?.({ pct: 5, message: "Starting Semgrep scan" });

    // ---- Semgrep ----
    try {
      const semgrepSarif = path.join(input.workdir, "semgrep.sarif");
      const semgrepArgs = [
        "--config",
        cfg.semgrepConfig ?? "p/default",
        "--sarif",
        "--output",
        semgrepSarif,
        "--quiet",
        "--no-rewrite-rule-ids",
        "--disable-version-check",
        "--metrics",
        "off",
      ];
      if (cfg.extraSemgrepArgs) semgrepArgs.push(...cfg.extraSemgrepArgs);
      semgrepArgs.push(input.repoLocalPath);

      input.onProgress?.({ pct: 10, message: "Running Semgrep (SAST)" });

      const semgrepRes = await this.spawnAndWait(input.runId, this.semgrepPath!, semgrepArgs, {
        timeoutMs,
      });

      if (semgrepRes.code !== 0 && semgrepRes.code !== 1) {
        lastError = `semgrep exited ${semgrepRes.code}: ${semgrepRes.stderr.slice(0, 500)}`;
        this.host?.logger?.warn?.(LOG_NAMESPACE, lastError);
      } else {
        input.onProgress?.({ pct: 30, message: "Parsing Semgrep SARIF" });
        await this.ingestSarif(
          semgrepSarif,
          "semgrep",
          "sast",
          findings,
          evidence,
          "no semgrep SARIF produced",
        );
      }
    } catch (err) {
      lastError = `semgrep step failed: ${String(err)}`;
      this.host?.logger?.error?.(LOG_NAMESPACE, lastError);
    }

    input.onProgress?.({ pct: 55, message: "Running osv-scanner (SCA)" });

    // ---- osv-scanner ----
    try {
      const osvSarif = path.join(input.workdir, "osv.sarif");
      const osvArgs = ["--format", "sarif", "--output", osvSarif];
      if (cfg.extraOsvScannerArgs) osvArgs.push(...cfg.extraOsvScannerArgs);
      osvArgs.push(input.repoLocalPath);

      const osvRes = await this.spawnAndWait(input.runId, this.osvScannerPath!, osvArgs, {
        timeoutMs,
      });

      // osv-scanner exit codes: 0 = no findings, 1 = findings present.
      // 128 = no manifests found (treated as success-with-zero-findings).
      if (osvRes.code !== 0 && osvRes.code !== 1 && osvRes.code !== 128) {
        const msg = `osv-scanner exited ${osvRes.code}: ${osvRes.stderr.slice(0, 500)}`;
        this.host?.logger?.warn?.(LOG_NAMESPACE, msg);
        if (!lastError) lastError = msg;
      } else {
        input.onProgress?.({ pct: 80, message: "Parsing osv-scanner SARIF" });
        await this.ingestSarif(
          osvSarif,
          "osv-scanner",
          "vuln",
          findings,
          evidence,
          "no osv-scanner SARIF produced",
        );
      }
    } catch (err) {
      const msg = `osv-scanner step failed: ${String(err)}`;
      this.host?.logger?.error?.(LOG_NAMESPACE, msg);
      if (!lastError) lastError = msg;
    }

    input.onProgress?.({ pct: 100, message: "Scan complete" });

    const summary = summarize(findings);
    const status =
      findings.length === 0 && lastError ? ("errored" as const) : ("succeeded" as const);

    return {
      runId: input.runId,
      status,
      findings,
      evidence,
      durationMs: Date.now() - startedAt,
      summary,
      errorReason: status === "errored" ? lastError : undefined,
    };
  }

  async cancel(runId: string): Promise<void> {
    const child = this.active.get(runId);
    if (!child) return;
    try {
      child.kill("SIGTERM");
      setTimeout(() => {
        try {
          child.kill("SIGKILL");
        } catch {
          /* already gone */
        }
      }, 5000);
    } finally {
      this.active.delete(runId);
    }
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
      description: "Semgrep (p/default ruleset) + osv-scanner for pull_request.deep",
    };
  }

  private async ingestSarif(
    sarifPath: string,
    providerLabel: string,
    category: "sast" | "vuln",
    findings: NormalizedFinding[],
    evidence: ScanEvidenceArtifact[],
    missingMessage: string,
  ): Promise<void> {
    try {
      const raw = await fs.readFile(sarifPath, "utf-8");
      const parsed = normalizeSarif(raw, providerLabel, category);
      for (const f of parsed) findings.push(f);
      const sha256 = createHash("sha256").update(raw).digest("hex");
      const stat = await fs.stat(sarifPath);
      evidence.push({
        type: "sarif",
        localPath: sarifPath,
        sha256,
        sizeBytes: stat.size,
      });
    } catch (err) {
      this.host?.logger?.warn?.(LOG_NAMESPACE, `${missingMessage}: ${String(err)}`);
    }
  }

  private spawnAndWait(
    runId: string,
    bin: string,
    args: string[],
    opts: { timeoutMs: number },
  ): Promise<{ code: number | null; stdout: string; stderr: string }> {
    return new Promise((resolve) => {
      const child = spawn(bin, args, { stdio: ["ignore", "pipe", "pipe"] });
      this.active.set(runId, child);
      let stdout = "";
      let stderr = "";
      const timer = setTimeout(() => {
        try {
          child.kill("SIGTERM");
        } catch {
          /* already gone */
        }
        setTimeout(() => {
          try {
            child.kill("SIGKILL");
          } catch {
            /* already gone */
          }
        }, 5000);
      }, opts.timeoutMs);
      child.stdout?.on("data", (b: Buffer) => (stdout += b.toString()));
      child.stderr?.on("data", (b: Buffer) => (stderr += b.toString()));
      child.on("close", (code) => {
        clearTimeout(timer);
        this.active.delete(runId);
        resolve({ code, stdout, stderr });
      });
      child.on("error", (err) => {
        clearTimeout(timer);
        this.active.delete(runId);
        resolve({ code: -1, stdout, stderr: err.message });
      });
    });
  }

  private async resolveSemgrep(log: {
    info?: (m: string) => void;
    warn?: (m: string) => void;
    error?: (m: string) => void;
  }): Promise<string> {
    // 1. PATH probe.
    const onPath = await this.whichBinary("semgrep");
    if (onPath) {
      const ver = await this.binaryVersionOutput(onPath);
      if (ver.includes(SEMGREP_VERSION)) {
        log.info?.(`semgrep found on PATH at ${onPath} (matches ${SEMGREP_VERSION})`);
        return onPath;
      }
      // Different version on PATH — still use it (the host probably knows).
      log.info?.(
        `semgrep found on PATH at ${onPath} (version output: ${ver.slice(0, 200)}); using it as-is`,
      );
      return onPath;
    }

    // 2. Auto-install: pipx preferred, then pip --user.
    const userBinDir = path.join(os.homedir(), ".local", "bin");

    if (await this.whichBinary("pipx")) {
      log.info?.(`semgrep not on PATH; running 'pipx install semgrep==${SEMGREP_VERSION}'`);
      try {
        await this.runOneShot("pipx", ["install", "--force", `semgrep==${SEMGREP_VERSION}`], {
          timeoutMs: 5 * 60 * 1000,
        });
        const semgrep = path.join(userBinDir, "semgrep");
        try {
          await fs.access(semgrep);
          return semgrep;
        } catch {
          // pipx may put binaries elsewhere; fall back to PATH probe.
          const afterPath = await this.whichBinary("semgrep");
          if (afterPath) return afterPath;
        }
      } catch (err) {
        log.warn?.(`pipx install semgrep failed: ${String(err)}`);
      }
    }

    if (await this.whichBinary("python3")) {
      log.info?.(
        `semgrep not on PATH; running 'python3 -m pip install --user semgrep==${SEMGREP_VERSION}'`,
      );
      try {
        await this.runOneShot(
          "python3",
          ["-m", "pip", "install", "--user", `semgrep==${SEMGREP_VERSION}`],
          { timeoutMs: 5 * 60 * 1000 },
        );
        const semgrep = path.join(userBinDir, "semgrep");
        try {
          await fs.access(semgrep);
          return semgrep;
        } catch {
          const afterPath = await this.whichBinary("semgrep");
          if (afterPath) return afterPath;
        }
      } catch (err) {
        log.warn?.(`pip install semgrep failed: ${String(err)}`);
      }
    }

    throw new Error(
      "semgrep not installed and no pipx/pip available. Install via 'pipx install semgrep' or 'pip install semgrep==" +
        SEMGREP_VERSION +
        "'.",
    );
  }

  private whichBinary(bin: string): Promise<string | null> {
    // Bun.which is cross-platform (honours PATHEXT / where semantics on
    // Windows) and returns an absolute path or null without spawning a
    // POSIX-only `which` process. Pass the live PATH explicitly — Bun.which
    // otherwise snapshots PATH at process start and would miss binaries
    // installed mid-run (e.g. a pipx/pip --user semgrep added to ~/.local/bin),
    // which the previous `spawn('which', ...)` resolved via the inherited env.
    return Promise.resolve(Bun.which(bin, { PATH: process.env.PATH }));
  }

  private binaryVersionOutput(bin: string): Promise<string> {
    return new Promise((resolve) => {
      const child = spawn(bin, ["--version"], { stdio: ["ignore", "pipe", "pipe"] });
      let out = "";
      child.stdout?.on("data", (b: Buffer) => (out += b.toString()));
      child.stderr?.on("data", (b: Buffer) => (out += b.toString()));
      child.on("close", () => resolve(out));
      child.on("error", () => resolve(""));
    });
  }

  private runOneShot(
    bin: string,
    args: string[],
    opts: { timeoutMs: number },
  ): Promise<{ code: number | null; stdout: string; stderr: string }> {
    return new Promise((resolve, reject) => {
      const child = spawn(bin, args, { stdio: ["ignore", "pipe", "pipe"] });
      let stdout = "";
      let stderr = "";
      const timer = setTimeout(() => {
        try {
          child.kill("SIGTERM");
        } catch {
          /* already gone */
        }
      }, opts.timeoutMs);
      child.stdout?.on("data", (b: Buffer) => (stdout += b.toString()));
      child.stderr?.on("data", (b: Buffer) => (stderr += b.toString()));
      child.on("close", (code) => {
        clearTimeout(timer);
        if (code === 0) resolve({ code, stdout, stderr });
        else reject(new Error(`${bin} exited ${code}: ${stderr.slice(0, 500)}`));
      });
      child.on("error", (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });
  }
}

function summarize(findings: NormalizedFinding[]): SecurityScanSummary {
  const s: SecurityScanSummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) s[f.severity]++;
  return s;
}
