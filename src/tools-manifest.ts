/**
 * Tools manifest for pull_request.deep stage.
 *
 *   semgrep       — v1.95.0; precompiled MUSL Linux only. Darwin/Windows
 *                   fall through to the PATH-resolution branch of the
 *                   tool-installer (developers typically `pipx install semgrep`).
 *   osv-scanner   — v1.10.0; Google ships prebuilt binaries for linux +
 *                   darwin on amd64 / arm64.
 *
 * TODO: backfill real sha256 values before promoting this plugin out of
 * scaffold status. References:
 *   https://github.com/semgrep/semgrep/releases/tag/v1.95.0
 *   https://github.com/google/osv-scanner/releases/tag/v1.10.0
 */
import type { ToolManifest } from "@vibecontrols/vibe-plugin-security/tool-installer";

export const SEMGREP_VERSION = "1.95.0";
export const OSV_SCANNER_VERSION = "1.10.0";

export const TOOLS_MANIFEST: ToolManifest = {
  semgrep: {
    version: SEMGREP_VERSION,
    binaryName: "semgrep",
    versionMatcher: SEMGREP_VERSION.replace(/\./g, "\\."),
    downloads: {
      // TODO: backfill real sha256 — placeholder for scaffold parity.
      "linux-x64": {
        url: `https://github.com/semgrep/semgrep/releases/download/v${SEMGREP_VERSION}/semgrep-${SEMGREP_VERSION}-musllinux_x86_64.tar.gz`,
        sha256: "0000000000000000000000000000000000000000000000000000000000000000",
        binaryWithinArchive: "semgrep",
        archive: "tar.gz",
      },
    },
  },
  "osv-scanner": {
    version: OSV_SCANNER_VERSION,
    binaryName: "osv-scanner",
    versionMatcher: OSV_SCANNER_VERSION.replace(/\./g, "\\."),
    downloads: {
      // TODO: backfill real sha256 values from the upstream release.
      "linux-x64": {
        url: `https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64`,
        sha256: "0000000000000000000000000000000000000000000000000000000000000000",
        binaryWithinArchive: "osv-scanner",
        archive: "raw",
      },
      "linux-arm64": {
        url: `https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_arm64`,
        sha256: "0000000000000000000000000000000000000000000000000000000000000000",
        binaryWithinArchive: "osv-scanner",
        archive: "raw",
      },
      "darwin-x64": {
        url: `https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_darwin_amd64`,
        sha256: "0000000000000000000000000000000000000000000000000000000000000000",
        binaryWithinArchive: "osv-scanner",
        archive: "raw",
      },
      "darwin-arm64": {
        url: `https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_darwin_arm64`,
        sha256: "0000000000000000000000000000000000000000000000000000000000000000",
        binaryWithinArchive: "osv-scanner",
        archive: "raw",
      },
    },
  },
};
