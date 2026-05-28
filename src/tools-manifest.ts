/**
 * Tools manifest for pull_request.deep stage.
 *
 *   semgrep       — v1.95.0; semgrep is distributed exclusively via PyPI
 *                   (pip / pipx). The v1.95.0 GitHub release publishes
 *                   no binary assets for any platform. The downloads
 *                   map is therefore empty and the tool-installer falls
 *                   back to PATH-resolution against `semgrep --version`.
 *                   Developers install via `pipx install semgrep`.
 *                   https://github.com/semgrep/semgrep/releases/tag/v1.95.0
 *
 *   osv-scanner   — v1.10.0 is pinned per the security plugin release
 *                   spec but Google has not yet published a v1.10.0
 *                   release (highest v1.x is v1.9.2; the project moved
 *                   to a v2.x line). Until v1.10.0 ships upstream the
 *                   sha256 entries remain placeholders and the binary
 *                   downloads will be rejected by the tool-installer's
 *                   hash check, forcing the PATH-resolution fallback.
 *
 * TODO: when osv-scanner v1.10.0 is published upstream, populate the
 * real sha256 values from
 *   https://github.com/google/osv-scanner/releases/download/v1.10.0/osv-scanner_SHA256SUMS
 * and bump this plugin's CalVer release.
 */
import type { ToolManifest } from "@vibecontrols/vibe-plugin-security/tool-installer";

export const SEMGREP_VERSION = "1.95.0";
export const OSV_SCANNER_VERSION = "1.10.0";
// Placeholder sha256: osv-scanner v1.10.0 has not yet been released by
// Google. Keep the version pin per the security plugin release spec and
// the tool-installer will reject the placeholder, falling back to PATH.
const OSV_SCANNER_TBD_SHA256 = "0000000000000000000000000000000000000000000000000000000000000000";

export const TOOLS_MANIFEST: ToolManifest = {
  semgrep: {
    version: SEMGREP_VERSION,
    binaryName: "semgrep",
    versionMatcher: SEMGREP_VERSION.replace(/\./g, "\\."),
    // no upstream binary for any platform — semgrep ships via PyPI only
    // (`pipx install semgrep`). tool-installer falls back to PATH probe.
    downloads: {},
  },
  "osv-scanner": {
    version: OSV_SCANNER_VERSION,
    binaryName: "osv-scanner",
    versionMatcher: OSV_SCANNER_VERSION.replace(/\./g, "\\."),
    downloads: {
      "linux-x64": {
        url: `https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64`,
        sha256: OSV_SCANNER_TBD_SHA256,
        binaryWithinArchive: "osv-scanner",
        archive: "raw",
      },
      "linux-arm64": {
        url: `https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_arm64`,
        sha256: OSV_SCANNER_TBD_SHA256,
        binaryWithinArchive: "osv-scanner",
        archive: "raw",
      },
      "darwin-x64": {
        url: `https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_darwin_amd64`,
        sha256: OSV_SCANNER_TBD_SHA256,
        binaryWithinArchive: "osv-scanner",
        archive: "raw",
      },
      "darwin-arm64": {
        url: `https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_darwin_arm64`,
        sha256: OSV_SCANNER_TBD_SHA256,
        binaryWithinArchive: "osv-scanner",
        archive: "raw",
      },
    },
  },
};
