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
 *   osv-scanner   — pinned to v1.9.2 (highest v1.x line). The original
 *                   pin v1.10.0 didn't exist upstream; Google moved
 *                   straight from v1.9.2 to a v2.x line. Repinned
 *                   2026-05-28 to v1.9.2 which ships per-platform raw
 *                   binaries verified by sha256.
 */
import type { ToolManifest } from "@vibecontrols/vibe-plugin-security/tool-installer";

export const SEMGREP_VERSION = "1.95.0";
export const OSV_SCANNER_VERSION = "1.9.2";

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
        sha256: "d6af4b67fa5de658598bd2d445efb99e90d1734b3146962418719c4350ecb74b",
        binaryWithinArchive: "osv-scanner",
        archive: "raw",
      },
      "linux-arm64": {
        url: `https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_arm64`,
        sha256: "9c6160afb26c79449a1f1b667323b989a57dda8fc19f22936c9ff920fd97ddfa",
        binaryWithinArchive: "osv-scanner",
        archive: "raw",
      },
      "darwin-x64": {
        url: `https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_darwin_amd64`,
        sha256: "487ab433b2c2a8c80b737c0bd428a80e6d2e211b4adf775a52a6964163fa3249",
        binaryWithinArchive: "osv-scanner",
        archive: "raw",
      },
      "darwin-arm64": {
        url: `https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_darwin_arm64`,
        sha256: "393f2c7089d9431bd26a3804d6e46d417b1c05abd5d49c41c7dfc174c520acf0",
        binaryWithinArchive: "osv-scanner",
        archive: "raw",
      },
    },
  },
};
