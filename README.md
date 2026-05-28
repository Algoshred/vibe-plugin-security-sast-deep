# @vibecontrols/vibe-plugin-security-sast-deep

`@vibecontrols/vibe-plugin-security-sast-deep` serves the `pull_request.deep` lifecycle stage. It registers itself with [`@vibecontrols/vibe-plugin-security`](https://www.npmjs.com/package/@vibecontrols/vibe-plugin-security) under the per-stage provider type `security.secrets` (which is shared with the other PR + developer.local secrets variants — see `PROVIDER_TYPE_FOR_STAGE` in the meta plugin) and the provider name `semgrep-osv-scanner`. It wraps Semgrep with the full ruleset (`--config auto`) for SAST and osv-scanner against package manifests for SCA.

Wave 2 scaffold — real tool integration is pending; see `src/provider.ts` TODO.

## Install

```bash
vibe plugin install @vibecontrols/vibe-plugin-security-sast-deep
vibe security providers set-default --stage pull_request.deep --provider semgrep-osv-scanner
```

The osv-scanner binary is downloaded automatically on first use (sha256-verified per platform) into `~/.boff/vibecontrols/agents/<profile>/tools/osv-scanner/`. Semgrep is downloaded for Linux only and falls back to PATH on darwin/windows (developers typically `pipx install semgrep`).

## Behavior (planned)

- `semgrep scan --config auto --sarif --output <workdir>/semgrep.sarif --metrics off` over `repoLocalPath` — full ruleset, SARIF normalized to `category: "sast"`.
- `osv-scanner --recursive --format json --output <workdir>/osv.json <repoLocalPath>` over package manifests (`package.json`, `go.mod`, `Cargo.toml`, `requirements.txt`, `Gemfile.lock`, `pom.xml`, etc.) — findings normalized to `category: "vuln"` with `cve` populated.
- SARIF + osv-scanner JSON returned as evidence artifacts.

## Configuration

Per-vibe config (stored in `RepositorySecurityConfig.pluginAssignments["pull_request.deep"].config`):

```yaml
provider: semgrep-osv-scanner
config:
  semgrepConfig: auto # or a comma-separated list of registry IDs / paths
  semgrepTimeoutSec: 600
  osvIgnore: [] # CVE IDs to suppress
  extraSemgrepArgs: []
  extraOsvArgs: []
```

## License

Proprietary — Burdenoff Consultancy Services Pvt. Ltd.
