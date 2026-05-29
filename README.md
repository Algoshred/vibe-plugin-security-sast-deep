# @vibecontrols/vibe-plugin-security-sast-deep

<!-- VIBECONTROLS_OSS_HEADER_START -->

> **License**: MIT — see [LICENSE](./LICENSE).
> **Note**: This plugin is open source. The `@vibecontrols/agent` runtime that loads it is **not** open source — it is a proprietary product of Burdenoff Consultancy Services Pvt. Ltd. See [vibecontrols.com](https://vibecontrols.com) for the agent.

<!-- VIBECONTROLS_OSS_HEADER_END -->

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

<!-- VIBECONTROLS_OSS_FOOTER_START -->

---

## License

Released under the [MIT License](./LICENSE).

Copyright (c) 2026 Burdenoff Consultancy Services Private Limited, Algoshred Technologies Private Limited, and all its sister companies.

Maintainer: **Vignesh T.V** — <https://github.com/tvvignesh>

## Credits

This plugin builds on the following upstream open-source projects. All trademarks and copyrights remain with their respective owners.

- **OSV-Scanner** — <https://github.com/google/osv-scanner>
- **Semgrep** — <https://github.com/semgrep/semgrep>

## About VibeControls

**VibeControls** is the agentic engineering mission control for AI-native teams. Vibe-plugins extend the VibeControls agent with new providers, tools, sessions, tunnels, storage backends, and security stages.

- Website: <https://vibecontrols.com>
- Documentation: <https://docs.vibecontrols.com>
- Plugin SDK: <https://github.com/algoshred/vibecontrols-plugin-sdk>
- All plugins: <https://github.com/algoshred?q=vibe-plugin-&type=all>

## Important: agent is not open source

The `@vibecontrols/agent` runtime that loads and orchestrates these plugins is **closed source** and proprietary to Burdenoff Consultancy Services Pvt. Ltd. Only the plugin contract and the plugins themselves are released under MIT. If you want a fully self-hostable agent, please open an issue or contact the maintainer.

<!-- VIBECONTROLS_OSS_FOOTER_END -->
