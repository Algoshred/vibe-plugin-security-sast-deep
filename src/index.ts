/**
 * @vibecontrols/vibe-plugin-security-sast-deep
 *
 * Semgrep (full ruleset) + osv-scanner provider for pull_request.deep.
 * Registers as a `security.secrets` provider (shares the secrets type
 * with the secrets-pr + developer.local variants — see
 * PROVIDER_TYPE_FOR_STAGE in @vibecontrols/vibe-plugin-security/types)
 * on the host's ServiceRegistry. The user picks "semgrep-osv-scanner"
 * as their default provider for the `pull_request.deep` stage and the
 * meta plugin dispatches.
 */
import { ProviderRegistry, TelemetryEmitter, createLifecycleHooks } from "@vibecontrols/plugin-sdk";
import type {
  HostServices,
  ProfileContext,
  VibePlugin,
  VibePluginFactory,
} from "@vibecontrols/plugin-sdk/contract";

import { SemgrepOsvScannerProvider } from "./provider.js";

const PLUGIN_NAME = "security-sast-deep";
const PLUGIN_VERSION = "2026.528.4";

export const createPlugin: VibePluginFactory = (_ctx: ProfileContext): VibePlugin => {
  const provider = new SemgrepOsvScannerProvider();
  const telemetry = new TelemetryEmitter(PLUGIN_NAME, PLUGIN_VERSION);

  const lifecycle = createLifecycleHooks({
    name: PLUGIN_NAME,
    telemetryEventName: "security.sast-deep.ready",
    onInit: async (host: HostServices) => {
      await provider.init(host);
      const registry = new ProviderRegistry(host);
      registry.registerProvider("security.secrets", "semgrep-osv-scanner", provider);
      telemetry.emit("security.sast-deep.registered", {
        provider: "semgrep-osv-scanner",
        toolVersion: provider.toolVersion,
      });
    },
  });

  return {
    name: PLUGIN_NAME,
    version: PLUGIN_VERSION,
    description: "Full SAST + SCA sweep for the pull_request.deep lifecycle stage.",
    tags: ["backend", "provider", "integration"],
    capabilities: {
      storage: "rw",
      subprocess: true,
      audit: true,
      telemetry: true,
    },
    onServerStart: lifecycle.onServerStart,
    onServerStop: lifecycle.onServerStop,
  };
};

export default createPlugin;
export { SemgrepOsvScannerProvider } from "./provider.js";
