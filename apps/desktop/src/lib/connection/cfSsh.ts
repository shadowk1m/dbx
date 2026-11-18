import type { CfSshConfig, SshTunnelConfig } from "@/types/database";

export function setCfSshMode(layer: SshTunnelConfig, enabled: boolean): void {
  if (!enabled) {
    delete layer.cf;
    return;
  }
  layer.cf ??= { api_endpoint: "", org: "", space: "", app: "", instance_index: 0 };
  layer.password = "";
  layer.key_path = "";
  layer.key_passphrase = "";
  layer.use_ssh_agent = false;
  layer.proxy_command = "";
  layer.allow_exec_channel_proxy = false;
  layer.expose_lan = false;
  delete layer.local_port;
  layer.connect_timeout_secs = Math.max(layer.connect_timeout_secs || 5, 30);
}

export function cfSshConfigError(config: CfSshConfig): string | null {
  try {
    const url = new URL(config.api_endpoint.trim());
    if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash || url.pathname !== "/") {
      return "CF API endpoint must be an HTTPS origin without credentials, query, or path";
    }
  } catch {
    return "CF API endpoint must be an HTTPS URL";
  }
  for (const [name, value] of [
    ["organization", config.org],
    ["space", config.space],
    ["application", config.app],
  ]) {
    const hasControlCharacters = Array.from(value).some((character) => {
      const code = character.charCodeAt(0);
      return code < 0x20 || (code >= 0x7f && code <= 0x9f);
    });
    if (!value.trim() || value.trim().startsWith("-") || hasControlCharacters) {
      return `CF ${name} is required and must not start with '-' or contain control characters`;
    }
  }
  if (!Number.isInteger(config.instance_index) || config.instance_index < 0 || config.instance_index > 0xffffffff) {
    return "CF instance index must be a non-negative integer";
  }
  return null;
}
