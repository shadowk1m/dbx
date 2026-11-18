import { describe, expect, it } from "vitest";
import { cfSshConfigError, setCfSshMode } from "../cfSsh";
import { detachTunnelProfileLayer, tunnelProfileReferenceLayer, tunnelProfileSummary } from "../tunnelProfiles";
import type { CfSshConfig, SshTunnelConfig, TunnelProfile } from "@/types/database";

function config(): CfSshConfig {
  return { api_endpoint: "https://api.cf.example.com", org: "team org", space: "dev", app: "ssh-proxy", instance_index: 0 };
}

describe("CF SSH configuration", () => {
  it("switches to CF without retaining unused SSH credentials or LAN exposure", () => {
    const layer: SshTunnelConfig = { id: "layer", host: "bastion", port: 22, user: "root", password: "secret", key_passphrase: "secret", expose_lan: true, use_ssh_agent: true, connect_timeout_secs: 5, local_port: 4059 };
    setCfSshMode(layer, true);
    expect(layer.cf).toEqual({ api_endpoint: "", org: "", space: "", app: "", instance_index: 0 });
    expect(layer.password).toBe("");
    expect(layer.key_passphrase).toBe("");
    expect(layer.expose_lan).toBe(false);
    expect(layer.use_ssh_agent).toBe(false);
    expect(layer.local_port).toBeUndefined();
    expect(layer.connect_timeout_secs).toBe(30);
    layer.cf!.app = "my-app";
    setCfSshMode(layer, true);
    expect(layer.cf!.app).toBe("my-app");
    setCfSshMode(layer, false);
    expect(layer.cf).toBeUndefined();
  });

  it("accepts a valid API and named target", () => {
    expect(cfSshConfigError(config())).toBeNull();
  });

  it.each(["http://api.example.com", "https://user:secret@api.example.com", "https://api.example.com/path", "https://api.example.com?token=secret", "not a URL"])("rejects unsafe API %s", (api_endpoint) => {
    expect(cfSshConfigError({ ...config(), api_endpoint })).not.toBeNull();
  });

  it.each(["", "  ", "--skip-host-validation", " --skip-host-validation", "app\nother"])("rejects invalid app %j", (app) => {
    expect(cfSshConfigError({ ...config(), app })).not.toBeNull();
  });

  it.each([-1, 0.5, NaN, 4294967296])("rejects invalid instance %s", (instance_index) => {
    expect(cfSshConfigError({ ...config(), instance_index })).not.toBeNull();
  });

  it("preserves CF settings through profile references and detachment", () => {
    const profile: TunnelProfile = { type: "ssh", id: "profile", host: "", port: 22, user: "", cf: config() };
    const reference = tunnelProfileReferenceLayer(profile);
    expect(reference.profile_id).toBe("profile");
    expect(reference.type === "ssh" && reference.cf).toBeUndefined();
    const detached = detachTunnelProfileLayer(reference, profile);
    expect(detached.type === "ssh" && detached.cf).toEqual(config());
    expect(tunnelProfileSummary(profile)).toBe("CF: team org/dev/ssh-proxy [0]");
  });
});
