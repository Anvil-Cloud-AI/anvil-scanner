/**
 * Anvil Scanner Bridge Plugin for OpenClaw
 *
 * Thin bridge that exposes Anvil Scanner CLI capabilities as agent tools.
 * The heavy work is done by the standalone `anvil-scanner` binary.
 */

import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export default definePluginEntry({
  id: "anvil-scanner",
  name: "Anvil Scanner",
  description: "Security scanning, OpenClaw container auditing, and automated hardening. Bridge to the external anvil-scanner CLI.",
  register(api) {
    const config = api.config || {};
    const binary = config.binaryPath || "anvil-scanner";
    const useSudo = config.defaultSudo !== false;
    const timeout = (config.timeoutSeconds || 120) * 1000;

    function buildArgs(args = []) {
      const base = useSudo ? ["sudo", binary] : [binary];
      return [...base, ...args];
    }

    async function runAnvil(args) {
      const cmd = buildArgs(args);
      try {
        const { stdout, stderr } = await execFileAsync(cmd[0], cmd.slice(1), {
          timeout,
          maxBuffer: 10 * 1024 * 1024,
        });
        return { success: true, stdout, stderr };
      } catch (err) {
        return {
          success: false,
          stdout: err.stdout || "",
          stderr: err.stderr || err.message,
          code: err.code,
        };
      }
    }

    // Tool registrations
    api.registerTool({
      name: "run_security_scan",
      description: "Run a full security scan using Anvil Scanner (host + OpenClaw audit + threat intel + optional AI).",
      parameters: {
        type: "object",
        properties: {
          includeThreatIntel: { type: "boolean", default: true },
          includeAI: { type: "boolean", default: false },
          skipOpenClaw: { type: "boolean", default: false },
          outputFormat: { type: "string", enum: ["summary", "json"], default: "summary" },
        },
      },
      async execute(params) {
        const args = [];
        if (!params.includeThreatIntel) args.push("--no-threat-intel");
        if (!params.includeAI) args.push("--no-ai");
        if (params.skipOpenClaw) args.push("--no-openclaw");
        if (params.outputFormat === "json") args.push("--json");

        const result = await runAnvil(args);
        if (!result.success) {
          return { content: [{ type: "text", text: `Scan failed: ${result.stderr}` }] };
        }
        return { content: [{ type: "text", text: result.stdout || "Scan completed." }] };
      },
    });

    api.registerTool({
      name: "audit_openclaw_containers",
      description: "Audit running OpenClaw containers for security issues (privileged, ports, mounts, etc.).",
      parameters: { type: "object", properties: {} },
      async execute() {
        const result = await runAnvil(["--json"]); // leverages container focus in full scan for now
        if (!result.success) {
          return { content: [{ type: "text", text: `Container audit failed: ${result.stderr}` }] };
        }
        return { content: [{ type: "text", text: result.stdout }] };
      },
    });

    api.registerTool({
      name: "apply_hardening",
      description: "Apply security hardening (SSH, firewall, fail2ban). Use dryRun for safety preview.",
      parameters: {
        type: "object",
        properties: {
          dryRun: { type: "boolean", default: false },
        },
      },
      async execute(params) {
        const args = ["--harden"];
        if (params.dryRun) args.push("--dry-run"); // note: CLI may need update to support this flag
        const result = await runAnvil(args);
        if (!result.success) {
          return { content: [{ type: "text", text: `Hardening failed: ${result.stderr}` }] };
        }
        return { content: [{ type: "text", text: result.stdout || "Hardening complete." }] };
      },
    });

    api.registerTool({
      name: "revert_anvil_changes",
      description: "Revert all changes made by previous Anvil Scanner runs (--uninstall).",
      parameters: {
        type: "object",
        properties: {
          force: { type: "boolean", default: false },
        },
      },
      async execute(params) {
        const args = ["--uninstall"];
        if (params.force) args.push("--force");
        const result = await runAnvil(args);
        if (!result.success) {
          return { content: [{ type: "text", text: `Revert failed: ${result.stderr}` }] };
        }
        return { content: [{ type: "text", text: result.stdout || "Changes reverted." }] };
      },
    });

    api.registerTool({
      name: "get_latest_report",
      description: "Get the most recent Anvil Scanner report summary.",
      parameters: { type: "object", properties: {} },
      async execute() {
        // Placeholder - in real impl, read from ~/.anvil-scanner-reports or last run
        const result = await runAnvil(["--json"]);
        if (!result.success) {
          return { content: [{ type: "text", text: `Failed to get report: ${result.stderr}` }] };
        }
        return { content: [{ type: "text", text: result.stdout }] };
      },
    });

    console.log("[anvil-scanner-bridge] Tools registered.");
  },
});