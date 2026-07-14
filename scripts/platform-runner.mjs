import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const [action, ...rawArgs] = process.argv.slice(2);

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    env: process.env,
    stdio: "inherit",
  });

  if (result.error) {
    console.error(`[BPD] Could not start ${command}: ${result.error.message}`);
    process.exit(1);
  }
  process.exit(result.status ?? 1);
}

function translateWindowsArgs(args) {
  const names = new Map([
    ["--include-mcp", "-IncludeMcp"],
    ["--skip-python", "-SkipPython"],
    ["--skip-node", "-SkipNode"],
    ["--skip-setup", "-SkipSetup"],
    ["--clean-ports", "-CleanPorts"],
    ["--check", "-Check"],
    ["--mode", "-Mode"],
    ["--backend-port", "-BackendPort"],
  ]);
  return args.map((arg) => names.get(arg) ?? arg);
}

if (!action) {
  console.error("Usage: node scripts/platform-runner.mjs <setup|start|test-backend|build-desktop|build-mac> [options]");
  process.exit(2);
}

if (action === "test-backend") {
  const python = process.platform === "win32"
    ? path.join(repoRoot, "backend", ".venv", "Scripts", "python.exe")
    : path.join(repoRoot, "backend", ".venv", "bin", "python");
  if (!existsSync(python)) {
    console.error("[BPD] Backend virtual environment is missing. Run `npm run setup` first.");
    process.exit(1);
  }
  run(python, ["-m", "pytest", "backend/tests", "-q", ...rawArgs]);
}

if (process.platform === "win32") {
  const script = action === "setup"
    ? "setup.ps1"
    : action === "start"
      ? "start.ps1"
      : action === "build-desktop"
        ? "dev.ps1"
        : null;
  if (!script) {
    console.error(`[BPD] ${action} is only available on macOS.`);
    process.exit(2);
  }
  run("powershell.exe", [
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", path.join(repoRoot, script),
    ...translateWindowsArgs(rawArgs),
  ]);
}

if (process.platform === "darwin") {
  const script = action === "setup"
    ? path.join(repoRoot, "scripts", "macos", "setup.sh")
    : action === "start"
      ? path.join(repoRoot, "scripts", "macos", "start.sh")
      : action === "build-desktop" || action === "build-mac"
        ? path.join(repoRoot, "scripts", "macos", "build.sh")
        : null;
  if (!script) {
    console.error(`[BPD] Unknown action: ${action}`);
    process.exit(2);
  }
  run("/bin/bash", [script, ...rawArgs]);
}

console.error("[BPD] The desktop launcher currently supports Windows and macOS.");
process.exit(2);
