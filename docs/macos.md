# Running Best Practices Doctor on macOS

Best Practices Doctor supports source-based desktop development on macOS Catalina 10.15 or newer. Both Apple Silicon and Intel Macs are supported through the native Rust target installed on the machine.

## Prerequisites

Install Apple's desktop build tools:

```bash
xcode-select --install
```

Install Node.js 20 or newer and Python 3.11 or newer. Homebrew is one option:

```bash
brew install node@20 python@3.12
```

Install Rust through rustup:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

The official Tauri prerequisites are documented at <https://v2.tauri.app/start/prerequisites/>.

For browser-only mode, Rust and Xcode Command Line Tools are optional; Node.js and Python are still required.

## First run

From the repository root:

```bash
npm run setup
npm start
```

`npm start` is the same canonical command used on Windows. On macOS it automatically selects the macOS launcher, starts Vite through Tauri, and starts the backend with `backend/.venv/bin/python`. Closing the desktop app also stops the backend.

The scripts can also be invoked directly:

```bash
bash scripts/macos/setup.sh
bash scripts/macos/start.sh
```

## Useful commands

```bash
npm run check        # verify macOS, Node, Python, Rust, and Xcode prerequisites
npm run dev:clean    # stop processes on the app ports before starting
npm run web          # browser-only mode; Rust is not required after setup
npm run test         # backend and frontend tests
npm run build:mac    # native .app and .dmg for the current Mac architecture
```

Browser mode cannot open the native folder picker. Paste an absolute project path such as `/Users/you/Projects/my-app` into the application.

For optional MCP development, install its dependencies once and use two Terminal tabs:

```bash
npm run setup:mcp
# Terminal 1
npm start
# Terminal 2
npm run mcp
```

The combined `npm run dev:full` service monitor remains Windows-only; it is not required to run or build the application on macOS.

## Building a macOS application

Run the build on a Mac:

```bash
npm run build:mac
```

The build script:

1. verifies and installs project dependencies;
2. packages the Python backend as a native PyInstaller sidecar;
3. names the sidecar for the current Rust host target (`aarch64-apple-darwin` or `x86_64-apple-darwin`);
4. builds native `.app` and `.dmg` bundles with Tauri.

Artifacts are written below:

```text
tauri/src-tauri/target/<target>/release/bundle/
```

When `APPLE_SIGNING_IDENTITY` is not set, local builds use ad-hoc signing. Public distribution requires an Apple Developer signing identity and notarization; configure the Apple signing and notarization environment variables before building. See <https://v2.tauri.app/distribute/sign/macos/>.

Build separately on Apple Silicon and Intel when both native architectures are needed. A universal sidecar is not produced automatically.

## Troubleshooting

### `xcrun` or linker errors

Run `xcode-select --install`, then confirm:

```bash
xcode-select -p
clang --version
```

### `cargo` is not found

Open a new Terminal window after installing rustup, or run:

```bash
source "$HOME/.cargo/env"
```

### Python packages fail to compile

Confirm Python is at least 3.11 and Xcode Command Line Tools are installed:

```bash
python3 --version
xcode-select -p
```

Then rebuild the virtual environment:

```bash
rm -rf backend/.venv
npm run setup
```

### macOS cannot scan a protected directory

Choose a project under your user directory, or grant the Terminal/application access under **System Settings → Privacy & Security**. The analyzer remains local and does not upload the selected source tree.
