# Running Best Practices Doctor on macOS

Best Practices Doctor can be downloaded as a prebuilt Apple Silicon application or run from source on Apple Silicon and Intel Macs.

- Intel source builds require macOS Catalina 10.15 or newer.
- Apple Silicon source builds require macOS 11 or newer.
- The GitHub artifact is currently Apple Silicon-only (`arm64`) and tested on GitHub's current macOS runner. Compatibility with older macOS releases is not yet certified. Intel users should use the source-build instructions below.

## Option 1: Download the GitHub build

This option does not require Node.js, Python, Rust, Homebrew, or Xcode.

1. Open the repository's [GitHub Actions page](https://github.com/HassanSalah120/Best-Practices-Doctor/actions).
2. Open the newest successful **CI** run for `main`.
3. Under **Artifacts**, download `best-practices-doctor-macos-arm64`.
4. Unzip the artifact and open the included DMG.
5. Drag **Best Practices Doctor** into **Applications**, then open it.

The CI artifact includes the React interface and packaged Python analysis backend. GitHub verifies the macOS setup, startup contract, backend tests, frontend tests, lint, MCP build, native `.app`, and DMG before publishing the artifact.

### First open and Gatekeeper

The CI build is ad-hoc signed, not signed and notarized with an Apple Developer certificate. macOS may therefore say that it cannot verify the developer.

Only continue when the artifact came from this repository's successful GitHub Actions run. In Finder, Control-click the application, choose **Open**, and confirm **Open**. If macOS still blocks it, go to **System Settings > Privacy & Security** and choose **Open Anyway** for Best Practices Doctor.

Public releases should be Apple-signed and notarized before being presented as normal end-user downloads.

## Option 2: Run from source

### Prerequisites

Install Apple's desktop build tools:

```bash
xcode-select --install
```

Install Node.js 20 or newer and Python 3.11 or newer. Homebrew is one option:

```bash
brew install node python@3.12
```

Install Rust through rustup:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

The official Tauri prerequisites are documented at <https://v2.tauri.app/start/prerequisites/>.

For browser-only mode, Rust and Xcode Command Line Tools are optional; Node.js and Python are still required.

Confirm the commands are available before cloning:

```bash
node --version
python3 --version
cargo --version
xcode-select -p
```

### First run

Clone the repository and run the canonical commands from its root:

```bash
git clone https://github.com/HassanSalah120/Best-Practices-Doctor.git
cd Best-Practices-Doctor
npm run setup
npm run check
npm start
```

`npm start` is the same canonical command used on Windows. On macOS it automatically selects the macOS launcher, starts Vite through Tauri, and starts the backend with `backend/.venv/bin/python`. Closing the desktop app also stops the backend.

The scripts can also be invoked directly:

```bash
bash scripts/macos/setup.sh
bash scripts/macos/start.sh
```

### Useful commands

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

### Building a macOS application

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
tauri/src-tauri/target/<target>/release/bundle/macos/Best Practices Doctor.app
tauri/src-tauri/target/<target>/release/bundle/dmg/*.dmg
```

When `APPLE_SIGNING_IDENTITY` is not set, local builds use ad-hoc signing. Public distribution requires an Apple Developer signing identity and notarization; configure the Apple signing and notarization environment variables before building. See <https://v2.tauri.app/distribute/sign/macos/>.

Build separately on Apple Silicon and Intel when both native architectures are needed. A universal sidecar is not produced automatically.

GitHub currently builds the Apple Silicon target on `macos-latest` and uploads the resulting app and DMG as `best-practices-doctor-macos-arm64`. Intel artifacts are not produced automatically.

### Troubleshooting

#### `xcrun` or linker errors

Run `xcode-select --install`, then confirm:

```bash
xcode-select -p
clang --version
```

#### `cargo` is not found

Open a new Terminal window after installing rustup, or run:

```bash
source "$HOME/.cargo/env"
```

#### `node` is not found after Homebrew installation

Open a new Terminal window and confirm Homebrew is on `PATH`:

```bash
eval "$(/opt/homebrew/bin/brew shellenv)"  # Apple Silicon
node --version
```

On Intel Macs, Homebrew normally uses `/usr/local/bin` instead of `/opt/homebrew/bin`.

#### Python packages fail to compile

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

#### macOS cannot scan a protected directory

Choose a project under your user directory, or grant the Terminal/application access under **System Settings → Privacy & Security**. The analyzer remains local and does not upload the selected source tree.

#### Ports 1420 or 50401 are already in use

Start with cleanup enabled:

```bash
npm run dev:clean
```

#### The downloaded application is blocked

Confirm it came from a successful workflow in this repository, then follow the **First open and Gatekeeper** steps above. The GitHub artifact is deliberately ad-hoc signed; removing macOS security attributes is not required.
