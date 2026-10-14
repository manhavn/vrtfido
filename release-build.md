- Build all release packages with one command

```shell
./release-build-all.sh
```

- Or build each type on its own

```shell
./build-extension.sh
./build-chrome.sh
./build-firefox.sh
./build-safari.sh

./build-android.sh

./build-cross.sh
```

Every build script stages its publish-ready files (`.zip`, `.tar.gz`, `.sha256`, `.apk`) in the `releases/` directory, replacing that build type's previous output, so one directory holds the whole release set. `build-extension.sh` already chains Chrome, Firefox and Safari; `release-build-all.sh` runs each build type once, keeps going when one of them fails, and reports the failures at the end.

- Linux packages (local)

`build-cross.sh` builds every Linux package with cargo-zigbuild, so all four targets are cross-built in one run and nothing but `zig` plus `cargo-zigbuild` has to be present (the script installs both itself through mise): no container engine, no foreign toolchain, no development package for a second architecture. The `gnu` archives are `cargo zigbuild --release --features gui --target <triple>.<glibc floor>` and carry the daemon with the `vrtfido-gui` prompt window; the `musl` archives drop the `gui` feature, stay static and hold the daemon alone, since they exist for servers and containers that need one self-contained file. The glibc floor for the `gnu` packages is pinned instead of inheriting the build machine's own libc — linking against that would silently raise the minimum every user needs — and defaults to `2.17`, changeable with `GLIBC_FLOOR=2.28 ./build-cross.sh`.

The window is an egui/eframe process that draws through winit + OpenGL/EGL and ships its own fonts and widgets, so the build host needs no toolkit development package and the machine that runs it needs no toolkit runtime.

- macOS and Windows packages (built on the target OS)

Neither platform can be cross-built from Linux: the Apple SDK may not be used off Apple hardware, and the MSVC targets need a Windows C toolchain for the C code that the bundled SQLite and the vendored libusb compile. Each of the four packages is therefore built once on the machine it targets, and the asset name is fixed, because `mise` picks an archive by the OS and CPU it reads in that name:

| architecture | target | asset |
|---|---|---|
| macOS Intel | `x86_64-apple-darwin` | `vrtfido-x86_64-apple-darwin.tar.gz` |
| macOS Apple silicon | `aarch64-apple-darwin` | `vrtfido-aarch64-apple-darwin.tar.gz` |
| Windows x64 | `x86_64-pc-windows-msvc` | `vrtfido-x86_64-pc-windows-msvc.zip` |
| Windows arm64 | `aarch64-pc-windows-msvc` | `vrtfido-aarch64-pc-windows-msvc.zip` |

On macOS (the example is Apple silicon; an Intel Mac uses the other triple, and either Mac can build both, since Xcode ships the SDK for both — `rustup target add x86_64-apple-darwin` first when the host is the other architecture):

```shell
cargo build --release --features gui --target aarch64-apple-darwin
stage="$(mktemp -d)"
cp target/aarch64-apple-darwin/release/vrtfido target/aarch64-apple-darwin/release/vrtfido-gui "$stage/"
tar -C "$stage" -czf releases/vrtfido-aarch64-apple-darwin.tar.gz .
rm -rf "$stage"
shasum -a 256 releases/vrtfido-aarch64-apple-darwin.tar.gz \
  > releases/vrtfido-aarch64-apple-darwin.tar.gz.sha256
```

On Windows (PowerShell; `arm64` needs the arm64 MSVC toolchain, the x64 one cannot produce it):

```powershell
cargo build --release --features gui --target x86_64-pc-windows-msvc
Compress-Archive -Force -DestinationPath dist\vrtfido-x86_64-pc-windows-msvc.zip `
  -Path target\x86_64-pc-windows-msvc\release\vrtfido.exe, target\x86_64-pc-windows-msvc\release\vrtfido-gui.exe
$hash = (Get-FileHash -Algorithm SHA256 dist\vrtfido-x86_64-pc-windows-msvc.zip).Hash.ToLower()
"$hash  vrtfido-x86_64-pc-windows-msvc.zip" | Set-Content dist\vrtfido-x86_64-pc-windows-msvc.zip.sha256
```

Both binaries sit at the root of each archive (`vrtfido.exe` and `vrtfido-gui.exe` inside the ZIP), exactly like the Linux ones, and each archive is published together with its `<archive>.sha256`.

- Publish

One tag per version (`v0.3.6`) with every file from `releases/` attached to it. The former `-gui` variants are gone: since the `gnu` package already contains the window as well as the daemon, there is nothing left to split by tag.

The release is put together by hand: create the tag, attach `releases/*.tar.gz`, `releases/*.zip`, `releases/*.apk` and their `.sha256` files from the release page or with `gh release upload <tag> releases/… --clobber`, and build the macOS and Windows archives on their own machines first (above). Nothing is attached automatically, so a half-finished release is just a release with fewer files.
