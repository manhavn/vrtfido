- Build all release packages with one command

```shell
./release-build-all.sh
```

- Or build each type on its own

```shell
./check-platforms.sh

./build-extension.sh
./build-chrome.sh
./build-firefox.sh
./build-safari.sh

./build-android.sh

./build-cross.sh     # Linux and Windows packages, on any host

./build-mac.sh       # macOS packages, on a Mac only
```

Every build script stages its publish-ready files (`.zip`, `.tar.gz`, `.sha256`, `.apk`) in the `releases/` directory, replacing that build type's previous output, so one directory holds the whole release set. `build-extension.sh` already chains Chrome, Firefox and Safari; `release-build-all.sh` runs each build type once, keeps going when one of them fails, and reports the failures at the end.

- Platform gating (no SDK needed)

`check-platforms.sh` type-checks the platform-gated backends (today `src/autostart`, one backend per operating system) for every platform family, on any machine: `rustc --emit=metadata` needs no SDK, no linker and no C toolchain, and that module depends on nothing but the standard library. It exists because a `#[cfg]` naming the wrong platforms compiles everywhere except on the platform it left out — the Android build once stopped with `unresolved import super::quote_arg` because the helper was gated to `linux` and `windows`, and neither a Mac building the Android package nor the reverse is something a machine can notice by itself. `release-build-all.sh` runs it first, before the builds that take minutes; the Windows families are not in its list because `src/autostart/windows.rs` uses the `winreg` crate, which a bare `rustc` call cannot resolve, so `build-cross.sh` compiles those for real.

- Linux packages (local)

`build-cross.sh` builds every Linux package with cargo-zigbuild, so all four targets are cross-built in one run and nothing but `zig` plus `cargo-zigbuild` has to be present (the script installs both itself through mise): no container engine, no foreign toolchain, no development package for a second architecture. The `gnu` archives are `cargo zigbuild --release --features gui --target <triple>.<glibc floor>` and carry the daemon with the `vrtfido-gui` prompt window; the `musl` archives drop the `gui` feature, stay static and hold the daemon alone, since they exist for servers and containers that need one self-contained file. The glibc floor for the `gnu` packages is pinned instead of inheriting the build machine's own libc — linking against that would silently raise the minimum every user needs — and defaults to `2.17`, changeable with `GLIBC_FLOOR=2.28 ./build-cross.sh`.

The window is an egui/eframe process that draws through winit + OpenGL/EGL and ships its own fonts and widgets, so the build host needs no toolkit development package and the machine that runs it needs no toolkit runtime.

- Windows packages (built on any host)

`build-cross.sh` also builds the two Windows archives, from this machine, with `cargo-xwin` for the MSVC ABI — the flavour `mise` expects to read in a Windows asset name. That needs `clang-cl`, `lld-link`, `llvm-lib` and `nasm`; mise does not carry them, so the script installs what is missing through the system package manager (`sudo apt install -y clang lld llvm nasm` on Debian/Ubuntu, `brew install llvm nasm` on macOS) — the only place a run asks for a password, and only when a `windows-msvc` target is in the list. `cargo-xwin` downloads Microsoft's CRT and Windows SDK headers and libraries into `~/.cache/cargo-xwin` the first time.

| architecture | target | asset |
|---|---|---|
| Windows x64 | `x86_64-pc-windows-msvc` | `vrtfido-x86_64-pc-windows-msvc.zip` |
| Windows arm64 | `aarch64-pc-windows-gnullvm` | `vrtfido-aarch64-pc-windows-gnullvm.zip` |

Both binaries sit at the root of the ZIP (`vrtfido.exe` and `vrtfido-gui.exe`), exactly like the Linux ones, and each archive is published together with its `<archive>.sha256`. The x64 package links the C runtime statically, so it needs no Visual C++ redistributable. arm64 is built with zig's toolchain (`gnullvm`) rather than MSVC: cargo-xwin 0.23 hands the aarch64 target's C sources to clang in GNU mode together with MSVC-style include flags, which fails inside `ring` and `libz-sys`, while `gnullvm` produces the same ARM64 binaries with no extra package — `aarch64-pc-windows-msvc` still works for anyone who wants to try it through `TARGETS=`. Asking for `TARGETS=x86_64-pc-windows-gnu,aarch64-pc-windows-gnullvm` builds both targets with zig's toolchain, needing no extra package at all.

- macOS packages (built by `build-mac.sh`, on a Mac)

The two macOS archives are the only ones no other host can produce, because the Apple SDK may not be used off Apple hardware, so they have their own builder: `build-mac.sh`. It runs on the Mac, refuses any other host with that reason, and `build-cross.sh` refuses the `*-apple-darwin*` targets with a pointer to it, so there is exactly one way to build each package:

| architecture | target | asset |
|---|---|---|
| macOS Intel | `x86_64-apple-darwin` | `vrtfido-x86_64-apple-darwin.tar.gz` |
| macOS Apple silicon | `aarch64-apple-darwin` | `vrtfido-aarch64-apple-darwin.tar.gz` |

It builds both architectures (`cargo build --release --features gui --target <triple>`, with `rustup target add` for the one that is not the host) and packages the two binaries at the root of a `.tar.gz` with its `<archive>.sha256`. The Mac needs the Apple command line tools — clang and the SDK headers — and the script starts `xcode-select --install` by itself when they are missing (that installer is a GUI one, so the next run finishes the job).

- Publish

One tag per version (`v0.3.8`) with every file from `releases/` attached to it. The former `-gui` variants are gone: since the `gnu` package already contains the window as well as the daemon, there is nothing left to split by tag.

The release is put together by hand: run `./release-build-all.sh` on the Linux machine (it runs the platform check, the extensions, the Android APK and the Linux plus Windows packages) and on the Mac (the same, plus `build-mac.sh` for the two macOS packages), then create the tag and attach `releases/*.tar.gz`, `releases/*.zip`, `releases/*.apk` and their `.sha256` files from the release page or with `gh release upload <tag> releases/… --clobber`. Nothing is attached automatically, so a half-finished release is just a release with fewer files.
