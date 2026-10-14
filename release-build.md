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

`build-cross.sh` builds every Linux package: the `gnu` archives (daemon plus the `vrtfido-gui` window, made inside a container image that carries the GTK3 stack for both architectures) and the static CLI-only `musl` archives (cargo-zigbuild). A container engine is therefore only needed for the `gnu` targets, and `TARGETS=x86_64-unknown-linux-musl ./build-cross.sh` still works without one.

- Publish

One tag per version (`v0.3.5`) with every file from `releases/` attached to it. The former `-gui` variants are gone: since the `gnu` package already contains the window as well as the daemon, there is nothing left to split by tag.
