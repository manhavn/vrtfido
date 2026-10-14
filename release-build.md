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

./build-gui.sh
```

Every build script stages its publish-ready files (`.zip`, `.tar.gz`, `.sha256`, `.apk`) in the `releases/` directory, replacing that build type's previous output, so one directory holds the whole release set. `build-extension.sh` already chains Chrome, Firefox and Safari; `release-build-all.sh` runs each build type once, keeps going when one of them fails, and reports the failures at the end.

`build-gui.sh` owns the `gnu` packages: each one carries `vrtfido` together with the `vrtfido-gui` window, and the daemon decides at runtime whether it can run the window, so one package serves a desktop and a headless server alike. `build-cross.sh` keeps the portable `musl` packages (static, no GTK at all) and still builds a GTK-free `gnu` package on request, e.g. `TARGETS=x86_64-unknown-linux-gnu ./build-cross.sh`.

- Publish

One tag per version (`v0.3.5`) with every file from `releases/` attached to it. The former `-gui` variants are gone: since the `gnu` package already contains the window as well as the daemon, there is nothing left to split by tag.
