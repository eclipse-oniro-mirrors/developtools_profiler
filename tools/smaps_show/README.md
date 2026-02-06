small tools to parse smaps information

## build

### native build:

```shell
# build with debug:
cargo build
# or release:
cargo build --release
```

#### static-linking Cross-Build for arm32:

```shell
#add toolchains:
rustup target add armv7-unknown-linux-musleabihf
rustup target add arm-unknown-linux-musleabihf
```

```shell
#add right linker to ~/.cargo/config:
[target.armv7-unknown-linux-musleabihf]
linker = "arm-linux-gnueabihf-ld"

[target.arm-unknown-linux-musleabihf]
linker = "arm-linux-gnueabihf-ld"
```

build:

```shell
cargo build --target=armv7-unknown-linux-musleabihf
#add --release for release
```

## run

    smaps-show -p PID [-v]

or
```shell
smaps-show -f FILE_PATH [-v]
```

