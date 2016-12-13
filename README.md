# tgl

Unofficial C++ Telegram client library.

Current versions:

- scheme.tl: Layer 38
- encrypted_scheme.tl: Layer 23

### API, Protocol documentation

Documentation for Telegram API is available here: https://core.telegram.org/api

Documentation for MTproto protocol is available here: https://core.telegram.org/mtproto

### Installation

```
git clone --recursive  https://github.com/tplgy/tgl.git && cd tgl
```

### MacOS and Linux Dependencies

It also requires a modern compiler with C++11/C++14 support like Clang or GCC, as well as CMake and Autotools.

tgl depends on the following libraries being present:
- openssl
- zlib
- boost

### Building

Assuming you are in the top-level tgl directory and would like to do an out of source build:
```
cd ..
mkdir tgl-build && cd tgl-build
cmake ../tgl
make
make install <optional>
```
