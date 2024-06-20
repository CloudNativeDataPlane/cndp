# Fuzz testing the CNDP API

## Introduction

Fuzzing or Fuzz Testing is the act of testing with random or otherwise
unexpected data. The files in this directory accomplish that with the help of
[libFuzzer](https://llvm.org/docs/LibFuzzer.html). Because we use the built-in
functionality from llvm, we need to compile with clang and clang++.

## Build CNDP with fuzzing support

Fortunately for us, meson provides native support for enabling sanitizers. To
build CNDP with the required sanitizers, use b_sanitize and b_lundef options.
Both release and debug examples are shown below, but you can use what you need.

```text
CC=clang CXX=clang++ meson -Dbuildtype=release -Db_sanitize=address -Db_lundef=false build-clang-release
CC=clang CXX=clang++ meson -Dbuildtype=debug -Db_sanitize=address -Db_lundef=false build-clang-debug
```

Build the environment that meson created using ninja.

```sh
ninja -C build-clang-release
ninja -C build-clang-debug
```

## Running the fuzzers

The fuzzers are built in, e.g. build-clang-\*/test/fuzz/fuzz\_\* from sources in
test/fuzz/\*.cc

Run the fuzzers using options like -detect_leaks=0, -max_total_time=180,
-help=1, etc.

## References

[libFuzzer Tutorial](https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md)
