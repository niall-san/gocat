# gocat

Updated to work with Hashcat v8.0.0.

gocat is a cgo library for interacting with libhashcat. gocat enables you to create purpose-built password cracking tools that leverage the capabilities of [hashcat](https://hashcat.net/hashcat/).

Below is a matrix that details which versions of hashcat we support:

| Branch        | Hashcat Version | Go Import                       |
| ------------- | --------------- | ------------------------------- |
| `master`      | `v8.0.0`        | `github.com/niall-san/gocat/v8` |
| `v7.1.2-2`    | `v7.1.2`        | `github.com/niall-san/gocat/v7` |
| `master `     | `v6.1.1`        | `github.com/mandiant/gocat/v6`  |
| `v5`          | `v5.X`          | `github.com/fireeye/gocat`      |


## Installation (Please Read)

gocat requires hashcat [v8.0.0](https://github.com/hashcat/hashcat/releases) or higher to be compiled as a shared library (`SHARED=1`, the default on Linux since v8.0.0). At this time, we also recommend disabling the brain functionality by setting `ENABLE_BRAIN` to `0`: `hashcat_status_t` changes layout with it, so gocat and libhashcat must agree.

    git clone https://github.com/hashcat/hashcat.git
    git checkout v8.0.0
    make install SHARED=1 ENABLE_BRAIN=0
    cp include/*.h OpenCL/inc_types.h /usr/local/include/hashcat/

The last step is needed because libhashcat's installed headers do not include everything gocat's cgo wrapper needs. gocat looks for headers in `/usr/local/include/hashcat` and the library in `/usr/local/lib`.

## Hash types

`types/hash_types.go` is generated from hashcat itself. `SupportedHashes()` lists every hash-mode the binary reports, and `LegacyHashModes()` maps retired mode numbers (still accepted by `-m`) to their replacements. To regenerate after a hashcat upgrade:

    $ cd types
    $ HASHCAT_BIN=/usr/local/bin/hashcat HASHCAT_SRC_PATH=<Place path here> go generate

## Testing

gocat tests need to be run from the `/usr/local/share/hashcat/` directory to access all of the shared files needed for testing.

    go test -c
    cp gocat.test /usr/local/share/hashcat
    cp -r testdata /usr/local/share/hashcat
    /usr/local/share/hashcat/gocat.test

## Known Issues

* Lack of Windows Support: This won't work on windows as I haven't figured out how to build hashcat on windows
* Memory Leaks: hashcat has several (small) memory leaks that could cause increase of process memory over time

## Contributing

Contributions are welcome via pull requests provided they meet the following criteria:

1. One feature or bug fix per PR
1. Code should be properly formatted (using go fmt)
1. Tests coverage should rarely decrease. All new features should have proper coverage
