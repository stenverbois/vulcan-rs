# vulcan-rs

Rust port of [VulCAN](https://github.com/sancus-pma/vulcan).
Developed as part of my [master's thesis](https://distrinet.cs.kuleuven.be/software/sancus/research.php#student) at KU Leuven.

## Structure

The `vulcan` directory contains the library itself, while proof-of-concept applications are
located in the `enclaves` directory.

## Compiling the example enclaves

 - `Rust SGX SDK`: The `Makefile` as well as the `Cargo.toml` of the examples need the
 location of a local copy of the Baidu Rust SGX SDK. The contents of this repo have been tested with with version `0.9.7`.
 For more information and troubeshooting, see the [Rust SGX SDK repo](https://github.com/baidu/rust-sgx-sdk).

## License

See [LICENSE](LICENSE) for details.
