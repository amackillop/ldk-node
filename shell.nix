let
  nix_channel = "24.05";
  rust_overlay = import (builtins.fetchTarball "https://github.com/oxalica/rust-overlay/archive/master.tar.gz");
  pkgs = import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/refs/tags/${nix_channel}.tar.gz") {
    overlays = [ rust_overlay ];
  };
  rust = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
in
pkgs.mkShell rec {
  buildInputs = [ rust ] ++ (with pkgs; [
    # Cargo stuff
    cargo-audit
    cargo-expand
    cargo-generate
    cargo-watch


    llvmPackages_18.bintools
    lldb_18
    # Binary dependencies
    bitcoind
    electrs

    # Use compose for dependencies like bitcoin, electrs, etc.
    podman-compose

  ]);

  # Rust
  RUST_BACKTRACE = 1;
  RUST_LOG = "debug cargo test";

  # For integration tests
  BITCOIND_EXE = "bitcoind";
  ELECTRS_EXE = "electrs";
  ELECTRSD_SKIP_DOWNLOAD = 1;
}
