{ pkgs ? import <nixpkgs> {
  overlays = [
    (import "${fetchTarball "https://github.com/nix-community/fenix/archive/main.tar.gz"}/overlay.nix")
  ];
} }:
pkgs.mkShell {
  buildInputs = [
    pkgs.go
    pkgs.nodejs-18_x
    pkgs.tree-sitter
    pkgs.nodePackages.eslint
    pkgs.nodePackages.prettier
    pkgs.rustc
    pkgs.rustfmt
    pkgs.clippy
    pkgs.cargo
    pkgs.rust-analyzer-nightly
  ];
  # Needed for rust-analyzer and others to function
  RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}"; 
}
