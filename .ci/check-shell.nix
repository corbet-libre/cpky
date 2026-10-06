# Native headers and runtime libraries for Linux verification (the crate
# graph links OpenSSL via openssl-sys, which needs pkg-config plus OpenSSL
# dev headers and shared libs at build and run time).
{ pkgs ? import (builtins.fetchTarball {
  url = "https://github.com/NixOS/nixpkgs/archive/b7c2ada94fe99c15b0dbcf4d11fd7850b957a436.tar.gz";
  sha256 = "sha256-IItrdb7Puk05RqOBWZYFC5X6Wl1sJmCfh5MWVHw5iMM=";
}) {} }:
pkgs.mkShell {
  buildInputs = with pkgs; [
    openssl
    (python3.withPackages (ps: [ ps.selenium ]))
  ];
  nativeBuildInputs = with pkgs; [
    pkg-config
    clang
  ];
  shellHook = ''
    export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [ pkgs.openssl ]}:''${LD_LIBRARY_PATH:-}";
  '';
}
