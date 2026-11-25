# SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
{
  description = "TALOS / LibreMobile OS Hermetic Reproducible Build Environment";

  inputs = {
    # Pinned NixOS 23.11 channel release for deterministic toolchain reproduction
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.11";
  };

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs supportedSystems (system: f (import nixpkgs { inherit system; }));
    in
    {
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          name = "talos-reproducible-build-env";
          buildInputs = with pkgs; [
            gcc
            gnumake
            nodejs_20
            python3
            e2fsprogs
            android-tools
            git
            gnutar
            xz
            diffutils
            bc
            bison
            flex
            openssl
            elfutils
          ];

          shellHook = ''
            export TZ="UTC"
            export LC_ALL="C"
            export SOURCE_DATE_EPOCH="1700000000"
            export E2FSPROGS_FAKE_TIME="1700000000"
            echo "✔ TALOS Hermetic Reproducible Shell Loaded (NixOS 23.11 Pinned)"
          '';
        };
      });

      packages = forAllSystems (pkgs: {
        default = pkgs.stdenv.mkDerivation {
          pname = "talos-mobile-os";
          version = "1.0.0";
          src = ./.;

          buildInputs = with pkgs; [
            gcc
            gnumake
            nodejs_20
            python3
            e2fsprogs
            git
            gnutar
            xz
          ];

          buildPhase = ''
            export SOURCE_DATE_EPOCH="1700000000"
            export E2FSPROGS_FAKE_TIME="1700000000"
            export TZ="UTC"
            export LC_ALL="C"
            ./scripts/repro-build.sh "$out"
          '';

          dontInstall = true;
        };
      });
    };
}
