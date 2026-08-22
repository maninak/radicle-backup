{
  # A build anyone can repeat. `nix build` here produces the same bytes on any machine that
  # runs it, which is what makes "this binary is the one the release announced" checkable
  # rather than a promise. The cargo build reproduces too, given the pinned toolchain in
  # rust-toolchain.toml and the path remapping `just dist` sets, but nix is the reference.
  description = "Back up, restore and move a Radicle identity, node state and repositories";

  # Pinned by revision rather than by branch, so a flake.lock is a convenience here and not
  # the only thing standing between two builds and two different results.
  inputs.nixpkgs.url = "git+https://github.com/NixOS/nixpkgs?ref=master&rev=0e251e24a4f24e036a084b6b4b2d2491af4167f4&shallow=1";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forEach = nixpkgs.lib.genAttrs systems;
      pkgsFor = system: nixpkgs.legacyPackages.${system};
      manifest = (nixpkgs.lib.importTOML ./Cargo.toml).package;
    in
    {
      packages = forEach (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = self.packages.${system}.rad-backup;

          rad-backup = pkgs.rustPlatform.buildRustPackage {
            pname = manifest.name;
            inherit (manifest) version;
            src = self;
            cargoLock.lockFile = ./Cargo.lock;

            # rusqlite and zstd build their C from source, so there is nothing to find on the
            # host and nothing that can differ between hosts.
            nativeBuildInputs = [ pkgs.installShellFiles ];

            # The suite drives the built binary against a real git, and `jq` because the
            # shipped `restore.sh` reads the manifest with it: without one the script puts
            # every repository back with no HEAD, and the test comparing it against this
            # tool fails on a difference that is the build environment's, not the code's.
            nativeCheckInputs = [ pkgs.git pkgs.jq ];

            postInstall = ''
              ln -s rad-backup $out/bin/rad-restore
              # A real file, not <(...): installManPage reads the section number off the
              # filename, and a process substitution is /dev/fd/63, which has none.
              $out/bin/rad-backup man > "$TMPDIR/rad-backup.1"
              installManPage "$TMPDIR/rad-backup.1"
              installShellCompletion --cmd rad-backup \
                --bash <($out/bin/rad-backup completions bash) \
                --fish <($out/bin/rad-backup completions fish) \
                --zsh  <($out/bin/rad-backup completions zsh)
            '';

            meta = {
              inherit (manifest) description;
              homepage = "https://radicle.tools";
              license = with pkgs.lib.licenses; [
                mit
                asl20
              ];
              mainProgram = "rad-backup";
              platforms = pkgs.lib.platforms.unix;
            };
          };
        }
      );

      devShells = forEach (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.cargo
              pkgs.rustc
              pkgs.clippy
              pkgs.rustfmt
              pkgs.just
              pkgs.git
              pkgs.age
              pkgs.sqlite
              pkgs.jq
              pkgs.lintian
              pkgs.dpkg
            ];
          };
        }
      );

      # `nix flake check` builds the package and runs its tests.
      checks = forEach (system: { inherit (self.packages.${system}) rad-backup; });

      apps = forEach (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.rad-backup}/bin/rad-backup";
        };
      });

      formatter = forEach (system: (pkgsFor system).nixfmt-rfc-style);
    };
}
