{
  # The reference reproducible build, producing the same bytes on any machine
  description = "Back up, restore and move a Radicle identity, node state and repositories";

  # Pinned by revision, so two builds agree without a flake.lock
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

            # rusqlite and zstd build their C from source, so nothing differs between hosts
            nativeBuildInputs = [ pkgs.installShellFiles ];

            # The suite drives the built binary against a real git. The shipped `restore.sh`
            # reads the manifest with `jq`, and without it restores every repository with no
            # HEAD, failing the test that compares it against this tool.
            nativeCheckInputs = [ pkgs.git pkgs.jq ];

            postInstall = ''
              ln -s rad-backup $out/bin/rad-restore
              # A real file, because installManPage reads the section number off the filename
              # and a process substitution is /dev/fd/63
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

      # `nix flake check` builds the package and runs its tests
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
