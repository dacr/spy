{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    utils.url = "github:numtide/flake-utils";
    sbt.url = "github:zaninime/sbt-derivation";
    sbt.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, utils, sbt }:
  utils.lib.eachDefaultSystem (system:
  let
    pkgs = import nixpkgs { inherit system; };
  in {
    # ---------------------------------------------------------------------------
    # nix develop
    devShells.default = pkgs.mkShell {
      buildInputs = [pkgs.sbt pkgs.metals pkgs.jdk21 pkgs.hello];
    };

    # ---------------------------------------------------------------------------
    # nix build
    packages.default = sbt.mkSbtDerivation.${system} {
      pname = "nix-spy";
      version = builtins.elemAt (builtins.match ''[^"]+"(.*)".*'' (builtins.readFile ./version.sbt)) 0;
      depsSha256 = "";

      src = ./.;

      buildInputs = [pkgs.sbt pkgs.jdk21_headless pkgs.makeWrapper];

      buildPhase = "sbt Universal/packageZipTarball";

      installPhase = ''
          mkdir -p $out
          tar xf target/universal/spy.tgz --directory $out
          makeWrapper $out/bin/spy $out/bin/nix-spy \
            --set PATH ${pkgs.lib.makeBinPath [
              pkgs.gnused
              pkgs.gawk
              pkgs.coreutils
              pkgs.bash
              pkgs.jdk21_headless
            ]}
      '';
    };

    # ---------------------------------------------------------------------------
    # simple nixos services integration
    nixosModules.default = { config, pkgs, lib, ... }: {
      options = {
        services.spy = {
          enable = lib.mkEnableOption "spy";
          user = lib.mkOption {
            type = lib.types.str;
            description = "User name that will run the spy service";
          };
          port = lib.mkOption {
            type = lib.types.int;
            description = "Service spy listing port";
            default = 8080;
          };
          url = lib.mkOption {
            type = lib.types.str;
            description = "How this service is known/reached from outside";
            default = "http://127.0.0.1:8080";
          };
          prefix = lib.mkOption {
            type = lib.types.str;
            description = "Service spy url prefix";
            default = "";
          };
          datastore = lib.mkOption {
            type = lib.types.str;
            description = "where spy stores its data";
            default = "/tmp/spy-cache-data";
          };
        };
      };
      config = lib.mkIf config.services.spy.enable {
        systemd.services.spy = {
          description = "Record your json data coming from websockets or webhooks";
          environment = {
            SPY_LISTEN_PORT = (toString config.services.spy.port);
            SPY_PREFIX      = config.services.spy.prefix;
            SPY_URL         = config.services.spy.url;
            SPY_STORE_PATH  = config.services.spy.datastore;
          };
          preStart = ''
            ${pkgs.toybox}/bin/mkdir -p ${config.services.spy.datastore}
            ${pkgs.toybox}/bin/chown ${config.services.spy.user}:${config.services.spy.user} ${config.services.spy.datastore}
          '';
          serviceConfig = {
            ExecStart = "${self.packages.${pkgs.system}.default}/bin/nix-spy";
            User = config.services.spy.user;
            Restart = "on-failure";
          };
          wantedBy = [ "multi-user.target" ];
        };
      };
    };
    # ---------------------------------------------------------------------------

  });
}
