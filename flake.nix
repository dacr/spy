{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    utils.url = "github:numtide/flake-utils";
    sbt.url = "github:zaninime/sbt-derivation";
    sbt.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, utils, sbt }:
  utils.lib.eachDefaultSystem (system:
  let
    pkgs = import nixpkgs { inherit system; };
    jdk = pkgs.jdk25_headless;
    sbt-jdk = pkgs.sbt.override { jre = jdk; };
  in {
    # ---------------------------------------------------------------------------
    # nix develop
    devShells.default = pkgs.mkShell {
      buildInputs = [
        (pkgs.sbt.override { jre = pkgs.jdk25; })
        (pkgs.metals.override { jre = pkgs.jdk25; })
        pkgs.jdk25
        pkgs.hello
      ];
    };

    # ---------------------------------------------------------------------------
    # nix build
    # sbt running on java 25 for both the dependencies fetching phase and the build itself
    packages.default = (sbt.mkSbtDerivation.${system}.withOverrides { sbt = sbt-jdk; }) {
      pname = "nix-spy";
      version = builtins.elemAt (builtins.match ''[^"]+"(.*)".*'' (builtins.readFile ./version.sbt)) 0;
      depsSha256 = "sha256-wOlafT3P2Nuaski9aDOQMA9bxTvudnziHoUbSDxotcM=";

      src = ./.;

      buildInputs = [sbt-jdk jdk pkgs.makeWrapper];

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
              jdk
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
          ip = lib.mkOption {
            type = lib.types.str;
            description = "Listening network interface - 0.0.0.0 for all interfaces";
            default = "127.0.0.1";
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
        systemd.tmpfiles.rules = [
              "d ${config.services.spy.datastore} 0750 ${config.services.spy.user} ${config.services.spy.user} -"
        ];
        systemd.services.spy = {
          description = "Spy service";
          environment = {
            SPY_LISTEN_IP   = config.services.spy.ip;
            SPY_LISTEN_PORT = (toString config.services.spy.port);
            SPY_PREFIX      = config.services.spy.prefix;
            SPY_URL         = config.services.spy.url;
            SPY_STORE_PATH  = config.services.spy.datastore;
          };
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
