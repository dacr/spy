# ![](images/logo-base-32.png) spy service [![License][licenseImg]][licenseLink] [![][SpyMvnImg]][SpyMvnLnk]

It has been deployed on [https://mapland.fr/spy][deployed]


## Quick local start

Thanks to [scala-cli][scl],
this application is quite easy to start, just execute :
```
scala-cli --dep fr.janalyse::spy:1.0.7 -e 'spy.Main.main(args)'
```

## Configuration

| Environment variable | Description                            | default value           |
|----------------------|----------------------------------------|-------------------------|
| SPY_LISTEN_IP        | Listening network interface            | "0.0.0.0"               |
| SPY_LISTEN_PORT      | Listening port                         | 8080                    |
| SPY_PREFIX           | Add a prefix to all defined routes     | ""                      |
| SPY_URL              | How this service is known from outside | "http://127.0.0.1:8080" |
| SPY_STORE_PATH       | Where data is stored                   | "/tmp/spy-data"         |
| SPY_REVERSE_DNS_LOOKUP | Resolve client IPs to host names     | true                    |

## Behind a reverse proxy

spy works with or without a reverse proxy, the mode is decided for each request : as soon as a
forwarding header (`Forwarded`, `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`, ...) gives the
client IP, the TCP peer is considered to be a reverse proxy. `/api/myclient` then describes the
client side connection (`connection`, `request`, `tls`) from the forwarded headers, and the proxy
hop itself in `proxy` (`peerAddress`, `peerProtocol`, `upstreamUrl`, ...).

Forwarding headers are trusted, so the proxy must **replace** them rather than append to what the
client sent. The client connection details only the proxy can see are read from these headers
(first name is the preferred one, the others are accepted aliases) :

| Information                    | Headers                                                     | nginx variable              |
|--------------------------------|-------------------------------------------------------------|-----------------------------|
| client port                    | X-Real-Port, X-Client-Port, X-Forwarded-Client-Port         | `$remote_port`              |
| client HTTP version            | X-Forwarded-Http-Version, X-Client-HTTP-Version             | `$server_protocol`          |
| TLS protocol                   | X-SSL-Protocol, X-Client-TLS-Protocol                       | `$ssl_protocol`             |
| TLS cipher                     | X-SSL-Cipher, X-Client-TLS-Cipher                           | `$ssl_cipher`               |
| TLS server name (SNI)          | X-SSL-Server-Name, X-Client-TLS-SNI                         | `$ssl_server_name`          |
| TLS session reused             | X-SSL-Session-Reused                                        | `$ssl_session_reused`       |
| TLS ALPN                       | X-SSL-ALPN                                                  | `$ssl_alpn_protocol`        |
| TLS key exchange curve         | X-SSL-Curve                                                 | `$ssl_curve`                |
| TLS 1.3 early data             | X-SSL-Early-Data                                            | `$ssl_early_data`           |
| ciphers offered by the client  | X-SSL-Client-Ciphers                                        | `$ssl_ciphers`              |
| curves offered by the client   | X-SSL-Client-Curves                                         | `$ssl_curves`               |
| JA3 / JA4 fingerprints         | X-JA3-Fingerprint, X-JA4-Fingerprint                        |                             |
| client certificate check       | X-SSL-Client-Verify                                         | `$ssl_client_verify`        |
| client certificate             | X-SSL-Client-Cert                                           | `$ssl_client_escaped_cert`  |
| client certificate subject     | X-SSL-Client-S-DN                                           | `$ssl_client_s_dn`          |
| client certificate issuer      | X-SSL-Client-I-DN                                           | `$ssl_client_i_dn`          |
| client certificate serial      | X-SSL-Client-Serial                                         | `$ssl_client_serial`        |
| client certificate validity    | X-SSL-Client-V-Start, X-SSL-Client-V-End                    | `$ssl_client_v_start/_end`  |
| client certificate fingerprint | X-SSL-Client-Fingerprint                                    | `$ssl_client_fingerprint`   |

nginx example :
```nginx
location / {
  proxy_pass http://127.0.0.1:8080/;
  proxy_set_header Host                     $host;
  proxy_set_header X-Real-IP                $remote_addr;
  proxy_set_header X-Forwarded-For          $remote_addr;
  proxy_set_header X-Forwarded-Proto        $scheme;
  proxy_set_header X-Forwarded-Host         $host;
  proxy_set_header X-Real-Port              $remote_port;
  proxy_set_header X-Forwarded-Http-Version $server_protocol;
  proxy_set_header X-SSL-Protocol           $ssl_protocol;
  proxy_set_header X-SSL-Cipher             $ssl_cipher;
  proxy_set_header X-SSL-Server-Name        $ssl_server_name;
  proxy_set_header X-SSL-Session-Reused     $ssl_session_reused;
  proxy_set_header X-SSL-ALPN               $ssl_alpn_protocol;
  proxy_set_header X-SSL-Curve              $ssl_curve;
  proxy_set_header X-SSL-Early-Data         $ssl_early_data;
  proxy_set_header X-SSL-Client-Ciphers     $ssl_ciphers;
  proxy_set_header X-SSL-Client-Curves      $ssl_curves;
}
```

[cs]: https://get-coursier.io/
[scl]: https://scala-cli.virtuslab.org/

[deployed]:   https://mapland.fr/spy
[akka-http]:  https://doc.akka.io/docs/akka-http/current/index.html

[Spy]:       https://github.com/dacr/spy
[SpyMvnImg]: https://img.shields.io/maven-central/v/fr.janalyse/spy_2.13.svg
[SpyMvnLnk]: https://search.maven.org/#search%7Cga%7C1%7Cfr.janalyse.spy

[licenseImg]: https://img.shields.io/github/license/dacr/spy.svg
[licenseLink]: LICENSE
