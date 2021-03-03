# ![](images/logo-base-32.png) spy service [![][SpyMvnImg]][SpyMvnLnk]

It has been deployed on https://mapland.fr/spy


## Quick local start

Thanks to [coursier][cs] from @alxarchambault,
this application is quite easy to start, just execute :
```
cs launch fr.janalyse::spy:1.0.0
```

## Configuration

| Environment variable | Description                                       | default value
| -------------------- | ------------------------------------------------- | -----------------
| SPY_LISTEN_IP        | Listening network interface                       | "0.0.0.0"
| SPY_LISTEN_PORT      | Listening port                                    | 8080
| SPY_PREFIX           | Add a prefix to all defined routes                | ""
| SPY_URL              | How this service is known from outside            | "http://127.0.0.1:8080"
| SPY_STORE_PATH       | Where data is stored                              | "/tmp/spy-data"

[cs]: https://get-coursier.io/

[deployed]:   https://mapland.fr/spy
[akka-http]:  https://doc.akka.io/docs/akka-http/current/index.html

[Spy]:       https://github.com/dacr/spy
[SpyMvnImg]: https://img.shields.io/maven-central/v/fr.janalyse/spy_2.13.svg
[SpyMvnLnk]: https://search.maven.org/#search%7Cga%7C1%7Cfr.janalyse.spy
