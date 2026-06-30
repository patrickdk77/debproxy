# Benchmarks

Docker builds of two sample images were tested across three modes: no proxy, proxy in live mode, and proxy with a snapshot.

## Summary

| Build | No Proxy | Live Mode | Snapshot | Live Savings | Snapshot Savings |
|-------|----------|-----------|----------|--------------|------------------|
| web (small) | 131.8s | 113.6s | 92.7s | 13.8% | 29.7% |
| web2 (large) | 743.6s | 542.9s | 460.5s | 27.0% | 38.0% |

The **web** image is a simple Apache server used as a base image. **web2** is a complex build that patches and rebuilds Apache, installs many packages, and calls `apt-get update` and `apt-get dist-upgrade` multiple times — nothing was changed to optimize the build logic.

The snapshot gains come from apt only having to download, parse, and index packages actually used in the CI/CD chain rather than the entire archive. Most docker build time is spent in this phase, so the reduction can be significant.

---

## web — Small Application Build

### No Proxy (131.8s)

```
[+] Building 131.8s (7/7) FINISHED                                                           docker:default
 => [internal] load build definition from Dockerfile                                                   0.0s
 => => transferring dockerfile: 6.92kB                                                                 0.0s
 => [internal] load metadata for docker.io/library/ubuntu:24.04                                        0.0s
 => [internal] load .dockerignore                                                                      0.0s
 => => transferring context: 45B                                                                       0.0s
 => [internal] load build context                                                                      0.4s
 => => transferring context: 25.46MB                                                                   0.4s
 => CACHED [stage-0 1/2] FROM docker.io/library/ubuntu:24.04                                           0.0s
 => [stage-0 2/2] RUN                                                                                121.6s
 => exporting to image                                                                                 9.6s
 => => exporting layers                                                                                9.6s
 => => writing image sha256:ba34ac8d1ffb5b1fe5821441cd2bc4bad1f20cb0991375c168e15a3d9ef93cd2           0.0s
 => => naming to docker.io/library/web                                                                 0.0s
```

### Proxy — Live Mode (113.6s, −13.8%)

```
[+] Building 113.6s (7/7) FINISHED                                                           docker:default
 => [internal] load build definition from Dockerfile                                                   0.0s
 => => transferring dockerfile: 6.92kB                                                                 0.0s
 => [internal] load metadata for docker.io/library/ubuntu:24.04                                        0.0s
 => [internal] load .dockerignore                                                                      0.0s
 => => transferring context: 45B                                                                       0.0s
 => [internal] load build context                                                                      0.0s
 => => transferring context: 13.83kB                                                                   0.0s
 => CACHED [stage-0 1/2] FROM docker.io/library/ubuntu:24.04                                           0.0s
 => [stage-0 2/2] RUN                                                                                103.8s
 => exporting to image                                                                                 9.6s
 => => exporting layers                                                                                9.6s
 => => writing image sha256:11dcf01fc34ab9e19ddbfd29409348864499672edfaaa8860beff6cc7b653c1d           0.0s
 => => naming to docker.io/library/web                                                                 0.0s
```

### Proxy — Snapshot (92.7s, −29.7%)

```
[+] Building 92.7s (7/7) FINISHED                                                            docker:default
 => [internal] load build definition from Dockerfile                                                   0.0s
 => => transferring dockerfile: 6.90kB                                                                 0.0s
 => [internal] load metadata for docker.io/library/ubuntu:24.04                                        0.0s
 => [internal] load .dockerignore                                                                      0.0s
 => => transferring context: 45B                                                                       0.0s
 => [internal] load build context                                                                      0.0s
 => => transferring context: 13.83kB                                                                   0.0s
 => CACHED [stage-0 1/2] FROM docker.io/library/ubuntu:24.04                                           0.0s
 => [stage-0 2/2] RUN                                                                                 83.0s
 => exporting to image                                                                                 9.5s
 => => exporting layers                                                                                9.5s
 => => writing image sha256:11913e8aa1ca6186addb29bf9aa20a431b342eac2691ad96a14d8f4573d65ab8           0.0s
 => => naming to docker.io/library/web                                                                 0.0s
```

---

## web2 — Large Application Build

### No Proxy (743.6s)

```
[+] Building 743.6s (13/13) FINISHED                                                         docker:default
 => [internal] load build definition from Dockerfile                                                   0.0s
 => => transferring dockerfile: 27.18kB                                                                0.0s
 => [internal] load metadata for docker.io/library/ubuntu:24.04                                        0.0s
 => [internal] load .dockerignore                                                                      0.0s
 => => transferring context: 2B                                                                        0.0s
 => [internal] load build context                                                                      0.9s
 => => transferring context: 473.34kB                                                                  0.8s
 => CACHED [weballbuild 1/6] FROM docker.io/library/ubuntu:24.04                                       0.0s
 => [build 2/6] RUN                                                                                    7.1s
 => [build 3/6] RUN                                                                                   45.0s
 => [build 4/6] RUN                                                                                  248.5s
 => [build 5/6] COPY                                                                                   0.1s
 => [build 6/6] RUN                                                                                    0.5s
 => [stage-1 2/3] RUN                                                                                332.0s
 => [stage-1 3/3] RUN                                                                                 92.3s
 => exporting to image                                                                                12.4s
 => => exporting layers                                                                               12.4s
 => => writing image sha256:0392526746ba00000d31218f064262e3b8547bb874dd418be2564b934070946a           0.0s
 => => naming to docker.io/library/web2                                                                0.0s
```

### Proxy — Live Mode (542.9s, −27.0%)

```
[+] Building 542.9s (13/13) FINISHED                                                         docker:default
 => [internal] load build definition from Dockerfile                                                   0.0s
 => => transferring dockerfile: 27.09kB                                                                0.0s
 => [internal] load metadata for docker.io/library/ubuntu:24.04                                        0.0s
 => [internal] load .dockerignore                                                                      0.0s
 => => transferring context: 2B                                                                        0.0s
 => [internal] load build context                                                                      0.4s
 => => transferring context: 473.34kB                                                                  0.4s
 => CACHED [weballbuild 1/6] FROM docker.io/library/ubuntu:24.04                                       0.0s
 => [build 2/6] RUN                                                                                    9.7s
 => [build 3/6] RUN                                                                                   32.9s
 => [build 4/6] RUN                                                                                  239.9s
 => [build 5/6] COPY                                                                                   0.1s
 => [build 6/6] RUN                                                                                    0.4s
 => [stage-1 2/3] RUN                                                                                179.4s
 => [stage-1 3/3] RUN                                                                                 62.5s
 => exporting to image                                                                                12.7s
 => => exporting layers                                                                               12.7s
 => => writing image sha256:dd292e420c2bb312b9942801c43e57841c77d45c11560c20ddb0064fbde3929a           0.0s
 => => naming to docker.io/library/web2                                                                0.0s
```

### Proxy — Snapshot (460.5s, −38.0%)

```
[+] Building 460.5s (13/13) FINISHED                                                         docker:default
 => [internal] load build definition from Dockerfile                                                   0.0s
 => => transferring dockerfile: 27.09kB                                                                0.0s
 => [internal] load metadata for docker.io/library/ubuntu:24.04                                        0.0s
 => [internal] load .dockerignore                                                                      0.0s
 => => transferring context: 2B                                                                        0.0s
 => CACHED [weballbuild 1/6] FROM docker.io/library/ubuntu:24.04                                       0.0s
 => [internal] load build context                                                                      0.4s
 => => transferring context: 473.34kB                                                                  0.3s
 => [build 2/6] RUN                                                                                    0.9s
 => [build 3/6] RUN                                                                                   28.3s
 => [build 4/6] RUN                                                                                  229.9s
 => [build 5/6] COPY                                                                                   0.1s
 => [build 6/6] RUN                                                                                    0.4s
 => [stage-1 2/3] RUN                                                                                149.8s
 => [stage-1 3/3] RUN                                                                                 33.5s
 => exporting to image                                                                                12.4s
 => => exporting layers                                                                               12.4s
 => => writing image sha256:11412d3b73b2a6b78803ff73e513459505cbfed1faae7407d80572680fd88839           0.0s
 => => naming to docker.io/library/web2                                                                0.0s
```
