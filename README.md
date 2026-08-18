# open-appsec traefik plugin

A [traefik](https://traefik.io) middleware plugin that inspects HTTP traffic
with [open-appsec](https://openappsec.io) (machine-learning based WAF).

Traefik plugins run inside the [Yaegi](https://github.com/traefik/yaegi)
interpreter, which cannot use cgo or shared memory. This plugin is therefore
pure Go (stdlib only) and forwards the request metadata, headers and body — and
optionally the upstream response — over HTTP to the `openappsec-traefik-daemon`,
which talks to the open-appsec agent over shared memory IPC. The plugin then
enforces the returned verdict (forward, block page, redirect, custom response).

The daemon and the container image live in the
[openappsec-attachment](https://github.com/jclab-oss/openappsec-attachment)
repository (`attachments/traefik/daemon`, `docker/openappsec-traefik`), which
embeds this repository as a git submodule at `attachments/traefik/plugin`.

## Configuration

Static configuration (local plugin):

```yaml
experimental:
  localPlugins:
    openappsec:
      moduleName: github.com/jclab-oss/openappsec-traefik-plugin
```

Dynamic configuration:

```yaml
http:
  middlewares:
    appsec:
      plugin:
        openappsec:
          daemonAddr: http://127.0.0.1:8579   # or unix:///path/to.sock
          responseInspection: true            # inspect upstream responses
          maxRequestBodySize: 10485760        # bytes buffered for inspection
          failClose: false                    # block traffic when the daemon is unreachable
          timeoutMs: 30000                    # per-call daemon timeout
          errorBackoffMs: 2000                # skip inspection after a daemon failure
```

The plugin fails open by default: when the daemon (or the agent behind it) is
unavailable, traffic is forwarded without inspection. Set `failClose: true` to
block instead.

## Development

```bash
make            # lint + test
make lint       # golangci-lint run
make test       # go test -v -cover ./...
make yaegi_test # run the tests through the Yaegi interpreter
```

`yaegi test` resolves the package by its module path under `GOPATH/src`, so the
checkout has to live at `$(go env GOPATH)/src/github.com/jclab-oss/openappsec-traefik-plugin`
(that is what CI does). Anything that passes `go test` but fails `yaegi test`
would also break inside traefik, so keep both green.
