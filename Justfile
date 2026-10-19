build:
    go build -o minispire ./cmd/main.go

build-wit-client:
    go build -o wit-client ./cmd/wit-client

test *args:
    go run gotest.tools/gotestsum@latest --format github-actions ./... {{args}}

run: build
    ./minispire

# Start minispire, run the WIT-SVID example client against it, then stop it.
test-wit-client: build build-wit-client
    #!/usr/bin/env bash
    set -euo pipefail
    socket=/tmp/spire.sock
    server_pid=
    trap '[ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null' EXIT
    ./minispire &
    server_pid=$!
    for _ in $(seq 50); do
        [ -S "$socket" ] && break
        sleep 0.1
    done
    [ -S "$socket" ] || { echo "minispire did not create $socket" >&2; exit 1; }
    ./wit-client -addr "unix://$socket"
