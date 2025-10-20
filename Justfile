proto-gen:
    buf generate --path ./pkg/wimse

build:
    go build -o minispire ./cmd/main.go

test *args:
    go run gotest.tools/gotestsum@latest --format github-actions ./... {{args}}

run: build
    ./minispire
