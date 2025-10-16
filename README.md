# minispire

`minispire` is a lightweight, experimental implementation of the [SPIFFE-compliant](https://spiffe.io) reference architecture [SPIRE](https://github.com/spiffe/spire). It provides an in-memory CA and partial implementation of the SPIFFE Workload API, and is geared towards rapid prototyping and experimentation in workload identity issuance and validation.

## Running

You can run `minispire` directly from source with:

```
go run ./cmd
```

Or as an external dependency

```
go run github.com/cofide/minispire/cmd
```
