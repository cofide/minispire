# minispire

`minispire` is a lightweight test utility for experimenting with aspects of the [SPIFFE](https://spiffe.io) standard. It provides an in-memory CA and a partial implementation of the SPIFFE Workload API. Unlike [SPIRE](https://github.com/spiffe/spire), `minispire` encapsulates both server and agent functionality into a single service.

This tool is geared towards rapid prototyping and experimentation in workload identity issuance and validation. It should in no way be considered a complete SPIFFE implementation or suitable for production use.

## Running

You can run `minispire` directly from source with:

```
go run ./cmd
```

Or as an external dependency

```
go run github.com/cofide/minispire/cmd
```
