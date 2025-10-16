# minispire

`minispire` is a lightweight test utility for experimenting with aspects of the [SPIFFE](https://spiffe.io) standard. It differs from [SPIRE](https://github.com/spiffe/spire) in that both server and agent functionality are encapsulated into one service. It provides an in-memory CA and partial implementation of the SPIFFE Workload API.

This tool is geared towards rapid prototyping and experimentation in workload identity issuance and validation. It should in no way be considered a full or productionised implementation of SPIFFE.

## Running

You can run `minispire` directly from source with:

```
go run ./cmd
```

Or as an external dependency

```
go run github.com/cofide/minispire/cmd
```
