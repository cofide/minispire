# minispire

`minispire` is a lightweight test utility for experimenting with aspects of the [SPIFFE](https://spiffe.io) standard. It provides an in-memory CA and a partial implementation of the SPIFFE Workload API. Unlike [SPIRE](https://github.com/spiffe/spire), `minispire` encapsulates both server and agent functionality into a single service.

This tool is geared towards rapid prototyping and experimentation in workload identity issuance and validation. It should in no way be considered a complete SPIFFE implementation or suitable for production use.

`minispire` exposes a SPIFFE workload API over a Unix domain socket at `/tmp/spire.sock`. Applications running on the same machine can use this API to obtain SPIFFE Secure Verifiable Identity Documents (SVIDs).

`minispire` includes a prototype implementation of a workload API for the Workload Identity in Multi-System Environments (WIMSE) [Workload Identity Token (WIT)](https://datatracker.ietf.org/doc/draft-ietf-wimse-s2s-protocol/) SVID.

## Running

You can run `minispire` directly from source with:

```
go run ./cmd
```

Or as an external dependency

```
go run github.com/cofide/minispire/cmd
```
