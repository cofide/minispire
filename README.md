# minispire

`minispire` is a lightweight test utility for experimenting with aspects of the [SPIFFE](https://spiffe.io) standard. It provides an in-memory CA and a partial implementation of the SPIFFE Workload API. Unlike [SPIRE](https://github.com/spiffe/spire), `minispire` encapsulates both server and agent functionality into a single service.

This tool is geared towards rapid prototyping and experimentation in workload identity issuance and validation. It should in no way be considered a complete SPIFFE implementation or suitable for production use.

`minispire` exposes a SPIFFE workload API over a Unix domain socket at `/tmp/spire.sock`. Applications running on the same machine can use this API to obtain SPIFFE Secure Verifiable Identity Documents (SVIDs).

`minispire` implements the experimental WIT-SVID profile of the SPIFFE Workload API (`FetchWITSVID` and `FetchWITBundles`), based on the Workload Identity in Multi-System Environments (WIMSE) [Workload Identity Token (WIT)](https://datatracker.ietf.org/doc/draft-ietf-wimse-s2s-protocol/). It can be consumed with the `workloadapi` client in go-spiffe v2.7.0 or later.

## Running

You can run `minispire` directly from source with:

```
go run ./cmd
```

Or as an external dependency

```
go run github.com/cofide/minispire/cmd
```

## Example WIT-SVID client

`cmd/wit-client` is a small client built on the go-spiffe `workloadapi` package. It fetches a WIT-SVID and the WIT bundle from the Workload API, verifies the SVID against the bundle, and prints the SPIFFE ID, key ID, expiry and token claims. It exits non-zero if any step fails.

With `minispire` running in one terminal, run the client in another:

```
go run ./cmd/wit-client
```

Flags:

- `-addr`: Workload API address, defaulting to `unix:///tmp/spire.sock`.
- `-timeout`: overall timeout, defaulting to `10s`.

`minispire` derives the SPIFFE ID from the calling process, so the ID in the output includes the client's binary name, UID, GID and PID. A successful run ends with `Verified:  OK`.

## Production Use Cases

At [Cofide](https://www.cofide.io), we're building a workload identity platform that is seamless and secure for multi and hybrid cloud environments. Feel free to browse our [public documentation](https://docs.cofide.dev) or read our introductory [blog post](https://www.cofide.io/resources/introducing-cofide-connect-the-control-plane-for-workload-identity-and-access-management-iam) for more info.

If you have a production use case for a workload identity platform with enterprise-level support, please [speak with us](https://www.cofide.io/contact) to find out more about our platform.
