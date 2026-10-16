package spiredevserver

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

const testDomain = "example.org"

// startServer runs a workload API server on a unix socket and returns its
// go-spiffe client address.
func startServer(t *testing.T) string {
	t.Helper()
	ca, err := NewInMemoryCA(KeyTypeECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	addr := filepath.Join(t.TempDir(), "spire.sock")
	lis, err := net.Listen("unix", addr)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(append(RequireWorkloadAPIHeader(), grpc.Creds(NewCredentials()))...)
	workload.RegisterSpiffeWorkloadAPIServer(srv, NewWorkloadHandler(Config{Domain: testDomain, CA: ca}))
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	return "unix://" + addr
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestWorkloadAPIRequiresHeader(t *testing.T) {
	addr := startServer(t)
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	client := workload.NewSpiffeWorkloadAPIClient(conn)
	ctx := testContext(t) // no workload.spiffe.io header

	for name, call := range map[string]func() error{
		"FetchWITSVID": func() error {
			s, err := client.FetchWITSVID(ctx, &workload.WITSVIDRequest{})
			if err != nil {
				return err
			}
			_, err = s.Recv()
			return err
		},
		"FetchWITBundles": func() error {
			s, err := client.FetchWITBundles(ctx, &workload.WITBundlesRequest{})
			if err != nil {
				return err
			}
			_, err = s.Recv()
			return err
		},
		"FetchX509SVID": func() error {
			s, err := client.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
			if err != nil {
				return err
			}
			_, err = s.Recv()
			return err
		},
		"FetchJWTSVID": func() error {
			_, err := client.FetchJWTSVID(ctx, &workload.JWTSVIDRequest{Audience: []string{"a"}})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); status.Code(err) != codes.InvalidArgument {
				t.Errorf("code = %v (%v), want InvalidArgument", status.Code(err), err)
			}
		})
	}
}
