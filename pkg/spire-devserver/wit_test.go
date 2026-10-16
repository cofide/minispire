package spiredevserver

import (
	"context"
	"crypto/ecdsa"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/exp/svid/witsvid"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func TestFetchWITSVIDVerifiesAgainstBundle(t *testing.T) {
	addr := startServer(t)
	ctx := testContext(t)
	opt := workloadapi.WithAddr(addr)

	svids, err := workloadapi.FetchWITSVIDs(ctx, "", opt)
	if err != nil {
		t.Fatalf("FetchWITSVIDs: %v", err)
	}
	if len(svids) != 1 {
		t.Fatalf("got %d SVIDs, want 1", len(svids))
	}
	bundles, err := workloadapi.FetchWITBundles(ctx, opt)
	if err != nil {
		t.Fatalf("FetchWITBundles: %v", err)
	}
	if bundles.Len() != 1 {
		t.Fatalf("got %d bundles, want 1", bundles.Len())
	}

	verified, err := witsvid.ParseAndValidate(svids[0].Marshal(), bundles)
	if err != nil {
		t.Fatalf("SVID does not verify against the fetched bundle: %v", err)
	}
	if verified.ID != svids[0].ID {
		t.Errorf("verified ID = %s, want %s", verified.ID, svids[0].ID)
	}
}

func TestWITSVIDClaims(t *testing.T) {
	addr := startServer(t)
	svids, err := workloadapi.FetchWITSVIDs(testContext(t), "", workloadapi.WithAddr(addr))
	if err != nil {
		t.Fatal(err)
	}
	svid := svids[0]

	tok, err := jwt.ParseSigned(svid.Marshal(), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	if typ := tok.Headers[0].ExtraHeaders[jose.HeaderType]; typ != "wit+jwt" {
		t.Errorf("typ header = %v, want wit+jwt", typ)
	}

	var claims map[string]any
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		t.Fatal(err)
	}
	if got := claims["sub"]; got != svid.ID.String() {
		t.Errorf("sub = %v, want %s", got, svid.ID)
	}
	if got, want := svid.ID.TrustDomain(), spiffeid.RequireTrustDomainFromString(testDomain); got != want {
		t.Errorf("trust domain = %s, want %s", got, want)
	}
	if got, want := claims["iss"], "spiffe://"+testDomain; got != want {
		t.Errorf("iss = %v, want %s", got, want)
	}
	if _, ok := claims["aud"]; ok {
		t.Error("WIT-SVID must not have an aud claim")
	}
	if _, ok := claims["exp"]; !ok {
		t.Error("missing exp claim")
	}

	// The returned private key must match the key bound by cnf.jwk.
	priv, ok := svid.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("private key is %T, want *ecdsa.PrivateKey", svid.PrivateKey)
	}
	pub, ok := svid.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key is %T, want *ecdsa.PublicKey", svid.PublicKey)
	}
	if !priv.PublicKey.Equal(pub) {
		t.Error("private key does not match cnf.jwk public key")
	}
}

func TestFetchWITSVIDEntitlement(t *testing.T) {
	addr := startServer(t)
	ctx := testContext(t)

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	client := workload.NewSpiffeWorkloadAPIClient(conn)
	ctx = metadata.AppendToOutgoingContext(ctx, "workload.spiffe.io", "true")

	// Learn the caller's own ID, then ask for it explicitly.
	own, err := workloadapi.FetchWITSVID(ctx, "", workloadapi.WithAddr(addr))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		id   string
		want codes.Code
	}{
		{"own ID", own.ID.String(), codes.OK},
		{"other ID", "spiffe://example.org/someone/else", codes.PermissionDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stream, err := client.FetchWITSVID(ctx, &workload.WITSVIDRequest{SpiffeId: tc.id})
			if err != nil {
				t.Fatal(err)
			}
			_, err = stream.Recv()
			if got := status.Code(err); got != tc.want {
				t.Errorf("code = %v (%v), want %v", got, err, tc.want)
			}
		})
	}
}

// fakeWITStream is a server stream that records sends and exposes its context.
type fakeWITStream struct {
	grpc.ServerStream
	ctx  context.Context
	sent chan struct{}
}

func (f *fakeWITStream) Context() context.Context { return f.ctx }

type fakeWITSVIDStream struct{ fakeWITStream }

func (f *fakeWITSVIDStream) Send(*workload.WITSVIDResponse) error { f.sent <- struct{}{}; return nil }

type fakeWITBundlesStream struct{ fakeWITStream }

func (f *fakeWITBundlesStream) Send(*workload.WITBundlesResponse) error {
	f.sent <- struct{}{}
	return nil
}

func TestWITStreamsEndWhenClientCancels(t *testing.T) {
	ca, err := NewInMemoryCA(KeyTypeECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	h := NewWorkloadHandler(Config{Domain: testDomain, CA: ca})

	for _, tc := range []struct {
		name string
		run  func(ctx context.Context, sent chan struct{}) error
	}{
		{"FetchWITSVID", func(ctx context.Context, sent chan struct{}) error {
			return h.FetchWITSVID(&workload.WITSVIDRequest{}, &fakeWITSVIDStream{fakeWITStream{ctx: ctx, sent: sent}})
		}},
		{"FetchWITBundles", func(ctx context.Context, sent chan struct{}) error {
			return h.FetchWITBundles(&workload.WITBundlesRequest{}, &fakeWITBundlesStream{fakeWITStream{ctx: ctx, sent: sent}})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(peer.NewContext(context.Background(), &peer.Peer{
				AuthInfo: AuthInfo{Caller: CallerInfo{PID: 1, UID: 1000, GID: 1000, BinaryName: "test"}},
			}))
			defer cancel()
			sent := make(chan struct{}, 4)
			done := make(chan error, 1)
			go func() { done <- tc.run(ctx, sent) }()

			select {
			case <-sent:
			case err := <-done:
				t.Fatalf("returned before sending: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for first response")
			}
			select {
			case err := <-done:
				t.Fatalf("returned before cancellation: %v", err)
			case <-time.After(100 * time.Millisecond):
			}

			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("returned %v after cancellation, want nil", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("handler did not return after cancellation")
			}
		})
	}
}
