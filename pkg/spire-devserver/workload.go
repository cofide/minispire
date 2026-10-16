package spiredevserver

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/url"
	"sync"
	"time"

	"github.com/cofide/cofide-sdk-go/pkg/id"
	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	pb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	spiffeid "github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type Config struct {
	CA     *InMemoryCA
	Domain string
}

type svidData struct {
	certBytes []byte
	keyBytes  []byte
	expiry    time.Time
}

// WorkloadHandler implements the Workload API interface
type WorkloadHandler struct {
	c Config

	svids   map[string]svidData
	svidsMu sync.RWMutex

	pb.UnimplementedSpiffeWorkloadAPIServer
}

func NewWorkloadHandler(c Config) *WorkloadHandler {
	return &WorkloadHandler{
		c:       c,
		svids:   make(map[string]svidData),
	}
}

func (w *WorkloadHandler) FetchX509SVID(req *pb.X509SVIDRequest, resp pb.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	ctx := resp.Context()
	spiffeID, err := w.generateSpiffeID(ctx)
	if err != nil {
		return err
	}

	log.Printf("Issuing SVID for %s", spiffeID.String())

	w.svidsMu.RLock()
	data, ok := w.svids[spiffeID.String()]
	w.svidsMu.RUnlock()
	if ok && time.Now().Add(2*time.Minute).Before(data.expiry) {
		err := resp.Send(&pb.X509SVIDResponse{
			Svids: []*pb.X509SVID{
				{
					SpiffeId:    spiffeID.String(),
					X509Svid:    data.certBytes,
					X509SvidKey: data.keyBytes,
				},
			},
			FederatedBundles: map[string][]byte{
				w.c.Domain: w.c.CA.GetCACert(),
			},
		})
		if err != nil {
			return err
		}

		return w.waitForCertUpdateAndSendSVIDs(req, resp, data.expiry)
	}
	var key crypto.Signer

	if w.c.CA.KeyType == KeyTypeRSA {
		var err error
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
	} else if w.c.CA.KeyType == KeyTypeECDSAP256 {
		var err error
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
	}

	pkcs8Key, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}

	certURL, err := url.Parse(spiffeID.String())
	if err != nil {
		return err
	}
	svidCsr := &x509.CertificateRequest{
		URIs: []*url.URL{certURL},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, svidCsr, key)
	if err != nil {
		return err
	}

	svidBytes, notAfter, err := w.c.CA.Sign(csrBytes)
	if err != nil {
		return err
	}

	w.svidsMu.Lock()
	w.svids[spiffeID.String()] = svidData{
		certBytes: svidBytes,
		keyBytes:  pkcs8Key,
		expiry:    notAfter,
	}
	w.svidsMu.Unlock()

	err = resp.Send(&pb.X509SVIDResponse{
		Svids: []*pb.X509SVID{
			{
				SpiffeId:    spiffeID.String(),
				X509Svid:    svidBytes,
				X509SvidKey: pkcs8Key,
			},
		},
		FederatedBundles: map[string][]byte{
			w.c.Domain: w.c.CA.GetCACert(),
		},
	})
	if err != nil {
		return err
	}

	return w.waitForCertUpdateAndSendSVIDs(req, resp, notAfter)
}

func (w *WorkloadHandler) waitForCertUpdateAndSendSVIDs(req *pb.X509SVIDRequest, resp pb.SpiffeWorkloadAPI_FetchX509SVIDServer, expiry time.Time) error {
	// this is over simplified logic, however ideal for a local development instance
	time.Sleep(time.Until(expiry.Add(-2 * time.Minute)))

	return w.FetchX509SVID(req, resp)
}

func (w *WorkloadHandler) FetchX509Bundles(req *pb.X509BundlesRequest, resp pb.SpiffeWorkloadAPI_FetchX509BundlesServer) error {
	resp.Send(&pb.X509BundlesResponse{
		Bundles: map[string][]byte{
			w.c.Domain: w.c.CA.GetCACert(),
		},
	})

	return nil
}

func (w *WorkloadHandler) FetchJWTSVID(ctx context.Context, req *pb.JWTSVIDRequest) (*pb.JWTSVIDResponse, error) {
	resp := new(pb.JWTSVIDResponse)

	sid, err := w.generateSpiffeID(ctx)
	if err != nil {
		return nil, err
	}

	token, err := w.c.CA.SignWorkloadJWTSVID(ctx, WorkloadJWTSVIDParams{
		SPIFFEID: sid.ToSpiffeID(),
		TTL:      time.Minute * 5,
		Audience: req.Audience,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign JWT SVID: %v", err)
	}

	log.Printf("JWT SVID issued: %s\n", token)

	resp.Svids = append(resp.Svids, &pb.JWTSVID{
		SpiffeId: sid.String(),
		Svid:     token,
	})

	return resp, nil
}

func (w *WorkloadHandler) FetchJWTBundles(req *pb.JWTBundlesRequest, stream pb.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	ca, err := x509.ParseCertificate(w.c.CA.GetCACert())
	if err != nil {
		return err
	}

	bundle := jwtbundle.FromJWTAuthorities(spiffeid.RequireTrustDomainFromString(w.c.Domain), map[string]crypto.PublicKey{"kid": ca.PublicKey})
	bundleBytes, err := bundle.Marshal()
	if err != nil {
		return err
	}

	err = stream.Send(&pb.JWTBundlesResponse{
		Bundles: map[string][]byte{
			w.c.Domain: bundleBytes,
		},
	})
	if err != nil {
		return err
	}
	return w.waitForCertUpdateAndSendJWTBundle(req, stream)
}

func (w *WorkloadHandler) waitForCertUpdateAndSendJWTBundle(req *pb.JWTBundlesRequest, stream pb.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	// this is over simplified logic, however ideal for a local development instance
	time.Sleep(time.Minute)

	return w.FetchJWTBundles(req, stream)
}

func (w *WorkloadHandler) ValidateJWTSVID(ctx context.Context, req *pb.ValidateJWTSVIDRequest) (*pb.ValidateJWTSVIDResponse, error) {
	if req.Audience == "" {
		return nil, errors.New("audience must be specified")
	}
	if req.Svid == "" {
		return nil, errors.New("svid must be specified")
	}
	svid, err := jwtsvid.ParseInsecure(req.Svid, []string{req.Audience})
	if err != nil {
		return nil, fmt.Errorf("failed to parse SPIFFE ID: %v", err)
	}
	claims, err := w.c.CA.ValidateWorkloadJWTSVID(svid.Marshal(), svid.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to validate JWT SVID: %v", err)
	}

	if !claims.Audience.Contains(req.Audience) {
		return nil, errors.New("audience does not match")
	}

	return &pb.ValidateJWTSVIDResponse{
		SpiffeId: svid.ID.String(),
	}, nil
}

func (w *WorkloadHandler) generateSpiffeID(ctx context.Context) (*id.SPIFFEID, error) {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return nil, errors.New("unable to get peer info")
	}
	ai, ok := peer.AuthInfo.(AuthInfo)
	if !ok {
		return nil, errors.New("unable to get auth info")
	}
	info := map[string]string{
		"uid": fmt.Sprint(ai.Caller.UID),
		"pid": fmt.Sprint(ai.Caller.PID),
		"gid": fmt.Sprint(ai.Caller.GID),
	}
	if ai.Caller.BinaryName != "" { // can be empty if the the user mini-spire is running as cannot read the ps data
		info["bin"] = ai.Caller.BinaryName
	}

	return id.NewID(w.c.Domain, info)
}

const witSVIDTTL = 5 * time.Minute

// checkWorkloadAPIHeader rejects callers that do not send the
// "workload.spiffe.io: true" metadata the SPIFFE Workload API requires, so
// that other gRPC clients are not handed private keys by accident.
func checkWorkloadAPIHeader(ctx context.Context) error {
	md, _ := metadata.FromIncomingContext(ctx)
	if v := md.Get("workload.spiffe.io"); len(v) == 0 || v[0] != "true" {
		return status.Error(codes.InvalidArgument, `security header missing from request: "workload.spiffe.io: true"`)
	}
	return nil
}

// RequireWorkloadAPIHeader returns server options that apply the
// "workload.spiffe.io: true" check to every Workload API call.
func RequireWorkloadAPIHeader() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			if err := checkWorkloadAPIHeader(ctx); err != nil {
				return nil, err
			}
			return handler(ctx, req)
		}),
		grpc.ChainStreamInterceptor(func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			if err := checkWorkloadAPIHeader(ss.Context()); err != nil {
				return err
			}
			return handler(srv, ss)
		}),
	}
}

func (w *WorkloadHandler) FetchWITSVID(req *pb.WITSVIDRequest, stream pb.SpiffeWorkloadAPI_FetchWITSVIDServer) error {
	ctx := stream.Context()
	sid, err := w.generateSpiffeID(ctx)
	if err != nil {
		return err
	}
	if req.SpiffeId != "" && req.SpiffeId != sid.String() {
		return status.Errorf(codes.PermissionDenied, "workload is not entitled to %s", req.SpiffeId)
	}

	// Re-issue at half the TTL until the client goes away.
	for {
		resp, err := w.mintWITSVID(ctx, sid)
		if err != nil {
			return err
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(witSVIDTTL / 2):
		}
	}
}

func (w *WorkloadHandler) mintWITSVID(ctx context.Context, sid *id.SPIFFEID) (*pb.WITSVIDResponse, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate workload keypair: %v", err)
	}
	privateJWK, err := jose.JSONWebKey{Key: key, Algorithm: "ES256", Use: "sig"}.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to encode workload private key: %v", err)
	}

	token, err := w.c.CA.SignWorkloadWITSVID(ctx, WorkloadWITSVIDParams{
		SPIFFEID: sid.ToSpiffeID(),
		TTL:      witSVIDTTL,
		Key: jose.JSONWebKey{
			Key:       &key.PublicKey,
			Algorithm: "ES256",
			Use:       "sig",
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign WIT SVID: %v", err)
	}

	log.Printf("WIT-SVID issued: %s\n", token)

	return &pb.WITSVIDResponse{
		Svids: []*pb.WITSVID{{
			SpiffeId:   sid.String(),
			WitSvid:    token,
			WitSvidKey: string(privateJWK),
		}},
	}, nil
}

func (w *WorkloadHandler) FetchWITBundles(req *pb.WITBundlesRequest, stream pb.SpiffeWorkloadAPI_FetchWITBundlesServer) error {
	// WIT-SVIDs are signed with the CA's JWT key.
	jwtKey := w.c.CA.jwtKey
	bundle := jwtbundle.FromJWTAuthorities(
		spiffeid.RequireTrustDomainFromString(w.c.Domain),
		map[string]crypto.PublicKey{jwtKey.Kid: jwtKey.Signer.Public()},
	)
	bundleBytes, err := bundle.Marshal()
	if err != nil {
		return err
	}

	if err := stream.Send(&pb.WITBundlesResponse{
		Bundles: map[string]string{w.c.Domain: string(bundleBytes)},
	}); err != nil {
		return err
	}

	// The key never rotates, so there is nothing further to send.
	<-stream.Context().Done()
	return nil
}
