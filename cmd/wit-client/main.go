// wit-client fetches a WIT-SVID and the WIT bundle from a SPIFFE Workload API
// endpoint, verifies the one against the other, and prints the result.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/exp/svid/witsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func main() {
	addr := flag.String("addr", "unix:///tmp/spire.sock", "Workload API address")
	timeout := flag.Duration("timeout", 10*time.Second, "overall timeout")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	opt := workloadapi.WithAddr(*addr)

	svid, err := workloadapi.FetchWITSVID(ctx, "", opt)
	if err != nil {
		log.Fatalf("fetch WIT-SVID: %v", err)
	}
	bundles, err := workloadapi.FetchWITBundles(ctx, opt)
	if err != nil {
		log.Fatalf("fetch WIT bundles: %v", err)
	}

	if _, err := witsvid.ParseAndValidate(svid.Marshal(), bundles); err != nil {
		log.Fatalf("WIT-SVID failed verification: %v", err)
	}

	tok, err := jwt.ParseSigned(svid.Marshal(), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		log.Fatalf("parse WIT-SVID: %v", err)
	}
	var claims map[string]any
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		log.Fatalf("read claims: %v", err)
	}

	fmt.Printf("SPIFFE ID: %s\n", svid.ID)
	fmt.Printf("Key ID:    %s\n", svid.KeyID)
	fmt.Printf("Expires:   %s\n", svid.Expiry.Format(time.RFC3339))
	fmt.Printf("Bundles:   %d\n", bundles.Len())
	fmt.Printf("Claims:    %v\n", claims)
	fmt.Println("Verified:  OK")
}
