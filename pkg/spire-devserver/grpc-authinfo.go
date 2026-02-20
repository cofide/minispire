// grpc_authinfo.go
package spiredevserver

import (
	"context"
	"errors"
	"log"
	"net"

	"google.golang.org/grpc/credentials"
)

var ErrInvalidConnection = errors.New("invalid connection")

type Conn struct {
	net.Conn
	Info AuthInfo
}

func (c *Conn) Close() error {
	return c.Conn.Close()
}

type grpcCredentials struct{}

func NewCredentials() credentials.TransportCredentials {
	return &grpcCredentials{}
}

func (c *grpcCredentials) ClientHandshake(_ context.Context, _ string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn.Close()
	return conn, AuthInfo{}, ErrInvalidConnection
}

func (c *grpcCredentials) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	wrappedCon, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		log.Printf("invalid connection type: %T", conn)
		return conn, AuthInfo{}, ErrInvalidConnection
	}

	// Call the platform-specific implementation
	callerInfo, err := getCallerInfo(wrappedCon)
	if err != nil {
		log.Printf("unable to get peer credentials: %v", err)
		conn.Close()
		return conn, AuthInfo{}, ErrInvalidConnection
	}

	return wrappedCon, AuthInfo{Caller: callerInfo}, nil
}

func (c *grpcCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		SecurityProtocol: "spire-attestation",
		SecurityVersion:  "0.2",
		ServerName:       "spire-agent",
	}
}

func (c *grpcCredentials) Clone() credentials.TransportCredentials {
	credentialsCopy := *c
	return &credentialsCopy
}

func (c *grpcCredentials) OverrideServerName(_ string) error {
	return nil
}

type CallerInfo struct {
	Addr       net.Addr
	PID        int32
	UID        uint32
	GID        uint32
	BinaryName string
}

type AuthInfo struct {
	Caller CallerInfo
}

func (AuthInfo) AuthType() string {
	return "spire-attestation"
}
