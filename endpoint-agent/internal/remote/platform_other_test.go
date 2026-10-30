//go:build !windows && !remote_fake

package remote

import (
	"context"
	"testing"
)

func TestUnsupportedPlatform(t *testing.T) {
	c := New(DefaultPlatform(), func(context.Context, string, string) (Conn, error) {
		t.Fatal("must not dial on an unsupported platform")
		return nil, nil
	})
	res := c.Start(context.Background(), Params{SessionID: "x"})
	if res.Status != "failed" || res.ErrorCode != ErrUnsupportedPlatform {
		t.Fatalf("got %+v", res)
	}
}
