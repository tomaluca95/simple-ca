package caissuingprocess_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tomaluca95/simple-ca/internal/caissuingprocess"
	"github.com/tomaluca95/simple-ca/internal/types"
)

func readCrlNumber(t *testing.T, caFilenameCrl string) *big.Int {
	t.Helper()
	crlPem, err := os.ReadFile(caFilenameCrl)
	if err != nil {
		t.Fatal(err)
	}
	crlBlock, _ := pem.Decode(crlPem)
	if crlBlock == nil {
		t.Fatalf("no pem block in %s", caFilenameCrl)
	}
	crl, err := x509.ParseRevocationList(crlBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return crl.Number
}

// waitForCrlNumberDifferentFrom waits until the CRL on disk is not the one with
// the given number, and returns its number.
func waitForCrlNumberDifferentFrom(t *testing.T, caFilenameCrl string, previous *big.Int, timeout time.Duration) *big.Int {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if current := readCrlNumber(t, caFilenameCrl); current.Cmp(previous) != 0 {
			return current
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("the CRL was not rewritten within %s", timeout)
	return nil
}

func TestRsaCrlIsRefreshedUntilTheContextIsDone(t *testing.T) {
	logger := &types.StdLogger{}

	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	// crl_ttl of 40ms means a refresh every 10ms: long enough for the test not
	// to depend on how fast the machine is, short enough to not wait. This is
	// below the minimum a config may ask for, which is the point: the loop has
	// to hold its interval whatever the value is, since LoadOneCa does not go
	// through the config validation.
	configData := types.CertificateAuthorityType{
		Subject: types.CertificateAuthoritySubjectType{
			CommonName: "test_ca_1",
		},
		KeyConfig: types.KeyConfigType{
			Type: "rsa",
			Config: types.KeyTypeRsaConfigType{
				Size: 2048,
			},
		},
		CrlTtl:            40 * time.Millisecond,
		Validity:          testCaValidity,
		PermittedIPRanges: []string{"0.0.0.0/0"},
		ExcludedIPRanges:  []string{"0.0.0.0/0"},
	}
	oneCa, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		configData,
	)
	if err != nil {
		t.Fatal(err)
		return
	}

	caFilenameCrl := filepath.Join(dataDirectory, caId, "ca.crl.pem")
	numberAtLoad := readCrlNumber(t, caFilenameCrl)

	refreshCtx, stopRefresh := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		oneCa.KeepCrlFreshUntilDone(refreshCtx, logger.With("ca_id", caId))
	}()

	// While the context is alive the CRL is rewritten, which is what keeps the
	// one a verifier fetches from expiring.
	refreshed := waitForCrlNumberDifferentFrom(t, caFilenameCrl, numberAtLoad, 10*time.Second)

	// After the context is done the refresh stops: nothing is left running once
	// the server is gone.
	stopRefresh()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the refresh did not stop when the context was done")
	}

	numberAfterStop := readCrlNumber(t, caFilenameCrl)
	time.Sleep(200 * time.Millisecond)
	if current := readCrlNumber(t, caFilenameCrl); current.Cmp(numberAfterStop) != 0 {
		t.Errorf("expected no refresh after the context was done: crl number went from %s to %s", numberAfterStop, current)
	}

	if refreshed.Cmp(numberAtLoad) == 0 {
		t.Error("expected the crl number to change")
	}
}

func TestRsaCrlTooShortToRefreshDoesNotPanic(t *testing.T) {
	logger := &types.StdLogger{}

	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	// A config cannot ask for this: crl_ttl is validated to be at least ten
	// minutes, because rewriting the CRL that often is a server signing and
	// committing as fast as the CPU allows. LoadOneCa is reachable without that
	// validation, so the guard below still has to hold for a value that small --
	// a quarter of a nanosecond leaves no interval to build a ticker from.
	configData := types.CertificateAuthorityType{
		Subject: types.CertificateAuthoritySubjectType{
			CommonName: "test_ca_1",
		},
		KeyConfig: types.KeyConfigType{
			Type: "rsa",
			Config: types.KeyTypeRsaConfigType{
				Size: 2048,
			},
		},
		CrlTtl:            2 * time.Nanosecond,
		Validity:          testCaValidity,
		PermittedIPRanges: []string{"0.0.0.0/0"},
		ExcludedIPRanges:  []string{"0.0.0.0/0"},
	}
	oneCa, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		configData,
	)
	if err != nil {
		t.Fatal(err)
	}

	// The refresh is skipped instead of panicking on a ticker that cannot be
	// built, and the CA still works.
	refreshCtx, stopRefresh := context.WithCancel(context.Background())
	defer stopRefresh()
	done := make(chan struct{})
	go func() {
		defer close(done)
		oneCa.KeepCrlFreshUntilDone(refreshCtx, logger.With("ca_id", caId))
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the refresh did not return on a crl_ttl too short to divide")
	}

	if err := oneCa.UpdateCrl(); err != nil {
		t.Error(err)
	}
}
