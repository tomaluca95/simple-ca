package webserver_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tomaluca95/simple-ca/internal/caissuingprocess"
	"github.com/tomaluca95/simple-ca/internal/pemhelper"
	"github.com/tomaluca95/simple-ca/internal/types"
	"github.com/tomaluca95/simple-ca/internal/webserver"
)

func TestRsaSignCsr(t *testing.T) {
	logger := &types.StdLogger{}

	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	opaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": true}`))
	}))
	defer opaServer.Close()

	opaUrl := opaServer.URL

	h, err := webserver.CreateHandler(
		newServerContext(t),
		logger,
		types.ConfigFileType{
			DataDirectory: dataDirectory,
			AllCaConfigs: map[string]types.CertificateAuthorityType{
				caId: {
					Subject: types.CertificateAuthoritySubjectType{
						CommonName: "test_ca_1",
					},
					KeyConfig: types.KeyConfigType{
						Type: "rsa",
						Config: types.KeyTypeRsaConfigType{
							Size: 2048,
						},
					},
					CrlTtl:            12 * time.Hour,
					Validity:          testCaValidity,
					PermittedIPRanges: []string{"0.0.0.0/0"},
					ExcludedIPRanges:  []string{"0.0.0.0/0"},
					OpaUrlSign:        &opaUrl,
					OpaUrlRevoke:      &opaUrl,
					OpaUrlIssueCa:     &opaUrl,
				},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	{
		req, err := http.NewRequest(
			http.MethodPost,
			"/ca/"+caId+"/csr/sign",
			csrSignBody(t, []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIICyjCCAbICAQAwGjEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnvKs8AjzDZgyC3bWnHV0S9mub2fHPwf/
Jx5IcP61h4c8E1rKtBXBv7SUV5dvwzGwaWGZyGVsX2EIN+UIGJXiK50y8Ayq9z1E
6t3Jg4vaWpxNpV4f5wzRPS5lEOf6xZmy6+0+QhlR3vxjSx5I11Wui/KFdJbL0BHY
oa2XZhx7Ocpa+gKl9dSi2X/C1Id3A4/vLlO6NkJAbrept07Rxa6RCBtMW6h0gmAc
MkacUamWmilnn/a10QJA1Fwg+90IN5PB7N0IohAb7hBGeegXWwfr7DMxPPoEb54x
rX5T18pFKoxKjfgnFd6YVYdJpyU6xYzj3dLAfF8gnRnjeL70NNJm6wIDAQABoGsw
aQYJKoZIhvcNAQkOMVwwWjAsBgNVHREEJTAjgg93d3cuZXhhbXBsZS5jb22CEHd3
dzIuZXhhbXBsZS5jb20wHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAsG
A1UdDwQEAwIFIDANBgkqhkiG9w0BAQsFAAOCAQEAmlQcazr6RNRNMfzboPNW+fIK
fVaKZgqI3prkP0BEY/g+kx0Oq6sTco+7sgavKsNGZokKhwP5oGm0NyBKcoE0rtxi
mSYsbRGX0/D35dYs1Y3lgZZetxBLPjsFpb2J67n9kX9RweQlDjIbj/4Ai/7RN3Yn
bmliWkoMtg7vO1JCzpZHwb4MkWMEI48mxBrv8tfjcxrRzSX+eEcgSn5nZ1tF9Fsw
JKS1ql5MOdoeXltvK2f9Thj/Spnd3sKzsy1TDkdMhN2LXTcCLj1TwFKHJm4S7jPa
N1FQ0v5KwW0Rhe30WZIMvflSuCzoj3nB3U/y4kD/j1HJ5TBRzV6wL3ZzdpXCuQ==
-----END CERTIFICATE REQUEST-----
`), ""),
		)
		if err != nil {
			t.Fatal(err)
		}
		h.ServeHTTP(rr, req)
	}

	if statusCode := rr.Result().StatusCode; statusCode != 200 {
		t.Fatalf("invalid status code %d", statusCode)
	}

	issueRespBody, err := io.ReadAll(rr.Body)
	if err != nil {
		t.Fatal(err)
	}

	c, err := pemhelper.FromPemToCertificate(issueRespBody)
	if err != nil {
		t.Fatal(err)
	}

	if c.Subject.String() != "CN=www.example.com" {
		t.Fatalf("invalid value %#v", c.Subject.String())
	}
}

func TestRsaSignCsrAndRevoke(t *testing.T) {
	logger := &types.StdLogger{}

	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	opaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": true}`))
	}))
	defer opaServer.Close()

	opaUrl := opaServer.URL

	h, err := webserver.CreateHandler(
		newServerContext(t),
		logger,
		types.ConfigFileType{
			DataDirectory: dataDirectory,
			AllCaConfigs: map[string]types.CertificateAuthorityType{
				caId: {
					Subject: types.CertificateAuthoritySubjectType{
						CommonName: "test_ca_1",
					},
					KeyConfig: types.KeyConfigType{
						Type: "rsa",
						Config: types.KeyTypeRsaConfigType{
							Size: 2048,
						},
					},
					CrlTtl:            12 * time.Hour,
					Validity:          testCaValidity,
					PermittedIPRanges: []string{"0.0.0.0/0"},
					ExcludedIPRanges:  []string{"0.0.0.0/0"},
					OpaUrlSign:        &opaUrl,
					OpaUrlRevoke:      &opaUrl,
					OpaUrlIssueCa:     &opaUrl,
				},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	rrSignRequest := httptest.NewRecorder()
	{
		req, err := http.NewRequest(
			http.MethodPost,
			"/ca/"+caId+"/csr/sign",
			csrSignBody(t, []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIICyjCCAbICAQAwGjEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnvKs8AjzDZgyC3bWnHV0S9mub2fHPwf/
Jx5IcP61h4c8E1rKtBXBv7SUV5dvwzGwaWGZyGVsX2EIN+UIGJXiK50y8Ayq9z1E
6t3Jg4vaWpxNpV4f5wzRPS5lEOf6xZmy6+0+QhlR3vxjSx5I11Wui/KFdJbL0BHY
oa2XZhx7Ocpa+gKl9dSi2X/C1Id3A4/vLlO6NkJAbrept07Rxa6RCBtMW6h0gmAc
MkacUamWmilnn/a10QJA1Fwg+90IN5PB7N0IohAb7hBGeegXWwfr7DMxPPoEb54x
rX5T18pFKoxKjfgnFd6YVYdJpyU6xYzj3dLAfF8gnRnjeL70NNJm6wIDAQABoGsw
aQYJKoZIhvcNAQkOMVwwWjAsBgNVHREEJTAjgg93d3cuZXhhbXBsZS5jb22CEHd3
dzIuZXhhbXBsZS5jb20wHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAsG
A1UdDwQEAwIFIDANBgkqhkiG9w0BAQsFAAOCAQEAmlQcazr6RNRNMfzboPNW+fIK
fVaKZgqI3prkP0BEY/g+kx0Oq6sTco+7sgavKsNGZokKhwP5oGm0NyBKcoE0rtxi
mSYsbRGX0/D35dYs1Y3lgZZetxBLPjsFpb2J67n9kX9RweQlDjIbj/4Ai/7RN3Yn
bmliWkoMtg7vO1JCzpZHwb4MkWMEI48mxBrv8tfjcxrRzSX+eEcgSn5nZ1tF9Fsw
JKS1ql5MOdoeXltvK2f9Thj/Spnd3sKzsy1TDkdMhN2LXTcCLj1TwFKHJm4S7jPa
N1FQ0v5KwW0Rhe30WZIMvflSuCzoj3nB3U/y4kD/j1HJ5TBRzV6wL3ZzdpXCuQ==
-----END CERTIFICATE REQUEST-----
`), ""),
		)
		if err != nil {
			t.Fatal(err)
		}
		h.ServeHTTP(rrSignRequest, req)
	}

	if statusCode := rrSignRequest.Result().StatusCode; statusCode != 200 {
		t.Fatalf("invalid status code %d", statusCode)
	}

	issueRespBody, err := io.ReadAll(rrSignRequest.Body)
	if err != nil {
		t.Fatal(err)
	}

	signedCrt, err := pemhelper.FromPemToCertificate(issueRespBody)
	if err != nil {
		t.Fatal(err)
	}

	if signedCrt.Subject.String() != "CN=www.example.com" {
		t.Fatalf("invalid value %#v", signedCrt.Subject.String())
	}

	rrRevoke := httptest.NewRecorder()
	{
		req, err := http.NewRequest(
			http.MethodPost,
			"/ca/"+caId+"/crt/revoke/"+signedCrt.SerialNumber.String(),
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		h.ServeHTTP(rrRevoke, req)
	}

	if statusCode := rrRevoke.Result().StatusCode; statusCode != 202 {
		t.Fatalf("invalid status code %d", statusCode)
	}

	rrCurrentCrl := httptest.NewRecorder()
	{
		req, err := http.NewRequest(
			http.MethodGet,
			"/ca/"+caId+"/crt/crl.pem",
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		h.ServeHTTP(rrCurrentCrl, req)
	}

	if statusCode := rrCurrentCrl.Result().StatusCode; statusCode != 200 {
		t.Fatalf("invalid status code %d", statusCode)
	}
	crlRespBody, err := io.ReadAll(rrCurrentCrl.Body)
	if err != nil {
		t.Fatal(err)
	}
	pemBlock, rest := pem.Decode(crlRespBody)
	if restLen := len(rest); restLen != 0 {
		t.Fatal("invalid reminder")
	}
	if pemBlock == nil {
		t.Fatalf("no pem block in %s", crlRespBody)
	}
	crlInfo, err := x509.ParseRevocationList(pemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, r := range crlInfo.RevokedCertificateEntries {
		found = found || r.SerialNumber.Cmp(signedCrt.SerialNumber) == 0
	}

	if !found {
		t.Fatal("crl not containing")
	}
}

func TestRsaGetIssuer(t *testing.T) {
	logger := &types.StdLogger{}

	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	opaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": true}`))
	}))
	defer opaServer.Close()

	opaUrl := opaServer.URL

	h, err := webserver.CreateHandler(
		newServerContext(t),
		logger,
		types.ConfigFileType{
			DataDirectory: dataDirectory,
			AllCaConfigs: map[string]types.CertificateAuthorityType{
				caId: {
					Subject: types.CertificateAuthoritySubjectType{
						CommonName: "test_ca_1",
					},
					KeyConfig: types.KeyConfigType{
						Type: "rsa",
						Config: types.KeyTypeRsaConfigType{
							Size: 2048,
						},
					},
					CrlTtl:            12 * time.Hour,
					Validity:          testCaValidity,
					PermittedIPRanges: []string{"0.0.0.0/0"},
					ExcludedIPRanges:  []string{"0.0.0.0/0"},
					OpaUrlSign:        &opaUrl,
					OpaUrlRevoke:      &opaUrl,
					OpaUrlIssueCa:     &opaUrl,
				},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	rrCurrentCrt := httptest.NewRecorder()
	{
		req, err := http.NewRequest(
			http.MethodGet,
			"/ca/"+caId+"/issuer.pem",
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		h.ServeHTTP(rrCurrentCrt, req)
	}

	if statusCode := rrCurrentCrt.Result().StatusCode; statusCode != 200 {
		t.Fatalf("invalid status code %d", statusCode)
	}
	crtRespBody, err := io.ReadAll(rrCurrentCrt.Body)
	if err != nil {
		t.Fatal(err)
	}
	pemBlock, rest := pem.Decode(crtRespBody)
	if restLen := len(rest); restLen != 0 {
		t.Fatal("invalid reminder")
	}
	if pemBlock == nil {
		t.Fatalf("no pem block in %s", crtRespBody)
	}
	crtInfo, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if crtInfo.Issuer.String() != "CN=test_ca_1" {
		t.Fatalf("crt not issuer %#v", crtInfo.Issuer.String())
	}
}

func TestRsaSignCsrHonorsNotAfter(t *testing.T) {
	logger := &types.StdLogger{}

	var lastOpaInput string
	opaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		lastOpaInput = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": true}`))
	}))
	defer opaServer.Close()

	dataDirectory := t.TempDir()
	caId := "test_ca_1"
	opaUrl := opaServer.URL

	h, err := webserver.CreateHandler(
		newServerContext(t),
		logger,
		types.ConfigFileType{
			DataDirectory: dataDirectory,
			AllCaConfigs: map[string]types.CertificateAuthorityType{
				caId: {
					Subject: types.CertificateAuthoritySubjectType{
						CommonName: "test_ca_1",
					},
					KeyConfig: types.KeyConfigType{
						Type: "rsa",
						Config: types.KeyTypeRsaConfigType{
							Size: 2048,
						},
					},
					CrlTtl:            12 * time.Hour,
					Validity:          testCaValidity,
					PermittedIPRanges: []string{"0.0.0.0/0"},
					ExcludedIPRanges:  []string{"0.0.0.0/0"},
					OpaUrlSign:        &opaUrl,
					OpaUrlRevoke:      &opaUrl,
					OpaUrlIssueCa:     &opaUrl,
				},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "www.example.com"},
		DNSNames: []string{"www.example.com"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	requested := time.Now().UTC().Truncate(time.Second).Add(2 * time.Hour)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodPost, "/ca/"+caId+"/csr/sign", csrSignBody(t, csrPEM, requested.Format(time.RFC3339)))
	if err != nil {
		t.Fatal(err)
	}
	h.ServeHTTP(rr, req)

	if statusCode := rr.Result().StatusCode; statusCode != 200 {
		t.Fatalf("invalid status code %d body=%v", statusCode, rr.Body.String())
	}
	leaf, err := pemhelper.FromPemToCertificate(rr.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !leaf.NotAfter.Equal(requested) {
		t.Fatalf("leaf NotAfter = %v, want requested %v", leaf.NotAfter, requested)
	}
	if !strings.Contains(lastOpaInput, `"not_after":"`+requested.Format(time.RFC3339)+`"`) {
		t.Fatalf("OPA input missing proposed_certificate.not_after, got %s", lastOpaInput)
	}

	rrBad := httptest.NewRecorder()
	reqBad, err := http.NewRequest(http.MethodPost, "/ca/"+caId+"/csr/sign", csrSignBody(t, csrPEM, "not-a-timestamp"))
	if err != nil {
		t.Fatal(err)
	}
	h.ServeHTTP(rrBad, reqBad)
	if statusCode := rrBad.Result().StatusCode; statusCode != 400 {
		t.Fatalf("invalid not_after must be 400, got %d", statusCode)
	}
}

func csrSignBody(t *testing.T, csrPem []byte, notAfter string) io.Reader {
	t.Helper()
	payload, err := json.Marshal(map[string]string{
		"csr":       string(csrPem),
		"not_after": notAfter,
	})
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(payload)
}

func TestRsaCrlAvailableBeforeFirstRevoke(t *testing.T) {
	logger := &types.StdLogger{}

	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	opaServer := newOpaServer(t, http.StatusOK, `{"result": true}`)

	h, err := webserver.CreateHandler(
		newServerContext(t),
		logger,
		newWebserverConfig(t, dataDirectory, opaServer.URL, opaServer.URL, opaServer.URL),
	)
	if err != nil {
		t.Fatal(err)
	}

	rrCrl := httptest.NewRecorder()
	{
		req, err := http.NewRequest(
			http.MethodGet,
			"/ca/"+caId+"/crt/crl.pem",
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		h.ServeHTTP(rrCrl, req)
	}

	if statusCode := rrCrl.Result().StatusCode; statusCode != 200 {
		t.Fatalf("invalid status code %d", statusCode)
	}
	crlRespBody, err := io.ReadAll(rrCrl.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(crlRespBody) == 0 {
		t.Fatal("expected a CRL body before the first revoke")
	}
	pemBlock, rest := pem.Decode(crlRespBody)
	if restLen := len(rest); restLen != 0 {
		t.Fatal("invalid reminder")
	}
	if pemBlock == nil {
		t.Fatalf("no pem block in %s", crlRespBody)
	}
	crlInfo, err := x509.ParseRevocationList(pemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if crlLen := len(crlInfo.RevokedCertificateEntries); crlLen != 0 {
		t.Fatalf("expected an empty CRL, got %d revoked entries", crlLen)
	}
}

func TestRsaPemResponsesContentType(t *testing.T) {
	logger := &types.StdLogger{}

	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	opaServer := newOpaServer(t, http.StatusOK, `{"result": true}`)

	h, err := webserver.CreateHandler(
		newServerContext(t),
		logger,
		newWebserverConfig(t, dataDirectory, opaServer.URL, opaServer.URL, opaServer.URL),
	)
	if err != nil {
		t.Fatal(err)
	}

	getPemContentType := func(path string) string {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, path, nil)
		if err != nil {
			t.Fatal(err)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if statusCode := rr.Result().StatusCode; statusCode != 200 {
			t.Fatalf("GET %s: invalid status code %d", path, statusCode)
		}
		return rr.Header().Get("Content-Type")
	}

	for _, path := range []string{
		"/ca/" + caId + "/issuer.pem",
		"/ca/" + caId + "/crt/crl.pem",
	} {
		if ct := getPemContentType(path); ct != "application/x-pem-file" {
			t.Errorf("GET %s: expected Content-Type application/x-pem-file, got %q", path, ct)
		}
	}

	// The sign response is also a PEM document.
	csrPem := makeCsrPem(t, nil, nil)
	req, err := http.NewRequest(
		http.MethodPost,
		"/ca/"+caId+"/csr/sign",
		csrSignBody(t, csrPem, ""),
	)
	if err != nil {
		t.Fatal(err)
	}
	rrSign := httptest.NewRecorder()
	h.ServeHTTP(rrSign, req)
	if statusCode := rrSign.Result().StatusCode; statusCode != 200 {
		t.Fatalf("POST sign: invalid status code %d", statusCode)
	}
	if ct := rrSign.Header().Get("Content-Type"); ct != "application/x-pem-file" {
		t.Errorf("POST sign: expected Content-Type application/x-pem-file, got %q", ct)
	}
}

func TestRsaRequestLogCarriesRequestId(t *testing.T) {
	var logOutput bytes.Buffer
	logger := types.NewStdLogger(slog.New(types.NewLogHandler(
		slog.NewTextHandler(&logOutput, &slog.HandlerOptions{Level: slog.LevelDebug}),
	)))

	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	// Deny the decision so the request produces an authorization log too.
	opaServer := newOpaServer(t, http.StatusOK, `{"result": false}`)

	h, err := webserver.CreateHandler(
		newServerContext(t),
		logger,
		newWebserverConfig(t, dataDirectory, opaServer.URL, opaServer.URL, opaServer.URL),
	)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(
		http.MethodPost,
		"/ca/"+caId+"/csr/sign",
		csrSignBody(t, makeCsrPem(t, nil, nil), ""),
	)
	if err != nil {
		t.Fatal(err)
	}
	clientRequestId := "req777abcdef"
	req.Header.Set("X-Request-ID", clientRequestId)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if statusCode := rr.Result().StatusCode; statusCode != http.StatusForbidden {
		t.Fatalf("invalid status code %d", statusCode)
	}

	// The id the client sent must be the id the logs use, and it must be
	// returned in the response header so the client can find it again.
	if got := rr.Result().Header.Get("X-Request-ID"); got != clientRequestId {
		t.Errorf("response X-Request-ID = %q, want the id the client sent", got)
	}

	// The access log and the authorization decision of the same request must
	// both carry the request id, so they can be traced together.
	tracedLines := 0
	for _, logLine := range strings.Split(strings.TrimSpace(logOutput.String()), "\n") {
		if strings.Contains(logLine, "request_id="+clientRequestId) {
			tracedLines++
		}
	}
	if tracedLines < 2 {
		t.Errorf("expected at least 2 log lines with the client request id, got %d:\n%s", tracedLines, logOutput.String())
	}
}

// The access log carries the client address, the same value the authorization
// input already sends to OPA. Without it the CA's own output cannot answer
// which client made a request -- only the OPA decision log can, and that is a
// separate system that may not be kept.
func TestRsaRequestLogCarriesTheClientAddress(t *testing.T) {
	var logOutput bytes.Buffer
	logger := types.NewStdLogger(slog.New(types.NewLogHandler(
		slog.NewTextHandler(&logOutput, &slog.HandlerOptions{Level: slog.LevelDebug}),
	)))

	h, err := webserver.CreateHandler(
		newServerContext(t),
		logger,
		newWebserverConfig(t, t.TempDir(), "http://opa.invalid/allow", "http://opa.invalid/allow", "http://opa.invalid/allow"),
	)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodGet, "/ca/test_ca_1/issuer.pem", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "192.0.2.1:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if statusCode := rr.Result().StatusCode; statusCode != http.StatusOK {
		t.Fatalf("invalid status code %d", statusCode)
	}

	found := false
	for _, logLine := range strings.Split(strings.TrimSpace(logOutput.String()), "\n") {
		if strings.Contains(logLine, `msg="http request"`) && strings.Contains(logLine, "remote_addr=192.0.2.1:1234") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the access log to carry remote_addr=192.0.2.1:1234, got:\n%s", logOutput.String())
	}
}

func TestRsaRequestIdAcceptanceAndEcho(t *testing.T) {
	var logOutput bytes.Buffer
	logger := types.NewStdLogger(slog.New(types.NewLogHandler(
		slog.NewTextHandler(&logOutput, &slog.HandlerOptions{Level: slog.LevelDebug}),
	)))
	h, err := webserver.CreateHandler(
		newServerContext(t),
		logger,
		newWebserverConfig(t, t.TempDir(), "http://opa.invalid/allow", "http://opa.invalid/allow", "http://opa.invalid/allow"),
	)
	if err != nil {
		t.Fatal(err)
	}

	// The id that was actually used must always be returned in the response
	// header. An alphanumeric id of up to maxRequestIdLength characters is used
	// as-is; a longer one is refused with a 400; a missing or non-alphanumeric
	// one is replaced by a generated UUID v4.
	requestWith := func(clientId string) (int, string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/ca/test_ca_1/issuer.pem", nil)
		if clientId != "" {
			req.Header.Set("X-Request-ID", clientId)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		used := rr.Result().Header.Get("X-Request-ID")
		if used == "" {
			t.Fatal("the response must carry an X-Request-ID")
		}
		return rr.Result().StatusCode, used
	}

	generatedUuid := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

	clientId := "req777abcdef"
	if status, used := requestWith(clientId); status != http.StatusOK || used != clientId {
		t.Errorf("an alphanumeric id must be used as-is, got status %d id %q", status, used)
	}

	longId := strings.Repeat("a", 36)
	if status, used := requestWith(longId); status != http.StatusOK || used != longId {
		t.Errorf("a 36-character id must be used as-is, got status %d id %q", status, used)
	}

	// One character too many and the request is refused, without the
	// client-controlled value ever reaching a log record.
	tooLong := strings.Repeat("a", 37)
	if status, used := requestWith(tooLong); status != http.StatusBadRequest || !generatedUuid.MatchString(used) {
		t.Errorf("a 37-character id must be refused with a generated id, got status %d id %q", status, used)
	}
	if strings.Contains(logOutput.String(), tooLong) {
		t.Error("a too-long id must never reach a log line")
	}

	if status, used := requestWith(""); status != http.StatusOK || !generatedUuid.MatchString(used) {
		t.Errorf("a missing id must be replaced by a generated UUID, got status %d id %q", status, used)
	}

	if status, used := requestWith("trace-123"); status != http.StatusOK || !generatedUuid.MatchString(used) {
		t.Errorf("a non-alphanumeric id must be replaced by a generated UUID, got status %d id %q", status, used)
	}
	if strings.Contains(logOutput.String(), "trace-123") {
		t.Error("a rejected non-alphanumeric id must never reach a log line")
	}

	huge := strings.Repeat("x", 50*1024)
	if status, used := requestWith(huge); status != http.StatusBadRequest || !generatedUuid.MatchString(used) {
		t.Errorf("an oversized id must be refused with a generated id, got status %d id %q", status, used)
	}
	if strings.Contains(logOutput.String(), huge) {
		t.Error("a rejected oversized id must never reach a log line")
	}
}

func TestRsaMissingCrlFileAnswersNoContent(t *testing.T) {
	logger := &types.StdLogger{}
	dataDirectory := t.TempDir()

	h, err := webserver.CreateHandler(
		newServerContext(t),
		logger,
		newWebserverConfig(t, dataDirectory, "http://opa.invalid/allow", "http://opa.invalid/allow", "http://opa.invalid/allow"),
	)
	if err != nil {
		t.Fatal(err)
	}

	fetchCrl := func() (int, []byte) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, "/ca/test_ca_1/crt/crl.pem", nil)
		if err != nil {
			t.Fatal(err)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		body, err := io.ReadAll(rr.Body)
		if err != nil {
			t.Fatal(err)
		}
		return rr.Result().StatusCode, body
	}

	// A freshly loaded CA serves its CRL.
	if status, body := fetchCrl(); status != http.StatusOK || len(body) == 0 {
		t.Fatalf("expected an existing CRL body, got status %d with %d bytes", status, len(body))
	}

	// Once the CRL file is gone, the same request must stop being a 200 with
	// an empty body (which clients read as "nothing is revoked").
	if err := os.Remove(filepath.Join(dataDirectory, "test_ca_1", "ca.crl.pem")); err != nil {
		t.Fatal(err)
	}
	status, body := fetchCrl()
	if status != http.StatusNoContent {
		t.Errorf("missing CRL file must answer 204, got %d", status)
	}
	if len(body) != 0 {
		t.Errorf("a 204 must carry no body, got %d bytes", len(body))
	}
}

// writeCrlPem signs a CRL for the CA in dataDirectory with the CA's own key and
// writes it over the published one. The route reads the file on every request,
// so this is how a test presents a client with a revision the server did not
// just write: an expired one, or a newer number.
func writeCrlPem(t *testing.T, h http.Handler, dataDirectory string, crlNumber int64, nextUpdate time.Time) {
	t.Helper()
	caId := "test_ca_1"

	keyPemBytes, err := os.ReadFile(filepath.Join(dataDirectory, caId, "ca.key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, _ := pem.Decode(keyPemBytes)
	if keyBlock == nil {
		t.Fatalf("no pem block in the CA key")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	// The issuer certificate is not in the data directory: it is served.
	rrIssuer := httptest.NewRecorder()
	{
		req, err := http.NewRequest(http.MethodGet, "/ca/"+caId+"/issuer.pem", nil)
		if err != nil {
			t.Fatal(err)
		}
		h.ServeHTTP(rrIssuer, req)
	}
	if statusCode := rrIssuer.Result().StatusCode; statusCode != http.StatusOK {
		t.Fatalf("GET issuer.pem: invalid status code %d", statusCode)
	}
	issuerBlock, _ := pem.Decode(rrIssuer.Body.Bytes())
	if issuerBlock == nil {
		t.Fatalf("no pem block in %s", rrIssuer.Body.Bytes())
	}
	issuer, err := x509.ParseCertificate(issuerBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	crlDer, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(crlNumber),
		// A thisUpdate an hour before the nextUpdate, whichever of the two the
		// caller picks: x509 refuses a list that is not a window.
		ThisUpdate: nextUpdate.Add(-time.Hour),
		NextUpdate: nextUpdate,
	}, issuer, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(dataDirectory, caId, "ca.crl.pem"),
		pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDer}),
		os.FileMode(0o644),
	); err != nil {
		t.Fatal(err)
	}
}

// fetchCrlPem requests the CRL of test_ca_1 with the given request headers.
func fetchCrlPem(t *testing.T, h http.Handler, requestHeaders map[string]string) (int, []byte, http.Header) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "/ca/test_ca_1/crt/crl.pem", nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range requestHeaders {
		req.Header.Set(name, value)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	body, err := io.ReadAll(rr.Body)
	if err != nil {
		t.Fatal(err)
	}
	return rr.Result().StatusCode, body, rr.Header()
}

func TestRsaCrlPemForcesRevalidationAndAnswersNotModified(t *testing.T) {
	logger := &types.StdLogger{}
	dataDirectory := t.TempDir()

	h, err := webserver.CreateHandler(
		newServerContext(t),
		logger,
		newWebserverConfig(t, dataDirectory, "http://opa.invalid/allow", "http://opa.invalid/allow", "http://opa.invalid/allow"),
	)
	if err != nil {
		t.Fatal(err)
	}

	// The first request is a full 200 with the caching headers: a strong ETag
	// over the exact body, the modification time a cache can re-answer from,
	// and a policy that makes the copy storable but never fresh.
	status, crlBody, headers := fetchCrlPem(t, h, nil)
	if status != http.StatusOK {
		t.Fatalf("invalid status code %d", status)
	}
	if len(crlBody) == 0 {
		t.Fatal("expected a CRL body")
	}
	if ct := headers.Get("Content-Type"); ct != "application/x-pem-file" {
		t.Errorf("Content-Type = %q, want application/x-pem-file", ct)
	}
	digest := sha256.Sum256(crlBody)
	etag := `"` + hex.EncodeToString(digest[:]) + `"`
	if got := headers.Get("ETag"); got != etag {
		t.Errorf("ETag = %q, want the strong tag %q over the body", got, etag)
	}
	// The client may keep the CRL, but every use of it must be a revalidation
	// request, and nothing may be served while the server cannot confirm it.
	if got := headers.Get("Cache-Control"); got != "no-cache, must-revalidate" {
		t.Errorf("Cache-Control = %q, want no-cache, must-revalidate", got)
	}
	// There is no window in which the body may be used as it is, so no Expires
	// is offered to a cache that would rather believe one than ask.
	if got := headers.Get("Expires"); got != "" {
		t.Errorf("Expires = %q, want no Expires on a response that is never fresh", got)
	}
	lastModified := headers.Get("Last-Modified")
	if _, err := http.ParseTime(lastModified); err != nil {
		t.Errorf("Last-Modified %q is not an HTTP date: %v", lastModified, err)
	}
	// The expiry is explicit and in ISO 8601, taken from the CRL itself: the
	// client can read the moment its copy stops being authoritative without
	// knowing anything about HTTP.
	pemBlock, _ := pem.Decode(crlBody)
	if pemBlock == nil {
		t.Fatalf("no pem block in %s", crlBody)
	}
	crlInfo, err := x509.ParseRevocationList(pemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := headers.Get("X-Crl-Next-Update"), crlInfo.NextUpdate.UTC().Format(time.RFC3339); got != want {
		t.Errorf("X-Crl-Next-Update = %q, want the CRL's own nextUpdate %q", got, want)
	}

	// The same validator: 304 with no body, still leading with the ETag so a
	// cache can re-answer the stored copy.
	status, body, headers := fetchCrlPem(t, h, map[string]string{"If-None-Match": etag})
	if status != http.StatusNotModified {
		t.Errorf("If-None-Match with the current ETag: status %d, want 304", status)
	}
	if len(body) != 0 {
		t.Errorf("a 304 must carry no body, got %d bytes", len(body))
	}
	if got := headers.Get("ETag"); got != etag {
		t.Errorf("a 304 must still carry the ETag, got %q", got)
	}
	if got := headers.Get("Cache-Control"); got != "no-cache, must-revalidate" {
		t.Errorf("a 304 must still carry the Cache-Control, got %q", got)
	}

	// "*" matches any current representation, and a W/ prefix on the cached
	// copy is ignored the way RFC 9110 requires for If-None-Match.
	if status, _, _ := fetchCrlPem(t, h, map[string]string{"If-None-Match": "*"}); status != http.StatusNotModified {
		t.Errorf("If-None-Match *: status %d, want 304", status)
	}
	if status, _, _ := fetchCrlPem(t, h, map[string]string{"If-None-Match": "W/" + etag}); status != http.StatusNotModified {
		t.Errorf("If-None-Match W/ with the current ETag: status %d, want 304", status)
	}
	if status, _, _ := fetchCrlPem(t, h, map[string]string{"If-None-Match": `"x", "y", ` + "W/" + etag}); status != http.StatusNotModified {
		t.Errorf("If-None-Match list containing the current ETag: status %d, want 304", status)
	}

	// A different validator means the copy is stale: full 200 again.
	if status, _, _ := fetchCrlPem(t, h, map[string]string{"If-None-Match": `"deadbeef"`}); status != http.StatusOK {
		t.Errorf("If-None-Match with a different ETag: status %d, want 200", status)
	}

	// If-Modified-Since answers from the Last-Modified moment: not newer is
	// not modified. A date before the CRL was written is newer by comparison.
	if status, _, _ := fetchCrlPem(t, h, map[string]string{"If-Modified-Since": lastModified}); status != http.StatusNotModified {
		t.Errorf("If-Modified-Since at Last-Modified: status %d, want 304", status)
	}
	if status, _, _ := fetchCrlPem(t, h, map[string]string{"If-Modified-Since": time.Now().Add(time.Hour).UTC().Format(http.TimeFormat)}); status != http.StatusNotModified {
		t.Errorf("If-Modified-Since in the future: status %d, want 304", status)
	}
	if status, _, _ := fetchCrlPem(t, h, map[string]string{"If-Modified-Since": "Mon, 01 Jan 1990 00:00:00 GMT"}); status != http.StatusOK {
		t.Errorf("If-Modified-Since before the CRL was written: status %d, want 200", status)
	}

	// The validator is decisive: a matching If-None-Match answers 304 even
	// against a contradicting If-Modified-Since, and a non-matching one must
	// answer 200 even when If-Modified-Since would have said 304.
	if status, _, _ := fetchCrlPem(t, h, map[string]string{
		"If-None-Match":     etag,
		"If-Modified-Since": "Mon, 01 Jan 1990 00:00:00 GMT",
	}); status != http.StatusNotModified {
		t.Errorf("matching If-None-Match must answer 304 despite a stale If-Modified-Since, got %d", status)
	}
	if status, _, _ := fetchCrlPem(t, h, map[string]string{
		"If-None-Match":     `"deadbeef"`,
		"If-Modified-Since": lastModified,
	}); status != http.StatusOK {
		t.Errorf("non-matching If-None-Match must answer 200 despite a fresh If-Modified-Since, got %d", status)
	}
}

func TestRsaCrlPemRefusesToConfirmAnExpiredCrl(t *testing.T) {
	logger := &types.StdLogger{}
	dataDirectory := t.TempDir()

	h, err := webserver.CreateHandler(
		newServerContext(t),
		logger,
		newWebserverConfig(t, dataDirectory, "http://opa.invalid/allow", "http://opa.invalid/allow", "http://opa.invalid/allow"),
	)
	if err != nil {
		t.Fatal(err)
	}

	// A CRL inside its validity is confirmed with 304, expiry and all.
	status, _, headers := fetchCrlPem(t, h, nil)
	if status != http.StatusOK {
		t.Fatalf("invalid status code %d", status)
	}
	etag := headers.Get("ETag")
	if nextUpdate, err := time.Parse(time.RFC3339, headers.Get("X-Crl-Next-Update")); err != nil {
		t.Fatalf("X-Crl-Next-Update is not an ISO 8601 timestamp: %v", err)
	} else if !nextUpdate.After(time.Now()) {
		t.Fatalf("X-Crl-Next-Update = %v, want a time in the future", nextUpdate)
	}
	if status, _, _ := fetchCrlPem(t, h, map[string]string{"If-None-Match": etag}); status != http.StatusNotModified {
		t.Fatalf("a CRL inside its validity must be confirmed with 304, got %d", status)
	}

	// An expired CRL published in place of the fresh one. The refresher renews
	// every crl_ttl/4, which is at least 2m30s, so nothing else writes the file
	// while this test reads it.
	writeCrlPem(t, h, dataDirectory, 2, time.Now().Add(-time.Hour))

	// The file as it is now, which no later request may change.
	_, _, headers = fetchCrlPem(t, h, nil)
	fileEtag := headers.Get("ETag")
	expiredAt := headers.Get("X-Crl-Next-Update")
	if nextUpdate, err := time.Parse(time.RFC3339, expiredAt); err != nil {
		t.Fatalf("X-Crl-Next-Update is not an ISO 8601 timestamp: %v", err)
	} else if nextUpdate.After(time.Now()) {
		t.Fatalf("X-Crl-Next-Update = %v, want the CRL to be expired by now", nextUpdate)
	}

	// The same bytes, the same validator, an expired list: 304 would tell the
	// client to go on trusting a CRL that is no longer authoritative.
	status, body, headers := fetchCrlPem(t, h, map[string]string{"If-None-Match": fileEtag})
	if status != http.StatusOK {
		t.Errorf("an expired CRL must not be confirmed as not changed: status %d, want 200", status)
	}
	if len(body) == 0 {
		t.Error("the full CRL must be served again once it has expired")
	}
	if got := headers.Get("ETag"); got != fileEtag {
		t.Errorf("the CRL file should not have changed, and the 200 is the expiry's doing: ETag %q, want %q", got, fileEtag)
	}
	if got := headers.Get("X-Crl-Next-Update"); got != expiredAt {
		t.Errorf("X-Crl-Next-Update = %q, want the expired %q", got, expiredAt)
	}
	// The date alone is refused the same way.
	if status, _, _ := fetchCrlPem(t, h, map[string]string{"If-Modified-Since": headers.Get("Last-Modified")}); status != http.StatusOK {
		t.Errorf("an expired CRL must not be confirmed with If-Modified-Since: status %d, want 200", status)
	}
}

func TestRsaCreateHandlerInvalidConfigFails(t *testing.T) {
	logger := &types.StdLogger{}
	dataDirectory := t.TempDir()

	configObject := newWebserverConfig(t, dataDirectory, "http://opa.example/allow", "http://opa.example/allow", "http://opa.example/allow")
	caConfig := configObject.AllCaConfigs["test_ca_1"]
	caConfig.CrlTtl = 0
	configObject.AllCaConfigs["test_ca_1"] = caConfig

	_, err := webserver.CreateHandler(newServerContext(t), logger, configObject)
	if !errors.Is(err, types.ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestRsaCreateHandlerLockedDataDirectoryFails(t *testing.T) {
	logger := &types.StdLogger{}
	dataDirectory := t.TempDir()

	unlockDataDirectory, err := caissuingprocess.LockDataDirectory(dataDirectory)
	if err != nil {
		t.Fatal(err)
	}
	defer unlockDataDirectory()

	unblockUrl := "http://127.0.0.1:1/allow"
	_, err = webserver.CreateHandler(
		newServerContext(t),
		logger,
		newWebserverConfig(t, dataDirectory, unblockUrl, unblockUrl, unblockUrl),
	)
	if !errors.Is(err, caissuingprocess.ErrDataDirectoryLocked) {
		t.Errorf("expected ErrDataDirectoryLocked, got %v", err)
	}
}

func TestRsaCreateHandlerKeepsDataDirectoryLocked(t *testing.T) {
	logger := &types.StdLogger{}
	dataDirectory := t.TempDir()

	opaServer := newOpaServer(t, http.StatusOK, `{"result": true}`)
	h, err := webserver.CreateHandler(
		newServerContext(t),
		logger,
		newWebserverConfig(t, dataDirectory, opaServer.URL, opaServer.URL, opaServer.URL),
	)
	if err != nil {
		t.Fatal(err)
	}
	if h == nil {
		t.Fatal("expected a handler")
	}

	// A server that drops its lock lets a CLI run, or a second server, work on
	// the same data directory while it is serving from it. The lock must
	// outlive CreateHandler, so it is probed after a garbage collection: with
	// the lock dropped, the lock file was finalized about 190ms into the
	// server life and the lock was gone.
	runtime.GC()
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	if _, err := caissuingprocess.LockDataDirectory(dataDirectory); !errors.Is(err, caissuingprocess.ErrDataDirectoryLocked) {
		t.Errorf("expected the data directory to still be locked, got %v", err)
	}
}

// newServerContext returns a context cancelled when the test ends, so the
// background CRL refresh every handler starts stops with the test instead of
// outliving it.
func newServerContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return ctx
}

func newWebserverConfig(t *testing.T, dataDirectory string, opaUrlSign string, opaUrlRevoke string, opaUrlIssueCa string) types.ConfigFileType {
	t.Helper()
	return types.ConfigFileType{
		DataDirectory: dataDirectory,
		AllCaConfigs: map[string]types.CertificateAuthorityType{
			"test_ca_1": {
				Subject:           types.CertificateAuthoritySubjectType{CommonName: "test_ca_1"},
				KeyConfig:         types.KeyConfigType{Type: "rsa", Config: types.KeyTypeRsaConfigType{Size: 2048}},
				CrlTtl:            12 * time.Hour,
				Validity:          testCaValidity,
				PermittedIPRanges: []string{"0.0.0.0/0"},
				ExcludedIPRanges:  []string{"0.0.0.0/0"},
				OpaUrlSign:        &opaUrlSign,
				OpaUrlRevoke:      &opaUrlRevoke,
				OpaUrlIssueCa:     &opaUrlIssueCa,
			},
		},
	}
}

func newOpaServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server
}

func makeCsrPem(t *testing.T, dnsNames []string, extraExtensions []pkix.Extension) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: "www.example.com"},
		DNSNames:        dnsNames,
		ExtraExtensions: extraExtensions,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func caTrueExtensions() []pkix.Extension {
	return []pkix.Extension{
		{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 0x03, 0x01, 0x01, 0xff}},
		{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: []byte{0x03, 0x02, 0x01, 0x06}},
	}
}

func postSign(t *testing.T, h http.Handler, caId string, csrPem []byte) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "/ca/"+caId+"/csr/sign", csrSignBody(t, csrPem, ""))
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Result().StatusCode
}

func postRevoke(t *testing.T, h http.Handler, caId string, serial string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "/ca/"+caId+"/crt/revoke/"+serial, nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Result().StatusCode
}

func postRevokeCertificate(t *testing.T, h http.Handler, caId string, certificatePem []byte) int {
	t.Helper()
	req, err := http.NewRequest(
		http.MethodPost,
		"/ca/"+caId+"/crt/revoke",
		bytes.NewReader([]byte(`{"certificate": `+strconv.Quote(string(certificatePem))+`}`)),
	)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Result().StatusCode
}

// signLeaf signs a CSR with the CA behind h and returns the certificate, so a
// test has a serial that is a leaf's and not the CA certificate's: the CA
// certificate is refused before the policy is asked, so it cannot stand in for
// an ordinary revocation.
func signLeaf(t *testing.T, h http.Handler, caId string) []byte {
	t.Helper()
	req, err := http.NewRequest(
		http.MethodPost,
		"/ca/"+caId+"/csr/sign",
		csrSignBody(t, makeCsrPem(t, []string{"www.example.com"}, nil), ""),
	)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if got := rr.Result().StatusCode; got != http.StatusOK {
		t.Fatalf("signing a CSR must succeed, got %d", got)
	}
	certificatePem, err := io.ReadAll(rr.Body)
	if err != nil {
		t.Fatal(err)
	}
	return certificatePem
}

func TestRsaSignOpaDenied(t *testing.T) {
	opaServer := newOpaServer(t, http.StatusOK, `{"result": false}`)
	h, err := webserver.CreateHandler(
		newServerContext(t),
		&types.StdLogger{},
		newWebserverConfig(t, t.TempDir(), opaServer.URL, opaServer.URL, opaServer.URL),
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := postSign(t, h, "test_ca_1", makeCsrPem(t, []string{"www.example.com"}, nil)); got != http.StatusForbidden {
		t.Fatalf("OPA deny must yield 403, got %d", got)
	}
}

func TestRsaSignOpaUndefinedDecision(t *testing.T) {
	opaServer := newOpaServer(t, http.StatusOK, `{}`)
	h, err := webserver.CreateHandler(
		newServerContext(t),
		&types.StdLogger{},
		newWebserverConfig(t, t.TempDir(), opaServer.URL, opaServer.URL, opaServer.URL),
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := postSign(t, h, "test_ca_1", makeCsrPem(t, []string{"www.example.com"}, nil)); got != http.StatusForbidden {
		t.Fatalf("undefined OPA decision must yield 403, got %d", got)
	}
}

func TestRsaSignOpaServerError(t *testing.T) {
	opaServer := newOpaServer(t, http.StatusInternalServerError, `boom`)
	h, err := webserver.CreateHandler(
		newServerContext(t),
		&types.StdLogger{},
		newWebserverConfig(t, t.TempDir(), opaServer.URL, opaServer.URL, opaServer.URL),
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := postSign(t, h, "test_ca_1", makeCsrPem(t, []string{"www.example.com"}, nil)); got != http.StatusServiceUnavailable {
		t.Fatalf("OPA server error must yield 503, got %d", got)
	}
}

func TestRsaSignOpaMalformedResponse(t *testing.T) {
	opaServer := newOpaServer(t, http.StatusOK, `not-json`)
	h, err := webserver.CreateHandler(
		newServerContext(t),
		&types.StdLogger{},
		newWebserverConfig(t, t.TempDir(), opaServer.URL, opaServer.URL, opaServer.URL),
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := postSign(t, h, "test_ca_1", makeCsrPem(t, []string{"www.example.com"}, nil)); got != http.StatusServiceUnavailable {
		t.Fatalf("malformed OPA response must yield 503, got %d", got)
	}
}

func TestRsaSignOpaUnreachable(t *testing.T) {
	opaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	opaUrl := opaServer.URL
	opaServer.Close()

	h, err := webserver.CreateHandler(
		newServerContext(t),
		&types.StdLogger{},
		newWebserverConfig(t, t.TempDir(), opaUrl, opaUrl, opaUrl),
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := postSign(t, h, "test_ca_1", makeCsrPem(t, []string{"www.example.com"}, nil)); got != http.StatusServiceUnavailable {
		t.Fatalf("unreachable OPA must yield 503, got %d", got)
	}
}

func TestRsaRevokeOpaDenied(t *testing.T) {
	// Signing is allowed so the test has a leaf to revoke; the revocation
	// input carries "certificate", the signing input "proposed_certificate",
	// so the policy can tell them apart and deny only the revocation.
	opaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Input map[string]json.RawMessage `json:"input"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("cannot decode OPA input: %v", err)
		}
		_, isRevoke := payload.Input["certificate"]
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"result": %t}`, !isRevoke)
	}))
	t.Cleanup(opaServer.Close)
	h, err := webserver.CreateHandler(
		newServerContext(t),
		&types.StdLogger{},
		newWebserverConfig(t, t.TempDir(), opaServer.URL, opaServer.URL, opaServer.URL),
	)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := pemhelper.FromPemToCertificate(signLeaf(t, h, "test_ca_1"))
	if err != nil {
		t.Fatal(err)
	}
	if got := postRevoke(t, h, "test_ca_1", leaf.SerialNumber.String()); got != http.StatusForbidden {
		t.Fatalf("OPA deny must yield 403, got %d", got)
	}
}

func TestRsaRevokeSendsNumericSerial(t *testing.T) {
	var opaInput struct {
		Input struct {
			Serial      json.Number `json:"serial"`
			Certificate struct {
				SerialNumber string `json:"serial_number"`
			} `json:"certificate"`
		} `json:"input"`
	}
	opaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&opaInput); err != nil {
			t.Errorf("cannot decode OPA input: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result": true}`))
	}))
	t.Cleanup(opaServer.Close)

	h, err := webserver.CreateHandler(
		newServerContext(t),
		&types.StdLogger{},
		newWebserverConfig(t, t.TempDir(), opaServer.URL, opaServer.URL, opaServer.URL),
	)
	if err != nil {
		t.Fatal(err)
	}

	leaf, err := pemhelper.FromPemToCertificate(signLeaf(t, h, "test_ca_1"))
	if err != nil {
		t.Fatal(err)
	}
	// The serial in the path is padded, and it is the parsed number that has
	// to reach the policy: a serial is a number, not a string of digits.
	paddedSerial := "0" + leaf.SerialNumber.String()
	if got := postRevoke(t, h, "test_ca_1", paddedSerial); got != http.StatusAccepted {
		t.Fatalf("revoke of a padded serial must succeed, got %d", got)
	}
	if opaInput.Input.Serial.String() != leaf.SerialNumber.String() {
		t.Fatalf("OPA input must carry the parsed serial, got %q", opaInput.Input.Serial)
	}
	if opaInput.Input.Certificate.SerialNumber != leaf.SerialNumber.String() {
		t.Fatalf("OPA input certificate serial mismatch, got %q", opaInput.Input.Certificate.SerialNumber)
	}
}

func TestRsaSignOpaInputContract(t *testing.T) {
	type receivedOpaInput struct {
		Input struct {
			Runtime             string `json:"runtime"`
			RemoteAddr          string `json:"remote_addr"`
			Authorization       string `json:"authorization"`
			ProposedCertificate struct {
				IsCA         bool   `json:"is_ca"`
				SerialNumber string `json:"serial_number"`
				Subject      struct {
					CommonName string `json:"common_name"`
				} `json:"subject"`
			} `json:"proposed_certificate"`
		} `json:"input"`
	}
	received := []receivedOpaInput{}
	opaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body receivedOpaInput
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("cannot decode OPA input: %v", err)
		}
		received = append(received, body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result": true}`))
	}))
	t.Cleanup(opaServer.Close)

	h, err := webserver.CreateHandler(
		newServerContext(t),
		&types.StdLogger{},
		newWebserverConfig(t, t.TempDir(), opaServer.URL, opaServer.URL, opaServer.URL),
	)
	if err != nil {
		t.Fatal(err)
	}

	token := "Bearer leaf-token-123"
	sign := func(csrPem []byte) {
		req := httptest.NewRequest(http.MethodPost, "/ca/test_ca_1/csr/sign", csrSignBody(t, csrPem, ""))
		req.Header.Set("Authorization", token)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if got := rr.Result().StatusCode; got != http.StatusOK {
			t.Fatalf("sign must succeed, got %d", got)
		}
	}
	sign(makeCsrPem(t, []string{"www.example.com"}, nil))
	sign(makeCsrPem(t, nil, caTrueExtensions()))

	if len(received) != 4 {
		t.Fatalf("expected 4 OPA calls (pre+post per sign), got %d", len(received))
	}
	for i, one := range received {
		if one.Input.Runtime != "http" {
			t.Errorf("call %d: input.runtime = %q, want http", i, one.Input.Runtime)
		}
		if one.Input.RemoteAddr != "192.0.2.1:1234" {
			t.Errorf("call %d: input.remote_addr = %q, want 192.0.2.1:1234", i, one.Input.RemoteAddr)
		}
		if one.Input.Authorization != token {
			t.Errorf("call %d: input.authorization = %q, want %q", i, one.Input.Authorization, token)
		}
	}
	if received[0].Input.ProposedCertificate.IsCA || received[1].Input.ProposedCertificate.IsCA {
		t.Error("leaf CSR must authorize a non-CA certificate on both pre and post checks")
	}
	if !received[2].Input.ProposedCertificate.IsCA || !received[3].Input.ProposedCertificate.IsCA {
		t.Error("CA-true CSR must authorize a CA certificate on both pre and post checks")
	}
	if received[0].Input.ProposedCertificate.Subject.CommonName != "www.example.com" {
		t.Errorf("leaf common_name = %q, want www.example.com", received[0].Input.ProposedCertificate.Subject.CommonName)
	}
	if received[0].Input.ProposedCertificate.SerialNumber == "" {
		t.Error("proposed_certificate.serial_number must be present")
	}
}

func TestRsaRevokeOpaInputContract(t *testing.T) {
	var received struct {
		Input struct {
			Runtime       string      `json:"runtime"`
			RemoteAddr    string      `json:"remote_addr"`
			Authorization string      `json:"authorization"`
			Serial        json.Number `json:"serial"`
			Certificate   struct {
				IsCA         bool   `json:"is_ca"`
				SerialNumber string `json:"serial_number"`
				Subject      struct {
					CommonName string `json:"common_name"`
				} `json:"subject"`
			} `json:"certificate"`
		} `json:"input"`
	}
	opaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("cannot decode OPA input: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result": true}`))
	}))
	t.Cleanup(opaServer.Close)

	h, err := webserver.CreateHandler(
		newServerContext(t),
		&types.StdLogger{},
		newWebserverConfig(t, t.TempDir(), opaServer.URL, opaServer.URL, opaServer.URL),
	)
	if err != nil {
		t.Fatal(err)
	}

	leaf, err := pemhelper.FromPemToCertificate(signLeaf(t, h, "test_ca_1"))
	if err != nil {
		t.Fatal(err)
	}

	token := "Bearer officer-token-456"
	req := httptest.NewRequest(
		http.MethodPost,
		"/ca/test_ca_1/crt/revoke/"+leaf.SerialNumber.String(),
		nil,
	)
	req.Header.Set("Authorization", token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if got := rr.Result().StatusCode; got != http.StatusAccepted {
		t.Fatalf("revoke must succeed, got %d", got)
	}
	if received.Input.Runtime != "http" {
		t.Errorf("input.runtime = %q, want http", received.Input.Runtime)
	}
	if received.Input.RemoteAddr != "192.0.2.1:1234" {
		t.Errorf("input.remote_addr = %q, want 192.0.2.1:1234", received.Input.RemoteAddr)
	}
	if received.Input.Authorization != token {
		t.Errorf("input.authorization = %q, want %q", received.Input.Authorization, token)
	}
	if received.Input.Serial.String() != leaf.SerialNumber.String() {
		t.Errorf("input.serial = %q, want %s", received.Input.Serial, leaf.SerialNumber.String())
	}
	if received.Input.Certificate.IsCA {
		t.Error("a revoked leaf certificate must not be a CA")
	}
	if received.Input.Certificate.SerialNumber != leaf.SerialNumber.String() {
		t.Errorf(
			"input.certificate.serial_number = %q, want %s",
			received.Input.Certificate.SerialNumber,
			leaf.SerialNumber.String(),
		)
	}
	if received.Input.Certificate.Subject.CommonName != "www.example.com" {
		t.Errorf("subject.common_name = %q, want www.example.com", received.Input.Certificate.Subject.CommonName)
	}
}

func TestRsaRevokeUnknownSerialSkipsOpa(t *testing.T) {
	called := false
	opaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.Write([]byte(`{"result": true}`))
	}))
	t.Cleanup(opaServer.Close)

	h, err := webserver.CreateHandler(
		newServerContext(t),
		&types.StdLogger{},
		newWebserverConfig(t, t.TempDir(), opaServer.URL, opaServer.URL, opaServer.URL),
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := postRevoke(t, h, "test_ca_1", "999999"); got != http.StatusNotFound {
		t.Fatalf("unknown serial must yield 404, got %d", got)
	}
	if called {
		t.Fatal("OPA must not be called for an unknown serial")
	}
}

func TestRsaRevokeSerialTooLongIsRejectedBeforeOpa(t *testing.T) {
	called := false
	opaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.Write([]byte(`{"result": true}`))
	}))
	t.Cleanup(opaServer.Close)

	h, err := webserver.CreateHandler(
		newServerContext(t),
		&types.StdLogger{},
		newWebserverConfig(t, t.TempDir(), opaServer.URL, opaServer.URL, opaServer.URL),
	)
	if err != nil {
		t.Fatal(err)
	}

	// A serial is at most 128 bits, 39 decimal digits. The length check runs
	// before the parser, so a path of arbitrary length is answered 400 in
	// constant time instead of spending seconds in big.Int.
	if got := postRevoke(t, h, "test_ca_1", strings.Repeat("9", 41)); got != http.StatusBadRequest {
		t.Fatalf("a 41-character serial must yield 400, got %d", got)
	}
	if got := postRevoke(t, h, "test_ca_1", strings.Repeat("9", 1_000_000)); got != http.StatusBadRequest {
		t.Fatalf("a megabyte serial must yield 400, got %d", got)
	}
	if called {
		t.Fatal("OPA must not be called for a rejected serial")
	}

	// 40 characters is the boundary: it passes the check, parses, and misses
	// the CA, so it is 404 like any other serial this CA never issued.
	if got := postRevoke(t, h, "test_ca_1", strings.Repeat("9", 40)); got != http.StatusNotFound {
		t.Fatalf("a 40-character serial must parse and miss, got %d", got)
	}
}

func TestRsaIssueCaUrlSelection(t *testing.T) {
	seenPaths := []string{}
	opaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPaths = append(seenPaths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result": true}`))
	}))
	defer opaServer.Close()

	h, err := webserver.CreateHandler(
		newServerContext(t),
		&types.StdLogger{},
		newWebserverConfig(t,
			t.TempDir(),
			opaServer.URL+"/sign",
			opaServer.URL+"/revoke",
			opaServer.URL+"/issue_ca",
		),
	)
	if err != nil {
		t.Fatal(err)
	}

	if got := postSign(t, h, "test_ca_1", makeCsrPem(t, []string{"www.example.com"}, nil)); got != http.StatusOK {
		t.Fatalf("leaf sign must succeed, got %d", got)
	}
	if got := postSign(t, h, "test_ca_1", makeCsrPem(t, nil, caTrueExtensions())); got != http.StatusOK {
		t.Fatalf("ca-true sign must succeed, got %d", got)
	}

	if len(seenPaths) != 4 {
		t.Fatalf("expected 4 OPA calls (pre+post per sign), got %d: %v", len(seenPaths), seenPaths)
	}
	if seenPaths[0] != "/sign" || seenPaths[1] != "/sign" {
		t.Fatalf("leaf request must use opa_url_sign twice, got %v", seenPaths[:2])
	}
	if seenPaths[2] != "/issue_ca" || seenPaths[3] != "/issue_ca" {
		t.Fatalf("ca-true request must use opa_url_issue_ca twice, got %v", seenPaths[2:])
	}
}

func newSignHandler(t *testing.T) http.Handler {
	t.Helper()
	opaServer := newOpaServer(t, http.StatusOK, `{"result": true}`)
	h, err := webserver.CreateHandler(
		newServerContext(t),
		&types.StdLogger{},
		newWebserverConfig(t, t.TempDir(), opaServer.URL, opaServer.URL, opaServer.URL),
	)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func postRawBody(t *testing.T, h http.Handler, caId string, body []byte) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "/ca/"+caId+"/csr/sign", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Result().StatusCode
}

func TestRsaSignStrictPayload(t *testing.T) {
	h := newSignHandler(t)
	csrPem := makeCsrPem(t, []string{"www.example.com"}, nil)
	quotedCsr := `"` + strings.ReplaceAll(strings.ReplaceAll(string(csrPem), "\n", "\\n"), `"`, `\"`) + `"`

	cases := []struct {
		name string
		body string
	}{
		{"missing csr", `{"not_after":"2026-09-26T12:00:00Z"}`},
		{"empty csr", `{}`},
		{"empty csr string", `{"csr":""}`},
		{"malformed json", `{`},
		{"not json", "hello"},
		{"unknown field", `{"csr":` + quotedCsr + `,"notafter":"2026-09-26T12:00:00Z"}`},
		{"invalid not_after", `{"csr":` + quotedCsr + `,"not_after":"not-a-timestamp"}`},
		{"trailing garbage", `{"csr":` + quotedCsr + `} trailing`},
		{"concatenated payloads", `{"csr":` + quotedCsr + `}{"csr":` + quotedCsr + `}`},
	}
	for _, tc := range cases {
		if got := postRawBody(t, h, "test_ca_1", []byte(tc.body)); got != http.StatusBadRequest {
			t.Fatalf("%s: expected 400, got %d (body %q)", tc.name, got, tc.body)
		}
	}

	validNotAfter := time.Now().UTC().Add(2 * time.Hour).Truncate(time.Second).Format(time.RFC3339)
	valid := `{"csr":` + quotedCsr + `,"not_after":"` + validNotAfter + `"}`
	if got := postRawBody(t, h, "test_ca_1", []byte(valid)); got != http.StatusOK {
		t.Fatalf("valid payload must sign, got %d", got)
	}
}

func TestRsaSignPastNotAfterMessage(t *testing.T) {
	h := newSignHandler(t)
	csrPem := makeCsrPem(t, []string{"www.example.com"}, nil)

	past := time.Now().UTC().Add(-time.Hour).Truncate(time.Second).Format(time.RFC3339)
	req, err := http.NewRequest(http.MethodPost, "/ca/test_ca_1/csr/sign", csrSignBody(t, csrPem, past))
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("past not_after must be 400, got %d", rr.Result().StatusCode)
	}
	if !strings.Contains(rr.Body.String(), "not in the future") {
		t.Fatalf("expected distinct lifetime error, got %s", rr.Body.String())
	}
}

func TestRsaCreateHandlerCaKeyMismatchFails(t *testing.T) {
	logger := &types.StdLogger{}
	dataDirectory := t.TempDir()

	opaServer := newOpaServer(t, http.StatusOK, `{"result": true}`)
	config := newWebserverConfig(
		t,
		dataDirectory,
		opaServer.URL,
		opaServer.URL,
		opaServer.URL,
	)

	// Bootstrap the CA without the server, then replace its key with a
	// different one of the same size: the server must refuse to start rather
	// than answer /issuer.pem with a certificate its own key cannot sign for.
	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		"test_ca_1",
		dataDirectory,
		config.AllCaConfigs["test_ca_1"],
	); err != nil {
		t.Fatal(err)
	}

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caKeyFilename := filepath.Join(dataDirectory, "test_ca_1", "ca.key.pem")
	if err := os.WriteFile(caKeyFilename, pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(otherKey),
	}), os.FileMode(0o600)); err != nil {
		t.Fatal(err)
	}

	if _, err := webserver.CreateHandler(
		newServerContext(t),
		logger,
		config,
	); !errors.Is(err, caissuingprocess.ErrCaKeyMismatch) {
		t.Errorf("expected ErrCaKeyMismatch, got %v", err)
	}
}

// servedCrlNumber reads the CRL a client gets from crl.pem.
func servedCrlNumber(t *testing.T, h http.Handler) *big.Int {
	t.Helper()
	rr := httptest.NewRecorder()
	{
		req, err := http.NewRequest(http.MethodGet, "/ca/test_ca_1/crt/crl.pem", nil)
		if err != nil {
			t.Fatal(err)
		}
		h.ServeHTTP(rr, req)
	}
	if statusCode := rr.Result().StatusCode; statusCode != 200 {
		t.Fatalf("invalid status code %d", statusCode)
	}
	body, err := io.ReadAll(rr.Body)
	if err != nil {
		t.Fatal(err)
	}
	pemBlock, rest := pem.Decode(body)
	if pemBlock == nil {
		t.Fatalf("no pem block in %s", body)
	}
	if restLen := len(rest); restLen != 0 {
		t.Fatal("invalid reminder")
	}
	crlInfo, err := x509.ParseRevocationList(pemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return crlInfo.Number
}

// The route reads the CRL file on every request, so a client gets whatever
// revision the CA has published -- that is what keeps a verifier's copy inside
// its own nextUpdate instead of on a body the server cached at startup. The
// refresh loop, and its stopping with the context, are covered in
// caissuingprocess: a crl_ttl is at least ten minutes, so no test may wait for
// a scheduled refresh.
func TestRsaServedCrlFollowsEveryPublishedRevision(t *testing.T) {
	dataDirectory := t.TempDir()

	h, err := webserver.CreateHandler(
		newServerContext(t),
		&types.StdLogger{},
		newWebserverConfig(t, dataDirectory, "http://opa.invalid/allow", "http://opa.invalid/allow", "http://opa.invalid/allow"),
	)
	if err != nil {
		t.Fatal(err)
	}

	numberAtStart := servedCrlNumber(t, h)
	_, _, headers := fetchCrlPem(t, h, nil)
	etagAtStart := headers.Get("ETag")

	// A second revision published in place of the first one, as the refresher
	// would write it. The refresher itself runs every crl_ttl/4, at least
	// 2m30s, so this file is not written twice.
	writeCrlPem(t, h, dataDirectory, numberAtStart.Int64()+1, time.Now().Add(12*time.Hour))

	status, body, headers := fetchCrlPem(t, h, nil)
	if status != http.StatusOK {
		t.Fatalf("invalid status code %d", status)
	}
	pemBlock, _ := pem.Decode(body)
	if pemBlock == nil {
		t.Fatalf("no pem block in %s", body)
	}
	crlInfo, err := x509.ParseRevocationList(pemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if crlInfo.Number.Cmp(numberAtStart) == 0 {
		t.Error("expected the served CRL to follow the published revision, still serving number", numberAtStart)
	}
	// A new revision is a new document: it carries its own validator, or a
	// client could never tell that its copy is the superseded one.
	if etag := headers.Get("ETag"); etag == etagAtStart {
		t.Errorf("a new CRL revision must carry a new ETag, both are %q", etagAtStart)
	}
	// And that new revision is the one a revalidating client is then told is
	// unchanged.
	if status, _, _ := fetchCrlPem(t, h, map[string]string{"If-None-Match": headers.Get("ETag")}); status != http.StatusNotModified {
		t.Errorf("the published revision must be confirmed with 304, got %d", status)
	}
}

// The CA certificate is refused before the policy is asked, on both paths, and
// the CRL never learns about it. x509.Verify accepts the self-signed root as a
// leaf, so this is its own check and not a side effect of verification.
func TestRsaRevokeTheCaCertificateIsRefusedOnBothPaths(t *testing.T) {
	opaCalls := 0
	opaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		opaCalls++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result": true}`))
	}))
	t.Cleanup(opaServer.Close)

	h, err := webserver.CreateHandler(
		newServerContext(t),
		&types.StdLogger{},
		newWebserverConfig(t, t.TempDir(), opaServer.URL, opaServer.URL, opaServer.URL),
	)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodGet, "/ca/test_ca_1/issuer.pem", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	caPemBytes := rr.Body.Bytes()

	if got := postRevoke(t, h, "test_ca_1", "1"); got != http.StatusConflict {
		t.Errorf("revoking the CA certificate by serial must yield 409, got %d", got)
	}
	if got := postRevokeCertificate(t, h, "test_ca_1", caPemBytes); got != http.StatusConflict {
		t.Errorf("revoking the CA certificate by certificate must yield 409, got %d", got)
	}
	if opaCalls != 0 {
		t.Errorf("expected the policy not to be asked about the CA certificate, got %d calls", opaCalls)
	}

	reqCrl, err := http.NewRequest(http.MethodGet, "/ca/test_ca_1/crt/crl.pem", nil)
	if err != nil {
		t.Fatal(err)
	}
	rrCrl := httptest.NewRecorder()
	h.ServeHTTP(rrCrl, reqCrl)
	crlPemBlock, _ := pem.Decode(rrCrl.Body.Bytes())
	if crlPemBlock == nil {
		t.Fatal("no pem block in CRL")
	}
	parseCrl, err := x509.ParseRevocationList(crlPemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(parseCrl.RevokedCertificateEntries) != 0 {
		t.Errorf("expected an empty CRL, got %d entries", len(parseCrl.RevokedCertificateEntries))
	}
}

// A copy of a certificate under another name is refused: the serial names the
// file, and the certificate in the file is not that one.
func TestRsaRevokeSerialOfACopyIsRefusedByHttp(t *testing.T) {
	opaServer := newOpaServer(t, http.StatusOK, `{"result": true}`)

	dataDirectory := t.TempDir()
	h, err := webserver.CreateHandler(
		newServerContext(t),
		&types.StdLogger{},
		newWebserverConfig(t, dataDirectory, opaServer.URL, opaServer.URL, opaServer.URL),
	)
	if err != nil {
		t.Fatal(err)
	}

	leaf, err := pemhelper.FromPemToCertificate(signLeaf(t, h, "test_ca_1"))
	if err != nil {
		t.Fatal(err)
	}
	leafPemBytes, err := pemhelper.ToPem(leaf)
	if err != nil {
		t.Fatal(err)
	}
	aliasSerial := new(big.Int).Add(leaf.SerialNumber, big.NewInt(1))
	if err := os.WriteFile(
		filepath.Join(dataDirectory, "test_ca_1", "data", "crt", aliasSerial.String()+".crt.pem"),
		leafPemBytes,
		os.FileMode(0o644),
	); err != nil {
		t.Fatal(err)
	}

	if got := postRevoke(t, h, "test_ca_1", aliasSerial.String()); got != http.StatusConflict {
		t.Errorf("revoking a serial whose file holds another certificate must yield 409, got %d", got)
	}
}

// A certificate this CA did not issue is refused on both paths, so a serial
// from another CA cannot end up in this CA's CRL.
func TestRsaRevokeACertificateOfAnotherCaIsRefusedByHttp(t *testing.T) {
	opaServer := newOpaServer(t, http.StatusOK, `{"result": true}`)

	// A second, independent CA over its own data directory.
	otherH, err := webserver.CreateHandler(
		newServerContext(t),
		&types.StdLogger{},
		newWebserverConfig(t, t.TempDir(), opaServer.URL, opaServer.URL, opaServer.URL),
	)
	if err != nil {
		t.Fatal(err)
	}
	otherLeaf, err := pemhelper.FromPemToCertificate(signLeaf(t, otherH, "test_ca_1"))
	if err != nil {
		t.Fatal(err)
	}
	otherLeafPemBytes, err := pemhelper.ToPem(otherLeaf)
	if err != nil {
		t.Fatal(err)
	}

	dataDirectory := t.TempDir()
	h, err := webserver.CreateHandler(
		newServerContext(t),
		&types.StdLogger{},
		newWebserverConfig(t, dataDirectory, opaServer.URL, opaServer.URL, opaServer.URL),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(dataDirectory, "test_ca_1", "data", "crt", otherLeaf.SerialNumber.String()+".crt.pem"),
		otherLeafPemBytes,
		os.FileMode(0o644),
	); err != nil {
		t.Fatal(err)
	}

	if got := postRevokeCertificate(t, h, "test_ca_1", otherLeafPemBytes); got != http.StatusConflict {
		t.Errorf("revoking another CA's certificate must yield 409, got %d", got)
	}
	if got := postRevoke(t, h, "test_ca_1", otherLeaf.SerialNumber.String()); got != http.StatusConflict {
		t.Errorf("revoking another CA's certificate by serial must yield 409, got %d", got)
	}
}

func TestRsaRevokeCertificateRevokesByCertificate(t *testing.T) {
	opaServer := newOpaServer(t, http.StatusOK, `{"result": true}`)
	h, err := webserver.CreateHandler(
		newServerContext(t),
		&types.StdLogger{},
		newWebserverConfig(t, t.TempDir(), opaServer.URL, opaServer.URL, opaServer.URL),
	)
	if err != nil {
		t.Fatal(err)
	}

	leafPemBytes := signLeaf(t, h, "test_ca_1")
	leaf, err := pemhelper.FromPemToCertificate(leafPemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if got := postRevokeCertificate(t, h, "test_ca_1", leafPemBytes); got != http.StatusAccepted {
		t.Fatalf("revoke by certificate must yield 202, got %d", got)
	}

	reqCrl, err := http.NewRequest(http.MethodGet, "/ca/test_ca_1/crt/crl.pem", nil)
	if err != nil {
		t.Fatal(err)
	}
	rrCrl := httptest.NewRecorder()
	h.ServeHTTP(rrCrl, reqCrl)
	crlPemBlock, _ := pem.Decode(rrCrl.Body.Bytes())
	if crlPemBlock == nil {
		t.Fatal("no pem block in CRL")
	}
	parseCrl, err := x509.ParseRevocationList(crlPemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(parseCrl.RevokedCertificateEntries) != 1 {
		t.Fatalf("expected one revoked entry, got %d", len(parseCrl.RevokedCertificateEntries))
	}
	if got := parseCrl.RevokedCertificateEntries[0].SerialNumber.String(); got != leaf.SerialNumber.String() {
		t.Errorf("CRL revokes %s, want %s", got, leaf.SerialNumber.String())
	}
}

func TestRsaRevokeCertificateRequestErrors(t *testing.T) {
	opaServer := newOpaServer(t, http.StatusOK, `{"result": true}`)
	h, err := webserver.CreateHandler(
		newServerContext(t),
		&types.StdLogger{},
		newWebserverConfig(t, t.TempDir(), opaServer.URL, opaServer.URL, opaServer.URL),
	)
	if err != nil {
		t.Fatal(err)
	}
	// A well-formed request, so the refusals below are the payload checks and
	// not the CA refusing a valid certificate.
	signLeaf(t, h, "test_ca_1")

	tests := []struct {
		name string
		body string
		want int
	}{
		{"not json", "not json at all", http.StatusBadRequest},
		{"unknown field", `{"certificate": "", "serial": "1"}`, http.StatusBadRequest},
		{"trailing data", `{"certificate": "x"} {"certificate": "y"}`, http.StatusBadRequest},
		{"no certificate", `{}`, http.StatusBadRequest},
		{"blank certificate", `{"certificate": "   "}`, http.StatusBadRequest},
		{"unparseable certificate", `{"certificate": "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n"}`, http.StatusBadRequest},
	}
	for _, test := range tests {
		req, err := http.NewRequest(
			http.MethodPost,
			"/ca/test_ca_1/crt/revoke",
			bytes.NewReader([]byte(test.body)),
		)
		if err != nil {
			t.Fatal(err)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if got := rr.Result().StatusCode; got != test.want {
			t.Errorf("%s: got %d, want %d", test.name, got, test.want)
		}
	}
}

// The serial sent to the policy on the certificate path is the one on the
// certificate, so the policy and the CRL are about the same certificate.
func TestRsaRevokeByCertificateSendsTheSerialOfTheCertificate(t *testing.T) {
	var opaInput struct {
		Input struct {
			Serial      json.Number `json:"serial"`
			Certificate struct {
				SerialNumber string `json:"serial_number"`
			} `json:"certificate"`
		} `json:"input"`
	}
	opaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&opaInput); err != nil {
			t.Errorf("cannot decode OPA input: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result": true}`))
	}))
	t.Cleanup(opaServer.Close)

	h, err := webserver.CreateHandler(
		newServerContext(t),
		&types.StdLogger{},
		newWebserverConfig(t, t.TempDir(), opaServer.URL, opaServer.URL, opaServer.URL),
	)
	if err != nil {
		t.Fatal(err)
	}

	leafPemBytes := signLeaf(t, h, "test_ca_1")
	leaf, err := pemhelper.FromPemToCertificate(leafPemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if got := postRevokeCertificate(t, h, "test_ca_1", leafPemBytes); got != http.StatusAccepted {
		t.Fatalf("revoke by certificate must yield 202, got %d", got)
	}
	if opaInput.Input.Serial.String() != leaf.SerialNumber.String() {
		t.Errorf("input.serial = %q, want %s", opaInput.Input.Serial, leaf.SerialNumber.String())
	}
	if opaInput.Input.Certificate.SerialNumber != leaf.SerialNumber.String() {
		t.Errorf(
			"input.certificate.serial_number = %q, want %s",
			opaInput.Input.Certificate.SerialNumber,
			leaf.SerialNumber.String(),
		)
	}
}
