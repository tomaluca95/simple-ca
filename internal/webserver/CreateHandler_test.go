package webserver_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tomaluca95/simple-ca/internal/pemhelper"
	"github.com/tomaluca95/simple-ca/internal/types"
	"github.com/tomaluca95/simple-ca/internal/webserver"
)

func TestRsaSignCsr(t *testing.T) {
	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	httpCaUsername := "username"
	httpCaPassword := "password"

	h, err := webserver.CreateHandler(
		context.Background(),
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
					PermittedIPRanges: []string{"0.0.0.0/0"},
					ExcludedIPRanges:  []string{"0.0.0.0/0"},
					HttpServerOptions: &types.HttpServerOptionsType{
						Users: map[string]string{
							httpCaUsername: httpCaPassword,
						},
					},
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
			bytes.NewBufferString(`-----BEGIN CERTIFICATE REQUEST-----
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
`),
		)
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth(httpCaUsername, httpCaPassword)
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
	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	httpCaUsername := "username"
	httpCaPassword := "password"

	h, err := webserver.CreateHandler(
		context.Background(),
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
					PermittedIPRanges: []string{"0.0.0.0/0"},
					ExcludedIPRanges:  []string{"0.0.0.0/0"},
					HttpServerOptions: &types.HttpServerOptionsType{
						Users: map[string]string{
							httpCaUsername: httpCaPassword,
						},
					},
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
			bytes.NewBufferString(`-----BEGIN CERTIFICATE REQUEST-----
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
`),
		)
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth(httpCaUsername, httpCaPassword)
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
		req.SetBasicAuth(httpCaUsername, httpCaPassword)
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
		req.SetBasicAuth(httpCaUsername, httpCaPassword)
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
	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	httpCaUsername := "username"
	httpCaPassword := "password"

	h, err := webserver.CreateHandler(
		context.Background(),
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
					PermittedIPRanges: []string{"0.0.0.0/0"},
					ExcludedIPRanges:  []string{"0.0.0.0/0"},
					HttpServerOptions: &types.HttpServerOptionsType{
						Users: map[string]string{
							httpCaUsername: httpCaPassword,
						},
					},
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
		req.SetBasicAuth(httpCaUsername, httpCaPassword)
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
