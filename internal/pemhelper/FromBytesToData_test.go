package pemhelper_test

import (
	"errors"
	"testing"

	"github.com/tomaluca95/simple-ca/internal/pemhelper"
)

var pemBlockPrivateKey4096 = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
`

var pemBlockCertificate = `-----BEGIN CERTIFICATE-----
MIIFiDCCA3CgAwIBAgIBATANBgkqhkiG9w0BAQsFADBBMQswCQYDVQQGEwJJVDES
MBAGA1UEChMJQUNNRSBDb3JwMQwwCgYDVQQLEwNQS0kxEDAOBgNVBAMTB015IENB
IDEwHhcNMjQwNTAxMDcwNTU5WhcNMjQwNjAxMDcwNTU5WjBBMQswCQYDVQQGEwJJ
VDESMBAGA1UEChMJQUNNRSBDb3JwMQwwCgYDVQQLEwNQS0kxEDAOBgNVBAMTB015
IENBIDEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCj3bHvr+vegbgP
L7GJWBV6TfcrIyx1rc6cDVACkXCy3l0bmxaiL46slykfdB3Zku1REgCRqV55bARY
AFdUY+23s15Tu3Un3L6/fMsbI+vScSt7bWmkgY0TGYtz2lseU3YOx8UFgEndA7l1
bQDgUxpn9TZlQgKtmFONH1P+Rbg513xHYS+vtNukmCMjXNugzBSrBfAt5pizNe1i
b7jUOMXvbcZudGFhTl01/38XYvtRYXcUD8Ldf+kJpPHu8fd5FsZ/c+YUbQaXk+Ad
DxkUoPgNd4LIbvUjoQmHXRGgUvl+Y3aTwUplEeRYo1mFeYEopW6mgOAVlDs/hP+r
PWuiTe3z79D9rlkoNFJ32lgt5JELJwhgaH/OgGmDjC70Dizn8MXH/tUGmj53HdC/
r1B1ps53FkKIqGi/ifvUJncb0Ttner9oMkYj9n1Gl3HKQaAqXU9CK8Zh9zGb0aga
zpVs+VTk0+EM/MDjQY+fSqMLdBRMcDujr3QAtVjk8xXeSUW8ajz0xzrIeQKwVdE+
alwARFrs6HStSKue35tWdw0sociXpazyeaP4mQrKQMiq5iH7N1jt6aLu2Eso+iPA
Efhmj8lYtTKhfKFXUUo0OziUDgHlIY2fSHjvye89tj0bKltFUgxL4GIv4XHmVOTE
/cRWjzpktH8lKC6QzI4zMEUNBzYlTQIDAQABo4GKMIGHMA4GA1UdDwEB/wQEAwIB
hjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUwAwEB
/zAdBgNVHQ4EFgQUFHUrUrqNmOOSAjyHmiW7cIfvZa8wJgYDVR0eAQH/BBwwGqAY
MAqHCMCoAAD//wAAMAqHCAoAAAD/AAAAMA0GCSqGSIb3DQEBCwUAA4ICAQBISkLy
N/+AztZTh+OYQjxAzbF3reBOQzWV2pBw8b/jCKrZwc9O50yzlsS+KC6EvO+67RIW
jOQHo4N1amOA4d33V+OV1a47zP11LyU/9Hk3eFTSewlzUyrpABDzx8+IUcok7VZV
L05linTN/ATscE0ivcCI1TbyM9fwIn2MGeVYexD41OSg4sG41CppIJzAuS3aMgjM
CDAoNUwmuMRyue80irGCpv039WHJ83XmXpS3EfCZQhdt6RA9OGjbNJ0hm64XzSIA
OzHz1WVZXLZqApeMClYz9TgvLlFjog5iGnclj++gNKTrIath18c9SOTyXSc91VDD
9AqyrpPZIy/SeSgoq+0nPnb/8CmTVAQ6w9aiDEipnzPwcgioTrSYfnHrW+KBH/7f
iGpfMv9gTb/0vwGcQBNpKTtDmlT1cJvw2FYbeY46cuSmGspERqACDlnph58Z3EBi
uKzsLjSNR8yubBSpqHzlNQtfxb5J3yos3D1qXTKA9LeBe3wBDkBmXLCkZBYzlnz1
zid/K7Vz47dbzib03y1aW0QwSbY+f4XtF4lUT6M8GH6F88ZXr1Y/hssjbto6xeaf
RAg9hOJup8eWuIlnTi2WArtX31OT47iBA02QfCW6d5iMu0g7lsF3LDNB3pSgwmTj
ltnMK3ilFbWP7m8/hHoQ7REDAaR9oCSO2RR8Nw==
-----END CERTIFICATE-----
`

var pemBlockCertificateRequest = `-----BEGIN CERTIFICATE REQUEST-----
MIICXzCCAUcCAQAwGjEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm289iVjK5/yDXMJ6/sJfjbyJ3reIOiDB
wqLwr32P9VDBOu1XWa/BZIf6aQ4Tr1k6cOw1CEPaIl9zNgVyThnLguxPWxenNZee
5DA5yt5AX/brNiOr4iNt7HYygY/YbwifJ1d/4N2UT7ydYJXi/fFVgqmtBKISQGlS
tZg5ykPBTwVXBC6akz6FfyuX30uDWZmoYczMHWAn+rLMFGVsCO8mwQcSdgIm8m3W
3QRZP1Qc3o5JflJpj5156E7Qmbvgf02SiJQaklVxHy5MuPAw62+35JK2XfSRcF33
qfuWneJy3w1C/qEoP6KVMPfbhHt1h+IChXdQKGdTtGhrAPjveUDxZQIDAQABoAAw
DQYJKoZIhvcNAQELBQADggEBAIcp98WbA3pi+NLstbkKDZUEGdfZLNIQTTJjuyvH
eIZ4x0QvIeEEbbIxk9wjhP+95D4GhMIWdGBWd0E9Yr3yS56awAYv2v7YjGYS8fcj
QfA2w4bqUZNup1NlPfZyqF16p0/3f1OfJCbt4A1hy9dq2kYo5RQkADuB0jcnsr6y
e5bmrwuFRfn64P+6MF//hNsYXzYI3TbZAJlRbW/yxkSVkoc/dC+bR/TWsF8v+VPx
t1W5ZG++w1XnchdeRGhtkWelHw/rdjVA6mXTUWu5gK2ibUle7O6Mlg74zh3Kw/9H
qnvAU9F4O0mKuVAbDwAH2vbIZd6cM5eRzkTvZctbT4Y09ic=
-----END CERTIFICATE REQUEST-----
`

func TestFromPemToRsaPrivateKeyEmptyPemBlock(t *testing.T) {
	pemBlock := ``
	privateKey, err := pemhelper.FromPemToRsaPrivateKey([]byte(pemBlock))
	if err != nil {
		if !errors.Is(err, pemhelper.ErrPemEmpty) {
			t.Error(err)
		}
	} else if privateKey != nil {
		t.Errorf("found key from no input data")
	} else {
		t.Errorf("invalid result data")
	}
}

func TestFromPemToRsaPrivateKey4096KeyPemBlock(t *testing.T) {
	privateKey, err := pemhelper.FromPemToRsaPrivateKey([]byte(pemBlockPrivateKey4096))
	if err != nil {
		t.Error(err)
	} else if privateKey != nil {
		if privateKey.N.BitLen() != 4096 {
			t.Errorf("invalid key size %d", privateKey.N.BitLen())
		}
	} else {
		t.Errorf("invalid result data")
	}
}

func TestFromPemToRsaPrivateKey4096KeyPemBlockInvalidRest(t *testing.T) {
	pemBlock := pemBlockPrivateKey4096 + "\n---"
	privateKey, err := pemhelper.FromPemToRsaPrivateKey([]byte(pemBlock))
	if err != nil {
		if !errors.Is(err, pemhelper.ErrPemInvalidReminder) {
			t.Error(err)
		}
	} else if privateKey != nil {
		t.Errorf("found key from no input data")
	} else {
		t.Errorf("invalid result data")
	}
}

func TestFromPemToRsaPrivateKeyInvalidKeyData(t *testing.T) {
	pemBlock := `-----BEGIN RSA PRIVATE KEY-----
MIIJKQIBAAKCAgEAo92x76/r3oG4Dy+xiVgVek33KyMsda3OnA1QApFwst5dG5sW
-----END RSA PRIVATE KEY-----
`
	privateKey, err := pemhelper.FromPemToRsaPrivateKey([]byte(pemBlock))
	if err != nil {
		t.Log(err)
	} else if privateKey != nil {
		t.Errorf("found key from no input data")
	} else {
		t.Errorf("invalid result data")
	}
}

func TestFromPemToRsaPrivateKeyInvalidBlock(t *testing.T) {
	pemBlock := `-----BEGIN INVALID BLOCK-----
-----END INVALID BLOCK-----
`
	privateKey, err := pemhelper.FromPemToRsaPrivateKey([]byte(pemBlock))
	if err != nil {
		if !errors.Is(err, pemhelper.ErrPemInvalidTypeFound) {
			t.Error(err)
		}
	} else if privateKey != nil {
		t.Errorf("found key from no input data")
	} else {
		t.Errorf("invalid result data")
	}
}

func TestFromPemToCertificateBlock(t *testing.T) {
	certificate, err := pemhelper.FromPemToCertificate([]byte(pemBlockCertificate))
	if err != nil {
		t.Error(err)
	} else if certificate != nil {

	} else {
		t.Errorf("invalid result data")
	}
}

func TestFromPemToCertificateInvalidKeyData(t *testing.T) {
	pemBlock := `-----BEGIN CERTIFICATE-----
MIIJKQIBAAKCAgEAo92x76/r3oG4Dy+xiVgVek33KyMsda3OnA1QApFwst5dG5sW
-----END CERTIFICATE-----
`
	certificate, err := pemhelper.FromPemToCertificate([]byte(pemBlock))
	if err != nil {
		t.Log(err)
	} else if certificate != nil {
		t.Errorf("found key from no input data")
	} else {
		t.Errorf("invalid result data")
	}
}

func TestFromPemToCertificateInvalidBlock(t *testing.T) {
	pemBlock := `-----BEGIN INVALID BLOCK-----
-----END INVALID BLOCK-----
`
	certificate, err := pemhelper.FromPemToCertificate([]byte(pemBlock))
	if err != nil {
		if !errors.Is(err, pemhelper.ErrPemInvalidTypeFound) {
			t.Error(err)
		}
	} else if certificate != nil {
		t.Errorf("found key from no input data")
	} else {
		t.Errorf("invalid result data")
	}
}

func TestFromPemToCertificateRequestBlock(t *testing.T) {
	certificateRequest, err := pemhelper.FromPemToCertificateRequest([]byte(pemBlockCertificateRequest))
	if err != nil {
		t.Error(err)
	} else if certificateRequest != nil {

	} else {
		t.Errorf("invalid result data")
	}
}

func TestFromPemToCertificateRequestInvalidKeyData(t *testing.T) {
	pemBlock := `-----BEGIN CERTIFICATE REQUEST-----
MIIJKQIBAAKCAgEAo92x76/r3oG4Dy+xiVgVek33KyMsda3OnA1QApFwst5dG5sW
-----END CERTIFICATE REQUEST-----
`
	certificateRequest, err := pemhelper.FromPemToCertificateRequest([]byte(pemBlock))
	if err != nil {
		t.Log(err)
	} else if certificateRequest != nil {
		t.Errorf("found key from no input data")
	} else {
		t.Errorf("invalid result data")
	}
}

func TestFromPemToCertificateRequestInvalidBlock(t *testing.T) {
	pemBlock := `-----BEGIN INVALID BLOCK-----
-----END INVALID BLOCK-----
`
	certificateRequest, err := pemhelper.FromPemToCertificateRequest([]byte(pemBlock))
	if err != nil {
		if !errors.Is(err, pemhelper.ErrPemInvalidTypeFound) {
			t.Error(err)
		}
	} else if certificateRequest != nil {
		t.Errorf("found key from no input data")
	} else {
		t.Errorf("invalid result data")
	}
}
