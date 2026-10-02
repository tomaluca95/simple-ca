package mainprocess_test

import (
	"time"

	"github.com/tomaluca95/simple-ca/internal/types"
)

// testCaValidity is the expiry the test CA configs declare: an absolute instant
// far enough ahead that creating a CA never fails for being born expired, and
// the same value on every call, because a load compares the declared instant
// against the one the certificate carries.
var testCaValidity = types.CertificateAuthorityValidityType{
	NotAfter: time.Date(2099, time.January, 1, 0, 0, 0, 0, time.UTC),
}
