package caissuingprocess_test

import (
	"time"

	"github.com/tomaluca95/simple-ca/internal/types"
)

// testCaValidity is the expiry the test CA configs declare: an absolute instant
// far enough ahead that creating a CA never fails for being born expired, and
// the same value on every call. That sameness is what the load check depends
// on -- it compares the declared instant against the one in the certificate -- so
// a helper computing "now plus two years" would make a test flaky whenever a
// create and its reload straddled a second.
var testCaValidity = types.CertificateAuthorityValidityType{
	NotAfter: time.Date(2099, time.January, 1, 0, 0, 0, 0, time.UTC),
}
