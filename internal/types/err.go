package types

import "fmt"

var ErrInvalidKeyTypeInCsr = fmt.Errorf("invalid key type for csr")
var ErrWeakPublicKey = fmt.Errorf("public key below the accepted minimum")
var ErrUnsupportedChangeToKeySize = fmt.Errorf("invalid key size")
var ErrUnsupportedChangeToCurve = fmt.Errorf("invalid change for curve name")
var ErrInvalidCurve = fmt.Errorf("invalid curve name")
var ErrInvalidCaId = fmt.Errorf("invalid ca id")
var ErrInvalidKeyType = fmt.Errorf("invalid key type")
var ErrInvalidConfig = fmt.Errorf("invalid configuration")
