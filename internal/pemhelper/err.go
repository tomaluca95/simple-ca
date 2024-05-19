package pemhelper

import "fmt"

var ErrPemEmpty = fmt.Errorf("no pem block")
var ErrPemInvalidReminder = fmt.Errorf("invalid rest length")
var ErrPemInvalidTypeFound = fmt.Errorf("invalid pem type found")
var ErrPemInvalidObject = fmt.Errorf("invalid object type")
