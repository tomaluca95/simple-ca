# Copyright (C) 2024-2026 Toma Luca
# SPDX-License-Identifier: GPL-3.0-only

package simple_ca_revoke

import rego.v1

default allow := false

# Demo placeholders: change before any real deployment.
leaf_token := "CHANGE-ME-leaf-signer"
officer_token := "CHANGE-ME-sub-ca-officer"

cert := input.certificate

is_officer if input.authorization == sprintf("Bearer %s", [officer_token])
is_authenticated if is_officer
is_authenticated if input.authorization == sprintf("Bearer %s", [leaf_token])

protected_serials := {1}

# input.serial is read off the certificate this CA is about to revoke, not off
# the request, so it is the same serial as cert.serial_number. Comparing it to
# cert.serial_number anyway turns that into a check rather than a comment: a
# policy that is asked about one certificate cannot have the CRL name another.
#   opa eval -I -d . 'data.simple_ca_revoke.allow' <<JSON
#   {"serial": 1, "certificate": {"serial_number": "1", "is_ca": true}}
#   JSON
# false
not_root if {
	input.serial == to_number(cert.serial_number)
	not input.serial in protected_serials
}

# Any holder of leaf_token or officer_token may revoke a non-CA leaf. Subordinate
# CA revocation is left to a deployment-specific policy; this example does not
# allow cert.is_ca == true.
allow if {
	is_authenticated
	not_root
	cert.is_ca == false
}
