# Copyright (C) 2024-2026 Toma Luca
# SPDX-License-Identifier: GPL-3.0-only

package simple_ca_issue_ca

import rego.v1

default allow := false

# Demo placeholder: change before any real deployment.
officer_token := "CHANGE-ME-sub-ca-officer"

cert := input.proposed_certificate

# Demo-only: the CLI/spool path is treated as a trusted local operator. Remove
# this rule (or require a token for runtime "cli" too) before copying these
# policies onto a shared host.
trusted if input.runtime == "cli"

trusted if {
	input.runtime == "http"
	input.authorization == sprintf("Bearer %s", [officer_token])
}

is_ca if cert.is_ca == true

ca_extension_oids := {
	"2.5.29.14", # subjectKeyIdentifier
	"2.5.29.15", # keyUsage
	"2.5.29.17", # subjectAltName
	"2.5.29.19", # basicConstraints
	"2.5.29.30", # nameConstraints
	"2.5.29.31", # cRLDistributionPoints
	"2.5.29.35", # authorityKeyIdentifier
	"2.5.29.37", # extendedKeyUsage
}

extensions_allowed if {
	every extension in cert.extensions {
		extension.oid in ca_extension_oids
	}
}

max_ca_seconds := 90 * 24 * 60 * 60

validity_ok if {
	not_before := time.parse_rfc3339_ns(cert.not_before)
	not_after := time.parse_rfc3339_ns(cert.not_after)
	not_after > not_before
	not_after - not_before <= max_ca_seconds * 1000000000
}

# A subordinate CA signs for as long as it exists, so its key is worth more than
# a leaf key: this is where a deployment raises the numbers above what the tool
# already enforces. A key of an algorithm that is not in the table has no
# minimum, this rule is undefined for it, and nothing is allowed.
min_key_bits_by_algorithm := {
	"RSA": 2048,
	"ECDSA": 256,
	"Ed25519": 256,
}

key_strong_enough if {
	minimum := min_key_bits_by_algorithm[cert.public_key.algorithm]
	cert.public_key.bits >= minimum
}

# Subordinates from this example may not mint further CAs: pathLen must be
# present and zero. An unconstrained pathLen is refused.
path_len_ok if cert.max_path_len == 0

allow if {
	trusted
	is_ca
	extensions_allowed
	validity_ok
	key_strong_enough
	path_len_ok
}
