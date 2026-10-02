# Copyright (C) 2024-2026 Toma Luca
# SPDX-License-Identifier: GPL-3.0-only

package simple_ca_sign

import rego.v1

default allow := false

# Demo placeholder: change before any real deployment.
leaf_token := "CHANGE-ME-leaf-signer"

cert := input.proposed_certificate

# Demo-only: the CLI/spool path is treated as a trusted local operator. Remove
# this rule (or require a token for runtime "cli" too) before copying these
# policies onto a shared host.
trusted if input.runtime == "cli"

trusted if {
	input.runtime == "http"
	input.authorization == sprintf("Bearer %s", [leaf_token])
}

is_leaf if cert.is_ca == false

leaf_extension_oids := {
	"2.5.29.14", # subjectKeyIdentifier
	"2.5.29.15", # keyUsage
	"2.5.29.17", # subjectAltName
	"2.5.29.19", # basicConstraints
	"2.5.29.35", # authorityKeyIdentifier
	"2.5.29.37", # extendedKeyUsage
}

extensions_allowed if {
	every extension in cert.extensions {
		extension.oid in leaf_extension_oids
	}
}

dns_name_allowed(name) if {
	glob.match("*.example.com", ["."], name)
}

# An empty dns_names list must not vacuously pass: require at least one SAN,
# and keep the subject CN inside the same allowlist (or empty).
sans_allowed if {
	count(cert.dns_names) > 0
	every name in cert.dns_names {
		dns_name_allowed(name)
	}
}

cn_allowed if cert.subject.common_name == ""

cn_allowed if dns_name_allowed(cert.subject.common_name)

no_other_sans if {
	count(cert.email_addresses) == 0
	count(cert.ip_addresses) == 0
	count(cert.uris) == 0
}

max_leaf_seconds := 24 * 60 * 60

validity_ok if {
	not_before := time.parse_rfc3339_ns(cert.not_before)
	not_after := time.parse_rfc3339_ns(cert.not_after)
	not_after > not_before
	not_after - not_before <= max_leaf_seconds * 1000000000
}

# The CA refuses a weak subject key on its own, so this rule is here for the
# deployments that want to be stricter than that. An algorithm missing from the
# table has no minimum, the rule below is undefined for it, and nothing is
# allowed: a key nobody thought about does not get through.
min_key_bits_by_algorithm := {
	"RSA": 2048,
	"ECDSA": 256,
	"Ed25519": 256,
}

key_strong_enough if {
	minimum := min_key_bits_by_algorithm[cert.public_key.algorithm]
	cert.public_key.bits >= minimum
}

# A leaf that can sign certificates or CRLs is a CA in all but name. The Go
# process refuses this too; the policy repeats it so a deployment that only
# audits OPA still sees the deny.
leaf_key_usage_ok if {
	not "certSign" in cert.key_usage
	not "crlSign" in cert.key_usage
}

allow if {
	trusted
	is_leaf
	extensions_allowed
	sans_allowed
	cn_allowed
	no_other_sans
	validity_ok
	key_strong_enough
	leaf_key_usage_ok
}
