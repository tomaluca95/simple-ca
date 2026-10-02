# Copyright (C) 2024-2026 Toma Luca
# SPDX-License-Identifier: GPL-3.0-only

# Tests for the example policies, run by `opa test examples/opa-policies/` in
# the checks job. Inputs mirror what the tool sends: runtime "cli" stands for a
# trusted local operator, and proposed_certificate is the certificate to be
# signed.
package simple_ca_policy_test

import rego.v1

sign_input(cert_value) := {"runtime": "cli", "proposed_certificate": cert_value}

leaf_cert := {
	"is_ca": false,
	"subject": {"common_name": "www.example.com"},
	"not_before": "2026-09-30T10:00:00Z",
	"not_after": "2026-09-30T16:00:00Z",
	"dns_names": ["www.example.com"],
	"email_addresses": [],
	"ip_addresses": [],
	"uris": [],
	"extensions": [],
	"key_usage": [],
	"public_key": {"algorithm": "RSA", "bits": 2048},
}

test_leaf_without_extensions_is_allowed if {
	req := sign_input(leaf_cert)
	data.simple_ca_sign.allow with input as req
}

test_leaf_with_explicit_basic_constraints_is_allowed if {
	with_extensions := object.union(leaf_cert, {"extensions": [
		{"oid": "2.5.29.35", "critical": false, "value_hex": "04"},
		{"oid": "2.5.29.17", "critical": false, "value_hex": "04"},
		{"oid": "2.5.29.19", "critical": true, "value_hex": "00"},
	]})
	req := sign_input(with_extensions)
	data.simple_ca_sign.allow with input as req
}

test_leaf_with_unlisted_extension_is_denied if {
	with_extensions := object.union(leaf_cert, {"extensions": [
		{"oid": "1.2.3.4", "critical": false, "value_hex": "04"},
	]})
	req := sign_input(with_extensions)
	not data.simple_ca_sign.allow with input as req
}

test_leaf_with_san_outside_allowlist_is_denied if {
	with_san := object.union(leaf_cert, {"dns_names": ["www.attacker.example"]})
	req := sign_input(with_san)
	not data.simple_ca_sign.allow with input as req
}

test_leaf_without_dns_names_is_denied if {
	no_san := object.union(leaf_cert, {"dns_names": []})
	req := sign_input(no_san)
	not data.simple_ca_sign.allow with input as req
}

test_leaf_with_cn_outside_allowlist_is_denied if {
	bad_cn := object.union(leaf_cert, {"subject": {"common_name": "www.attacker.example"}})
	req := sign_input(bad_cn)
	not data.simple_ca_sign.allow with input as req
}

test_leaf_with_cert_sign_key_usage_is_denied if {
	with_ku := object.union(leaf_cert, {"key_usage": ["digitalSignature", "certSign"]})
	req := sign_input(with_ku)
	not data.simple_ca_sign.allow with input as req
}

test_leaf_with_crl_sign_key_usage_is_denied if {
	with_ku := object.union(leaf_cert, {"key_usage": ["crlSign"]})
	req := sign_input(with_ku)
	not data.simple_ca_sign.allow with input as req
}

ca_cert := {
	"is_ca": true,
	"subject": {"common_name": "sub-ca.example.com"},
	"not_before": "2026-09-30T10:00:00Z",
	"not_after": "2026-10-30T10:00:00Z",
	"dns_names": [],
	"email_addresses": [],
	"ip_addresses": [],
	"uris": [],
	"extensions": [],
	"max_path_len": 0,
	"public_key": {"algorithm": "RSA", "bits": 2048},
}

test_subca_without_extensions_is_allowed if {
	req := sign_input(ca_cert)
	data.simple_ca_issue_ca.allow with input as req
}

test_subca_with_core_extensions_is_allowed if {
	with_extensions := object.union(ca_cert, {"extensions": [
		{"oid": "2.5.29.19", "critical": true, "value_hex": "00"},
		{"oid": "2.5.29.15", "critical": true, "value_hex": "04"},
	]})
	req := sign_input(with_extensions)
	data.simple_ca_issue_ca.allow with input as req
}

test_subca_with_authority_info_access_is_denied if {
	with_extensions := object.union(ca_cert, {"extensions": [
		{"oid": "2.5.29.19", "critical": true, "value_hex": "00"},
		{"oid": "2.5.29.36", "critical": false, "value_hex": "04"},
	]})
	req := sign_input(with_extensions)
	not data.simple_ca_issue_ca.allow with input as req
}

test_subca_with_unlisted_extension_is_denied if {
	with_extensions := object.union(ca_cert, {"extensions": [
		{"oid": "2.5.29.19", "critical": true, "value_hex": "00"},
		{"oid": "1.2.3.4", "critical": false, "value_hex": "04"},
	]})
	req := sign_input(with_extensions)
	not data.simple_ca_issue_ca.allow with input as req
}

test_subca_without_max_path_len_is_denied if {
	no_path_len := object.remove(ca_cert, {"max_path_len"})
	req := sign_input(no_path_len)
	not data.simple_ca_issue_ca.allow with input as req
}

test_subca_with_nonzero_max_path_len_is_denied if {
	deep := object.union(ca_cert, {"max_path_len": 2})
	req := sign_input(deep)
	not data.simple_ca_issue_ca.allow with input as req
}

revoke_input(serial, cert_value) := {
	"serial": serial,
	"authorization": "Bearer CHANGE-ME-sub-ca-officer",
	"certificate": cert_value,
}

test_revoke_leaf_is_allowed if {
	req := revoke_input(42, {"serial_number": "42", "is_ca": false})
	data.simple_ca_revoke.allow with input as req
}

test_revoke_root_is_denied if {
	req := revoke_input(1, {"serial_number": "1", "is_ca": true})
	not data.simple_ca_revoke.allow with input as req
}

test_revoke_subca_is_denied if {
	req := revoke_input(42, {"serial_number": "42", "is_ca": true})
	not data.simple_ca_revoke.allow with input as req
}

test_revoke_mismatched_serial_is_denied if {
	req := revoke_input(41, {"serial_number": "42", "is_ca": false})
	not data.simple_ca_revoke.allow with input as req
}

test_revoke_unauthenticated_is_denied if {
	req := {
		"serial": 42,
		"authorization": "Bearer wrong-token",
		"certificate": {"serial_number": "42", "is_ca": false},
	}
	not data.simple_ca_revoke.allow with input as req
}
