# Simple CA

This tool is a simple CA intended to be executed via cli and http.

Mainly intended for development/testing environments.

## Build executable

```bash
go build
```

## Update `config.yml`

```yaml
data_directory: ./tmp/
http_server:
    listen_address: 127.0.0.1
    listen_port: 5000
all_ca_configs:
    ca_1:
        subject:
            common_name: My CA 1
            country:
                - IT
            organization:
                - ACME Corp
            organizational_unit:
                - PKI
            locality: []
            province: []
            street_address: []
            postal_code: []
        validity:
            years: 1
            months: 1
            days: 10
        key_config:
            type: rsa
            config:
                size: 4096
        crl_ttl: 12h
        permitted_dns_domains_critical: true
        permitted_dns_domains: []
        excluded_dns_domains: []
        permitted_ip_ranges:
            - 192.168.0.0/16
            - 10.0.0.0/8
        excluded_ip_ranges: []
        permitted_email_addresses: []
        excluded_email_addresses: []
        permitted_uri_domains: []
        excluded_uri_domains: []

        opa_url_sign: http://localhost:8181/v1/data/simple_ca/allow
        opa_url_revoke: http://localhost:8181/v1/data/simple_ca/allow


```

## Bootstrap CAs

```bash
./simple-ca
```

## Local use

### Generate csr using openssl

```bash
openssl req \
    -nodes \
    -subj "/CN=www.example.com" \
     -addext "subjectAltName = DNS:www.example.com , DNS:www2.example.com" \
    -addext "extendedKeyUsage = serverAuth, clientAuth" \
    -addext "keyUsage=keyEncipherment" \
    -newkey rsa:2048 \
    -keyout ${KEYS_DIR}/www.example.com.key.pem \
    -out ${CSRPOOL}/www.example.com.csr.pem


openssl req \
    -in ${CSRPOOL}/www.example.com.csr.pem \
    -noout \
    -text
```

### Sign all CSRs and generate new CRL

```bash
./simple-ca
```

## Authorization with OPA

The HTTP server uses Open Policy Agent (OPA) for authorization. You need to have an OPA instance running.

Create a directory for your policies, for example `policies`.

```bash
mkdir policies
```

Inside that directory, create a file named `simple_ca.rego`.

```rego
# policies/simple_ca.rego
package simple_ca

default allow = false

# Allow all requests by default for demonstration purposes.
allow = true
```

You can run OPA using Docker and load the policy files from the `policies` directory.

```bash
docker container run \
    -p 8181:8181 \
    -v $(pwd)/policies:/policies \
    openpolicyagent/opa run --addr 0.0.0.0:8181 --server /policies
```

This command starts an OPA server on port 8181 and loads all policies from the `/policies` directory inside the container. The application will then query OPA to authorize incoming HTTP requests.


## HTTP server

### Run

```bash
./simple-ca http
```

### Requests

```bash
openssl req \
    -nodes \
    -subj "/CN=www.example.com" \
     -addext "subjectAltName = DNS:www.example.com , DNS:www2.example.com" \
    -addext "extendedKeyUsage = serverAuth, clientAuth" \
    -addext "keyUsage=keyEncipherment" \
    -newkey rsa:2048 \
    -keyout ${KEYS_DIR}/www.example.com.key.pem \
    -out ${CSR_DIR}/www.example.com.csr.pem


openssl req \
    -in ${CSR_DIR}/www.example.com.csr.pem \
    -noout \
    -text

CA_ID=ca_1

curl \
    -sSLf \
    -T ${CSR_DIR}/www.example.com.csr.pem \
    -X POST \
    http://localhost:5000/ca/$CA_ID/csr/sign

curl \
    -sSLf \
    -X POST \
    http://localhost:5000/ca/$CA_ID/crt/revoke/12345
