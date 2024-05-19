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
        http_server_options:
            users:
                my_user: my_pass

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
    --user my_user:my_pass \
    -X POST \
    http://localhost:5000/ca/$CA_ID/csr/sign

curl \
    -sSLf \
    --user my_user:my_pass \
    -X POST \
    http://localhost:5000/ca/$CA_ID/crt/revoke/12345
```