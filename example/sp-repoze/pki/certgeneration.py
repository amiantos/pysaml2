#!/usr/bin/env python
import datetime
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


__author__ = "haho0032"


cert_info_ca = {
    "cn": "localhost.ca",
    "country_code": "se",
    "state": "ac",
    "city": "umea",
    "organization": "ITS Umea University",
    "organization_unit": "DIRG",
}

# Generate private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Create certificate
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, cert_info_ca["country_code"]),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, cert_info_ca["state"]),
    x509.NameAttribute(NameOID.LOCALITY_NAME, cert_info_ca["city"]),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, cert_info_ca["organization"]),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, cert_info_ca["organization_unit"]),
    x509.NameAttribute(NameOID.COMMON_NAME, cert_info_ca["cn"]),
])

cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    private_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.now(datetime.timezone.utc)
).not_valid_after(
    datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)
).add_extension(
    x509.SubjectAlternativeName([
        x509.DNSName(cert_info_ca["cn"]),
    ]),
    critical=False,
).sign(private_key, hashes.SHA256())

# Write certificate to file
cert_file = f"{cert_info_ca['cn']}.crt"
key_file = f"{cert_info_ca['cn']}.key"

with open(cert_file, "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

with open(key_file, "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

ca_cert = cert_file
ca_key = key_file
