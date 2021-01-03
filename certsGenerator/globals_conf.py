from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization


nameAttributesMapping = {
    "COUNTRY_NAME": NameOID.COUNTRY_NAME,
    "STATE_OR_PROVINCE_NAME": NameOID.STATE_OR_PROVINCE_NAME,
    "LOCALITY_NAME": NameOID.LOCALITY_NAME,
    "ORGANIZATION_NAME": NameOID.ORGANIZATION_NAME,
    "COMMON_NAME": NameOID.COMMON_NAME,
}

extentionMapping = {
    "SubjectAlternativeName": x509.SubjectAlternativeName,
    "KeyUsage": x509.KeyUsage,
    "BasicConstraints": x509.BasicConstraints,
    "NameConstraints": x509.NameConstraints,
    "NameAttribute": x509.NameAttribute,
    "AuthorityKeyIdentifier": x509.AuthorityKeyIdentifier,
    "DNSName": x509.DNSName,
    "IPAddress": x509.IPAddress,
}

# one supported for the moment
curveMapping = {"SECP521R1": ec.SECP521R1()}

serialization_mapping = {
    "PEM": serialization.Encoding.PEM,
    "PKCS8": serialization.PrivateFormat.PKCS8,
}

hash_mapping = {"sha512": hashes.SHA512(), "sha256": hashes.SHA256()}

keyUsage = set(
    [
        "digital_signature",
        "content_commitment",
        "key_encipherment",
        "data_encipherment",
        "key_agreement",
        "key_cert_sign",
        "crl_sign",
        "encipher_only",
        "decipher_only",
    ]
)

extendedKeyUsageMapping = {
    "SERVER_AUTH": x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
    "CLIENT_AUTH": x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
    "CODE_SIGNING": x509.oid.ExtendedKeyUsageOID.CODE_SIGNING,
    "EMAIL_PROTECTION": x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION,
    "TIME_STAMPING": x509.oid.ExtendedKeyUsageOID.TIME_STAMPING,
    "OCSP_SIGNING": x509.oid.ExtendedKeyUsageOID.OCSP_SIGNING,
    "ANY_EXTENDED_KEY_USAGE": x509.oid.ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE,
}
