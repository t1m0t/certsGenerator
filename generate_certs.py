import os
import stat
import datetime
import io
import orjson
from orjson import JSONEncodeError
from pathlib import Path
from typing import Union
from ipaddress import IPv4Address

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

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
curveMapping = {
    "SECP521R1": ec.SECP521R1(),
}

serialization_mapping = {
    "PEM": serialization.Encoding.PEM,
    "PKCS8": serialization.PrivateFormat.PKCS8,
}

hash_mapping = {"sha512": hashes.SHA512(), "sha256": hashes.SHA256()}

key_usage = set(
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


def checkConf(generalConf: dict):
    # check if no redundant certs names
    certs = generalConf["certs"]
    names: dict = {}
    for cert in certs:
        if cert["name"] in names.keys():
            names[cert["name"]] += 1
        else:
            names[cert["name"]] = 1
    for k, v in names.items():
        if v > 1:
            raise ValueError(f"Configuration file error: {k} appears {v} times")

    # check not_valid_before not_valid_after
    for certConf in certs:
        certConf = certConf["conf"]
        if certConf["not_valid_before"] == "now":
            nvb = datetime.datetime.utcnow()
        elif isinstance(int(), certConf["not_valid_before"]) or isinstance(
            int, certConf["not_valid_after"]
        ):
            nvb = datetime.datetime.utcnow() + datetime.timedelta(
                days=certConf["not_valid_before"]
            )
        else:
            raise ValueError(f'invalid value from {nvb}, should be of int or "now"')


def loadConf(fileName: str, format: str = "json") -> dict:
    generalConf = {}
    try:
        with io.open(fileName, mode="r", encoding="utf-8") as file:
            try:
                generalConf = orjson.loads(file.read())
                checkConf(generalConf)
            except JSONEncodeError:
                print(f"enable to load string from {fileName}")
    except OSError:
        print(f"failed to open {fileName}")
    return generalConf


def loadPassPhrase(fileName: str) -> bytes:
    content = b""
    try:
        with open(fileName, mode="rb") as f:
            content = f.read()
    except OSError:
        print(f"failed to open {fileName}")
    return content


def loadKey(fileName: str) -> bytes:
    content = b""
    try:
        with open(fileName, mode="rb") as file:
            content = file.read()
    except OSError:
        print(f"failed to open {fileName}")
    return content


def getPassphrase(certConf: dict) -> bytes:
    # get passphrase
    p = certConf["private_key"]["passphrase"]["path"]
    n = certConf["private_key"]["passphrase"]["fileName"]
    passFile = f"{p}/{n}"
    passphrase = loadPassPhrase(passFile)

    if not type(passphrase) == bytes:
        raise ValueError("passphrase should be of bytes type")

    return passphrase


def getFileExtensions(generalConf: dict) -> dict:
    keyExt = generalConf["defaults"]["file_extentions"]["private_key"]
    csrExt = generalConf["defaults"]["file_extentions"]["certificate_signing_request"]
    crtExt = generalConf["defaults"]["file_extentions"]["signed_certificate"]

    ext = {"key": keyExt, "csr": csrExt, "crt": crtExt}
    return ext


def getCertConf(generalConf: dict, certName: str) -> dict:
    certs = generalConf["certs"]
    conf = {}
    for cert in certs:
        if cert["name"] == certName:
            conf = cert
            break
    return conf["conf"]


def storePrivateKey(
    certConf: dict,
    private_key: Union[
        ec.EllipticCurvePrivateKeyWithSerialization, ec.EllipticCurvePrivateKey
    ],
    path: str,
) -> None:
    # get passphrase
    passphrase = getPassphrase(certConf=certConf)
    encryption_algorithm: serialization.KeySerializationEncryption
    if passphrase:
        encryption_algorithm = serialization.BestAvailableEncryption(passphrase)
    else:
        encryption_algorithm = serialization.NoEncryption()  # type: ignore

    # get other params from conf
    encoding = certConf["private_key"]["encoding"]
    key_format = certConf["private_key"]["format"]
    try:
        with open(path, mode="wb") as f:
            encoding = serialization_mapping[encoding]
            fmt = serialization_mapping[key_format]
            f.write(
                # mypy type issue here
                # in vscode private_key has no private_bytes method
                # but python console shows one
                private_key.private_bytes(  # type: ignore
                    encoding=encoding,
                    format=fmt,  # type: ignore
                    encryption_algorithm=encryption_algorithm,
                )
            )
        try:
            os.chmod(path, stat.S_IRUSR)
        except OSError:
            print(f"can't set permission {stat.S_IRUSR} on {path}")
    except OSError:
        print(f"failed to write file {path}")


def storePublicKey(path: str, cert: x509.Certificate) -> None:
    try:
        with open(path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    except OSError:
        print(f"can't save public key in {path}")


def buildNameAttributes(snaConf: dict) -> x509.Name:
    nameAttrList = []
    for k in snaConf.keys():
        nameAttrList.append(x509.NameAttribute(nameAttributesMapping[k], snaConf[k]))
    name_attr = x509.Name(nameAttrList)

    return name_attr


def setNotValid(
    generalConf: dict, certName: str, builder: x509.CertificateBuilder
) -> x509.CertificateBuilder:
    certConf = getCertConf(generalConf=generalConf, certName=certName)
    nvb = None
    if certConf["not_valid_before"] == "now":
        nvb = datetime.datetime.utcnow()
    else:
        nvb = datetime.datetime.utcnow() + datetime.timedelta(
            days=certConf["not_valid_before"]
        )
    nva = datetime.datetime.utcnow() + datetime.timedelta(
        days=certConf["not_valid_after"]
    )
    builder = builder.not_valid_before(nvb)
    builder = builder.not_valid_after(nva)

    return builder


def setNameAttributes(
    generalConf: dict, certName: str, builder: x509.CertificateBuilder
) -> x509.CertificateBuilder:
    # set subject name attributes
    subjectConf = getCertConf(generalConf=generalConf, certName=certName)
    snaConf = subjectConf["subject_name_attributes"]
    if snaConf:
        name_subject = buildNameAttributes(snaConf=snaConf)
        builder = builder.subject_name(name_subject)
        # set issuer name attributes
        if certName == subjectConf["subject_name"]:
            if subjectConf["issuer_name"] == subjectConf["subject_name"]:
                # here we have a self signed certificate (generally the root CA)
                # so name attributes are equal both for issuer and subject
                builder = builder.issuer_name(name_subject)
            else:
                # here we need to get the name attributes for the related issuer
                issuerConf = getCertConf(
                    generalConf=generalConf, certName=subjectConf["issuer_name"]
                )
                inaConf = issuerConf["subject_name_attributes"]
                if inaConf:
                    name_issuer = buildNameAttributes(snaConf=inaConf)
                    builder = builder.issuer_name(name_issuer)
                else:
                    raise ValueError("issuer_name_attributes not found")
        else:
            sn = subjectConf["subject_name"]
            raise ValueError(
                f"certname {certName} has to be the same as in the conf {sn} to be found"
            )
    else:
        raise ValueError("subject_name_attributes not found in conf")

    return builder


def setSAN(SANConf: dict, builder: x509.CertificateBuilder) -> x509.CertificateBuilder:
    items = SANConf["items"]
    isCritical = True if SANConf["critical"] == "true" else False
    elList = []
    for item in items:
        el = None
        if item.get("DNSName"):
            el = extentionMapping["DNSName"](item.get("DNSName"))
        elif item.get("IPAddressV4"):
            el = extentionMapping["IPAddress"](IPv4Address(item.get("IPAddressV4")))
        else:
            raise ValueError(f"{item} not supported")
        elList.append(el)

    return builder.add_extension(
        x509.SubjectAlternativeName(elList), critical=isCritical
    )


def setKeyUsage(
    extConf: dict, builder: x509.CertificateBuilder
) -> x509.CertificateBuilder:
    # check correctness of conf
    for el in extConf["items"]:
        if el not in key_usage:
            raise ValueError(f"{el} not found in allowed key_usage")
    # set conf
    kwargs = {}
    for el in key_usage:
        if el in extConf["items"]:
            kwargs[el] = True
        else:
            kwargs[el] = False

    isCritical = True if extConf["critical"] == "true" else False

    return builder.add_extension(x509.KeyUsage(**kwargs), critical=isCritical)


def setBasicConstraints(
    extConf: dict, builder: x509.CertificateBuilder
) -> x509.CertificateBuilder:
    isCA = True if extConf["ca"] == "true" else False
    pathLenght = (
        None if extConf["path_length"] == "none" else int(extConf["path_length"])
    )
    isCritical = True if extConf["critical"] == "true" else False

    return builder.add_extension(
        x509.BasicConstraints(ca=isCA, path_length=pathLenght), critical=isCritical
    )


def setNameConstraints(
    extConf: dict, builder: x509.CertificateBuilder
) -> x509.CertificateBuilder:
    isCritical = True if extConf["critical"] == "true" else False
    permittedList = []
    if (extConf.get("permitted_subtrees") is not None) and (
        len(extConf["permitted_subtrees"]) >= 1
    ):
        for p in extConf["permitted_subtrees"]:
            permittedList.append(extentionMapping[p["type"]](p["value"]))
    else:
        permittedList = None  # type: ignore
    excludedList = []
    if (extConf.get("excluded_subtrees") is not None) and (
        len(extConf["excluded_subtrees"]) >= 1
    ):
        for p in extConf["excluded_subtrees"]:
            excludedList.append(extentionMapping[p["type"]](p["value"]))
    else:
        excludedList = None  # type: ignore

    return builder.add_extension(
        x509.NameConstraints(
            permitted_subtrees=permittedList, excluded_subtrees=excludedList
        ),
        critical=isCritical,
    )


def setSubjectKeyIdentifier(
    extConf: dict, builder: x509.CertificateBuilder, key: ec.EllipticCurvePrivateKey
) -> x509.CertificateBuilder:
    if extConf["set"] == "true":
        isCritical = True if extConf["critical"] == "true" else False

    return builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
        critical=isCritical,
    )


def setAuthorityKeyIdentifier(
    generalConf: dict,
    certConf: dict,
    extConf: dict,
    builder: x509.CertificateBuilder,
) -> x509.CertificateBuilder:
    # we need to get the SubjectKeyIdentifier of the issuer (aka authority)
    # we'll get it from the public key
    issuer_name = certConf["issuer_name"]
    issue_conf = getCertConf(generalConf=generalConf, certName=issuer_name)
    # construct path
    path = issue_conf["storage"]["path"]
    fileName = issue_conf["storage"]["fileName"]
    ext = getFileExtensions(generalConf=generalConf)["crt"]
    issuerCrtFile = f"{path}/{issuer_name}.{ext}"
    # load crt file from constructed path
    issuer_cert = None
    if os.path.exists(issuerCrtFile):
        pem_data = loadKey(fileName=issuerCrtFile)
        issuer_cert = x509.load_pem_x509_certificate(pem_data)  # type: ignore
    else:
        raise ValueError(f"can't find issuer crt file {issuerCrtFile}")
    # get subject key id from issuer
    ski_ext = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    # add the value to the extension in the builder
    isCritical = True if extConf["critical"] == "true" else False
    
    return builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()),
        critical=isCritical,
    )


def setExtensions(
    generalConf: dict,
    certName: str,
    builder: x509.CertificateBuilder,
    key: ec.EllipticCurvePrivateKey,
) -> x509.CertificateBuilder:
    certConf = getCertConf(generalConf=generalConf, certName=certName)
    extensionsConf = certConf["extensions"]
    if extensionsConf:
        for k in extensionsConf.keys():
            if k == "SubjectAlternativeName":
                builder = setSAN(SANConf=extensionsConf[k], builder=builder)
            elif k == "KeyUsage":
                builder = setKeyUsage(extConf=extensionsConf[k], builder=builder)
            elif k == "BasicConstraints":
                builder = setBasicConstraints(
                    extConf=extensionsConf[k], builder=builder
                )
            elif k == "NameConstraints":
                builder = setNameConstraints(extConf=extensionsConf[k], builder=builder)
            elif k == "SubjectKeyIdentifier":
                builder = setSubjectKeyIdentifier(
                    extConf=extensionsConf[k], builder=builder, key=key
                )
            elif k == "AuthorityKeyIdentifier":
                if certConf["subject_name"] != certConf["issuer_name"]:
                    builder = setAuthorityKeyIdentifier(
                        generalConf=generalConf,
                        certConf=certConf,
                        extConf=extensionsConf[k],
                        builder=builder,
                    )
            else:
                raise ValueError(f"incorrect or not implemented extension {k}")

    return builder


def buildCerticate(
    generalConf: dict, certName: str, key: ec.EllipticCurvePrivateKey
) -> x509.Certificate:
    certConf = getCertConf(generalConf=generalConf, certName=certName)

    certBuilder = x509.CertificateBuilder()
    certBuilder = setNameAttributes(
        generalConf=generalConf, certName=certName, builder=certBuilder
    )
    certBuilder = setNotValid(
        generalConf=generalConf, certName=certName, builder=certBuilder
    )
    certBuilder = setExtensions(
        generalConf=generalConf, certName=certName, builder=certBuilder, key=key
    )
    certBuilder = certBuilder.serial_number(x509.random_serial_number())
    certBuilder = certBuilder.public_key(key.public_key())
    hashAlg = hash_mapping[certConf["private_key"]["sign_with_alg"]]
    cert = certBuilder.sign(private_key=key, algorithm=hashAlg)  # type: ignore

    return cert


def getPrivateKey(certConf: dict, extensions: dict) -> ec.EllipticCurvePrivateKey:
    if "storage" not in certConf.keys():
        raise ValueError(f"key not found in {certConf}")
    path = certConf["storage"]["path"]
    fileName = certConf["storage"]["fileName"]
    certName = certConf["subject_name"]

    curve_conf = certConf["private_key"]["algorithm"]["params"]["curve"]

    keyExt = extensions["key"]
    keyFile = f"{path}/{fileName}.{keyExt}"
    private_key = None
    if not os.path.exists(path):
        os.mkdir(path)
    elif os.path.exists(keyFile):
        private_key_bytes = loadKey(fileName=keyFile)
        password = getPassphrase(certConf)
        if password:
            private_key = serialization.load_pem_private_key(private_key_bytes, password=password)  # type: ignore
        else:
            private_key = serialization.load_pem_private_key(private_key_bytes)  # type: ignore
    else:
        private_key = ec.generate_private_key(curve=curveMapping[curve_conf])  # type: ignore
        storePrivateKey(certConf=certConf, private_key=private_key, path=keyFile)
    return private_key  # type: ignore


def createCerts(certConf: dict, generalConf: dict, extensions: dict) -> None:
    # get the private key (created if it doesn't exist yet)
    private_key = getPrivateKey(certConf=certConf, extensions=extensions)

    # regarding cert
    path = certConf["storage"]["path"]
    fileName = certConf["storage"]["fileName"]
    crtExt = extensions["crt"]
    certFile = f"{path}/{fileName}.{crtExt}"
    # check if cert exists
    if not os.path.exists(certFile):
        # but to create the cert, we need issuer key
        issuer_name = certConf["issuer_name"]
        issuerConf = getCertConf(generalConf=generalConf, certName=issuer_name)
        issuer_private_key = getPrivateKey(certConf=issuerConf, extensions=extensions)
        # ok then we build the cert
        subject_name = certConf["subject_name"]
        cert = buildCerticate(
            generalConf=generalConf, certName=subject_name, key=issuer_private_key
        )

        storePublicKey(path=certFile,cert=cert)


if __name__ == "__main__":
    CONF_FILE = "conf.json"
    generalConf = loadConf(CONF_FILE)
    fileExt = getFileExtensions(generalConf=generalConf)

    for certConf in generalConf["certs"]:
        createCerts(
            certConf=certConf["conf"], generalConf=generalConf, extensions=fileExt
        )
