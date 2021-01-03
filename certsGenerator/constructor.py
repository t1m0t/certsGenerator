import os
import sys
import datetime
from ipaddress import IPv4Address

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from certsGenerator.storage import getCertConf
from certsGenerator.storage import getFileExtensions
from certsGenerator.storage import loadFile

from certsGenerator.globals_conf import nameAttributesMapping
from certsGenerator.globals_conf import extentionMapping
from certsGenerator.globals_conf import keyUsage
from certsGenerator.globals_conf import extendedKeyUsageMapping


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
                    sys.exit()
        else:
            sn = subjectConf["subject_name"]
            raise ValueError(
                f"certname {certName} has to be the same as in the conf {sn} to be found"
            )
            sys.exit()
    else:
        raise ValueError("subject_name_attributes not found in conf")
        sys.exit()

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
            sys.exit()
        elList.append(el)

    return builder.add_extension(
        x509.SubjectAlternativeName(elList), critical=isCritical
    )


def setKeyUsage(
    extConf: dict, builder: x509.CertificateBuilder
) -> x509.CertificateBuilder:
    # check correctness of conf
    for el in extConf["items"]:
        if el not in keyUsage:
            raise ValueError(f"{el} not found in allowed keyUsage")
            sys.exit()
    # set conf
    kwargs = {}
    for el in keyUsage:
        if el in extConf["items"]:
            kwargs[el] = True
        else:
            kwargs[el] = False

    isCritical = True if extConf["critical"] == "true" else False

    return builder.add_extension(x509.KeyUsage(**kwargs), critical=isCritical)


def setExtendedKeyUsage(
    extConf: dict, builder: x509.CertificateBuilder
) -> x509.CertificateBuilder:
    eku = []
    for el in extConf["items"]:
        if el.upper() not in extendedKeyUsageMapping.keys():
            raise ValueError(f"{el} not found in allowed extendedKeyUsage")
            sys.exit()
        else:
            eku.append(extendedKeyUsageMapping[el.upper()])

    isCritical = True if extConf["critical"] == "true" else False

    return builder.add_extension(x509.ExtendedKeyUsage(eku), critical=isCritical)


def setBasicConstraints(
    extConf: dict, builder: x509.CertificateBuilder
) -> x509.CertificateBuilder:
    isCA = True if extConf["ca"] == "true" else False
    pathLenght = (
        None if extConf["path_length"] == "none" else int(extConf["path_length"])
    )
    isCritical = True if extConf["critical"] == "true" else False

    return builder.add_extension(
        x509.BasicConstraints(ca=isCA, path_length=pathLenght),
        critical=isCritical,
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
    extConf: dict,
    builder: x509.CertificateBuilder,
    key: ec.EllipticCurvePrivateKey,
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
        pem_data = loadFile(fileName=issuerCrtFile)
        issuer_cert = x509.load_pem_x509_certificate(pem_data)  # type: ignore
    else:
        raise ValueError(f"can't find issuer crt file {issuerCrtFile}")
        sys.exit()
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
            elif k == "ExtendedKeyUsage":
                builder = setExtendedKeyUsage(
                    extConf=extensionsConf[k], builder=builder
                )
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
                sys.exit()

    return builder
