import os
import sys
import datetime
import logging
from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network
from typing import Union

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa

from certsGenerator.conf import Conf
from certsGenerator.helpers import loadFile


class CertBuilder:
    def __init__(
        self,
        certName: str,
        conf: Conf,
        ski: x509.SubjectKeyIdentifier,
    ):
        self.certName = certName
        self.conf: Conf = conf
        self.ski = ski

        self.builder = x509.CertificateBuilder()
        self.certificate: x509.Certificate
        self._setAll()

    def buildSubjectNameAttributes(self, certName: str) -> x509.Name:
        nameAttributesMapping = self.conf.nameAttributesMapping
        nameAttrList = []
        snaConf = self.conf.get(
            certName=certName, field="subject_name_attributes", isExt=False
        )
        for k in snaConf.keys():
            nameAttrList.append(
                x509.NameAttribute(nameAttributesMapping[k], snaConf[k])
            )
        name_attr = x509.Name(nameAttrList)

        return name_attr

    def _setNotValid(self) -> None:
        certConf = self.conf.getCert(certName=self.certName)
        nvb = None
        try:
            if certConf["not_valid_before"] == "now":
                nvb = datetime.datetime.utcnow()
            else:
                nvb = datetime.datetime.utcnow() + datetime.timedelta(
                    days=certConf["not_valid_before"]
                )
        except ValueError() as e:
            logging.error(f"can't set not_valid_before: {e}")
            sys.exit()
        nva: None
        try:
            nva = datetime.datetime.utcnow() + datetime.timedelta(
                days=certConf["not_valid_after"]
            )
        except ValueError() as e:
            logging.error(f"can't set not_valid_after: {e}")
            sys.exit()

        self.builder = self.builder.not_valid_before(nvb)
        self.builder = self.builder.not_valid_after(nva)

    def _setNameAttributes(self) -> None:
        subjectConf = self.conf.getCert(certName=self.certName)
        sna = self.buildSubjectNameAttributes(certName=self.certName)
        self.builder = self.builder.subject_name(sna)
        # set issuer name attributes
        if subjectConf["issuer_name"] == subjectConf["subject_name"]:
            # here we have a self signed certificate (generally the root CA)
            # so name attributes are equal both for issuer and subject
            self.builder = self.builder.issuer_name(sna)
        else:
            # here we need to get the name attributes for the related issuer
            ina = self.buildSubjectNameAttributes(certName=subjectConf["issuer_name"])
            self.builder = self.builder.issuer_name(ina)

    def _setSubjectAlternativeName(self, extConf: dict) -> None:
        items = extConf["items"]
        isCritical = True if extConf["critical"] == "true" else False
        elList = []
        for item in items:
            el = None
            if item.get("DNSName"):
                el = self.conf.extensionMapping["DNSName"](item.get("DNSName"))
            elif item.get("IPAddressV4"):
                el = self.conf.extensionMapping["IPAddress"](
                    IPv4Address(item.get("IPAddressV4"))
                )
            elif item.get("IPAddressV6"):
                el = self.conf.extensionMapping["IPAddress"](
                    IPv6Address(item.get("IPAddressV6"))
                )
            elif item.get("IPNetworkV4"):
                el = self.conf.extensionMapping["IPAddress"](
                    IPv4Address(item.get("IPNetworkV4"))
                )
            elif item.get("IPNetworkV6"):
                el = self.conf.extensionMapping["IPAddress"](
                    IPv6Address(item.get("IPNetworkV6"))
                )
            else:
                logging.error(f"can't find SubjectAlternativeName {item}")
                raise ValueError()
                sys.exit()
            elList.append(el)

        self.builder = self.builder.add_extension(
            x509.SubjectAlternativeName(elList), critical=isCritical
        )

    def _setKeyUsage(self, extConf: dict) -> None:
        kwargs = {}
        for el in self.conf.keyUsage:
            if el in extConf["items"]:
                kwargs[el] = True
            else:
                kwargs[el] = False

        isCritical = True if extConf.get("critical") == "true" else False

        self.builder = self.builder.add_extension(
            x509.KeyUsage(**kwargs), critical=isCritical
        )

    def _setExtendedKeyUsage(self, extConf: dict) -> None:
        eku = []
        for el in extConf["items"]:
            eku.append(self.conf.extendedKeyUsageMapping[el.upper()])

        isCritical = True if extConf.get("critical") == "true" else False

        self.builder = self.builder.add_extension(
            x509.ExtendedKeyUsage(eku), critical=isCritical
        )

    def _setBasicConstraints(self, extConf: dict) -> None:
        pathLenght = None
        if "path_length" in extConf.keys():
            if extConf["path_length"] == "none":
                pathLenght = None
            else:
                pathLenght = int(extConf["path_length"])
        isCA = True if extConf.get("ca") == "true" else False
        isCritical = True if extConf.get("critical") == "true" else False

        self.builder = self.builder.add_extension(
            x509.BasicConstraints(ca=isCA, path_length=pathLenght),
            critical=isCritical,
        )

    def _setNameConstraints(self, extConf: dict) -> None:
        isCritical = True if extConf.get("critical") == "true" else False

        permittedList = []
        if (extConf.get("permitted_subtrees") is not None) and (
            len(extConf["permitted_subtrees"]) >= 1
        ):
            for p in extConf["permitted_subtrees"]:
                permittedList.append(self.conf.extensionMapping[p["type"]](p["value"]))
        else:
            permittedList = None  # type: ignore

        excludedList = []
        if (extConf.get("excluded_subtrees") is not None) and (
            len(extConf["excluded_subtrees"]) >= 1
        ):
            for p in extConf["excluded_subtrees"]:
                excludedList.append(self.conf.extensionMapping[p["type"]](p["value"]))
        else:
            excludedList = None  # type: ignore

        self.builder = self.builder.add_extension(
            x509.NameConstraints(
                permitted_subtrees=permittedList, excluded_subtrees=excludedList
            ),
            critical=isCritical,
        )

    def _setSubjectKeyIdentifier(self, extConf: dict) -> None:
        if extConf["set"] == "true":
            isCritical = True if extConf.get("critical") == "true" else False

            self.builder = self.builder.add_extension(
                self.ski,
                critical=isCritical,
            )

    def _setAuthorityKeyIdentifier(self, extConf: dict) -> None:
        if extConf["set"] == "true":
            # we need to get the SubjectKeyIdentifier of the issuer (aka authority)
            # we'll get it from the public key
            certConf = self.conf.getCert(certName=self.certName)

            if certConf["subject_name"] != certConf["issuer_name"]:
                issuer_name = certConf["issuer_name"]
                issuer_conf = self.conf.getCert(certName=issuer_name)
                issuerCrtFile = self.conf.getCertPath(
                    certName=issuer_name, ext="signed_certificate"
                )
                issuer_cert = None
                # load crt file from constructed path if it exists
                if os.path.exists(issuerCrtFile):
                    cert_data = loadFile(fileName=issuerCrtFile)
                    enc = issuer_conf.get("public_key").get("encoding")
                    if enc == "DER":
                        issuer_cert = x509.load_der_x509_certificate(cert_data)
                    elif enc == "PEM":
                        issuer_cert = x509.load_pem_x509_certificate(cert_data)

                else:
                    logging.error(f"can't find issuer crt file {issuerCrtFile}")
                    raise ValueError()
                    sys.exit()

                isCritical = True if extConf.get("critical") == "true" else False

                self.builder = self.builder.add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(
                        issuer_cert.public_key()
                    ),
                    critical=isCritical,
                )
            else:
                logging.error(
                    "AuthorityKeyIdentifier can't be set because subject_name == issuer_name (self-signed), please correct the configuration"
                )
                raise ValueError()
                sys.exit()

    def _setExtensions(self) -> None:
        certConf = self.conf.getCert(certName=self.certName)
        if certConf.get("extensions"):
            extensionsConf = certConf.get("extensions")
            for k in extensionsConf.keys():
                if k == "SubjectAlternativeName":
                    self._setSubjectAlternativeName(extConf=extensionsConf[k])
                elif k == "KeyUsage":
                    self._setKeyUsage(extConf=extensionsConf[k])
                elif k == "ExtendedKeyUsage":
                    self._setExtendedKeyUsage(extConf=extensionsConf[k])
                elif k == "BasicConstraints":
                    self._setBasicConstraints(extConf=extensionsConf[k])
                elif k == "NameConstraints":
                    self._setNameConstraints(extConf=extensionsConf[k])
                elif k == "SubjectKeyIdentifier":
                    self._setSubjectKeyIdentifier(extConf=extensionsConf[k])
                elif k == "AuthorityKeyIdentifier":
                    self._setAuthorityKeyIdentifier(extConf=extensionsConf[k])
                else:
                    logging.error(f"incorrect or not implemented extension {k}")
                    raise ValueError()
                    sys.exit()

    def _setAll(self) -> None:
        # get the conf
        certConf = self.conf.getCert(certName=self.certName)
        # set the cert configuration
        self._setNameAttributes()
        self._setNotValid()
        self._setExtensions()
        self.builder = self.builder.serial_number(x509.random_serial_number())
