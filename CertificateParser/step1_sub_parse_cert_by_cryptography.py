# -*- coding: utf-8 -*-
import re
import binascii
import base64
import hashlib
import warnings
from cryptography import x509
from cryptography import x509 as X509
from cryptography.hazmat._oid import ExtensionOID
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.dh import DHPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from CertParser import cert_parser_helper
from CertParser.cert_parser_helper import KeyType
from CertParser.cert_parser_helper import CertStatus


def get_pem_cert(pem_cert_str):
    pem_cert = None
    try:
        encoded_pem_str = pem_cert_str.encode("utf-8")
        pem_cert = X509.load_pem_x509_certificate(encoded_pem_str, default_backend())
        status = CertStatus.Done
    except Exception as e:
        status = CertStatus.GET_PEM_ERROR
    return pem_cert, status


def get_pem_cert_fingerprints(pem_cert):
    pem_cert_bin_fp_1 = None
    pem_cert_bin_fp_2 = None
    try:
        pem_cert_bin_fp_1 = binascii.hexlify(pem_cert.fingerprint(hashes.SHA1())).decode()
        pem_cert_bin_fp_2 = binascii.hexlify(pem_cert.fingerprint(hashes.SHA256())).decode()
        status = CertStatus.Done
    except Exception as e:
        status = CertStatus.GET_PEM_FP_ERROR
    return pem_cert_bin_fp_1, pem_cert_bin_fp_2, status


def pem_cert_from_public_bytes(pem_cert):
    public_bytes = None
    try:
        public_bytes = str(pem_cert.public_bytes(encoding=serialization.Encoding.PEM).decode())
        status = CertStatus.Done
    except Exception as e:
        status = CertStatus.GET_PEM_PKB_ERROR
    if public_bytes is None:
        status = CertStatus.GET_PEM_PKB_ERROR
    return public_bytes, status


def get_pem_cert_inner_str(pem_cert_str):
    inner_string = None
    try:
        inner_string = re.search(r"(?<=-----BEGIN CERTIFICATE-----).*?(?=-----END CERTIFICATE-----)",
                         pem_cert_str, flags=re.DOTALL)
        status = CertStatus.Done
    except Exception as e:
        status = CertStatus.GET_PEM_STR
    return inner_string, status


def get_der_bin(pem_cert_inner_str):
    der_bin = None
    try:
        der_bin = base64.b64decode(pem_cert_inner_str.group())
        status = CertStatus.Done
    except Exception as e:
        status = CertStatus.GET_DER_BIN_ERROR
    return der_bin, status


def get_der_cert(der_bin):
    der_cert = None
    try:
        der_cert = X509.load_der_x509_certificate(der_bin, default_backend())
        status = CertStatus.Done
    except Exception as e:
        status = CertStatus.GET_DER_ERROR
    return der_cert, status


def get_der_thumbprints(der_cert):
    hash_md5 = None
    hash_sha1 = None
    hash_sha256 = None
    try:
        public_bytes = der_cert.public_bytes(Encoding.DER)
        hash_md5 = hashlib.md5(public_bytes).hexdigest().lower()
        hash_sha1 = hashlib.sha1(public_bytes).hexdigest().lower()
        hash_sha256 = hashlib.sha256(public_bytes).hexdigest().lower()
        status = CertStatus.Done
    except Exception as e:
        status = CertStatus.GET_DER_TP_ERROR
    return hash_md5, hash_sha1, hash_sha256, status


def get_key_thumbprints(der_cert):
    pkp_1 = None
    pkp_2 = None
    try:
        public_key_info = der_cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        if public_key_info is not None:
            sha1 = hashlib.sha1(public_key_info).digest()
            sha1_base64 = base64.b64encode(sha1)
            pkp_1 = sha1_base64.decode("utf-8")

            sha2 = hashlib.sha256(public_key_info).digest()
            sha2_base64 = base64.b64encode(sha2)
            pkp_2 = sha2_base64.decode("utf-8")
        status = CertStatus.Done
    except Exception as e:
        status = CertStatus.GET_KEY_TP_ERROR
    return pkp_1, pkp_2, status


def get_key_thumbprints_by_key(der_cert_public_key):
    pkp_1 = None
    pkp_2 = None
    try:
        public_key_info = der_cert_public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        if public_key_info is not None:
            sha1 = hashlib.sha1(public_key_info).digest()
            sha1_base64 = base64.b64encode(sha1)
            pkp_1 = sha1_base64.decode("utf-8")

            sha2 = hashlib.sha256(public_key_info).digest()
            sha2_base64 = base64.b64encode(sha2)
            pkp_2 = sha2_base64.decode("utf-8")
        status = CertStatus.Done
    except Exception as e:
        status = CertStatus.GET_KEY_TP_ERROR
    return pkp_1, pkp_2, status


def get_der_cert_version(der_cert):
    version = None
    try:
        version = der_cert.version
        status = CertStatus.Done
    except Exception as e:
        status = CertStatus.GET_DER_VR_ERROR
    return version, status


def get_der_cert_serial_no(der_cert):
    serial_number = None
    try:
        serial_number = der_cert.serial_number
        status = CertStatus.Done
    except Exception as e:
        status = CertStatus.GET_DER_SRN_ERROR
    return str(serial_number), status


def get_der_cert_public_key_info(der_cert):
    public_key_info = None
    try:
        public_key_info = der_cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        public_key_info = cert_parser_helper.get_encoded_base64(public_key_info)
        status = CertStatus.Done
    except Exception as e:
        status = CertStatus.GET_DER_PKI_ERROR
    return public_key_info, status


def get_public_key_rsa(key_data):
    key_type = KeyType.RSA.value
    size = None
    numbers = []
    try:
        size = int(key_data.key_size)
        exponent = str(int(key_data.public_numbers().e))
        modulus = hex(key_data.public_numbers().n)[2:]
        numbers = [exponent, modulus]
        status = CertStatus.Done
    except Exception as e:
        status = CertStatus.GET_DER_PK_RSA_ERROR
    return key_type, size, numbers, status


def get_public_key_dsa(key_data):
    key_type = KeyType.DSA.value
    size = None
    numbers = []
    try:
        size = int(key_data.key_size)
        np = hex(key_data.public_numbers().parameter_numbers.p)[2:]
        nq = hex(key_data.public_numbers().parameter_numbers.q)[2:]
        ng = hex(key_data.public_numbers().parameter_numbers.g)[2:]
        numbers = [np, nq, ng]
        status = CertStatus.Done
    except Exception as e:
        status = CertStatus.GET_DER_PK_DSA_ERROR
    return key_type, size, numbers, status


def get_public_key_ec(key_data):
    key_type = KeyType.EC.value
    size = None
    numbers = []
    try:
        size = int(key_data.key_size)
        cv = str(key_data.public_numbers().curve.name)
        nx = hex(key_data.public_numbers().x)[2:]
        ny = hex(key_data.public_numbers().y)[2:]
        numbers = [cv, nx, ny]
        status = CertStatus.Done
    except Exception as e:
        status = CertStatus.GET_DER_PK_EC_ERROR
    return key_type, size, numbers, status


def get_public_key(der_cert):
    key_type = None
    size = None
    numbers = None
    try:
        public_key_info = der_cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        der_public_key = load_der_public_key(public_key_info)

        if isinstance(der_public_key, RSAPublicKey):
            key_type, size, numbers, status = get_public_key_rsa(der_public_key)
        elif isinstance(der_public_key, DSAPublicKey):
            key_type, size, numbers, status = get_public_key_dsa(der_public_key)
        elif isinstance(der_public_key, EllipticCurvePublicKey):
            key_type, size, numbers, status = get_public_key_ec(der_public_key)
        elif isinstance(der_public_key, Ed448PublicKey):
            key_type = KeyType.ED448.value
            status = CertStatus.Done
        elif isinstance(der_public_key, Ed25519PublicKey):
            key_type = KeyType.ED25519.value
            status = CertStatus.Done
        elif isinstance(der_public_key, DHPublicKey):
            key_type = KeyType.DH.value
            status = CertStatus.Done
        elif isinstance(der_public_key, X448PublicKey):
            key_type = KeyType.X448.value
            status = CertStatus.Done
        elif isinstance(der_public_key, X25519PublicKey):
            key_type = KeyType.X25519.value
            status = CertStatus.Done
        else:
            status = CertStatus.GET_DER_PK_ERROR
    except Exception as e:
        status = CertStatus.GET_DER_PK_ERROR
    return str(key_type), str(size), numbers, status


def get_der_cert_sig_alg(der_cert):
    cert_sig = None
    try:
        signature_algorithm_oid = der_cert.signature_algorithm_oid
        oid = str(signature_algorithm_oid.dotted_string)
        cert_sig = str(signature_algorithm_oid._name)
        status = CertStatus.Done
    except:
        status = CertStatus.GET_DER_SIG_ALG_ERROR
    return cert_sig, status


def get_der_validity(der_cert):
    valid_from = None
    valid_to = None
    try:
        valid_from = der_cert.not_valid_before
        valid_to = der_cert.not_valid_after
        status = CertStatus.Done
    except:
        status = CertStatus.GET_DER_VL_ERROR
    return str(valid_from), str(valid_to), status


def get_der_cert_subject(der_cert):
    warnings.filterwarnings("ignore")
    cert_attr_list = []
    try:
        custom_cert_attr_list = []
        for attr_name, oid in NameOID.__dict__.items():
            if str(attr_name).startswith('__'):
                pass
            else:
                try:
                    # TODO: ValueError: error parsing asn1 value: ParseError { kind: InvalidValue, location: ["subject"] }
                    oid_attr_list = der_cert.subject.get_attributes_for_oid(oid)
                    if oid_attr_list is None or len(oid_attr_list) == 0:
                        pass
                    else:
                        attr_value = []
                        for item in oid_attr_list:
                            attr_value.append(str(item.value))
                        cert_attr_list.append({'oid': str(oid), 'value': attr_value})
                        custom_cert_attr_list.append({'oid': oid, 'value': attr_value})
                except:
                    return
        for attr_name, oid in ExtensionOID.__dict__.items():
            if str(attr_name).startswith('__'):
                pass
            else:
                try:
                    # TODO: ValueError: error parsing asn1 value: ParseError { kind: InvalidValue, location: ["subject"] }
                    oid_attr_list = der_cert.subject.get_attributes_for_oid(oid)
                    if oid_attr_list is None or len(oid_attr_list) == 0:
                        pass
                    else:
                        attr_value = []
                        for item in oid_attr_list:
                            attr_value.append(str(item.value))
                        cert_attr_list.append({'oid': str(oid), 'value': attr_value})
                        custom_cert_attr_list.append({'oid': oid, 'value': attr_value})
                except:
                    raise

        attributes = []
        for item in custom_cert_attr_list:
            for value in item['value']:
                attributes.append(x509.NameAttribute(item['oid'], str(value), _validate=False))

        custom_subject = x509.Name(attributes)

        main_subject = str(der_cert.subject)
        custom_subject = str(custom_subject)

        main_subject_inner_part = main_subject
        if main_subject_inner_part.startswith('<Name('):
            main_subject_inner_part = main_subject_inner_part[6:]
        if main_subject_inner_part.endswith(')>'):
            length = len(main_subject_inner_part)
            main_subject_inner_part = main_subject_inner_part[:length - 2]

        custom_subject_inner_part = custom_subject
        if custom_subject_inner_part.startswith('<Name('):
            custom_subject_inner_part = custom_subject_inner_part[6:]
        if custom_subject_inner_part.endswith(')>'):
            length = len(custom_subject_inner_part)
            custom_subject_inner_part = custom_subject_inner_part[:length - 2]

        main_subject_elements = main_subject_inner_part.split(',')
        custom_subject_elements = custom_subject_inner_part.split(',')

        try:
            for item in custom_subject_elements:
                main_subject_elements.remove(item)
        except Exception as e:
            raise AssertionError('Error in regenerating the subject: ', e)

        try:
            if len(main_subject_elements) != 0:
                for item in main_subject_elements:
                    if item.__contains__('='):
                        unknown_elements = item.split('=')
                        oid = unknown_elements[0]
                        attr_value = unknown_elements[1]
                        cert_attr_list.append({'oid': str(oid), 'value': str(attr_value)})
                    else:
                        raise AssertionError('cert subject: bad unknown format: ', item)
        except Exception as e:
            raise AssertionError('cert subject: unknown oid: ', e)

        status = CertStatus.Done
    except Exception as e:
        status = CertStatus.GET_DER_SJ_ERROR
    return cert_attr_list, status


def get_der_cert_issuer(der_cert):
    warnings.filterwarnings("ignore")
    cert_attr_list = []
    try:
        custom_cert_attr_list = []

        for attr_name, oid in NameOID.__dict__.items():
            if str(attr_name).startswith('__'):
                pass
            else:
                try:
                    # TODO error4 ValueError: error parsing asn1 value: ParseError { kind: InvalidValue, location: ["issuer"] }
                    oid_attr_list = der_cert.issuer.get_attributes_for_oid(oid)
                    if oid_attr_list is None or len(oid_attr_list) == 0:
                        pass
                    else:
                        attr_value = []
                        for item in oid_attr_list:
                            attr_value.append(str(item.value))
                        cert_attr_list.append({'oid': str(oid), 'value': attr_value})
                        custom_cert_attr_list.append({'oid': oid, 'value': attr_value})
                except:
                    # print(eval(der_cert.issuer))
                    # print(repr(der_cert.issuer))
                    # raise
                    pass

        for attr_name, oid in ExtensionOID.__dict__.items():
            if str(attr_name).startswith('__'):
                pass
            else:
                try:
                    oid_attr_list = der_cert.issuer.get_attributes_for_oid(oid)
                    if oid_attr_list is None or len(oid_attr_list) == 0:
                        pass
                    else:
                        attr_value = []
                        for item in oid_attr_list:
                            attr_value.append(str(item.value))
                        cert_attr_list.append({'oid': str(oid), 'value': attr_value})
                        custom_cert_attr_list.append({'oid': oid, 'value': attr_value})
                except:
                    return

        attributes = []
        for item in custom_cert_attr_list:
            for value in item['value']:
                attributes.append(x509.NameAttribute(item['oid'], str(value), _validate=False))
        custom_issuer = x509.Name(attributes)
        main_issuer = str(der_cert.issuer)

        main_issuer_inner_part = main_issuer
        if main_issuer_inner_part.startswith('<Name('):
            main_issuer_inner_part = main_issuer_inner_part[6:]
        if main_issuer_inner_part.endswith(')>'):
            length = len(main_issuer_inner_part)
            main_issuer_inner_part = main_issuer_inner_part[:length - 2]

        custom_issuer_inner_part = str(custom_issuer)
        if custom_issuer_inner_part.startswith('<Name('):
            custom_issuer_inner_part = custom_issuer_inner_part[6:]
        if custom_issuer_inner_part.endswith(')>'):
            length = len(custom_issuer_inner_part)
            custom_issuer_inner_part = custom_issuer_inner_part[:length - 2]

        main_issuer_elements = main_issuer_inner_part.split(',')
        custom_issuer_elements = custom_issuer_inner_part.split(',')

        try:
            for item in custom_issuer_elements:
                main_issuer_elements.remove(item)
        except Exception as e:
            raise AssertionError('Error in regenerating the issuer: ', e)

        try:
            if len(main_issuer_elements) != 0:
                for item in main_issuer_elements:
                    if item.__contains__('='):
                        unknown_elements = item.split('=')
                        oid = unknown_elements[0]
                        attr_value = unknown_elements[1]
                        cert_attr_list.append({'oid': str(oid), 'value': str(attr_value)})
                    else:
                        raise AssertionError('cert issuer: bad unknown format: ', item)
        except Exception as e:
            raise AssertionError('cert issuer: unknown oid: ', e)

        status = CertStatus.Done
    except Exception as e:
        status = CertStatus.GET_DER_IS_ERROR
    return cert_attr_list, status


def get_der_cert_extensions(der_cert):
    cert_ext_list = []
    ext_count = 0
    try:
        ext_count = len(der_cert.extensions)
    except:
        pass
    try:
        for ext_name, oid in ExtensionOID.__dict__.items():
            if str(ext_name).startswith('__'):
                pass
            else:
                oid_ext = None
                try:
                    oid_ext = der_cert.extensions.get_extension_for_oid(oid)
                except:
                    pass
                if oid_ext is None:
                    pass
                else:
                    if oid.__eq__(ExtensionOID.BASIC_CONSTRAINTS):
                        value = [{'ca': str(oid_ext.value.ca)},
                                 {'path_length': str(oid_ext.value.path_length)}]
                        cert_ext_list.append({'oid': str(oid), 'critical': str(oid_ext.critical), 'value': value})
                    elif oid.__eq__(ExtensionOID.SUBJECT_KEY_IDENTIFIER):
                        value = [{'digest': cert_parser_helper.get_encoded_base64(oid_ext.value.digest)}]
                        cert_ext_list.append({'oid': str(oid), 'critical': str(oid_ext.critical), 'value': value})
                    elif oid.__eq__(ExtensionOID.AUTHORITY_KEY_IDENTIFIER):
                        key_id_value = oid_ext.value.key_identifier
                        if key_id_value is not None:
                            key_id_value = cert_parser_helper.get_encoded_base64(oid_ext.value.key_identifier)
                        value = [{'key_identifier': key_id_value},
                                 {'authority_cert_issuer': str(oid_ext.value.authority_cert_issuer)},
                                 {'authority_cert_serial_number': str(oid_ext.value.authority_cert_serial_number)}]
                        cert_ext_list.append({'oid': str(oid), 'critical': str(oid_ext.critical), 'value': value})
                    elif oid.__eq__(ExtensionOID.CERTIFICATE_POLICIES):
                        inner_value = []
                        for item in oid_ext.value:
                            if item.__eq__(x509.extensions.PolicyInformation):
                                inner_value.append({'policy_identifier': str(item.policy_identifier),
                                                    'policy_qualifiers': str(item.policy_qualifiers)})
                            else:
                                raise AssertionError('unhandled extension CERTIFICATE_POLICIES')

                        value = inner_value
                        cert_ext_list.append({'oid': str(oid), 'critical': str(oid_ext.critical), 'value': value})
                    elif oid.__eq__(ExtensionOID.CRL_DISTRIBUTION_POINTS):
                        inner_value = []
                        for item in oid_ext.value:
                            if item.__eq__(x509.extensions.DistributionPoint):
                                # full_name_value = []
                                # if type(item.full_name) is list:
                                #     for i in item.full_name:
                                #         if type(i) is UniformResourceIdentifier:
                                #             full_name_value.append(i.value)
                                #         else:
                                #             full_name_value.append(str(i.value))
                                # else:
                                #     full_name_value = str(item.full_name)

                                full_name_value = str(item.full_name)
                                inner_value.append({'full_name': full_name_value,
                                                    'relative_name': str(item.relative_name),
                                                    'reasons': str(item.reasons),
                                                    'crl_issuer': str(item.crl_issuer)})
                            else:
                                raise AssertionError('unhandled extension CRLDistributionPoints')
                        value = inner_value
                        cert_ext_list.append({'oid': str(oid), 'critical': str(oid_ext.critical), 'value': value})
                    elif oid.__eq__(ExtensionOID.AUTHORITY_INFORMATION_ACCESS):
                        inner_value = []
                        for item in oid_ext.value:
                            if item.__eq__(x509.extensions.AccessDescription):
                                inner_value.append({'access_method': str(item.access_method),
                                                    'access_location': str(item.access_location)})
                            else:
                                raise AssertionError('unhandled extension AUTHORITY_INFORMATION_ACCESS')

                        value = inner_value
                        cert_ext_list.append({'oid': str(oid), 'critical': str(oid_ext.critical), 'value': value})
                    elif oid.__eq__(ExtensionOID.EXTENDED_KEY_USAGE):
                        inner_value = []
                        for item in oid_ext.value:
                            inner_value.append(str(item))
                        value = inner_value
                        cert_ext_list.append({'oid': str(oid), 'critical': str(oid_ext.critical), 'value': value})
                    elif oid.__eq__(ExtensionOID.KEY_USAGE):
                        value = [{'digital_signature': str(oid_ext.value.digital_signature)},
                                 {'content_commitment': str(oid_ext.value.content_commitment)},
                                 {'key_encipherment': str(oid_ext.value.key_encipherment)},
                                 {'data_encipherment': str(oid_ext.value.data_encipherment)},
                                 {'key_agreement': str(oid_ext.value.key_agreement)},
                                 {'key_cert_sign': str(oid_ext.value.key_cert_sign)},
                                 {'crl_sign': str(oid_ext.value.crl_sign)}]
                        if oid_ext.value.key_agreement:
                            value.append({'encipher_only': str(oid_ext.value.encipher_only)})
                            value.append({'decipher_only': str(oid_ext.value.decipher_only)})
                        else:
                            value.append({'encipher_only': str(False)})
                            value.append({'decipher_only': str(False)})
                        cert_ext_list.append({'oid': str(oid), 'critical': str(oid_ext.critical), 'value': value})
                    elif oid.__eq__(ExtensionOID.SUBJECT_ALTERNATIVE_NAME):
                        dns_list = oid_ext.value.get_values_for_type(x509.DNSName)
                        dns_list_str = []
                        for i in dns_list:
                            dns_list_str.append(repr(i))
                        value = [{str(x509.DNSName.__name__): dns_list_str}]
                        cert_ext_list.append({'oid': oid, 'critical': str(oid_ext.critical), 'value': value})
                        custom_dns_list = []

                        for item in dns_list_str:
                            custom_dns_list.append(x509.DNSName(str(item.encode('utf-8'))))

                        main_dns_list = dns_list_str
                        custom_ext = x509.SubjectAlternativeName(general_names=custom_dns_list)
                        custom_dns_list = custom_ext.get_values_for_type(x509.DNSName)

                        for i in custom_dns_list:
                            for j in main_dns_list:
                                if str(j.encode('utf-8')).__eq__(i):
                                    main_dns_list.remove(j)

                        if len(main_dns_list) != 0:
                            raise AssertionError('cert extension: unknown name in SUBJECT_ALTERNATIVE_NAME')
                    elif oid.__eq__(ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS):
                        inner_value = []
                        for item in oid_ext.value:
                            if item.__eq__(x509.extensions.SignedCertificateTimestamps):
                                inner_value.append({'version': str(item.version),
                                                    'log_id': cert_parser_helper.get_encoded_base64(item.log_id),
                                                    'timestamp': str(item.timestamp),
                                                    'signature': cert_parser_helper.get_encoded_base64(item.signature),
                                                    # 'signature_algorithm': str(item.signature_algorithm),
                                                    # 'signature_hash_algorithm': str(item.signature_hash_algorithm),
                                                    'signature_alg': '{}-with-{}'.format(item.signature_algorithm.name.lower(), item.signature_hash_algorithm.name.upper()),
                                                    # 'entry_type': str(item.entry_type),
                                                    # 'extension_bytes': str(item.extension_bytes)
                                                    })
                            else:
                                raise AssertionError('unhandled extension PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS')
                        value = inner_value
                        cert_ext_list.append({'oid': str(oid), 'critical': str(oid_ext.critical), 'value': value})
                    elif oid.__eq__(ExtensionOID.ISSUER_ALTERNATIVE_NAME):
                        RFC822_list = oid_ext.value.get_values_for_type(x509.RFC822Name)
                        RFC822_list_str = []
                        for i in RFC822_list:
                            RFC822_list_str.append(str(i))
                        value = [{str(x509.RFC822Name.__name__): RFC822_list_str}]
                        cert_ext_list.append({'oid': oid, 'critical': str(oid_ext.critical), 'value': value})

                        custom_RFC822_list = []
                        for item in RFC822_list:
                            custom_RFC822_list.append(x509.RFC822Name(item))

                        main_RFC822_list = RFC822_list
                        custom_ext = x509.IssuerAlternativeName(general_names=custom_RFC822_list)
                        custom_RFC822_list = custom_ext.get_values_for_type(x509.RFC822Name)
                        for i in custom_RFC822_list:
                            main_RFC822_list.remove(i)
                        if len(main_RFC822_list) != 0:
                            raise AssertionError('cert extension: unknown name in ISSUER_ALTERNATIVE_NAME')
                    elif oid.__eq__(ExtensionOID.TLS_FEATURE):
                        inner_value = []
                        for item in oid_ext.value:
                            if item.__eq__(x509.extensions.TLSFeatureType):
                                feature_list_str = []
                                for f in oid_ext.value._features:
                                    feature_list_str.append({str(f): str(f.value)})
                                inner_value.append({'features': feature_list_str})
                            else:
                                raise AssertionError('unhandled extension TLS_FEATURE')
                        value = inner_value
                        cert_ext_list.append({'oid': str(oid), 'critical': str(oid_ext.critical), 'value': value})
                    elif oid.__eq__(ExtensionOID.SUBJECT_DIRECTORY_ATTRIBUTES):
                        inner_value = []
                        if oid_ext.value.__eq__(x509.extensions.UnrecognizedExtension):
                            item_oid = oid_ext.value.oid
                            item_value = oid_ext.value.value
                            inner_value.append({'oid': str(item_oid),
                                                'value': str(item_value)})
                        else:
                            raise AssertionError('unhandled extension SUBJECT_DIRECTORY_ATTRIBUTES')
                        value = inner_value
                        cert_ext_list.append({'oid': str(oid), 'critical': str(oid_ext.critical), 'value': value})
                    elif oid.__eq__(ExtensionOID.OCSP_NO_CHECK):
                        value = [{'value': str(oid_ext.value)}]
                        cert_ext_list.append({'oid': str(oid), 'critical': str(oid_ext.critical), 'value': value})
                    elif oid.__eq__(ExtensionOID.FRESHEST_CRL):
                        inner_value = []
                        for item in oid_ext.value:
                            if item.__eq__(x509.extensions.DistributionPoint):
                                inner_value.append({'full_name': str(item.full_name),
                                                    'relative_name': str(item.relative_name),
                                                    'reasons': str(item.reasons),
                                                    'crl_issuer': str(item.crl_issuer)})
                            else:
                                raise AssertionError('unhandled extension FRESHEST_CRL')
                        value = inner_value
                        cert_ext_list.append({'oid': str(oid), 'critical': str(oid_ext.critical), 'value': value})
                    elif oid.__eq__(ExtensionOID.NAME_CONSTRAINTS):
                        value = [{'permitted_subtrees': str(oid_ext.value.permitted_subtrees),
                                  'excluded_subtrees': str(oid_ext.value.excluded_subtrees)}]
                        cert_ext_list.append({'oid': str(oid), 'critical': str(oid_ext.critical), 'value': value})
                    elif oid.__eq__(ExtensionOID.SIGNED_CERTIFICATE_TIMESTAMPS):
                        inner_value = []
                        if oid_ext.value.__eq__(x509.extensions.UnrecognizedExtension):
                            item_oid = oid_ext.value.oid
                            item_value = oid_ext.value.value
                            inner_value.append({'oid': str(item_oid),
                                                'value': cert_parser_helper.get_encoded_base64(item_value)})
                        else:
                            raise AssertionError('unhandled extension SUBJECT_DIRECTORY_ATTRIBUTES')
                        value = inner_value
                        cert_ext_list.append({'oid': str(oid), 'critical': str(oid_ext.critical), 'value': value})
                    elif oid.__eq__(ExtensionOID.SUBJECT_INFORMATION_ACCESS):
                        inner_value = []
                        for item in oid_ext.value:
                            if item.__eq__(x509.extensions.AccessDescription):
                                inner_value.append({'access_method': str(item.access_method),
                                                    'access_location': str(item.access_location)})
                            else:
                                raise AssertionError('unhandled extension SUBJECT_INFORMATION_ACCESS')
                        value = inner_value
                        cert_ext_list.append({'oid': str(oid), 'critical': str(oid_ext.critical), 'value': value})
                    elif oid.__eq__(ExtensionOID.POLICY_CONSTRAINTS):
                        value = [{'require_explicit_policy': str(oid_ext.value.require_explicit_policy)},
                                 {'inhibit_policy_mapping': str(oid_ext.value.inhibit_policy_mapping)}]
                        cert_ext_list.append({'oid': str(oid), 'critical': str(oid_ext.critical), 'value': value})
                    elif oid.__eq__(ExtensionOID.PRECERT_POISON):
                        value = [oid_ext.value]
                        cert_ext_list.append({'oid': str(oid), 'critical': str(oid_ext.critical), 'value': value})
                    elif oid.__eq__(ExtensionOID.POLICY_MAPPINGS):
                        inner_value = []
                        if oid_ext.value.__eq__(x509.extensions.UnrecognizedExtension):
                            item_oid = oid_ext.value.oid
                            item_value = oid_ext.value.value
                            inner_value.append({'oid': str(item_oid),
                                                'value': cert_parser_helper.get_encoded_base64(item_value)})
                        else:
                            raise AssertionError('unhandled extension POLICY_MAPPINGS')
                        value = inner_value
                        cert_ext_list.append({'oid': str(oid), 'critical': str(oid_ext.critical), 'value': value})
                    elif oid.__eq__(ExtensionOID.INHIBIT_ANY_POLICY):
                        value = [oid_ext.value]
                        cert_ext_list.append({'oid': str(oid), 'critical': str(oid_ext.critical), 'value': value})
                    else:
                        print(oid_ext)
                        print(oid)
                        raise AssertionError('unhandled ExtensionOID', 'oid: ', oid, 'oid_ext: ', oid_ext)
        status = CertStatus.Done
    except Exception as e:
        status = CertStatus.GET_DER_EX_ERROR

    return cert_ext_list, ext_count, status


