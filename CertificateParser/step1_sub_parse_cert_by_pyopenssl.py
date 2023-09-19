# -*- coding: utf-8 -*-
import base64
import hashlib

import OpenSSL
from OpenSSL import crypto
from OpenSSL.crypto import X509
from CertParser import cert_parser_helper
from CertParser.cert_parser_helper import KeyType
from CertParser.cert_parser_helper import CertStatus


def get_der_cert(pem_cert):
    der_cert = None
    try:
        der_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_cert)
        status = CertStatus.Done
    except Exception as e:
        status = CertStatus.GET_DER_ERROR
    return der_cert, status


def get_cert_issuer(cert: X509):
    result = []
    try:
        issuer = cert.get_issuer()
        issuer_components = issuer.get_components()
        for item in issuer_components:
            if item.__len__() == 2:
                # key = str(item[0])[2:-1]
                # value = str(item[1])[2:-1]
                key = cert_parser_helper.get_str(item[0])
                value = cert_parser_helper.get_str(item[1])
                result.append({key: value})
            else:
                raise AssertionError('issuer, components: unhandled length')
        status = CertStatus.Done
    except Exception as e:
        status = CertStatus.GET_DER_IS_ERROR
    return result, status


def get_cert_subject(cert: X509):
    result = []
    try:
        subject = cert.get_subject()
        subject_components = subject.get_components()
        for item in subject_components:
            if item.__len__() == 2:
                # key = str(item[0])
                # value = str(item[1])
                key = cert_parser_helper.get_str(item[0])
                value = cert_parser_helper.get_str(item[1])
                result.append({key: value})
            else:
                raise AssertionError('subject, components: unhandled length')
        status = CertStatus.Done
    except Exception as e:
        status = CertStatus.GET_DER_SJ_ERROR
    return result, status


def get_cert_version(cert: X509):
    version = None
    try:
        version = cert.get_version()
        status = CertStatus.Done
    except Exception as e:
        status = CertStatus.GET_DER_VR_ERROR
    return str(version), status


def get_cert_serial_number(cert: X509):
    serial_number = None
    try:
        serial_number = cert.get_serial_number()
        status = CertStatus.Done
    except Exception as e:
        status = CertStatus.GET_DER_SRN_ERROR
    return str(serial_number), status


def get_cert_validity(cert: X509):
    valid_from = None
    valid_to = None
    try:
        valid_from = cert.get_notBefore()
        valid_to = cert.get_notAfter()

        valid_from = cert_parser_helper.get_str(valid_from)
        valid_to = cert_parser_helper.get_str(valid_to)

        status = CertStatus.Done
    except Exception as e:
        status = CertStatus.GET_DER_VL_ERROR
    return valid_from, valid_to, status


def get_cert_sig_alg(cert: X509):
    sig_alg = None
    try:
        sig_alg = cert.get_signature_algorithm()
        sig_alg = cert_parser_helper.get_str(sig_alg)
        status = CertStatus.Done
    except Exception as e:
        status = CertStatus.GET_DER_SIG_ALG_ERROR
    return sig_alg, status


def get_cert_extensions(cert: X509):
    result = []
    try:
        ext_count = cert.get_extension_count()
        for index in range(ext_count):
            try:
                ext = cert.get_extension(index)
                ext_str = str(ext)
                ext_short_name = ext.get_short_name()
                ext_short_name = cert_parser_helper.get_str(ext_short_name)
                ext_critical = str(ext.get_critical())
                data = ext.get_data()
                ext_data = cert_parser_helper.get_encoded_base64(data)
                result.append(
                    {'short_name': ext_short_name, 'critical': ext_critical, 'value': ext_str, 'data': ext_data})
            except Exception as e:
                raise e
        status = CertStatus.Done
    except Exception as e:
        status = CertStatus.GET_DER_EX_ERROR
    return result, ext_count, status


def get_cert_public_key_info(cert: X509):
    public_key_info = None
    try:
        public_key = cert.get_pubkey()
        public_key_info = crypto.dump_publickey(crypto.FILETYPE_ASN1, public_key)
        public_key_info = cert_parser_helper.get_encoded_base64(public_key_info)
        status = CertStatus.Done
    except Exception as e:
        status = CertStatus.GET_DER_PKI_ERROR
    return public_key_info, status


def get_cert_public_key(cert: X509):
    size = None
    numbers = None
    key_type = None
    try:
        # key_size = public_key.bits()
        # key = crypto.load_publickey(crypto.FILETYPE_PEM, cert_public_key_info)
        public_key = cert.get_pubkey()
        der_key_type = public_key.type()

        if der_key_type == crypto.TYPE_RSA:
            key_data = public_key.to_cryptography_key()
            key_type, size, numbers, status = get_public_key_rsa(key_data)
        elif der_key_type == crypto.TYPE_DSA:
            key_data = public_key.to_cryptography_key()
            key_type, size, numbers, status = get_public_key_dsa(key_data)
        elif der_key_type == crypto.TYPE_EC:
            key_data = public_key.to_cryptography_key()
            key_type, size, numbers, status = get_public_key_ec(key_data)
        elif der_key_type == crypto.TYPE_DH:
            key_type = KeyType.DH.value
            status = CertStatus.Done
        else:
            status = CertStatus.GET_DER_PK_ERROR
    except Exception as e:
        status = CertStatus.GET_DER_PK_ERROR
    return str(key_type), str(size), numbers, status


def get_public_key_rsa(key_data):
    key_type = KeyType.RSA.value
    size = None
    numbers = []

    try:
        size = int(key_data.key_size)
        numbers_n = key_data.public_numbers().n
        numbers_e = key_data.public_numbers().e
        modulus = hex(numbers_n)[2:]
        exponent = str(int(numbers_e))
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


def get_cert_thumbprints(cert: X509):
    hash_md5 = None
    hash_sha1 = None
    hash_sha256 = None
    try:
        public_bytes = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
        hash_md5 = hashlib.md5(public_bytes).hexdigest().lower()
        hash_sha1 = hashlib.sha1(public_bytes).hexdigest().lower()
        hash_sha256 = hashlib.sha256(public_bytes).hexdigest().lower()
        status = CertStatus.Done
    except Exception as e:
        status = CertStatus.GET_DER_TP_ERROR
    return hash_md5, hash_sha1, hash_sha256, status


def get_key_thumbprints(cert: X509):
    pkp_1 = None
    pkp_2 = None
    try:
        public_key = cert.get_pubkey()
        public_key_info = crypto.dump_publickey(crypto.FILETYPE_ASN1, public_key)

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


def get_key_thumbprints_by_key(public_key_info):
    pkp_1 = None
    pkp_2 = None
    try:
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


def parse_der_by_pyopenssl(pem_cert):
    version = None
    serial_number = None
    valid_from = None
    valid_to = None
    sig_alg = None
    cert_ext_list = None
    ext_count = None
    subject_attr_list = None
    issuer_attr_list = None
    tp_md5 = None
    tp_sha1 = None
    tp_sha2 = None
    tp_hpkp_1 = None
    tp_hpkp_2 = None
    public_key_info = None
    pub_key_type = None
    pub_key_size = None
    pub_key_numbers = None
    status_code = '999999999999'
    status = CertStatus.Started
    try:
        der_cert, status = get_der_cert(pem_cert)
        if der_cert is not None:
            version, status =get_cert_version(der_cert)
            serial_number, status =get_cert_serial_number(der_cert)
            valid_from, valid_to, status =get_cert_validity(der_cert)
            sig_alg, status =get_cert_sig_alg(der_cert)
            tp_md5, tp_sha1, tp_sha2, status =get_cert_thumbprints(der_cert)
            cert_ext_list, ext_count, status =get_cert_extensions(der_cert)
            subject_attr_list, status =get_cert_subject(der_cert)
            issuer_attr_list, status =get_cert_issuer(der_cert)
            public_key_info, status =get_cert_public_key_info(der_cert)
            tp_hpkp_1, tp_hpkp_2, status =get_key_thumbprints(der_cert)
            pub_key_type, pub_key_size, pub_key_numbers, status =get_cert_public_key(der_cert)
    except Exception as e:
        status = CertStatus.GET_BY_SSL_ERROR

    if status == CertStatus.Started:
        status = CertStatus.Unknown

    log = {
        'status': status_code,
        'version': version,
        'serial_number': serial_number,
        'valid_from': valid_from,
        'valid_to': valid_to,
        'sig_alg': sig_alg,
        'ext_count': ext_count,
        'ext_list': cert_ext_list,
        'subject_attr_list': subject_attr_list,
        'issuer_attr_list': issuer_attr_list,
        'tp_md5': tp_md5,
        'tp_sha1': tp_sha1,
        'tp_sha2': tp_sha2,
        'tp_hpkp_1': tp_hpkp_1,
        'tp_hpkp_2': tp_hpkp_2,
        'public_key_info': public_key_info,
        'pub_key_type': pub_key_type,
        'pub_key_size': pub_key_size,
        'pub_key_numbers': pub_key_numbers
    }
    return log, status