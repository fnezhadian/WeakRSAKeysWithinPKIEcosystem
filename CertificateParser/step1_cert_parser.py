import base64
import hashlib
import io
import json
import sys
from datetime import datetime
from CertParser.cert_parser_helper import CertStatus
from Helper import io_helper
import step1_sub_parse_cert_by_cryptography as CryptoParser
import step1_sub_parse_cert_by_pyopenssl as PysslParser


def update_status_code(status_code, status, position):
    success = '1'
    fail = '0'
    if status == CertStatus.Done:
        status_code = status_code[:position] + success + status_code[position + 1:]
    else:
        status_code = status_code[:position] + fail + status_code[position + 1:]
    return status_code


def parse_der_by_cryptography(der_bin):
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
        der_cert, status = CryptoParser.get_der_cert(der_bin)
        status_code = update_status_code(status_code, status, 0)
        if der_cert is not None:
            version, status = CryptoParser.get_der_cert_version(der_cert)
            status_code = update_status_code(status_code, status, 1)
            serial_number, status = CryptoParser.get_der_cert_serial_no(der_cert)
            status_code = update_status_code(status_code, status, 2)
            valid_from, valid_to, status = CryptoParser.get_der_validity(der_cert)
            status_code = update_status_code(status_code, status, 3)
            sig_alg, status = CryptoParser.get_der_cert_sig_alg(der_cert)
            status_code = update_status_code(status_code, status, 4)
            tp_md5, tp_sha1, tp_sha2, status = CryptoParser.get_der_thumbprints(der_cert)
            status_code = update_status_code(status_code, status, 5)
            cert_ext_list, ext_count, status = CryptoParser.get_der_cert_extensions(der_cert)
            status_code = update_status_code(status_code, status, 6)
            subject_attr_list, status = CryptoParser.get_der_cert_subject(der_cert)
            status_code = update_status_code(status_code, status, 7)
            issuer_attr_list, status = CryptoParser.get_der_cert_issuer(der_cert)
            status_code = update_status_code(status_code, status, 8)
            public_key_info, status = CryptoParser.get_der_cert_public_key_info(der_cert)
            status_code = update_status_code(status_code, status, 9)
            tp_hpkp_1, tp_hpkp_2, status = CryptoParser.get_key_thumbprints(der_cert)
            status_code = update_status_code(status_code, status, 10)
            pub_key_type, pub_key_size, pub_key_numbers, status = CryptoParser.get_public_key(der_cert)
            status_code = update_status_code(status_code, status, 11)
    except Exception as e:
        status = CertStatus.GET_BY_CRYPTO_ERROR

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
        der_cert, status = PysslParser.get_der_cert(pem_cert)
        status_code = update_status_code(status_code, status, 0)
        if der_cert is not None:
            version, status = PysslParser.get_cert_version(der_cert)
            status_code = update_status_code(status_code, status, 1)
            serial_number, status = PysslParser.get_cert_serial_number(der_cert)
            status_code = update_status_code(status_code, status, 2)
            valid_from, valid_to, status = PysslParser.get_cert_validity(der_cert)
            status_code = update_status_code(status_code, status, 3)
            sig_alg, status = PysslParser.get_cert_sig_alg(der_cert)
            status_code = update_status_code(status_code, status, 4)
            tp_md5, tp_sha1, tp_sha2, status = PysslParser.get_cert_thumbprints(der_cert)
            status_code = update_status_code(status_code, status, 5)
            cert_ext_list, ext_count, status = PysslParser.get_cert_extensions(der_cert)
            status_code = update_status_code(status_code, status, 6)
            subject_attr_list, status = PysslParser.get_cert_subject(der_cert)
            status_code = update_status_code(status_code, status, 7)
            issuer_attr_list, status = PysslParser.get_cert_issuer(der_cert)
            status_code = update_status_code(status_code, status, 8)
            public_key_info, status = PysslParser.get_cert_public_key_info(der_cert)
            status_code = update_status_code(status_code, status, 9)
            tp_hpkp_1, tp_hpkp_2, status = PysslParser.get_key_thumbprints(der_cert)
            status_code = update_status_code(status_code, status, 10)
            pub_key_type, pub_key_size, pub_key_numbers, status = PysslParser.get_cert_public_key(der_cert)
            status_code = update_status_code(status_code, status, 11)
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


def main_der_by_crypto(xline):
    log = None
    try:
        # xline = create_struct(xline)  # sometimes needed
        # xline = create_pem_struct(xline)  # sometimes needed
        cert = base64.b64decode(xline)
        # # print(repr(cert))
        # # print(str(cert)[2:-1].replace("\\n", "\n"))
        log, status = parse_der_by_cryptography(cert)
    except Exception as e:
        status = CertStatus.GET_BY_CRYPTO_ERROR
    return log, status


def main_der_by_ssl(xline):
    log = None
    try:
        pem_cert = create_pem_struct(xline)
        # print(str(content)[2:-1].replace("\\n", "\n"))
        log, status = parse_der_by_pyopenssl(pem_cert)
    except Exception as e:
        status = CertStatus.GET_BY_SSL_ERROR
    return log, status


def create_pem_struct(xline):
    begin = '-----BEGIN CERTIFICATE-----'
    end = '-----END CERTIFICATE-----'
    n = 64
    parts = [xline[i:i + n] for i in range(0, len(xline), n)]
    content = ''
    for part in parts:
        content = content + '\n' + part
    content = begin + content + '\n' + end
    return content


def create_struct(xline):
    n = 64
    parts = [xline[i:i + n] for i in range(0, len(xline), n)]
    content = ''
    for part in parts:
        content = content + '\n' + part
    return content


def get_base64(xline):
    content = create_pem_struct(xline)
    content = base64.b64encode(content.encode('utf-8'))
    content = str(content)[2:-1]
    return content


def main(full_path, dataset_name, delimiter, position, last_index=0):
    failed_cert_file = io_helper.create_same_target_file(full_path, 'txt')
    json_file = io_helper.create_same_json_file(full_path)
    index = -1
    print(datetime.now())
    with io.open(full_path, 'r', encoding='utf-8') as file:
        for line in file:
            index = index + 1
            if index <= last_index:
                continue
            xline = line.replace("\n", "").strip().split(delimiter)[position]
            # print('current index: ', index)
            if index % 100000 == 0:
                print(datetime.now())
                print('index: ', index)

            crypto_log, crypto_status = main_der_by_crypto(xline)
            ssl_log, ssl_status = main_der_by_ssl(xline)
            encoded_base64 = get_base64(xline)
            pem_structure = create_pem_struct(xline)
            encoded_pem_structure = pem_structure.encode('utf-8')
            pem_sha1 = hashlib.sha1(encoded_pem_structure).hexdigest().lower()

            if crypto_status in (
                    CertStatus.Started, CertStatus.Unknown, CertStatus.GET_BY_CRYPTO_ERROR) and ssl_status in (
                    CertStatus.Started, CertStatus.Unknown, CertStatus.GET_BY_SSL_ERROR):
                io_helper.write_line_into_file(failed_cert_file, xline)
            else:
                log = {
                    'index': str(index),
                    'encoded_base64': encoded_base64,
                    'pem_sha1': pem_sha1,
                    'crypto_log': crypto_log,
                    'pyopenssl_log': ssl_log,
                    'dataset_name': dataset_name}
                log_json = json.dumps(log, default=str)
                # io_helper.write_line_into_file(json_file, log_json)
                # db_id = cert_db.main(encoded_base64, pem_sha1, dataset_name, crypto_log, ssl_log)



if __name__ == "__main__":
    # full_path = '/media/user01/WORK_2/CONTAMINATION/Dataset_FR_13/allcerts.csv'
    # last_index = 0
    # xline = line.replace("\n", "").strip().split("|")[1]

    full_path = '/media/user01/WORK_2/CONTAMINATION/Dataset_APK/APK_all_files_decoded_RSA_certs.txt'
    last_index = 0
    # xline = line.replace("\n", "").strip().split("|")[2]

    dataset_name = io_helper.get_file_name(full_path)

    main(full_path, dataset_name, "|", 1)

# main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
# sys.exit(0)
