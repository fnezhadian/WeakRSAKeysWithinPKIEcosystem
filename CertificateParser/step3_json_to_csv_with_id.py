import csv
import io
import json
import os
import shutil
from datetime import datetime

from CertParser import cert_parser_helper
from CertParser.cert_parser_helper import KeyType
from DB.entity import Certificate, CryptoIssuerDetail, CryptoSubjectDetail, \
    CryptoExtensionDetail, SSLSubject, SSLIssuer, SSLExtension, RSAKey, DSAKey, ECKey, \
    CryptoExtension, CryptoIssuer, CryptoSubject, CertificateAndDependants, Key, CertificateSource, TableName
from Helper import io_helper


def log_error(encoded_base64, error, failed_cert_file):
    error_content = '{}|{}'.format(encoded_base64, error)
    io_helper.write_line_into_file(failed_cert_file, error_content)


def convert_json_to_cert(encoded_base64, pem_sha1, dataset_name, crypto_log, ssl_log, last_id_list, failed_cert_file):
    parsed_time = str(datetime.now())
    if crypto_log:
        crypto_status = crypto_log['status']
        crypto_sig_alg = crypto_log['sig_alg']
    else:
        crypto_status = '099999999999'
        crypto_sig_alg = None
    ssl_status = ssl_log['status']
    pub_key_type = ssl_log['pub_key_type']
    pub_key_numbers = ssl_log['pub_key_numbers']
    serial_number = ssl_log['serial_number']
    ssl_sig_alg = ssl_log['sig_alg']
    tp_md5 = ssl_log['tp_md5']
    tp_sha1 = ssl_log['tp_sha1']
    tp_sha2 = ssl_log['tp_sha2']
    tp_hpkp_1 = ssl_log['tp_hpkp_1']
    tp_hpkp_2 = ssl_log['tp_hpkp_2']
    pub_key_size = ssl_log['pub_key_size']
    public_key_info = ssl_log['public_key_info']
    crypto_ext_count = ssl_log['ext_count']
    ssl_ext_count = ssl_log['ext_count']
    valid_from = ssl_log['valid_from']
    valid_to = ssl_log['valid_to']
    version = ssl_log['version']
    if not version:
        if crypto_log:
            version = crypto_log['version']

    if not (crypto_status == '099999999999' or ssl_status == crypto_status):
        if crypto_log['serial_number'] != ssl_log['serial_number']:
            error = 'conflict in serial_number {} != {}'.format(crypto_log['serial_number'], ssl_log['serial_number'])
            log_error(encoded_base64, error, failed_cert_file)
        if crypto_log['tp_md5'] != ssl_log['tp_md5']:
            error = 'conflict in tp_md5 {} != {}'.format(crypto_log['tp_md5'], ssl_log['tp_md5'])
            log_error(encoded_base64, error, failed_cert_file)
        if crypto_log['tp_sha1'] != ssl_log['tp_sha1']:
            error = 'conflict in tp_sha1 {} != {}'.format(crypto_log['tp_sha1'], ssl_log['tp_sha1'])
            log_error(encoded_base64, error, failed_cert_file)
        if crypto_log['tp_sha2'] != ssl_log['tp_sha2']:
            error = 'conflict in tp_sha2 {} != {}'.format(crypto_log['tp_sha2'], ssl_log['tp_sha2'])
            log_error(encoded_base64, error, failed_cert_file)
        if crypto_log['tp_hpkp_1'] != ssl_log['tp_hpkp_1']:
            error = 'conflict in tp_hpkp_1 {} != {}'.format(crypto_log['tp_hpkp_1'], ssl_log['tp_hpkp_1'])
            log_error(encoded_base64, error, failed_cert_file)
        if crypto_log['tp_hpkp_2'] != ssl_log['tp_hpkp_2']:
            error = 'conflict in tp_hpkp_2 {} != {}'.format(crypto_log['tp_hpkp_2'], ssl_log['tp_hpkp_2'])
            log_error(encoded_base64, error, failed_cert_file)
        if crypto_log['pub_key_size'] != ssl_log['pub_key_size']:
            error = 'conflict in pub_key_size {} != {}'.format(crypto_log['pub_key_size'], ssl_log['pub_key_size'])
            log_error(encoded_base64, error, failed_cert_file)
        if crypto_log['public_key_info'] != ssl_log['public_key_info']:
            error = 'conflict in public_key_info {} != {}'.format(crypto_log['public_key_info'],
                                                                  ssl_log['public_key_info'])
            log_error(encoded_base64, error, failed_cert_file)
        if crypto_log['pub_key_type'] != ssl_log['pub_key_type']:
            error = 'conflict in pub_key_type {} != {}'.format(crypto_log['pub_key_type'], ssl_log['pub_key_type'])
            log_error(encoded_base64, error, failed_cert_file)
        if crypto_log['pub_key_numbers'] != ssl_log['pub_key_numbers']:
            error = 'conflict in pub_key_numbers {} != {}'.format(crypto_log['pub_key_numbers'],
                                                                  ssl_log['pub_key_numbers'])
            log_error(encoded_base64, error, failed_cert_file)

        crypto_valid_from = crypto_log['valid_from']
        if crypto_valid_from:
            crypto_valid_from = crypto_valid_from.replace(':', '')
            crypto_valid_from = crypto_valid_from.replace('-', '')
            crypto_valid_from = crypto_valid_from.replace(' ', '')

        ssl_valid_from = ssl_log['valid_from']
        if ssl_valid_from:
            if ssl_valid_from.endswith('Z'):
                ssl_valid_from = ssl_valid_from[:len(ssl_valid_from) - 1]

            if crypto_valid_from != ssl_valid_from:
                error = 'conflict in valid_from {} != {}'.format(crypto_valid_from, ssl_valid_from)
                log_error(encoded_base64, error, failed_cert_file)
        else:
            valid_from = crypto_log['valid_from']

        crypto_valid_to = crypto_log['valid_to']
        if crypto_valid_to:
            crypto_valid_to = crypto_valid_to.replace(':', '')
            crypto_valid_to = crypto_valid_to.replace('-', '')
            crypto_valid_to = crypto_valid_to.replace(' ', '')

        ssl_valid_to = ssl_log['valid_to']
        if ssl_valid_to:
            if ssl_valid_to.endswith('Z'):
                ssl_valid_to = ssl_valid_to[:len(ssl_valid_to) - 1]

            if crypto_valid_to != ssl_valid_to:
                error = 'conflict in valid_to {} != {}'.format(crypto_valid_to, ssl_valid_to)
                log_error(encoded_base64, error, failed_cert_file)
        else:
            valid_to = crypto_log['valid_to']

    rsa_key = None
    dsa_key = None
    ec_key = None
    crypto_extensions = []
    crypto_issuers = []
    crypto_subjects = []
    ssl_extensions = []
    ssl_issuers = []
    ssl_subjects = []

    certificate_id = int(last_id_list['certificate_id']) + 1
    certificate_source_id = last_id_list['certificate_source_id'] + 1
    crypto_extension_id = last_id_list['crypto_extension_id']
    crypto_extension_detail_id = last_id_list['crypto_extension_detail_id']
    crypto_subject_id = last_id_list['crypto_subject_id']
    crypto_subject_detail_id = last_id_list['crypto_subject_detail_id']
    crypto_issuer_id = last_id_list['crypto_issuer_id']
    crypto_issuer_detail_id = last_id_list['crypto_issuer_detail_id']
    ssl_extension_id = last_id_list['ssl_extension_id']
    ssl_subject_id = last_id_list['ssl_subject_id']
    ssl_issuer_id = last_id_list['ssl_issuer_id']
    key_id = last_id_list['key_id'] + 1
    rsa_key_id = last_id_list['rsa_key_id']
    dsa_key_id = last_id_list['dsa_key_id']
    ec_key_id = last_id_list['ec_key_id']

    cert = Certificate(encoded=encoded_base64, version=version, serial_number=serial_number,
                       valid_from=valid_from, valid_to=valid_to, ssl_sig_alg=ssl_sig_alg,
                       crypto_sig_alg=crypto_sig_alg, crypto_ext_count=crypto_ext_count, ssl_ext_count=ssl_ext_count,
                       tp_md5=tp_md5, tp_sha1=tp_sha1,
                       tp_sha2=tp_sha2, crypto_status=crypto_status,
                       ssl_status=ssl_status, parsed_time=parsed_time, pem_sha1=pem_sha1, id=certificate_id)

    source = CertificateSource(dataset_name=dataset_name, certificate_id=certificate_id, id=certificate_source_id)

    if pub_key_type == KeyType.RSA.value:
        rsa_key_id = rsa_key_id + 1
        rsa_key = RSAKey(exponent=pub_key_numbers[0], modulus=pub_key_numbers[1], key_id=key_id, id=rsa_key_id)
    elif pub_key_type == KeyType.DSA.value:
        dsa_key_id = dsa_key_id + 1
        dsa_key = DSAKey(p=pub_key_numbers[0], q=pub_key_numbers[1], g=pub_key_numbers[2], key_id=key_id, id=dsa_key_id)
    elif pub_key_type == KeyType.EC.value:
        ec_key_id = ec_key_id + 1
        ec_key = ECKey(curve=pub_key_numbers[0], x=pub_key_numbers[1], y=pub_key_numbers[2], key_id=key_id,
                       id=ec_key_id)

    cert_key = Key(pub_key_type=pub_key_type, pub_key_size=pub_key_size, public_key_info=public_key_info,
                   tp_hpkp_1=tp_hpkp_1, tp_hpkp_2=tp_hpkp_2, dataset_name=dataset_name,
                   rsa_key=rsa_key, dsa_key=dsa_key, ec_key=ec_key, certificate_id=certificate_id, id=key_id)

    if crypto_log:
        if crypto_log['ext_list'] is not None:
            for item in crypto_log['ext_list']:
                crypto_extension_id = crypto_extension_id + 1
                crypto_extension_details = []
                for value in item['value']:
                    crypto_extension_detail_id = crypto_extension_detail_id + 1
                    if type(value) is dict:
                        elements = [element for element in value]
                        for element in elements:
                            key = element
                            val = value[key]
                            crypto_extension_detail = CryptoExtensionDetail(key=key, value=val,
                                                                            extension_id=crypto_extension_id,
                                                                            id=crypto_extension_detail_id)
                            crypto_extension_details.append(crypto_extension_detail)
                    else:
                        crypto_extension_detail = CryptoExtensionDetail(key=None, value=value,
                                                                        extension_id=crypto_extension_id,
                                                                        id=crypto_extension_detail_id)
                        crypto_extension_details.append(crypto_extension_detail)
                crypto_extensions.append(
                    CryptoExtension(oid=item['oid'], critical=item['critical'], details=crypto_extension_details,
                                    certificate_id=certificate_id, id=crypto_extension_id))

        if crypto_log['issuer_attr_list'] is not None:
            for item in crypto_log['issuer_attr_list']:
                crypto_issuer_id = crypto_issuer_id + 1
                crypto_issuer_details = []
                for value in item['value']:
                    crypto_issuer_detail_id = crypto_issuer_detail_id + 1
                    crypto_issuer_detail = CryptoIssuerDetail(value=value, issuer_id=crypto_issuer_id,
                                                              id=crypto_issuer_detail_id)
                    crypto_issuer_details.append(crypto_issuer_detail)
                crypto_issuers.append(
                    CryptoIssuer(oid=item['oid'], details=crypto_issuer_details, certificate_id=certificate_id,
                                 id=crypto_issuer_id))

        if crypto_log['subject_attr_list'] is not None:
            for item in crypto_log['subject_attr_list']:
                crypto_subject_id = crypto_subject_id + 1
                crypto_subject_details = []
                for value in item['value']:
                    crypto_subject_detail_id = crypto_subject_detail_id + 1
                    crypto_subject_detail = CryptoSubjectDetail(value=value, subject_id=crypto_subject_id,
                                                                id=crypto_subject_detail_id)
                    crypto_subject_details.append(crypto_subject_detail)
                crypto_subjects.append(
                    CryptoSubject(oid=item['oid'], details=crypto_subject_details, certificate_id=certificate_id,
                                  id=crypto_subject_id))

    if ssl_log:
        if ssl_log['ext_list'] is not None:
            for item in ssl_log['ext_list']:
                ssl_extension_id = ssl_extension_id + 1
                ssl_extension = SSLExtension(value=item['value'], short_name=item['short_name'], data=item['data'],
                                             critical=item['critical'], certificate_id=certificate_id, id=ssl_extension_id)
                ssl_extensions.append(ssl_extension)

        if ssl_log['issuer_attr_list'] is not None:
            for item in ssl_log['issuer_attr_list']:
                elements = [element for element in item]
                for element in elements:
                    ssl_issuer_id = ssl_issuer_id + 1
                    key = element
                    value = item[key]
                    ssl_issuer = SSLIssuer(key=key, value=value, certificate_id=certificate_id, id=ssl_issuer_id)
                    ssl_issuers.append(ssl_issuer)

        if ssl_log['subject_attr_list'] is not None:
            for item in ssl_log['subject_attr_list']:
                elements = [element for element in item]
                for element in elements:
                    ssl_subject_id = ssl_subject_id + 1
                    key = element
                    value = item[key]
                    ssl_subject = SSLSubject(key=key, value=value, certificate_id=certificate_id, id=ssl_subject_id)
                    ssl_subjects.append(ssl_subject)

    certificate = CertificateAndDependants(certificate=cert, crypto_subject=crypto_subjects,
                                           crypto_issuer=crypto_issuers,
                                           crypto_extensions=crypto_extensions,
                                           ssl_extensions=ssl_extensions,
                                           ssl_subject=ssl_subjects, ssl_issuer=ssl_issuers,
                                           key=cert_key, source=source)
    last_id_list['certificate_id'] = certificate_id
    last_id_list['certificate_source_id'] = certificate_source_id
    last_id_list['crypto_extension_id'] = crypto_extension_id
    last_id_list['crypto_extension_detail_id'] = crypto_extension_detail_id
    last_id_list['crypto_subject_id'] = crypto_subject_id
    last_id_list['crypto_subject_detail_id'] = crypto_subject_detail_id
    last_id_list['crypto_issuer_id'] = crypto_issuer_id
    last_id_list['crypto_issuer_detail_id'] = crypto_issuer_detail_id
    last_id_list['ssl_extension_id'] = ssl_extension_id
    last_id_list['ssl_subject_id'] = ssl_subject_id
    last_id_list['ssl_issuer_id'] = ssl_issuer_id
    last_id_list['key_id'] = key_id
    last_id_list['rsa_key_id'] = rsa_key_id
    last_id_list['dsa_key_id'] = dsa_key_id
    last_id_list['ec_key_id'] = ec_key_id

    return certificate, last_id_list


def main(parsed_cert_file_path, failed_cert_file, csv_folder_path):
    last_id_list_path = os.path.join(csv_folder_path, 'last_id_list.json')
    with io.open(last_id_list_path, 'r', encoding='utf-8') as file:
        for line in file:
            last_id_list = json.loads(line)
    print(datetime.now())

    # last_index = 0
    # index = 0
    with io.open(parsed_cert_file_path, 'r', encoding='utf-8') as file:
        for line in file:
            # index = index + 1
            # if index < last_index:
            #     continue
            try:
                data = json.loads(line)
            except Exception as e:
                print(line)
                print(e)
                continue
            encoded = data['encoded_base64']
            crypto_log = data['crypto_log']
            pyopenssl_log = data['pyopenssl_log']
            pem_sha1 = data['pem_sha1']
            dataset_name = data['dataset_name']

            # seen_certificate_id = None
            # duplicate_cert_flag = False
            #
            # with io.open(os.path.join(csv_folder_path, '{}.csv'.format(TableName.Certificate.value))) as f:
            #     for line_number, csv_line in enumerate(f, 1):
            #         if pem_sha1 in csv_line:
            #             seen_certificate_id = csv_line.split(',')[0]
            #             break
            #         else:
            #             pass
            #
            # if seen_certificate_id is not None:
            #     with io.open(os.path.join(csv_folder_path, '{}.csv'.format(TableName.CertificateSource.value))) as f:
            #         for line_number, csv_line in enumerate(f, 1):
            #             current_certificate_id = csv_line.split(',')[1]
            #             if current_certificate_id.__eq__(seen_certificate_id):
            #                 with io.open(
            #                         os.path.join(csv_folder_path, '{}.csv'.format(TableName.CertificateSource.value)),
            #                         'a') as file:
            #                     certificate_source_id = last_id_list['certificate_source_id'] + 1
            #                     last_id_list['certificate_source_id'] = certificate_source_id
            #                     writer = csv.writer(file)
            #                     row_list = [certificate_source_id, seen_certificate_id, "'{}'".format(dataset_name)]
            #                     writer.writerow(row_list)
            #                     duplicate_cert_flag = True
            #                     break
            #
            # if duplicate_cert_flag == False:
            entity, last_id_list = convert_json_to_cert(encoded_base64=encoded, dataset_name=dataset_name,
                                                        pem_sha1=pem_sha1, crypto_log=crypto_log,
                                                        ssl_log=pyopenssl_log,
                                                        last_id_list=last_id_list,
                                                        failed_cert_file=failed_cert_file)

            with io.open(os.path.join(csv_folder_path, '{}.csv'.format(TableName.Certificate.value)), 'a') as f:
                writer = csv.writer(f)
                cert = entity.certificate
                row_list = [cert.id, "'{}'".format(cert.encoded), "'{}'".format(cert.version),
                            "'{}'".format(cert.serial_number),
                            "'{}'".format(cert.valid_from), "'{}'".format(cert.valid_to),
                            "'{}'".format(cert.ssl_sig_alg),
                            "'{}'".format(cert.crypto_sig_alg), "'{}'".format(cert.tp_md5),
                            "'{}'".format(cert.tp_sha1),
                            "'{}'".format(cert.tp_sha2), cert.crypto_ext_count, cert.ssl_ext_count,
                            "'{}'".format(cert.crypto_status),
                            "'{}'".format(cert.ssl_status), "'{}'".format(cert.parsed_time),
                            "'{}'".format(cert.pem_sha1)]
                writer.writerow(row_list)

            with io.open(os.path.join(csv_folder_path, '{}.csv'.format(TableName.CertificateSource.value)),
                         'a') as f:
                writer = csv.writer(f)
                source = entity.source
                writer.writerow([source.id, source.certificate_id, "'{}'".format(source.dataset_name)])

            key = None
            with io.open(os.path.join(csv_folder_path, '{}.csv'.format(TableName.Key.value)), 'a') as f:
                writer = csv.writer(f)
                key = entity.key
                writer.writerow(
                    [key.id, key.certificate_id, "'{}'".format(key.public_key_info),
                     "'{}'".format(key.pub_key_type),
                     key.pub_key_size, "'{}'".format(key.tp_hpkp_1), "'{}'".format(key.tp_hpkp_2), "'{}'".format(source.dataset_name)])

            if key.rsa_key is not None:
                with io.open(os.path.join(csv_folder_path, '{}.csv'.format(TableName.RSAKey.value)), 'a') as f:
                    writer = csv.writer(f)
                    writer.writerow([key.rsa_key.id, key.rsa_key.key_id, "'{}'".format(key.rsa_key.exponent),
                                     "'{}'".format(key.rsa_key.modulus)])

            if key.dsa_key is not None:
                with io.open(os.path.join(csv_folder_path, '{}.csv'.format(TableName.DSAKey.value)), 'a') as f:
                    writer = csv.writer(f)
                    writer.writerow(
                        [key.dsa_key.id, key.dsa_key.key_id, "'{}'".format(key.dsa_key.p),
                         "'{}'".format(key.dsa_key.g),
                         "'{}'".format(key.dsa_key.q)])

            if key.ec_key is not None:
                with io.open(os.path.join(csv_folder_path, '{}.csv'.format(TableName.ECKey.value)), 'a') as f:
                    writer = csv.writer(f)
                    writer.writerow(
                        [key.ec_key.id, key.ec_key.key_id, "'{}'".format(key.ec_key.x), "'{}'".format(key.ec_key.y),
                         "'{}'".format(key.ec_key.curve)])

            extensions = []
            with io.open(os.path.join(csv_folder_path, '{}.csv'.format(TableName.CryptoExtension.value)), 'a') as f:
                writer = csv.writer(f)
                extensions = entity.crypto_extensions
                for extension in extensions:
                    writer.writerow([extension.id, extension.certificate_id, "'{}'".format(extension.oid),
                                     "'{}'".format(extension.critical)])

            for extension in extensions:
                with io.open(os.path.join(csv_folder_path, '{}.csv'.format(TableName.CryptoExtensionDetail.value)),
                             'a') as f:
                    writer = csv.writer(f)
                    details = extension.details
                    for detail in details:
                        writer.writerow(
                            [detail.id, detail.extension_id, "'{}'".format(detail.key),
                             "'{}'".format(detail.value)])

            issuers = []
            with io.open(os.path.join(csv_folder_path, '{}.csv'.format(TableName.CryptoIssuer.value)), 'a') as f:
                writer = csv.writer(f)
                issuers = entity.crypto_issuer
                for issuer in issuers:
                    writer.writerow([issuer.id, issuer.certificate_id, "'{}'".format(issuer.oid)])

            for issuer in issuers:
                with io.open(os.path.join(csv_folder_path, '{}.csv'.format(TableName.CryptoIssuerDetail.value)),
                             'a') as f:
                    writer = csv.writer(f)
                    details = issuer.details
                    for detail in details:
                        detail_value = cert_parser_helper.get_encoded_base64(detail.value.encode('utf-8'))
                        writer.writerow([detail.id, detail.issuer_id, "'{}'".format(detail_value)])

            subjects = []
            with io.open(os.path.join(csv_folder_path, '{}.csv'.format(TableName.CryptoSubject.value)), 'a') as f:
                writer = csv.writer(f)
                subjects = entity.crypto_subject
                for subject in subjects:
                    writer.writerow([subject.id, subject.certificate_id, "'{}'".format(subject.oid)])

            for subject in subjects:
                with io.open(os.path.join(csv_folder_path, '{}.csv'.format(TableName.CryptoSubjectDetail.value)),
                             'a') as f:
                    writer = csv.writer(f)
                    details = subject.details
                    for detail in details:
                        detail_value = cert_parser_helper.get_encoded_base64(detail.value.encode('utf-8'))
                        writer.writerow([detail.id, detail.subject_id, "'{}'".format(detail_value)])

            extensions = []
            with io.open(os.path.join(csv_folder_path, '{}.csv'.format(TableName.SSLExtension.value)), 'a') as f:
                writer = csv.writer(f)
                extensions = entity.ssl_extensions
                for extension in extensions:
                    extension_short_name = cert_parser_helper.get_encoded_base64(extension.short_name.encode('utf-8'))
                    extension_value = cert_parser_helper.get_encoded_base64(extension.value.encode('utf-8'))
                    extension_data = cert_parser_helper.get_encoded_base64(extension.data.encode('utf-8'))
                    writer.writerow([extension.id, extension.certificate_id, "'{}'".format(extension_short_name),
                                     "'{}'".format(extension.critical), "'{}'".format(extension_value),
                                     "'{}'".format(extension_data)])

            subjects = []
            with io.open(os.path.join(csv_folder_path, '{}.csv'.format(TableName.SSLSubject.value)), 'a') as f:
                writer = csv.writer(f)
                subjects = entity.ssl_subject
                for subject in subjects:
                    subject_value = cert_parser_helper.get_encoded_base64(subject.value.encode('utf-8'))
                    writer.writerow(
                        [subject.id, subject.certificate_id, "'{}'".format(subject_value), "'{}'".format(subject.key)])

            issuers = []
            with io.open(os.path.join(csv_folder_path, '{}.csv'.format(TableName.SSLIssuer.value)), 'a') as f:
                writer = csv.writer(f)
                issuers = entity.ssl_issuer
                for issuer in issuers:
                    issuer_value = cert_parser_helper.get_encoded_base64(issuer.value.encode('utf-8'))
                    writer.writerow(
                        [issuer.id, issuer.certificate_id, "'{}'".format(issuer_value), "'{}'".format(issuer.key)])

            last_id_list_json = json.dumps(last_id_list, default=str)
            io_helper.write_line_into_file(last_id_list_path, last_id_list_json, True)

    last_id_list_json = json.dumps(last_id_list, default=str)
    print(last_id_list_json)
    io_helper.write_line_into_file(last_id_list_path, last_id_list_json, True)


def create_initial_files(csv_folder_path):
    ## io_helper.remove_dir_content(csv_folder_path)
    # last_id_list = {'certificate_id': 0,
    #                 'certificate_source_id': 0,
    #                 'crypto_extension_id': 0,
    #                 'crypto_extension_detail_id': 0,
    #                 'crypto_subject_id': 0,
    #                 'crypto_subject_detail_id': 0,
    #                 'crypto_issuer_id': 0,
    #                 'crypto_issuer_detail_id': 0,
    #                 'ssl_extension_id': 0,
    #                 'ssl_subject_id': 0,
    #                 'ssl_issuer_id': 0,
    #                 'key_id': 0,
    #                 'rsa_key_id': 0,
    #                 'dsa_key_id': 0,
    #                 'ec_key_id': 0}
    #
    # last_id_list_json = json.dumps(last_id_list, default=str)
    # io_helper.create_and_save_file(location=csv_folder_path, file_name='last_id_list', file_ext='json')
    # io_helper.write_line_into_file(os.path.join(csv_folder_path, 'last_id_list.json'), last_id_list_json, True)

    for table in TableName:
        io_helper.create_and_save_file(location=csv_folder_path, file_name=table.value, file_ext='csv')


if __name__ == "__main__":
    # csv_folder_path = '/media/user01/WD_3/FR13_DB/CSV'
    # parsed_cert_file_path = '/media/user01/WORK_2/CONTAMINATION/Dataset_FR_13/allcerts.json'

    # csv_folder_path = '/media/user01/WD_3/PE_VX_DB/CSV'
    # parsed_cert_file_path = '/media/user01/WORK_2/CONTAMINATION/Dataset_PE/PE_VX_all_file_lines.json'

    # csv_folder_path = '/media/user01/WD_2/R7_21_MORE_DB/CSV'
    # parsed_cert_file_path = '/media/user01/WORK_2/CONTAMINATION/Dataset_R7_19_21/moressl_allcerts.json'
    #
    # create_initial_files(csv_folder_path)
    # pure_file_name = io_helper.get_pure_file_name(parsed_cert_file_path)
    # failed_cert_file = io_helper.create_and_save_file(csv_folder_path, '{}_failed'.format(pure_file_name), 'txt')
    # main(parsed_cert_file_path, failed_cert_file, csv_folder_path)

    # csv_folder_path = '/media/user01/WD_3/R7_21_SSL_1_DB/CSV'
    # parsed_cert_file_path = '/media/user01/WORK_2/CONTAMINATION/Dataset_R7_19_21/1_ssl_allcerts.json'
    # create_initial_files(csv_folder_path)
    # pure_file_name = io_helper.get_pure_file_name(parsed_cert_file_path)
    # failed_cert_file = io_helper.create_and_save_file(csv_folder_path, '{}_failed'.format(pure_file_name), 'txt')
    # main(parsed_cert_file_path, failed_cert_file, csv_folder_path)


    # csv_folder_path = '/media/user01/WD_3/R7_21_SSL_2_DB/CSV'
    # parsed_cert_file_path = '/media/user01/WORK_2/CONTAMINATION/Dataset_R7_19_21/2_ssl_allcerts.json'
    # create_initial_files(csv_folder_path)
    # pure_file_name = io_helper.get_pure_file_name(parsed_cert_file_path)
    # failed_cert_file = io_helper.create_and_save_file(csv_folder_path, '{}_failed'.format(pure_file_name), 'txt')
    # main(parsed_cert_file_path, failed_cert_file, csv_folder_path)

    # csv_folder_path = '/media/user01/WD_3/SBA_DB/CSV'
    # parsed_cert_file_path = '/media/user01/WORK_2/CONTAMINATION/Dataset_SBA/2015-05-05-1430805600-smtp_starttls_25_certs.json'
    # create_initial_files(csv_folder_path)
    # pure_file_name = io_helper.get_pure_file_name(parsed_cert_file_path)
    # failed_cert_file = io_helper.create_and_save_file(csv_folder_path, '{}_failed'.format(pure_file_name), 'txt')
    # main(parsed_cert_file_path, failed_cert_file, csv_folder_path)

    # csv_folder_path = '/media/user01/WD_3/SBA_DB/CSV'
    # parsed_cert_file_path = '/media/user01/WORK_2/CONTAMINATION/Dataset_SBA/2015-05-06-1433484000-smtp_starttls_25_certs.json'
    # create_initial_files(csv_folder_path)
    # pure_file_name = io_helper.get_pure_file_name(parsed_cert_file_path)
    # failed_cert_file = io_helper.create_and_save_file(csv_folder_path, '{}_failed'.format(pure_file_name), 'txt')
    # main(parsed_cert_file_path, failed_cert_file, csv_folder_path)

    csv_folder_path = '/media/user01/WD_3/APK_DB/CSV'
    parsed_cert_file_path = '/media/user01/WORK_2/CONTAMINATION/Dataset_APK/APK_all_files_decoded_RSA_certs.json'
    create_initial_files(csv_folder_path)
    pure_file_name = io_helper.get_pure_file_name(parsed_cert_file_path)
    failed_cert_file = io_helper.create_and_save_file(csv_folder_path, '{}_failed'.format(pure_file_name), 'txt')
    main(parsed_cert_file_path, failed_cert_file, csv_folder_path)






