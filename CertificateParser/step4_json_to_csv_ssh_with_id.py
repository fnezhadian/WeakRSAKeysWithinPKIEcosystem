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


def convert_json_to_key(data, last_id_list):
    tp_hpkp_1 = data['tp_hpkp_1']
    tp_hpkp_2 = data['tp_hpkp_2']
    public_key_info = data['public_key_info']
    pub_key_type = data['pub_key_type']
    pub_key_size = data['pub_key_size']
    pub_key_numbers = data['pub_key_numbers']
    dataset_name = data['dataset_name']

    rsa_key = None
    dsa_key = None
    ec_key = None

    certificate_id = int(last_id_list['certificate_id'])    # for ssh just to keep the pattern and real last id
    certificate_source_id = last_id_list['certificate_source_id']    # for ssh just to keep the pattern and real last id
    crypto_extension_id = last_id_list['crypto_extension_id']    # for ssh just to keep the pattern and real last id
    crypto_extension_detail_id = last_id_list['crypto_extension_detail_id']    # for ssh just to keep the pattern and real last id
    crypto_subject_id = last_id_list['crypto_subject_id']    # for ssh just to keep the pattern and real last id
    crypto_subject_detail_id = last_id_list['crypto_subject_detail_id']    # for ssh just to keep the pattern and real last id
    crypto_issuer_id = last_id_list['crypto_issuer_id']    # for ssh just to keep the pattern and real last id
    crypto_issuer_detail_id = last_id_list['crypto_issuer_detail_id']    # for ssh just to keep the pattern and real last id
    ssl_extension_id = last_id_list['ssl_extension_id']    # for ssh just to keep the pattern and real last id
    ssl_subject_id = last_id_list['ssl_subject_id']    # for ssh just to keep the pattern and real last id
    ssl_issuer_id = last_id_list['ssl_issuer_id']    # for ssh just to keep the pattern and real last id
    key_id = last_id_list['key_id'] + 1
    rsa_key_id = last_id_list['rsa_key_id']
    dsa_key_id = last_id_list['dsa_key_id']
    ec_key_id = last_id_list['ec_key_id']

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
                   rsa_key=rsa_key, dsa_key=dsa_key, ec_key=ec_key, certificate_id=0, id=key_id)

    last_id_list['certificate_id'] = certificate_id    # for ssh just to keep the pattern and real last id
    last_id_list['certificate_source_id'] = certificate_source_id    # for ssh just to keep the pattern and real last id
    last_id_list['crypto_extension_id'] = crypto_extension_id    # for ssh just to keep the pattern and real last id
    last_id_list['crypto_extension_detail_id'] = crypto_extension_detail_id    # for ssh just to keep the pattern and real last id
    last_id_list['crypto_subject_id'] = crypto_subject_id    # for ssh just to keep the pattern and real last id
    last_id_list['crypto_subject_detail_id'] = crypto_subject_detail_id    # for ssh just to keep the pattern and real last id
    last_id_list['crypto_issuer_id'] = crypto_issuer_id    # for ssh just to keep the pattern and real last id
    last_id_list['crypto_issuer_detail_id'] = crypto_issuer_detail_id    # for ssh just to keep the pattern and real last id
    last_id_list['ssl_extension_id'] = ssl_extension_id    # for ssh just to keep the pattern and real last id
    last_id_list['ssl_subject_id'] = ssl_subject_id    # for ssh just to keep the pattern and real last id
    last_id_list['ssl_issuer_id'] = ssl_issuer_id    # for ssh just to keep the pattern and real last id
    last_id_list['key_id'] = key_id
    last_id_list['rsa_key_id'] = rsa_key_id
    last_id_list['dsa_key_id'] = dsa_key_id
    last_id_list['ec_key_id'] = ec_key_id

    return cert_key, last_id_list


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
            # print(datetime.now())
            try:
                data = json.loads(line)
            except Exception as e:
                print(line)
                print(e)
                continue
            key, last_id_list = convert_json_to_key(data=data, last_id_list=last_id_list)

            with io.open(os.path.join(csv_folder_path, '{}.csv'.format(TableName.Key.value)), 'a') as f:
                writer = csv.writer(f)
                writer.writerow(
                    [key.id, key.certificate_id, "'{}'".format(key.public_key_info),
                     "'{}'".format(key.pub_key_type),
                     key.pub_key_size, "'{}'".format(key.tp_hpkp_1), "'{}'".format(key.tp_hpkp_2),
                     "'{}'".format(key.dataset_name)])

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

            last_id_list_json = json.dumps(last_id_list, default=str)
            io_helper.write_line_into_file(last_id_list_path, last_id_list_json, True)

    last_id_list_json = json.dumps(last_id_list, default=str)
    print(last_id_list_json)
    io_helper.write_line_into_file(last_id_list_path, last_id_list_json, True)


def create_initial_files(csv_folder_path):
    # io_helper.remove_dir_content(csv_folder_path)
    for table in TableName:
        io_helper.create_and_save_file(location=csv_folder_path, file_name=table.value, file_ext='csv')


if __name__ == "__main__":
    csv_folder_path = '/media/user01/WD_3/SSH_DB/CSV'
    parsed_cert_file_path = '/media/user01/WORK_2/CONTAMINATION/Dataset_SSH/ssh_key.json'
    create_initial_files(csv_folder_path)
    pure_file_name = io_helper.get_pure_file_name(parsed_cert_file_path)
    failed_cert_file = io_helper.create_and_save_file(csv_folder_path, '{}_failed'.format(pure_file_name), 'txt')
    main(parsed_cert_file_path, failed_cert_file, csv_folder_path)

