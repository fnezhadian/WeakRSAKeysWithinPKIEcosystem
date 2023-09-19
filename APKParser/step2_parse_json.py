import csv
import datetime
import io
import json
import os
import shutil

from Helper import io_helper
from apk_certificate import extract_cert_key


def create_initial_files(csv_folder_path):
    # io_helper.remove_dir_content(csv_folder_path)
    last_id_list = {'apk_id': 0,
                    'apk_signature_name_id': 0,
                    'apk_crypto_file_id': 0
                    }
    last_id_list_json = json.dumps(last_id_list, default=str)
    io_helper.create_and_save_file(location=csv_folder_path, file_name='last_id_list', file_ext='json')
    io_helper.write_line_into_file(os.path.join(csv_folder_path, 'last_id_list.json'), last_id_list_json, True)

    last_id_crypto_list = {'certificate_id': 0,
                           'public_key_id': 0,
                           'private_key_id': 0,
                           'encrypted_private_key_id': 0
                           }
    last_id_crypto_list_json = json.dumps(last_id_crypto_list, default=str)
    io_helper.create_and_save_file(location=csv_folder_path, file_name='last_id_crypto_list', file_ext='json')
    io_helper.write_line_into_file(os.path.join(csv_folder_path, 'last_id_crypto_list.json'), last_id_crypto_list_json, True)


def get_dataset_code(dataset_name):
    if 'androgalaxy' in dataset_name:
        return 1
    if 'VirusShare' in dataset_name:
        return 2
    if 'apkpure' in dataset_name:
        return 3
    if 'VirusTotal' in dataset_name:
        return 4
    if 'mob_org' in dataset_name:
        return 5
    if 'androidapkfree' in dataset_name:
        return 6
    if 'crackshash' in dataset_name:
        return 7
    if 'crackhash' in dataset_name:
        return 7
    if 'xiaomi' in dataset_name:
        return 8
    if 'anzhi' in dataset_name:
        return 9
    if 'googleplay' in dataset_name:
        return 10
    if 'apkgod' in dataset_name:
        return 11
    if 'apkmaza' in dataset_name:
        return 12
    if 'appsapkcom' in dataset_name:
        return 13
    if 'mobile1' in dataset_name:
        return 14
    if 'slideme' in dataset_name:
        return 15
    if 'appsapk' in dataset_name:
        return 16
    if 'fdroid' in dataset_name:
        return 17
    if 'appvn' in dataset_name:
        return 18
    if 'up2down' in dataset_name:
        return 19
    return 0


def step0():
    print('db')
    apk_data_table_script = 'CREATE TABLE apk_data (id INTEGER, dataset_name TEXT, dataset_year INTEGER, dataset_code integer, ' \
                      ' signature_v1 TEXT, signature_v2 TEXT, signature_v3 TEXT, signature_v31 TEXT, signature_v4 TEXT,' \
                      ' num_signers TEXT, apk_signer_test_status TEXT, apk_aapt2_status TEXT, apk_compileSdkVersion TEXT, ' \
                      ' apk_sdkVersion TEXT, apk_targetSdkVersion TEXT, apk_maxSdkVersion TEXT, apk_is_valid TEXT, max_sdk_version TEXT, min_sdk_version TEXT, ' \
                      ' target_sdk_version TEXT, internal_files_count INTEGER, parsed_time TEXT, file_mod_time TEXT, file_size TEXT, md5 TEXT, sha1 TEXT, sha256 TEXT, file_name_base64 TEXT);'

    apk_data_copy_script = "\copy apk_data FROM '/home/user01/PycharmProjects/pythonProject/APKParser/id_list/apk.csv' delimiter ',' csv;"
    update_query = 'UPDATE apk_data SET dataset_code = dataset_code::integer;'
    alter_query = 'ALTER TABLE apk_data ALTER COLUMN dataset_code TYPE integer;'

    apk_signature_table_script = 'CREATE TABLE apk_signature (id INTEGER, apk_data_id INTEGER, signature_path TEXT);'
    apk_signature_copy_script = "\copy apk_signature FROM '/home/user01/PycharmProjects/pythonProject/APKParser/id_list/apk_signature.csv' delimiter ',' csv;"

    apk_internal_file_table_script = 'CREATE TABLE apk_crypto_file (id INTEGER, apk_data_id INTEGER, parsed_time TEXT, file_mod_time TEXT, file_size TEXT, ' \
                                     ' md5 TEXT, sha1 TEXT, sha256 TEXT, file_renamed TEXT, original_file_extension TEXT, new_file_extension TEXT, file_name_base64 TEXT, original_path TEXT, file_name TEXT, file_location TEXT);'
    apk_internal_file_copy_script = "\copy apk_crypto_file FROM '/home/user01/PycharmProjects/pythonProject/APKParser/id_list/apk_crypto_file.csv' delimiter ',' csv;"
    update_query = "UPDATE apk_crypto_file  SET original_path = REPLACE(original_path, '''', '');"

    apk_certificate_table_script = 'CREATE TABLE apk_certificate(id INTEGER, certificate_sha1 TEXT, file_sha1 TEXT, apk_sha1 TEXT, file_extension TEXT, certificate_string TEXT);'
    apk_certificate_copy_script = "\copy apk_certificate FROM '/home/user01/PycharmProjects/pythonProject/APKParser/id_list/apk_certificate.csv' delimiter ',' csv;"

    apk_public_key_table_script = 'CREATE TABLE apk_public_key(id INTEGER, public_key_sha1 TEXT, file_sha1 TEXT, apk_sha1 TEXT, file_extension TEXT, public_key_string TEXT);'
    apk_public_key_copy_script = "\copy apk_public_key FROM '/home/user01/PycharmProjects/pythonProject/APKParser/id_list/apk_public_key.csv' delimiter ',' csv;"

    apk_private_key_table_script = 'CREATE TABLE apk_private_key(id INTEGER, private_key_sha1 TEXT, file_sha1 TEXT, apk_sha1 TEXT, file_extension TEXT, private_key_string TEXT);'
    apk_private_key_copy_script = "\copy apk_private_key FROM '/home/user01/PycharmProjects/pythonProject/APKParser/id_list/apk_private_key.csv' delimiter ',' csv;"


def step1_get_apk_info(csv_folder_path, last_id_list, key_folder_list, json_file_path, dataset_name, dataset_year, dataset_code):
    io_helper.create_and_save_file(location=csv_folder_path, file_name='apk_data', file_ext='csv')
    io_helper.create_and_save_file(location=csv_folder_path, file_name='apk_signature', file_ext='csv')
    io_helper.create_and_save_file(location=csv_folder_path, file_name='apk_crypto_file', file_ext='csv')

    with io.open(json_file_path, 'r', encoding='utf-8') as file:
        for line in file:
            try:
                data = json.loads(line)
            except Exception as e:
                print(line)
                print(e)
                continue

            apk_id = int(last_id_list['apk_id']) + 1
            apk_signature_name_id = last_id_list['apk_signature_name_id']
            apk_crypto_file_id = last_id_list['apk_crypto_file_id']

            apk_validity = data['apk_validity']
            apk_file_info_result = data['apk_file_info_result']
            internal_file_info_result = data['internal_file_info_result']

            apksigner = apk_validity['apksigner']
            signature_v1 = apksigner['signature_v1']
            signature_v2 =apksigner['signature_v2']
            signature_v3 = apksigner['signature_v3']
            signature_v31 = apksigner['signature_v31']
            signature_v4 = apksigner['signature_v4']
            num_signers = apksigner['num_signers']
            apk_signer_test_status = apksigner['apk_signer_test_status']

            aapt2 = apk_validity['aapt2']
            apk_aapt2_status = aapt2['apk_aapt2_status']
            apk_compileSdkVersion = aapt2['apk_compileSdkVersion']
            apk_sdkVersion = aapt2['apk_sdkVersion']
            apk_targetSdkVersion = aapt2['apk_targetSdkVersion']
            apk_maxSdkVersion = aapt2['apk_maxSdkVersion']

            apk_parse3 = apk_validity['apk_parse3']
            if apk_parse3:
                apk_is_valid = apk_parse3['apk_is_valid']
                max_sdk_version = apk_parse3['max_sdk_version']
                min_sdk_version = apk_parse3['min_sdk_version']
                target_sdk_version = apk_parse3['target_sdk_version']
                signature_names = apk_parse3['signature_names']
            else:
                apk_is_valid = ''
                max_sdk_version = ''
                min_sdk_version = ''
                target_sdk_version = ''
                signature_names = None


            parsed_time = int(apk_file_info_result['file_parse_time'])
            parsed_time = datetime.datetime.fromtimestamp(parsed_time).strftime('%Y-%m-%d %H:%M:%S')
            file_mod_time = int(apk_file_info_result['file_mod_time'])
            file_mod_time = datetime.datetime.fromtimestamp(file_mod_time).strftime('%Y-%m-%d %H:%M:%S')
            apk_sha1 = apk_file_info_result['sha1']

            with io.open(os.path.join(csv_folder_path, 'apk_data.csv'), 'a') as f:
                writer = csv.writer(f)
                row_list = [apk_id, dataset_name, dataset_year, dataset_code, signature_v1, signature_v2, signature_v3,
                            signature_v31, signature_v4, num_signers,
                            apk_signer_test_status, apk_aapt2_status,
                            apk_compileSdkVersion, apk_sdkVersion, apk_targetSdkVersion, apk_maxSdkVersion,
                            apk_is_valid, max_sdk_version, min_sdk_version,
                            target_sdk_version, len(internal_file_info_result), "'{}'".format(parsed_time), "'{}'".format(file_mod_time), apk_file_info_result['file_size'],
                            apk_file_info_result['md5'], apk_sha1, apk_file_info_result['sha256'],
                            apk_file_info_result['file_name_base64']]
                writer.writerow(row_list)

            if signature_names:
                for signature_path in signature_names:
                    apk_signature_name_id = apk_signature_name_id + 1
                    with io.open(os.path.join(csv_folder_path, 'apk_signature.csv'), 'a') as f:
                        writer = csv.writer(f)
                        writer.writerow([apk_signature_name_id, apk_id, signature_path])

            last_apk_crypto_file_id = get_crypto_files(key_folder_list, apk_id, apk_sha1, internal_file_info_result, apk_crypto_file_id)

            last_id_list['apk_id'] = apk_id
            last_id_list['apk_signature_name_id'] = apk_signature_name_id
            last_id_list['apk_crypto_file_id'] = last_apk_crypto_file_id

    last_id_list_json = json.dumps(last_id_list, default=str)
    print(last_id_list_json)
    io_helper.write_line_into_file(last_id_list_path, last_id_list_json, True)


def get_crypto_files(key_folder_list, apk_id, apk_sha1, internal_file_info_result, last_apk_crypto_file_id):
    depth_0 = apk_sha1[0]
    depth_1 = apk_sha1[1]

    for item in internal_file_info_result:
        item_sha1 = item['sha1']
        part_of_path = '/{}/{}/{}/{}.'.format(depth_0, depth_1, apk_sha1, item_sha1)

        # matching_item = next((item for item in key_file_path_list if part_of_path in item), None)
        # if matching_item:

        for folder_path in key_folder_list:
            extension = folder_path.split('/')[-1]
            full_path = folder_path + part_of_path + extension
            if os.path.isfile(full_path):
                last_apk_crypto_file_id = last_apk_crypto_file_id + 1
                with io.open(os.path.join(csv_folder_path, 'apk_crypto_file.csv'), 'a') as f:
                    writer = csv.writer(f)
                    parsed_time = int(item['file_parse_time'])
                    parsed_time = datetime.datetime.fromtimestamp(parsed_time).strftime('%Y-%m-%d %H:%M:%S')
                    file_mod_time = int(item['file_mod_time'])
                    file_mod_time = datetime.datetime.fromtimestamp(file_mod_time).strftime('%Y-%m-%d %H:%M:%S')
                    file_safe_path = item['file_safe_path']
                    original_path = file_safe_path.split('unzipped/')[1]
                    file_name = os.path.basename(file_safe_path)
                    file_location = os.path.dirname(original_path)
                    original_file_extension = os.path.splitext(file_name)[-1]
                    # new_file_extension = matching_item.split('.')[-1]
                    new_file_extension = full_path.split('.')[-1]

                    row_list = [last_apk_crypto_file_id, apk_id, "'{}'".format(parsed_time), "'{}'".format(file_mod_time),
                                item['file_size'], item['md5'], item['sha1'], item['sha256'], item['file_renamed'], original_file_extension, new_file_extension,
                                item['file_name_base64'], "'{}'".format(original_path), "'{}'".format(file_name), "'{}'".format(file_location)]
                    writer.writerow(row_list)

    return last_apk_crypto_file_id


def step2_get_cert_key(csv_folder_path, last_id_crypto_list, key_folder_path):
    certificate_list, pub_key_list, private_key_list, encrypted_private_key_list = extract_cert_key.get_cert_key(key_folder_path)

    certificate_id = int(last_id_crypto_list['certificate_id'])
    public_key_id = int(last_id_crypto_list['public_key_id'])
    private_key_id = int(last_id_crypto_list['private_key_id'])

    for certificate in certificate_list:
        certificate_id = certificate_id + 1
        with io.open(os.path.join(csv_folder_path, 'apk_certificate.csv'), 'a') as f:
            writer = csv.writer(f)
            row_list = [certificate_id, certificate['certificate_sha1'], certificate['file_sha1'],
                        certificate['apk_sha1'], certificate['file_extension'], certificate['certificate']]
            writer.writerow(row_list)

    for public_key in pub_key_list:
        public_key_id = public_key_id + 1
        with io.open(os.path.join(csv_folder_path, 'apk_public_key.csv'), 'a') as f:
            writer = csv.writer(f)
            row_list = [public_key_id, public_key['public_key_sha1'], public_key['file_sha1'],
                        public_key['apk_sha1'], public_key['file_extension'], public_key['public_key']]
            writer.writerow(row_list)

    for private_key in private_key_list:
        private_key_id = private_key_id + 1
        with io.open(os.path.join(csv_folder_path, 'apk_private_key.csv'), 'a') as f:
            writer = csv.writer(f)
            row_list = [private_key_id, private_key['private_key_sha1'], private_key['file_sha1'],
                        private_key['apk_sha1'], private_key['file_extension'], private_key['private_key']]
            writer.writerow(row_list)

    last_id_crypto_list['certificate_id'] = certificate_id
    last_id_crypto_list['public_key_id'] = public_key_id
    last_id_crypto_list['private_key_id'] = private_key_id

    last_id_crypto_list_json = json.dumps(last_id_crypto_list, default=str)
    print(last_id_crypto_list_json)
    io_helper.write_line_into_file(last_id_crypto_list_path, last_id_crypto_list_json, True)


if __name__ == "__main__":
    id_folder_path = 'id_list'
    # create_initial_files(id_folder_path)
    last_id_list_path = os.path.join(id_folder_path, 'last_id_list.json')
    with io.open(last_id_list_path, 'r', encoding='utf-8') as file:
        for line in file:
            last_id_list = json.loads(line)

    last_id_crypto_list_path = os.path.join(id_folder_path, 'last_id_crypto_list.json')
    with io.open(last_id_crypto_list_path, 'r', encoding='utf-8') as file:
        for line in file:
            last_id_crypto_list = json.loads(line)

    # data_source_path = '/media/user01/WORK_2/apk_repository_2/androgalaxy_2019_logs'
    # data_source_path = '/media/user01/WORK_2/apk_repository_2/VirusShare_Android_APK_2012_logs'
    # data_source_path = '/media/user01/WORK_2/apk_repository_2/VirusShare_Android_APK_2013_logs'
    # data_source_path = '/media/user01/WD_2/apk_repository_4/VirusTotal_2020_logs'
    # data_source_path = '/media/user01/WD_1/apk_repository/VirusShare_Android_APK_2016_logs'
    # data_source_path = '/media/user01/WORK_2/apk_repository_2/VirusShare_Android_APK_2014_logs'
    # data_source_path = '/media/user01/WD_1/apk_repository/apkpure_2021_logs'
    # data_source_path = '/media/user01/WD_3/apk_repository_3/VirusShare_Android_APK_2018_logs'
    # data_source_path = '/media/user01/WD_3/apk_repository_3/VirusShare_Android_APK_2017_logs'
    # data_source_path = '/media/user01/WD_3/apk_repository_3/androgalaxy_2017_logs'
    # data_source_path = '/media/user01/WD_3/apk_repository_3/androidapkfree_2020_logs'
    # data_source_path = '/media/user01/WD_1/apk_repository/androgalaxy_2018_logs'
    # data_source_path = '/media/user01/WORK_2/apk_repository_2/VirusShare_Android_APK_2015_logs'
    # data_source_path = '/media/user01/WD_1/apk_repository/crackshash_2021_logs'
    # data_source_path = '/media/user01/WD_3/apk_repository_3/anzhi_2017_logs'
    # data_source_path = '/media/user01/WD_3/apk_repository_3/apkmaza_2020_logs'
    # data_source_path = '/media/user01/WD_3/apk_repository_3/crackhash_2022_logs'
    # data_source_path = '/media/user01/WD_3/apk_repository_3/mob_org_2020_logs'
    # data_source_path = '/media/user01/WD_1/apk_repository/anzhi_2020_logs'
    # data_source_path = '/media/user01/WD_2/apk_repository_4/VirusShare_Android_APK_2022_logs'
    # data_source_path = '/media/user01/WD_3/apk_repository_3/xiaomi_2020_logs'
    # data_source_path = '/media/user01/WD_3/apk_repository_3/mobile1_2020_logs'
    # data_source_path = '/media/user01/WORK_2/apk_repository_2/slideme_2020_logs'
    # data_source_path = '/media/user01/WD_1/apk_repository/apkgod_2020_logs'
    # data_source_path = '/media/user01/WD_1/apk_repository/googleplay_2020_logs'
    # data_source_path = '/media/user01/WD_1/apk_repository/appsapk_com_2020_logs'
    # data_source_path = '/media/user01/WD_1/apk_repository/fdroid_2020_logs'
    # data_source_path = '/media/user01/WD_1/apk_repository/VirusTotal_2021_logs'
    # data_source_path = '/media/user01/WD_1/apk_repository/googleplay_2023_logs'
    # data_source_path = '/media/user01/WORK_2/apk_repository_2/apkpure_2020_logs'
    # data_source_path = '/media/user01/WD_1/apk_repository/apkpure_2023_logs'
    # data_source_path = '/media/user01/WORK_2/apk_repository_2/VirusShare_Android_APK_2019_p2_logs'
    # data_source_path = '/media/user01/WD_2/apk_repository_4/appvn_2020_logs'
    # data_source_path = '/media/user01/WD_3/apk_repository_3/VirusShare_Android_APK_2021_logs'
    # data_source_path = '/media/user01/WD_2/apk_repository_4/VirusShare_Android_APK_2019_p1_logs'
    # data_source_path = '/media/user01/WD_1/apk_repository/VirusShare_Android_APK_2020_logs'
    # data_source_path = '/media/user01/WD_3/apk_repository_3/up2down_2020_large_logs'
    # data_source_path = '/media/user01/WD_3/apk_repository_3/up2down_2020_large_2_logs'
    # data_source_path = '/media/user01/WD_3/apk_repository_3/up2down_2020_large_3_logs'
    # data_source_path = '/media/user01/WORK_2/apk_repository_2/up2down_2020_logs'
    # data_source_path = '/media/user01/WD_1/apk_repository/up2down_2020_p2_logs'
    # data_source_path = '/media/user01/WD_2/apk_repository_4/up2down_2020_p3_logs'
    # data_source_path = '/media/user01/WORK_2/apk_repository_2/up2down_2020_p4_logs'
    # data_source_path = '/media/user01/WD_3/apk_repository_3/up2down_2020_p5_logs'
    # data_source_path = '/media/user01/WD_1/apk_repository/up2down_2020_p5_p2_logs'
    # data_source_path = '/media/user01/WD_2/apk_repository_4/up2down_2020_p5_p3_logs'
    # data_source_path = '/media/user01/WD_3/apk_repository_3/up2down_2020_p5_p4_logs'
    # data_source_path = '/media/user01/WORK_2/apk_repository_2/up2down_2020_p5_p1_logs'
    data_source_path = ''

    data_source_json_path = data_source_path + '/json'
    data_source_key_path = data_source_path + '/maybe_keys'

    path_items = data_source_path.split('/')
    last_item = path_items[len(path_items) - 1]
    last_item = last_item.replace('_logs', '')
    items = last_item.split('_')
    dataset_name = '_'.join(items[0:-1])
    dataset_year = items[-1]
    dataset_code = get_dataset_code(dataset_name)
    if dataset_code == 0:
        raise 'Unknown Dataset'

    csv_folder_path = '/'.join(data_source_path.split('/')[0:-1])
    csv_folder_path = '{}/{}_{}_csv/'.format(csv_folder_path, dataset_name, dataset_year)
    print(csv_folder_path)

    json_file_path_list = set()
    io_helper.get_all_file_paths(data_source_json_path, json_file_path_list)
    key_folder_list = io_helper.get_subdir_list_first_level(data_source_key_path)

    for json_file_path in json_file_path_list:
        step1_get_apk_info(csv_folder_path, last_id_list, key_folder_list, json_file_path, dataset_name, dataset_year, dataset_code)
    shutil.copy2(last_id_list_path, os.path.join(csv_folder_path, 'last_id_list.json'))

    step2_get_cert_key(csv_folder_path, last_id_crypto_list, data_source_key_path)
    shutil.copy2(last_id_crypto_list_path, os.path.join(csv_folder_path, 'last_id_crypto_list.json'))


    print("\copy apk_data FROM '{}apk_data.csv' delimiter ',' csv;".format(csv_folder_path))
    print("\copy apk_signature FROM '{}apk_signature.csv' delimiter ',' csv;".format(csv_folder_path))
    print("\copy apk_crypto_file FROM '{}apk_crypto_file.csv' delimiter ',' csv;".format(csv_folder_path))
    print("\copy apk_certificate FROM '{}apk_certificate.csv' delimiter ',' csv;".format(csv_folder_path))
    print("\copy apk_public_key FROM '{}apk_public_key.csv' delimiter ',' csv;".format(csv_folder_path))
    print("\copy apk_private_key FROM '{}apk_private_key.csv' delimiter ',' csv;".format(csv_folder_path))
    print("UPDATE apk_crypto_file  SET original_path = REPLACE(original_path, '''', '');")