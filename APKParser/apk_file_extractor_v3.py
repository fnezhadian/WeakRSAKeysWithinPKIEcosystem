import zipfile
from collections import OrderedDict

import py7zr
import os
from pathlib import Path
import shutil
import time
import subprocess

from APKParser import apk_parser_v3
from Helper import file_helper, io_helper


def absoluteFilePaths(directory):
    result = list()
    for dirpath ,_ ,filenames in os.walk(directory):
        for f in filenames:
            result.append(os.path.abspath(os.path.join(dirpath, f)))
    return(result)


key_extensions = [".asc", ".sig", ".ca-bundle",
                  ".pem", ".crt", ".cer", ".cert" ,".csr", ".key",
                  ".p7a", ".p7b", ".p7c", ".p7s", ".p7m",
                  ".der", ".rsa", ".pub", ".priv", ".sec",
                  ".private", ".secure", ".public",
                  ".pfx", ".p12", ".spc",
                  ".gpg", ".pgp", ".gpg-key",
                  ".exe",
                  ".key", ".keystore", ".jks", ".bks", ".jceks", '.uber', '.bcfks', '.bks-v1',
                  ".ppk", ".gxk", ".sign", ".signature", ".dsa", ".ec", ".aes", ".kdb", ".kdbx", ".appkey", ".ovpn"]


def extract_files(apk_file_path, zip_dest_path, maybe_keys_path):
    if os.path.exists(zip_dest_path):
        shutil.rmtree(zip_dest_path)

    apk_file_info_result = []
    internal_file_info_result = []
    if not os.path.exists(apk_file_path) or not os.path.isfile(apk_file_path):
        return apk_file_info_result, internal_file_info_result

    if os.path.exists(apk_file_path) and os.path.getsize(apk_file_path) > 0:
        apk_file_info_result = apk_parser_v3.parse_file(apk_file_path)
        apk_file_info_result['file_renamed'] = ''
        apk_sha1 = apk_file_info_result['sha1']
        depth_0 = apk_sha1[0]
        depth_1 = apk_sha1[1]

        try:
            cmd = "python3 zipdump.py --separator=';' '{}' | cut -d';' -f3 | sort | uniq | grep -v 'Encrypted'".format(
                apk_file_path)
            output = subprocess.check_output(cmd, shell=True, encoding='utf-8')
            if output.__contains__('1'):
                return apk_file_info_result, internal_file_info_result
        except:
            return apk_file_info_result, internal_file_info_result

        Path(zip_dest_path).mkdir(parents=True, exist_ok=True)

        zip_status = "OK"
        try:
            with zipfile.ZipFile(apk_file_path, 'r') as zip_ref:
                zip_ref.extractall(zip_dest_path)
            zip_status = "OK"
        except Exception as e:
            zip_status = "ERR"

        if zip_status == "ERR":
            try:
                with py7zr.SevenZipFile(apk_file_path, mode='r') as zip_ref:
                    zip_ref.extractall(zip_dest_path)
                zip_status = "OK"
            except Exception as e:
                zip_status = "ERR"

        tot_apk_zip_files = 0
        tot_apk_maybe_keys_files = 0

        if zip_status == "OK":
            all_temp_files = absoluteFilePaths(zip_dest_path)

            for xfile in all_temp_files:
                tot_apk_zip_files = tot_apk_zip_files + 1

                md5, sha1, sha256 = file_helper.get_file_hash_v2(xfile)
                # if sha256 in parsed_files:
                #     xfile_info_result = OrderedDict()
                #     xfile_info_result['file_parse_time'] = str(int(time.time()))
                #     xfile_info_result['file_type_magic'] = ''
                #     xfile_info_result['file_mod_time'] = ''
                #     xfile_info_result['file_size'] = ''
                #     xfile_info_result['file_mime_type'] = ''
                #     # xfile_info_result['file_exif'] = ''
                #     xfile_info_result['md5'] = md5
                #     xfile_info_result['sha1'] = sha1
                #     xfile_info_result['sha256'] = sha256
                #     xfile_info_result['file_name_base64'] = file_helper.get_file_name_base64(xfile)
                #     xfile_info_result['file_safe_path'] = file_helper.get_safe_path(xfile)
                #     xfile_info_result['seen_before'] = True
                #     xfile_info_result['file_renamed'] = ''
                #     internal_file_info_result.append(xfile_info_result)
                #     continue

                matching_item = next((item for item in internal_file_info_result if item.get('sha256') == sha256), None)
                if matching_item:
                    matching_item['file_parse_time'] = str(int(time.time()))
                    matching_item['file_name_base64'] = file_helper.get_file_name_base64(xfile)
                    matching_item['file_safe_path'] = file_helper.get_safe_path(xfile)
                    matching_item['seen_before'] = True
                    internal_file_info_result.append(matching_item)
                    continue

                xfile_fullname = str(xfile).split("/")[-1]
                xfile_fext = "none"
                if '.' in xfile_fullname:
                    xfile_fext = xfile_fullname[xfile_fullname.rfind('.'):].lower()

                xfile_info_result = apk_parser_v3.parse_file(xfile)
                xfile_sha1 = xfile_info_result['sha1']
                xfile_fmagic = xfile_info_result['file_type_magic']
                xfile_renamed = True

                if xfile_fext in key_extensions or xfile_fext.startswith(".pkcs"):
                    tot_apk_maybe_keys_files = tot_apk_maybe_keys_files + 1
                    # create folder path
                    maybe_dir_path = "%s/%s/%s/%s/%s" % \
                                     (maybe_keys_path, xfile_fext.lstrip("."), depth_0, depth_1, apk_sha1)
                    # print("MAYBE FINAL DIR PATH --> ", maybe_dir_path)
                    Path(maybe_dir_path).mkdir(parents=True, exist_ok=True)
                    fcopy_path = maybe_dir_path + "/" + xfile_sha1 + xfile_fext
                    # print("MAYBE FINAL FILE PATH --> ", fcopy_path)
                    if not os.path.isfile(fcopy_path):
                        shutil.copy2(xfile, fcopy_path)
                    xfile_renamed = False
                elif "OpenPGP Public Key" in xfile_fmagic:
                    # "pubkey_pgp/"
                    # create folder path
                    maybe_dir_path = "%s/%s/%s/%s/%s" % (maybe_keys_path, "pubkey_pgp", depth_0, depth_1, apk_sha1)
                    # print("MAYBE FINAL DIR PATH --> ", maybe_dir_path)
                    Path(maybe_dir_path).mkdir(parents=True, exist_ok=True)
                    fcopy_path = maybe_dir_path + "/" + xfile_sha1 + ".pubkey_pgp"
                    # print("MAYBE FINAL FILE PATH --> ", fcopy_path)
                    if not os.path.isfile(fcopy_path):
                        shutil.copy2(xfile, fcopy_path)
                elif "OpenPGP Secret Key" in xfile_fmagic:
                    # "seckey_pgp/"
                    # create folder path
                    maybe_dir_path = "%s/%s/%s/%s/%s" % (maybe_keys_path, "seckey_pgp", depth_0, depth_1, apk_sha1)
                    # print("MAYBE FINAL DIR PATH --> ", maybe_dir_path)
                    Path(maybe_dir_path).mkdir(parents=True, exist_ok=True)
                    fcopy_path = maybe_dir_path + "/" + xfile_sha1 + ".seckey_pgp"
                    # print("MAYBE FINAL FILE PATH --> ", fcopy_path)
                    if not os.path.isfile(fcopy_path):
                        shutil.copy2(xfile, fcopy_path)
                elif "PGP Public Key" in xfile_fmagic:
                    # "pubkey_pgp/"
                    # create folder path
                    maybe_dir_path = "%s/%s/%s/%s/%s" % (maybe_keys_path, "pubkey_pgp", depth_0, depth_1, apk_sha1)
                    # print("MAYBE FINAL DIR PATH --> ", maybe_dir_path)
                    Path(maybe_dir_path).mkdir(parents=True, exist_ok=True)
                    fcopy_path = maybe_dir_path + "/" + xfile_sha1 + ".pubkey_pgp"
                    # print("MAYBE FINAL FILE PATH --> ", fcopy_path)
                    if not os.path.isfile(fcopy_path):
                        shutil.copy2(xfile, fcopy_path)
                elif "PGP Secret Key" in xfile_fmagic:
                    # "seckey_pgp/"
                    maybe_dir_path = "%s/%s/%s/%s/%s" % (maybe_keys_path, "seckey_pgp", depth_0, depth_1, apk_sha1)
                    # print("MAYBE FINAL DIR PATH --> ", maybe_dir_path)
                    Path(maybe_dir_path).mkdir(parents=True, exist_ok=True)
                    fcopy_path = maybe_dir_path + "/" + xfile_sha1 + ".seckey_pgp"
                    # print("MAYBE FINAL FILE PATH --> ", fcopy_path)
                    if not os.path.isfile(fcopy_path):
                        shutil.copy2(xfile, fcopy_path)
                elif "PGP Secret Sub-key" in xfile_fmagic:
                    # "seckey_pgp/"
                    maybe_dir_path = "%s/%s/%s/%s/%s" % (maybe_keys_path, "seckey_pgp", depth_0, depth_1, apk_sha1)
                    # print("MAYBE FINAL DIR PATH --> ", maybe_dir_path)
                    Path(maybe_dir_path).mkdir(parents=True, exist_ok=True)
                    fcopy_path = maybe_dir_path + "/" + xfile_sha1 + ".seckey_pgp"
                    # print("MAYBE FINAL FILE PATH --> ", fcopy_path)
                    if not os.path.isfile(fcopy_path):
                        shutil.copy2(xfile, fcopy_path)
                elif "PEM certificate request" in xfile_fmagic:
                    # "pem/"
                    maybe_dir_path = "%s/%s/%s/%s/%s" % (maybe_keys_path, "csr", depth_0, depth_1, apk_sha1)
                    # print("MAYBE FINAL DIR PATH --> ", maybe_dir_path)
                    Path(maybe_dir_path).mkdir(parents=True, exist_ok=True)
                    fcopy_path = maybe_dir_path + "/" + xfile_sha1 + ".csr"
                    # print("MAYBE FINAL FILE PATH --> ", fcopy_path)
                    if not os.path.isfile(fcopy_path):
                        shutil.copy2(xfile, fcopy_path)
                elif "PEM certificate" in xfile_fmagic:
                    # "pem/"
                    maybe_dir_path = "%s/%s/%s/%s/%s" % (maybe_keys_path, "pem", depth_0, depth_1, apk_sha1)
                    # print("MAYBE FINAL DIR PATH --> ", maybe_dir_path)
                    Path(maybe_dir_path).mkdir(parents=True, exist_ok=True)
                    fcopy_path = maybe_dir_path + "/" + xfile_sha1 + ".pem"
                    # print("MAYBE FINAL FILE PATH --> ", fcopy_path)
                    if not os.path.isfile(fcopy_path):
                        shutil.copy2(xfile, fcopy_path)
                elif "Certificate, Version=" in xfile_fmagic:
                    # "pem/"
                    maybe_dir_path = "%s/%s/%s/%s/%s" % (maybe_keys_path, "pem", depth_0, depth_1, apk_sha1)
                    # print("MAYBE FINAL DIR PATH --> ", maybe_dir_path)
                    Path(maybe_dir_path).mkdir(parents=True, exist_ok=True)
                    fcopy_path = maybe_dir_path + "/" + xfile_sha1 + ".pem"
                    # print("MAYBE FINAL FILE PATH --> ", fcopy_path)
                    if not os.path.isfile(fcopy_path):
                        shutil.copy2(xfile, fcopy_path)
                elif "DER Encoded" in xfile_fmagic:
                    # "der/"
                    maybe_dir_path = "%s/%s/%s/%s/%s" % (maybe_keys_path, "der", depth_0, depth_1, apk_sha1)
                    # print("MAYBE FINAL DIR PATH --> ", maybe_dir_path)
                    Path(maybe_dir_path).mkdir(parents=True, exist_ok=True)
                    fcopy_path = maybe_dir_path + "/" + xfile_sha1 + ".der"
                    # print("MAYBE FINAL FILE PATH --> ", fcopy_path)
                    if not os.path.isfile(fcopy_path):
                        shutil.copy2(xfile, fcopy_path)
                elif "Java KeyStore" in xfile_fmagic:
                    # "jks/"
                    maybe_dir_path = "%s/%s/%s/%s/%s" % (maybe_keys_path, "jks", depth_0, depth_1, apk_sha1)
                    # print("MAYBE FINAL DIR PATH --> ", maybe_dir_path)
                    Path(maybe_dir_path).mkdir(parents=True, exist_ok=True)
                    fcopy_path = maybe_dir_path + "/" + xfile_sha1 + ".jks"
                    # print("MAYBE FINAL FILE PATH --> ", fcopy_path)
                    if not os.path.isfile(fcopy_path):
                        shutil.copy2(xfile, fcopy_path)
                elif "PEM RSA private key" in xfile_fmagic:
                    # "key/"
                    maybe_dir_path = "%s/%s/%s/%s/%s" % (maybe_keys_path, "key", depth_0, depth_1, apk_sha1)
                    # print("MAYBE FINAL DIR PATH --> ", maybe_dir_path)
                    Path(maybe_dir_path).mkdir(parents=True, exist_ok=True)
                    fcopy_path = maybe_dir_path + "/" + xfile_sha1 + ".key"
                    # print("MAYBE FINAL FILE PATH --> ", fcopy_path)
                    if not os.path.isfile(fcopy_path):
                        shutil.copy2(xfile, fcopy_path)
                elif "PGP public key block Public-Key (old)" in xfile_fmagic:
                    # "key/"
                    maybe_dir_path = "%s/%s/%s/%s/%s" % (maybe_keys_path, "pubkey_pgp", depth_0, depth_1, apk_sha1)
                    # print("MAYBE FINAL DIR PATH --> ", maybe_dir_path)
                    Path(maybe_dir_path).mkdir(parents=True, exist_ok=True)
                    fcopy_path = maybe_dir_path + "/" + xfile_sha1 + ".pubkey_pgp"
                    # print("MAYBE FINAL FILE PATH --> ", fcopy_path)
                    if not os.path.isfile(fcopy_path):
                        shutil.copy2(xfile, fcopy_path)
                elif "PGP key security ring" in xfile_fmagic:
                    # "key/"
                    maybe_dir_path = "%s/%s/%s/%s/%s" % (maybe_keys_path, "secring_pgp", depth_0, depth_1, apk_sha1)
                    # print("MAYBE FINAL DIR PATH --> ", maybe_dir_path)
                    Path(maybe_dir_path).mkdir(parents=True, exist_ok=True)
                    fcopy_path = maybe_dir_path + "/" + xfile_sha1 + ".secring_pgp"
                    # print("MAYBE FINAL FILE PATH --> ", fcopy_path)
                    if not os.path.isfile(fcopy_path):
                        shutil.copy2(xfile, fcopy_path)
                elif "PE32 executable" in xfile_fmagic:
                    # "key/"
                    maybe_dir_path = "%s/%s/%s/%s/%s" % (maybe_keys_path, "exe", depth_0, depth_1, apk_sha1)
                    # print("MAYBE FINAL DIR PATH --> ", maybe_dir_path)
                    Path(maybe_dir_path).mkdir(parents=True, exist_ok=True)
                    fcopy_path = maybe_dir_path + "/" + xfile_sha1 + ".exe"
                    # print("MAYBE FINAL FILE PATH --> ", fcopy_path)
                    if not os.path.isfile(fcopy_path):
                        shutil.copy2(xfile, fcopy_path)
                elif "PE32+ executable" in xfile_fmagic:
                    # "key/"
                    maybe_dir_path = "%s/%s/%s/%s/%s" % (maybe_keys_path, "exe", depth_0, depth_1, apk_sha1)
                    # print("MAYBE FINAL DIR PATH --> ", maybe_dir_path)
                    Path(maybe_dir_path).mkdir(parents=True, exist_ok=True)
                    fcopy_path = maybe_dir_path + "/" + xfile_sha1 + ".exe"
                    # print("MAYBE FINAL FILE PATH --> ", fcopy_path)
                    if not os.path.isfile(fcopy_path):
                        shutil.copy2(xfile, fcopy_path)
                else:
                    xfile_renamed = False
                    pass
                xfile_info_result['seen_before'] = False
                xfile_info_result['file_renamed'] = xfile_renamed
                internal_file_info_result.append(xfile_info_result)

        if os.path.exists(zip_dest_path):
            shutil.rmtree(zip_dest_path)

        return apk_file_info_result, internal_file_info_result


def main(file_path, zip_dest_path, maybe_keys_path):
    apk_file_info_result = []
    internal_file_info_result = []

    try:
        apk_file_info_result, internal_file_info_result = extract_files(file_path, zip_dest_path, maybe_keys_path)
    except:
        pass

    return apk_file_info_result, internal_file_info_result



if __name__ == "__main__":
    # file_path = '/home/user01/PycharmProjects/pythonProject/APKParser/apk/VirusShare_0a0ad9ecdb66068400986f530498d366.apk'
    #
    input_folder = ''
    output_folder = str(input_folder) + "_logs"
    maybe_keys_path = output_folder + "/maybe_keys"
    zip_dest_path = output_folder + "/unzipped"
    #
    # main(file_path, zip_dest_path, maybe_keys_path)

    data_source_path_list = [
        '/media/user01/WD_1/apk_repository/VirusShare_Android_APK_2012',
        # '/media/user01/WD_1/apk_repository/androgalaxy_2019',
        # '/media/user01/WD_1/apk_repository/VirusShare_Android_APK_2017',
        # '/media/user01/WD_1/apk_repository/VirusShare_Android_APK_2016',
        # '/media/user01/WD_1/apk_repository/VirusShare_Android_APK_2013',
        # '/media/user01/WD_1/apk_repository/apkpure_2021',
        # '/media/user01/WD_1/apk_repository/VirusShare_Android_APK_2014',
        # '/media/user01/WD_1/apk_repository/VirusShare_Android_APK_2018',
        # '/media/user01/WD_1/apk_repository/VirusShare_Android_APK_2015'
    ]

    for data_source_path in data_source_path_list:
        apk_files = io_helper.get_file_list(data_source_path)
        for apk_file in apk_files:
            main(apk_file, zip_dest_path, maybe_keys_path)