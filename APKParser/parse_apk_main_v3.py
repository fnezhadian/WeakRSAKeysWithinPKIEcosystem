import time
from Helper import file_helper

from datetime import datetime
from APKParser import apk_parser, apk_parser_v2, apk_parser_v3
from Helper import io_helper


# def main(data_source_path, parsed_files_path):
#     try:
#         apk_files = io_helper.get_file_list(data_source_path)
#         for apk_file in apk_files:
#             parsed_files = io_helper.read_list_from_file(parsed_files_path)
#             if apk_file in parsed_files:
#                 continue
#             print('--------------------------------------')
#             print(time.time())
#             print('PARSING FILE --> ', apk_file)
#             apk_parser_v3.main(apk_file, data_source_path)
#             print(time.time())
#             io_helper.write_line_into_file(parsed_files_path, apk_file)
#     except:
#         return False


def main(data_source_path, parsed_files_path):
    # LOAD LIST PARSED FILES
    parsed_apks = io_helper.read_list_from_file(parsed_files_path)

    apk_files = io_helper.get_file_list(data_source_path)
    # SORT FILE LIST
    apk_files = sorted(apk_files)
    # GET TOTAL FILES
    tot_files = len(apk_files)
    parsed = 0
    for apk_file in apk_files:
        print('--------------------------------------')
        start_time = datetime.now()
        print('FILE --> ', apk_file)

        md5, sha1, sha256, sha3_224 = file_helper.get_file_hash(apk_file)
        # INCREASE COUNTER
        parsed = parsed + 1
        # IF APK ALREADY PARSED, SKIP
        if not sha256 in parsed_apks:
            # PARSE APK
            print('FILE NOT PARSED, PARSING --> ', apk_file)
            try:
                # PARSE APK
                apk_parser_v3.main(apk_file, data_source_path)
                # SAVE PARSED IN FILE
                io_helper.write_line_into_file(parsed_apks, sha256)

                #TODO: parsed_files
            except:
                return False
        else:
            # SKIPPING
            print('FILE ALREADY PARSED, SKIPPING --> ', apk_file)

            # COUNT TIME AND PROGRESS
        remaining = tot_files - parsed
        parsed_p = round((parsed / tot_files) * 100, 3)
        time_elapsed = datetime.now() - start_time
        print('PARSING TIME (hh:mm:ss.ms) --> {}'.format(time_elapsed))
        print('PARSED --> %s (%s) | REMAINING --> %s ' % (parsed, parsed_p, remaining))


if __name__ == "__main__":
    parsed_files_path = '/media/user01/WD_1/apk_repository/parsed_files_v3.txt'

    data_source_path_list = [
        '/media/user01/WD_1/apk_repository/VirusShare_Android_APK_2015',
        '/media/user01/WD_1/apk_repository/VirusShare_Android_APK_2018',
        '/media/user01/WD_1/apk_repository/VirusShare_Android_APK_2014',
        '/media/user01/WD_1/apk_repository/apkpure_2021',
        '/media/user01/WD_1/apk_repository/VirusShare_Android_APK_2013',
        '/media/user01/WD_1/apk_repository/VirusShare_Android_APK_2016',
        '/media/user01/WD_1/apk_repository/VirusShare_Android_APK_2017',
        '/media/user01/WD_1/apk_repository/androgalaxy_2019',
        '/media/user01/WD_1/apk_repository/VirusShare_Android_APK_2012',
    ]

    for data_source_path in data_source_path_list:
        main(data_source_path, parsed_files_path)