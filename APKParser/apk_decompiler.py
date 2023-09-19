# -*- coding: utf-8 -*-
import json
import os
import re
import subprocess

from APKParser import apk_parser, apk_helper
from APKParser.nonsdk_parser import get_veridex
from Helper import io_helper, file_helper


def get_match_list(file_path, pattern_list):
    match_list = []
    lines = io_helper.read_list_from_file(file_path)
    for line in lines:
        for pattern in pattern_list:
            call_path = pattern['call_path']
            position = line.find(call_path)
            if position == -1:
                continue
            preceding = line[position-1:position]
            new_position = position + len(call_path)
            successor = line[new_position:new_position+1]
            attached_char_pattern = re.compile('[a-zA-Z]')
            if not attached_char_pattern.match(preceding) and not attached_char_pattern.match(successor):
                print('call_path: ', call_path)
                print('{}{}{}'.format(preceding, call_path, successor))
                match_list.append(line)

                # https://android.googlesource.com/platform/art/+/refs/heads/master/tools/veridex/hidden_api.cc
    return match_list


def decode_by_jadx(apk_path, destination_folder):
    tool_source = '/home/user01/PycharmProjects/pythonProject/APKParser/jadx/build/jadx/bin/jadx'
    str_result, status = apk_helper.jadx_decode(apk_path, destination_folder, tool_source)
    return str_result, status


def get_call_match_list(file_list, pattern_list):
    match_list = []
    for file in file_list:
        match_list = get_match_list(file, pattern_list)
    return match_list


def main(apk_path, destination_folder, pattern_list_10, pattern_list_11, pattern_list_12, pattern_list_13):
    # str_result, status = decode_by_jadx(apk_path, destination_folder)
    # print('jadx result:', str_result)
    decompiled_file_list = io_helper.get_file_list(destination_folder)

    print('10')
    match_list_10 = get_call_match_list(decompiled_file_list, pattern_list_10)
    print('11')
    match_list_11 = get_call_match_list(decompiled_file_list, pattern_list_11)
    print('12')
    match_list_12 = get_call_match_list(decompiled_file_list, pattern_list_12)
    print('13')
    match_list_13 = get_call_match_list(decompiled_file_list, pattern_list_13)

    aapt_log = apk_parser.parse_aapt2_log(apk_path)
    parse3_log = apk_parser.parse_apk_parse3(apk_path)

    file_sha1 = file_helper.get_file_hash(apk_path)[1]
    json_file_name = '{}_calls'.format(file_sha1)
    json_file = io_helper.create_file('/home/user01/Documents/APK_Call', json_file_name, 'json')
    log = {
        'file_sha1': file_sha1,
        'match_list_10': match_list_10,
        'match_list_11': match_list_11,
        'match_list_12': match_list_12,
        'match_list_13': match_list_13,
        'aapt_log': aapt_log,
        'parse3_log': parse3_log}
    log_json = json.dumps(log, default=str)
    io_helper.write_line_into_file(json_file, log_json)


if __name__ == "__main__":
    destination_folder = '/home/user01/Documents/APK_Result'
    # io_helper.remove_dir_content(destination_folder)

    pattern_list_10, pattern_list_11, pattern_list_12, pattern_list_13 = get_veridex.main()

    # apk_path = '/home/user01/Downloads/Alibaba_marketplace 8_7_3_Apkpure.apk'
    # apk_path = '/home/user01/Downloads/Slack_23.01.10.0-B_Apkpure.apk'
    apk_path = '/home/user01/Downloads/Kushcoin-android.apk'
    main(apk_path, destination_folder, pattern_list_10, pattern_list_11, pattern_list_12, pattern_list_13)
