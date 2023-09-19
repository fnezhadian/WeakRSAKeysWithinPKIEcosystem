# -*- coding: utf-8 -*-
import io
import json
import os
import sys
import re
import xml.etree.ElementTree as fp
from datetime import datetime

import step2_sub_parse_ssh_key_cryptography as SSHParser
from CertParser.cert_parser_helper import KeyType
from Helper import io_helper

NON_PRINTABLE_TRANS_TABLE = {    i: None for i in range(0, sys.maxunicode + 1) if not chr(i).isprintable()}


def get_ssh_banner_xml_root(xml_file_path):
    xml_tree = fp.parse(xml_file_path)
    xml_root = xml_tree.getroot()
    return xml_root


def make_printable(content):
    """Replace non-printable characters in a string."""
    return content.translate(NON_PRINTABLE_TRANS_TABLE)


def parse_banner(banner_string, xml_root_data):
    r = {
        'service_component_vendor': None,
        'service_component_family': None,
        'service_component_product': None,
        'service_vendor': None,
        'service_product': None,
        'service_family': None,
        'service_version': None,
        'service_version_version': None,
        'service_version_version_version': None,
        'service_version_version_version_version': None,
        'hw_vendor': None,
        'os_vendor': None,
        'os_product': None,
        'os_family': None,
        'os_device': None,
        #'openssh_comment': None,
        'hardware_software': 'Software',
    }

    xx = str(banner_string).strip()
    if xx:
        if "|" in xx:
            xx = xx.replace("|", " ")
        if "," in xx:
            xx = xx.replace(",", " ")
    banner_string = str(xx)

    for fp in xml_root_data:
        match = re.match(fp.get('pattern'), banner_string, re.M | re.I)
        if match:
            for data in fp.findall('param'):
                name = data.get('name')
                is_hardware = False
                if name == 'service.product':
                    r['service_product'] = data.get('value')
                    #continue
                elif name == 'service.version':
                    pos = int(data.get('pos'))
                    r['service_version'] = match.group(pos)
                    #continue
                elif name == 'service.component.vendor':
                    pos = int(data.get('pos'))
                    r['service_component_vendor'] = match.group(pos)
                    #continue
                elif name == 'service.component.family':
                    r['service_component_family'] = data.get('value')
                    #continue
                elif name == 'service.component.product':
                    r['service_component_product'] = data.get('value')
                    #continue
                elif name == 'service.vendor':
                    r['service_vendor'] = data.get('value')
                    #continue
                elif name == 'service.family':
                    r['service_family'] = data.get('value')
                    #continue
                #elif name == 'service.version.version':
                #    r['service_version_version'] = match.get(pos)
                #elif name == 'service.version.version.version':
                #    pos = int(data.get('pos'))
                #    r['service_version_version_version'] = match.get(pos)
                #elif name == 'service.version.version.version.version':
                #    pos = int(data.get('pos'))
                #    r['service_version_version_version_version'] = match.get(pos)
                elif name == 'hw.vendor':
                    r['hw_vendor'] = data.get('value')
                    is_hardware = True
                    #continue
                elif name == 'os.vendor':
                    r['os_vendor'] = data.get('value')
                    #continue
                elif name == 'os.product':
                    r['os_product'] = data.get('value')
                    #continue
                elif name == 'os.family':
                    r['os_family'] = data.get('value')
                    #continue
                elif name == 'os.device':
                    r['os_device'] = data.get('value')
                    #continue
                #elif name == 'openssh.comment':
                #    pos = int(data.get('pos'))
                #    r['openssh_comment'] = match.group(pos)

    count = 0
    result = [
            count,
            str(r['service_vendor']).strip(),
            str(r['service_version']).strip(),
            str(r['service_product']).strip(),
            str(r['service_family']).strip(),
            #str(r['service_version_version']).strip(),
            #str(r['service_version_version_version']).strip(),
            #str(r['service_version_version_version_version']).strip(),
            str(r['service_component_vendor']).strip(),
            str(r['service_component_family']).strip(),
            str(r['service_component_product']).strip(),
            str(r['hw_vendor']).strip(),
            str(r['os_vendor']).strip(),
            str(r['os_product']).strip(),
            str(r['os_family']).strip(),
            str(r['os_device']).strip(),
          ]

    for item in result:
        if not item == "None":
            count = count + 1

    result[0] = str(count)
    #result = result + [str(r['openssh_comment']).strip()]
    result = result + [str(r['hardware_software']).strip()]

    if not len(result) == 14:
        print("+++++++++++++++")
        print(len(result))
        print(result)
        raise AssertionError("ERROR: malformed recog result")
    return result


def main(source_file_path, target_file_path):
    index = 0
    with io.open(source_file_path, 'r', encoding='utf-8') as file:
        for line in file:
            index = index + 1
            if index % 1000000 == 0:
                print(datetime.now())
                print('index: ', index)

            line = make_printable(line)
            line_items = line.split("|")
            if line.endswith("|'") or line.endswith("{}".format('|"')):
                key_index = len(line_items) - 2
            else:
                key_index = len(line_items) - 1
            ssh_response_key = line_items[key_index]
            key_items = ssh_response_key.split(" ")
            ip = key_items[0]
            type = key_items[1]
            key = key_items[2]
            public_key_info = "{} {}".format(type, key)
            tp_hpkp_1, tp_hpkp_2 = SSHParser.get_key_thumbprints(public_key_info)
            pub_key_type, pub_key_size, pub_key_numbers = SSHParser.get_public_key(public_key_info)

            log = {
                'tp_hpkp_1': tp_hpkp_1,
                'tp_hpkp_2': tp_hpkp_2,
                'public_key_info': public_key_info,
                'pub_key_type': pub_key_type,
                'pub_key_size': pub_key_size,
                'pub_key_numbers': pub_key_numbers,
                'dataset_name': 'SSH'}
            log_json = json.dumps(log, default=str)
            io_helper.write_line_into_file(target_file_path, log_json)


if __name__ == "__main__":
    # xml_file_path = '/home/user01/PycharmProjects/pythonProject/CertParser/materials/ssh_banners.xml'
    # ssh_banner_xml_root = get_ssh_banner_xml_root(xml_file_path)

    target_file_path = io_helper.create_file('/media/user01/WORK_2/CONTAMINATION/Dataset_SSH/', 'ssh_key', 'json')
    # source_file_list = ['/media/user01/WORK_2/CONTAMINATION/Dataset_SSH/7zip_data_1.csv',
    #                     '/media/user01/WORK_2/CONTAMINATION/Dataset_SSH/7zip_data_2.csv',
    #                     '/media/user01/WORK_2/CONTAMINATION/Dataset_SSH/7zip_data_23.csv',
    #                     '/media/user01/WORK_2/CONTAMINATION/Dataset_SSH/7zip_data_2222.csv',
    #                     '/media/user01/WORK_2/CONTAMINATION/Dataset_SSH/7zip_data_4444.csv',
    #                     '/media/user01/WORK_2/CONTAMINATION/Dataset_SSH/7zip_data_5000.csv',
    #                     '/media/user01/WORK_2/CONTAMINATION/Dataset_SSH/7zip_data_10001.csv',
    #                     '/media/user01/WORK_2/CONTAMINATION/Dataset_SSH/7zip_data_ALL.csv',
    #                     '/media/user01/WORK_2/CONTAMINATION/Dataset_SSH/mess.csv' ]
    # for source_file in source_file_list:
    source_file = '/media/user01/WORK_2/CONTAMINATION/Dataset_SSH/7zip_data_ALL.csv'
    main(source_file, target_file_path)