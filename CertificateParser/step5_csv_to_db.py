import io
import os.path

import psycopg2

from DB.entity_version2 import TableName


def create_connection():
    connection = psycopg2.connect(database='cert_db', user="postgres", password="Passw0rd",
                                       host="192.168.1.50",
                                       port="5432")
    return connection


def run_select_query(connection, query):
    cursor = connection.cursor()
    cursor.execute(query)
    return cursor.fetchall()


def run_query(connection, query):
    result = connection.cursor().execute(query)
    connection.commit()
    return result


def create_table(tbl_name, column_list, constraint_list=None):
    connection = create_connection()
    cursor = connection.cursor()
    try:
        create_cmd = 'CREATE TABLE {0}'.format(tbl_name)
        column_cmd = ''
        constraint_cmd = ''
        for column in column_list:
            column_cmd = '{}, {}'.format(column_cmd, column)
        column_cmd = column_cmd[2:len(column_cmd)]

        if constraint_list is not None:
            constraint_cmd = ', '
            for constraint in constraint_list:
                constraint_cmd = constraint_cmd + ' CONSTRAINT {} UNIQUE ({}) '.format(constraint['constraint_name'], constraint['field_name'])

        command = '{} ({} {});'.format(create_cmd, column_cmd, constraint_cmd)
        print(command)
        cursor.execute(command)
        connection.commit()
        connection.close()
    except Exception as e:
        print(e)
    finally:
        if connection:
            cursor.close()
            connection.close()


def create_table_certificate():
    column_list = ['id bigint NULL',
                   'encoded text NULL',
                   'version text NULL',
                   'serial_number text NULL',
                   'valid_from text NULL',
                   'valid_to text NULL',
                   'ssl_sig_alg text NULL',
                   'crypto_sig_alg text NULL',
                   'tp_md5 text NULL',
                   'tp_sha1 text NULL',
                   'tp_sha2 text NULL',
                   'crypto_ext_count text NULL',
                   'ssl_ext_count text NULL',
                   'crypto_status text NULL',
                   'ssl_status text NULL',
                   'parsed_time text NULL',
                   'pem_sha1 text NULL']
    tbl_name = TableName.Certificate.value
    create_table(tbl_name, column_list)


def create_table_certificate_source():
    column_list = ['id bigint NULL',
                   'certificate_id bigint NULL',
                   'dataset_name text NULL']
    tbl_name = TableName.CertificateSource.value
    create_table(tbl_name, column_list)


def create_table_key():
    column_list = ['id bigint NULL',
                   'certificate_id bigint NULL',
                   'public_key_info text NULL',
                   'pub_key_type text NULL',
                   'pub_key_size text NULL',
                   'tp_hpkp_1 text NULL',
                   'tp_hpkp_2 text NULL',
                   'dataset_name text NULL']
    tbl_name = TableName.Key.value
    create_table(tbl_name, column_list)


def create_table_rsa_key():
    column_list = ['id bigint NULL',
                   'key_id bigint NULL',
                   'exponent text NULL',
                   'modulus text NULL',
                   'modulus_sha1 text NULL']
    tbl_name = TableName.RSAKey.value
    create_table(tbl_name, column_list)


def create_table_dsa_key():
    column_list = ['id bigint NULL',
                   'key_id bigint NULL',
                   'p text NULL',
                   'q text NULL',
                   'g text NULL']
    tbl_name = TableName.DSAKey.value
    create_table(tbl_name, column_list)


def create_table_ec_key():
    column_list = ['id bigint NULL',
                   'key_id bigint NULL',
                   'x text NULL',
                   'y text NULL',
                   'curve text NULL']
    tbl_name = TableName.ECKey.value
    create_table(tbl_name, column_list)


def create_table_crypto_subject():
    column_list = ['id bigint NULL',
                   'certificate_id bigint NULL',
                   'oid text NULL']
    tbl_name = TableName.CryptoSubject.value
    create_table(tbl_name, column_list)


def create_table_crypto_subject_detail():
    column_list = ['id bigint NULL',
                   'subject_id bigint NULL',
                   'value text NULL']
    tbl_name = TableName.CryptoSubjectDetail.value
    create_table(tbl_name, column_list)


def create_table_ssl_subject():
    column_list = ['id bigint NULL',
                   'certificate_id bigint NULL',
                   'value text NULL',
                   'key text NULL']
    tbl_name = TableName.SSLSubject.value
    create_table(tbl_name, column_list)


def create_table_crypto_issuer():
    column_list = ['id bigint NULL',
                   'certificate_id bigint NULL',
                   'oid text NULL']
    tbl_name = TableName.CryptoIssuer.value
    create_table(tbl_name, column_list)


def create_table_crypto_issuer_detail():
    column_list = ['id bigint NULL',
                   'issuer_id bigint NULL',
                   'value text NULL']
    tbl_name = TableName.CryptoIssuerDetail.value
    create_table(tbl_name, column_list)


def create_table_ssl_issuer():
    column_list = ['id bigint NULL',
                   'certificate_id bigint NULL',
                   'value text NULL',
                   'key text NULL']
    tbl_name = TableName.SSLIssuer.value
    create_table(tbl_name, column_list)


def create_table_crypto_extension():
    column_list = ['id bigint NULL',
                   'certificate_id bigint NULL',
                   'oid text NULL',
                   'critical text NULL']
    tbl_name = TableName.CryptoExtension.value
    create_table(tbl_name, column_list)


def create_table_crypto_extension_detail():
    column_list = ['id bigint NULL',
                   'extension_id bigint NULL',
                   'key text NULL',
                   'value text NULL']
    tbl_name = TableName.CryptoExtensionDetail.value
    create_table(tbl_name, column_list)


def create_table_ssl_extension():
    column_list = ['id bigint NULL',
                   'certificate_id bigint NULL',
                   'short_name text NULL',
                   'critical text NULL',
                   'value text NULL',
                   'data text NULL']
    tbl_name = TableName.SSLExtension.value
    create_table(tbl_name, column_list)


def prepare_db():
    create_table_certificate()
    create_table_certificate_source()
    create_table_key()
    create_table_rsa_key()
    create_table_dsa_key()
    create_table_ec_key()
    create_table_crypto_subject()
    create_table_crypto_subject_detail()
    create_table_crypto_issuer()
    create_table_crypto_issuer_detail()
    create_table_ssl_subject()
    create_table_ssl_issuer()
    create_table_crypto_extension()
    create_table_crypto_extension_detail()
    create_table_ssl_extension()


def create_copy_command_per_ds(ds_path):
    target_path = os.path.join(ds_path, 'CSV')

    for table_name in TableName:
        temp_target_path = os.path.join(target_path, table_name.value)
        final_target_path = '{}.csv'.format(temp_target_path)
        login_command = "PGPASSWORD=Passw0rd psql -U postgres -d cert_db -c"
        copy_command = "copy {} FROM '{}' delimiter ',' csv;".format(table_name.value, final_target_path)
        copy_command = '"\\\\{}"'.format(copy_command)
        command = "{} {}".format(login_command, copy_command)
        print(command)


def create_copy_command():
    create_copy_command_per_ds('/media/user01/Disk_12TB/FLOR/APK_DB')
    create_copy_command_per_ds('/media/user01/Disk_12TB/FLOR/FR13_DB')
    create_copy_command_per_ds('/media/user01/Disk_12TB/FLOR/PE_VX_DB')
    create_copy_command_per_ds('/media/user01/Disk_12TB/FLOR/PE_VS_DB')
    create_copy_command_per_ds('/media/user01/Disk_12TB/FLOR/SBA_DB/SET_1')
    create_copy_command_per_ds('/media/user01/Disk_12TB/FLOR/SBA_DB/SET_2')
    create_copy_command_per_ds('/media/user01/Disk_12TB/FLOR/R7_21_SSL_1_DB_SET_1')
    create_copy_command_per_ds('/media/user01/Disk_12TB/FLOR/R7_21_SSL_1_DB_SET_2')
    create_copy_command_per_ds('/media/user01/Disk_12TB/FLOR/R7_21_SSL_2_DB/SET_1')
    create_copy_command_per_ds('/media/user01/Disk_12TB/FLOR/R7_21_SSL_2_DB/SET_2')
    create_copy_command_per_ds('/media/user01/Disk_12TB/FLOR/R7_21_MORE_DB')
    create_copy_command_per_ds('/media/user01/Disk_12TB/FLOR/SSH_DB')


def data_cleaning():
    connection = create_connection()
    query = "select id from key where pub_key_size like '%None%';"
    result = run_select_query(connection, query)
    print('key with pub_key_size None: ', result)


if __name__ == "__main__":
    # prepare_db()
    create_copy_command()
