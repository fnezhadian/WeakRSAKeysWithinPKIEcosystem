import base64
from enum import Enum


class KeyType(Enum):
    RSA = 'rsaEncryption'
    DSA = 'dsaEncryption'
    EC = 'id-ecPublicKey'
    ED448 = 'Ed448'
    ED25519 = 'ed25519'
    DH = 'DH'
    X448 = 'x448'
    X25519 = 'x25519'


class CertStatus(Enum):
    Started = 0
    Done = 1
    Unknown = 2
    GET_PEM_ERROR = 3
    GET_PEM_FP_ERROR = 4
    GET_PEM_PKB_ERROR = 5
    GET_PEM_STR = 6
    GET_DER_BIN_ERROR = 7
    GET_DER_ERROR = 8
    GET_DER_TP_ERROR = 9
    GET_DER_VR_ERROR = 10
    GET_DER_SRN_ERROR = 11
    GET_DER_PKI_ERROR = 12
    GET_DER_PK_ERROR = 13
    GET_DER_PK_RSA_ERROR = 14
    GET_DER_PK_DSA_ERROR = 15
    GET_DER_PK_EC_ERROR = 16
    GET_DER_SIG_ALG_ERROR = 17
    GET_DER_VL_ERROR = 18
    GET_DER_SJ_ERROR = 19
    GET_DER_IS_ERROR = 20
    GET_DER_EX_ERROR = 21
    GET_BY_SSL_ERROR = 22
    GET_BY_CRYPTO_ERROR = 23
    GET_KEY_TP_ERROR = 24


class ParserSource(Enum):
    CRYPTO = 1
    SSL = 2
    CRYPTO_SSL = 3


def get_str(value: str):
    """removes the b"""
    return str(value)[2:-1]


def get_encoded_base64(data: bytes):
    encoded_data = base64.b64encode(data)
    encoded_data = str(encoded_data)[2:-1]
    return encoded_data



