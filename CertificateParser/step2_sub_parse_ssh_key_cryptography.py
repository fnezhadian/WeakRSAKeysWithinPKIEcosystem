import base64
import hashlib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.hazmat.primitives.asymmetric.dh import DHPublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey

from CertParser.cert_parser_helper import KeyType


def get_pubkey_rsa(key_data):
    key_type = KeyType.RSA.value
    size = None
    numbers = []
    try:
        size = int(key_data.key_size)
        exponent = str(int(key_data.public_numbers().e))
        modulus = hex(key_data.public_numbers().n)[2:]
        numbers = [exponent, modulus]
    except Exception as e:
        print(key_data)
        print(str(key_data))
        print(e)
    return key_type, size, numbers


def get_pubkey_dsa(key_data):
    key_type = KeyType.DSA.value
    size = None
    numbers = []
    try:
        size = int(key_data.key_size)
        np = hex(key_data.public_numbers().p)[2:]
        nq = hex(key_data.public_numbers().q)[2:]
        ng = hex(key_data.public_numbers().g)[2:]

        # np = hex(key_data.public_numbers().parameter_numbers.p)[2:]
        # nq = hex(key_data.public_numbers().parameter_numbers.q)[2:]
        # ng = hex(key_data.public_numbers().parameter_numbers.g)[2:]
        numbers = [np, nq, ng]
    except Exception as e:
        print(key_data)
        print(str(key_data))
        print(e)
    return key_type, size, numbers


def get_pubkey_ec(key_data):
    key_type = KeyType.EC.value
    size = None
    numbers = []
    try:
        size = int(key_data.key_size)
        cv = str(key_data.public_numbers().curve.name)
        nx = hex(key_data.public_numbers().x)[2:]
        ny = hex(key_data.public_numbers().y)[2:]
        numbers = [cv, nx, ny]
    except Exception as e:
        print(key_data)
        print(str(key_data))
        print(e)
    return key_type, size, numbers


def get_public_key(input_key):
    key_type = None
    size = None
    numbers = None
    try:
        ssh_public_key = serialization.load_ssh_public_key(input_key.encode("utf-8"), default_backend())
        public_key_numbers = ssh_public_key.public_numbers()
        if public_key_numbers:
            if isinstance(public_key_numbers, rsa.RSAPublicNumbers):
                key_type, size, numbers = get_pubkey_rsa(ssh_public_key)
            elif isinstance(public_key_numbers, dsa.DSAPublicNumbers):
                key_type, size, numbers = get_pubkey_dsa(ssh_public_key)
            elif isinstance(public_key_numbers, ec.EllipticCurvePublicNumbers):
                key_type, size, numbers = get_pubkey_ec(ssh_public_key)
            elif isinstance(public_key_numbers, Ed448PublicKey):
                key_type = KeyType.ED448.value
            elif isinstance(public_key_numbers, Ed25519PublicKey):
                key_type = KeyType.ED25519.value
            elif isinstance(public_key_numbers, DHPublicKey):
                key_type = KeyType.DH.value
            elif isinstance(public_key_numbers, X448PublicKey):
                key_type = KeyType.X448.value
            elif isinstance(public_key_numbers, X25519PublicKey):
                key_type = KeyType.X25519.value
    except Exception as e:
        print(e)
    return str(key_type), str(size), numbers


def get_key_thumbprints(pubkey):
    pkp_1 = None
    pkp_2 = None
    try:
        encoded_pubkey = str(pubkey).encode("utf-8")
        sha1 = hashlib.sha1(encoded_pubkey).digest()
        sha1_base64 = base64.b64encode(sha1)
        pkp_1 = sha1_base64.decode("utf-8")

        sha2 = hashlib.sha256(encoded_pubkey).digest()
        sha2_base64 = base64.b64encode(sha2)
        pkp_2 = sha2_base64.decode("utf-8")
    except Exception as e:
        print(e)
    return pkp_1, pkp_2




