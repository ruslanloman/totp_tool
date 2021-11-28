#!/usr/bin/env python3

import argparse
import logging
import os
import secrets
import time
from base64 import urlsafe_b64decode as b64d, urlsafe_b64encode as b64e
from getpass import getpass

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from prettytable import PrettyTable

import pyotp

import yaml

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger('totp_tool')

backend = default_backend()
iterations = 100_000


def totp(key: str) -> int:
    return pyotp.TOTP(key).now()


def _derive_key(password: bytes, salt: bytes, iterations: int = iterations) -> bytes:
    """Derive a secret key from a given password and salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=iterations, backend=backend)
    return b64e(kdf.derive(password))


def password_encrypt(message: bytes, password: str, iterations: int = iterations) -> bytes:
    salt = secrets.token_bytes(16)
    key = _derive_key(password.encode(), salt, iterations)
    return b64e(
        b'%b%b%b' % (
            salt,
            iterations.to_bytes(4, 'big'),
            b64d(Fernet(key).encrypt(message)),
        )
    )


def password_decrypt(token: bytes, password: str) -> bytes:
    decoded = b64d(token)
    salt, iter, token = decoded[:16], decoded[16:20], b64e(decoded[20:])
    iterations = int.from_bytes(iter, 'big')
    key = _derive_key(password.encode(), salt, iterations)
    return Fernet(key).decrypt(token)


def generate_totp(secret: dict, one_time: bool, timeout: int = 10):
    table = PrettyTable(['Name', '2FA key'])

    while True:
        for k, v in secret.items():
            table.add_row([k, totp(v)])
        print(table)

        if one_time:
            return

        time.sleep(timeout)
        os.system('clear')
        table.clear_rows()


def convert_plantext_encrypt(src: str, dst: str, password: str = None):
    encrypted = {}

    with open(src) as fd:
        src_secret = yaml.safe_load(fd)

    for k, v in src_secret.items():
        encrypted.update({k: password_encrypt(bytes(v, encoding='utf-8'), password)})

    with open(dst, 'w') as fd:
        fd.write(yaml.safe_dump(encrypted))


def main():
    parser = argparse.ArgumentParser(description='totp generator')
    parser.add_argument('--one-time', help='run once', action='store_true', default=False)
    parser.add_argument('--config', help='config with secret keys', default='secret.yaml')
    parser.add_argument('--password', help='Password to encrypt/decrypt secret file',
                        action='store_true', dest='password')

    subprasers = parser.add_subparsers(dest='command')
    convert = subprasers.add_parser('convert', help='Convert plaintext file to encrypted')
    convert.add_argument('--src', help='Plantext config with secret keys', default='secret.yaml')
    convert.add_argument('--dst', help='Encrypted config with secret keys', default='secret_encrypted.yaml')

    add_secret = subprasers.add_parser('add', help='Add 2fa to the secret file')
    add_secret.add_argument('--data', help='Secret data')
    add_secret.add_argument('--name', help='Secret key name')

    args = parser.parse_args()

    if args.password:
        password = getpass()

    if args.command == 'convert' and password:
        convert_plantext_encrypt(args.src, args.dst, password)
        exit()

    if args.command == 'add':
        convert_plantext_encrypt(args.src, args.dst, password)
        exit()

    secret = {}

    with open(args.config) as fd:
        _secret = yaml.safe_load(fd)

    for k, v in _secret.items():
        if type(v) == bytes:
            try:
                secret.update({k: password_decrypt(v, password)})
            except UnboundLocalError:
                logger.error('Please specify password %s')
                exit(1)
        else:
            secret.update({k: v})

    generate_totp(secret, args.one_time)


if __name__ == '__main__':
    main()
