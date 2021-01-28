#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright(c) 2021 The MITRE Corporation. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
#
# You may obtain a copy of the License at:
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import logging
import argparse
import hashlib
from Crypto.PublicKey import RSA
sys.setrecursionlimit(1000000)

__version__ = "1.0.0"
__author__ = "Jason Batchelor"

log = logging.getLogger(__name__)


# Extended Euclidean Recursive algorithm
# Reference:
# https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm#Python
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, x, y = egcd(b % a, a)
        return (g, y - (b // a) * x, x)


def gen_private_key(p, q, e):
    """
    Use supplied values to generate an RSA private key.

    :param int p: First prime.
    :param int q: Second prime.
    :param int e: Public exponent.

    :return: Private key
    :rtype: str
    """

    # Calculate 'n', n = p x q
    n = p * q
    # Calculate 'd', d = e^(-1) mod [(p-1)x(q-1)]
    phi = (p - 1) * (q - 1)
    # Need to use extended euclidean algorithm for 'd'
    gcd, d, b = egcd(e, phi)

    # Assign key parameters
    key_params = (n, e, d, p, q)
    # Construct private key
    key = RSA.construct(key_params)

    return key.exportKey()


def gen_public_key(n, e):
    """
    Use supplied values to generate an RSA public key.

    :param int n: Public modulus .
    :param int e: Public exponent.

    :return: Public key
    :rtype: str
    """

    # Assign key parameters
    key_params = (n, e)
    # Construct private key
    key = RSA.construct(key_params)

    return key.exportKey()


def autoint(x):
    if x.startswith('0x'):
        x = int(x, 16)
    else:
        x = int(x)
    return x


def initialize_parser():
    parser = argparse.ArgumentParser(
        description='Generate RSA keys given corresponding values. Numeric '
                    'values may be provided as regular integers or '
                    'hexadecimal with the \'0x\' prefix.')
    parser.add_argument('-p', '--first-prime', type=autoint, default=0,
                        help='First prime value. Used along with \'Q\' '
                             'for private key generation.')
    parser.add_argument('-q', '--second-prime', type=autoint, default=0,
                        help='Second prime value. Used along with \'P\' '
                             'for private key generation.')
    parser.add_argument('-e', '--public-exponent', type=autoint,
                        default=0x010001,
                        help='Public exponent used for private and public key '
                             'generation. (Default: 0x010001)')
    parser.add_argument('-n', '--public-modulus', type=autoint, default=0,
                        help='Public modulus used when generating '
                             'public keys.')
    parser.add_argument('-v', '--verbose', action='store_true', default=False,
                        help='Output additional information when processing '
                             '(mostly for debugging purposes).')
    return parser


def main():
    p = initialize_parser()
    args = p.parse_args()

    root = logging.getLogger()
    logging.basicConfig()
    if args.verbose:
        root.setLevel(logging.DEBUG)
    else:
        root.setLevel(logging.WARNING)

    e = args.public_exponent
    pub_key = b''
    priv_key = b''
    if args.first_prime > 0 and args.second_prime > 0:
        p = args.first_prime
        q = args.second_prime
        priv_key = gen_private_key(p, q, e)
        file_md5 = hashlib.md5(priv_key).hexdigest()
        name = '%s_priv.key' % file_md5
        if len(priv_key) > 0:
            with open(name, 'wb+') as f:
                f.write(priv_key)
                print('Private key generated. Written to %s' % name)

    if args.public_modulus > 0:
        n = args.public_modulus

        try:
            pub_key = gen_public_key(n, e)
        except ValueError:
            log.error('Invalid RSA public value(s).')

        file_md5 = hashlib.md5(pub_key).hexdigest()
        name = '%s_pub.key' % file_md5
        if len(pub_key) > 0:
            with open(name, 'wb+') as f:
                f.write(pub_key)
                print('Public key generated. Written to %s' % name)


if __name__ == '__main__':
    main()
