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
#
# Desc:
# -----
# Python 2/3 compatible version of RC4 cipher. Easy enough to tinker with
# for custom implementations or just experimenting.
#
# Usage:
# ------
# import myRC4
# d = myRC4.Crypter(key, buff)
# sys.stdout.buffer.write(d.crypted)
#

from __future__ import print_function

__version__ = "1.0.0"
__author__ = "Jason Batchelor"


class Crypter:
    """
    En/Decrypts malware payload.

    :ivar bytearray crypted: Crypted contents of supplied data.
    """

    def __init__(self, key, buff, sbox_size=256):
        self.buff = bytearray(buff)
        self.key = bytearray(key)
        self.sbox_size = sbox_size
        self.crypted = self._crypt()

    def _generate_key_ring(self):
        """
        Generate SBOX using supplied key.

        :return: Populated list of SBOX elements for the algorithm.
        :rtype: list
        """

        keyring = bytearray(b'\x00' * self.sbox_size)

        for i in range(0, len(keyring)):
            keyring[i] = i % self.sbox_size

        byte_idx = 0
        for i in range(0, len(keyring)):
            byte_idx = (self.key[i % len(self.key)] + byte_idx + keyring[i]) \
                       % self.sbox_size
            t = keyring[i]
            keyring[i] = keyring[byte_idx]
            keyring[byte_idx] = t

        return keyring

    def _crypt(self):
        """
        Process and crypt data.

        :return: Crypted string.
        :rtype: bytearray
        """

        keyring = self._generate_key_ring()
        crypted = bytearray()
        sch_idx_1, sch_idx_2 = 0, 0

        for i in range(0, len(self.buff)):
            sch_idx_1 = (i + 1) % self.sbox_size
            sch_idx_2 = (sch_idx_2 + keyring[sch_idx_1]) % self.sbox_size

            t = keyring[sch_idx_1]
            keyring[sch_idx_1] = keyring[sch_idx_2]
            keyring[sch_idx_2] = t

            key_idx = (keyring[sch_idx_2] +
                       keyring[sch_idx_1]) % self.sbox_size
            crypted.append(self.buff[i] ^ keyring[key_idx])

        return crypted


if __name__ == '__main__':

    import sys
    import os

    if not os.path.isfile('enc.bin'):
        print('[+] enc.bin file not found!')
        sys.exit(2)

    if not os.path.isfile('key.bin'):
        print('[+] key.bin file not found!')
        sys.exit(2)

    with open('enc.bin', 'rb') as f:
        buff = f.read()

    with open('key.bin', 'rb') as f:
        key = f.read()

    d = Crypter(key, buff)
    if hasattr(sys.stdout, 'buffer'):
        sys.stdout.buffer.write(d.crypted)
    else:
        sys.stdout.write(d.crypted)
