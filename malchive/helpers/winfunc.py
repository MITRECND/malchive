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
# Python implementations designed to emulate certain Windows functions.
#
# Usage:
# ------
# >>> from malchive.helpers import winfunc
# >>> winfunc.CryptDeriveKey(b'test')
#
#

import logging
import hashlib

__version__ = "1.0.0"
__author__ = "Jason Batchelor"

log = logging.getLogger(__name__)


def CryptDeriveKey(password, key_len=0x20):
    """
    Emulate MS CryptDeriveKey
    https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptderivekey

    :param bytes password: Password to base the key off of.
    :param int key_len: Length of key to be used.

    :return: Sequence of bytes representing the key to use.
    :rtype: bytes
    """

    base_data = hashlib.sha1(password).digest()
    b1, b2 = bytearray(b'\x00' * 0x40), bytearray(b'\x00' * 0x40)
    for i in range(0, 0x40):
        b1[i] = 0x36
        b2[i] = 0x5c
        if i < len(base_data):
            b1[i] ^= base_data[i]
            b2[i] ^= base_data[i]
    key_hash = hashlib.sha1(b1).digest() + hashlib.sha1(b2).digest()
    return key_hash[:key_len]


def msvcrt_rand(s=0, size=1):
    """
    Emulate interplay of srand() and rand()

    :param int s: The seed.
    :param int size: Desired length of returned data.

    :return: A sequence of bytes computed using the supplied arguments.
    :rtype: bytearray
    """

    result = bytearray()
    for i in range(0, size):
        s = (214013*s + 2531011) & 0x7fffffff
        result.append(s >> 16 & 0xff)
    return result
