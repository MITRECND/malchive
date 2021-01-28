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

import os
import sys
import sqlite3
import logging
import pefile
import argparse
import binascii
import datetime

__version__ = "1.0.0"
__author__ = "Jason Batchelor"

log = logging.getLogger(__name__)


def ror(data, key):
    return (data >> key | data << (32 - key)) & 0xFFFFFFFF


def gen_standard_hash(func, key):
    """
    Perform standard hashing algorithm commonly observed in practice.

    :param bytearray func: Name of the function to hash.
    :param int key: Number for rotations to perform.

    :return: hash
    :rtype: int
    """
    h = 0
    for c in func:
        h = c + ror(h, key) & 0xFFFFFFFF
    return h


# Ref:
# https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/hash.py
def convert_unicode(string, uppercase=True):
    result = ""
    if uppercase:
        string = string.upper()
    for c in string:
        result += c + "\x00"
    return result


# Ref:
# https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/hash.py
def gen_metasploit_hash(lib, func, key):
    """
    Perform Metasploit's hashing algorithm.

    :param bytearray lib: Name of the library associated with function.
    Used in hash calculation.
    :param bytearray func: Name of the function to hash.
    :param int key: Number for rotations to perform.

    :return: hash
    :rtype: int
    """
    module_hash = 0
    function_hash = 0
    for c in convert_unicode(lib + "\x00"):
        module_hash = ror(module_hash, key)
        module_hash += ord(c)
    for c in bytes(func + b'\x00'):
        function_hash = ror(function_hash, key)
        function_hash += c
    h = module_hash + function_hash & 0xFFFFFFFF
    return h


def gen_crc32_hash(func):
    """
    Perform a simple CRC32 computation of the supplied function name.

    :param str func: Name of the function to hash.

    :return: hash
    :rtype: int
    """
    h = binascii.crc32(func)
    if h > 0x7FFFFFFF:
        h -= 0x100000000 & 0xffffffff
    return h


def gen_js_hash(func):
    """
    Perform JSHash computation of the supplied function name.

    :param bytearray func: Name of the function to hash.

    :return: hash
    :rtype: int
    """
    h = 1315423911
    for c in func:
        h ^= ((h << 5) + c + (h >> 2) & 0xFFFFFFFF)
    return h


def gen_carberp_hash(func):
    """
    Perform hash computation of function name using Carberp algorithm.

    :param bytearray func: Name of the function to hash.

    :return: hash
    :rtype: int
    """
    h = 0
    for c in func:
        h = ((h << 7) & 0xFFFFFFFE) | (h >> (32 - 7))
        h = h ^ c
    return h


def initialize_parser():
    parser = argparse.ArgumentParser(
        description='Generate an sqlite database of API hashes using '
                    'algorithms commonly observed in shellcode. Input files'
                    ' must be valid Windows DLLs.')
    parser.add_argument('dll', metavar='FILE', nargs='*',
                        help='Full path to the DLL(s) to be processed.')
    parser.add_argument('-v', '--verbose', action='store_true', default=False,
                        help='Output additional information when '
                             'processing (mostly for debugging purposes).')
    parser.add_argument('-db', '--database-name', type=str,
                        default='apihashes.db',
                        help='Name of database file to be generated.'
                             ' (default: apihashes.db)')

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

    if len(args.dll) == 0:
        log.error('No files were supplied. Please provide a DLL for hash '
                  'generation.')
        p.print_help()
        sys.exit(2)

    for filename in args.dll:

        basename = os.path.basename(filename)
        log.info('Generating hashes for %s...' % basename)

        if not os.path.isfile(filename):
            log.warning('Failed to find file %s, skipping...' % filename)
            continue

        f = open(filename, 'rb')
        stream = f.read()

        symbols = []
        try:
            pe = pefile.PE(data=stream)
            symbols = pe.DIRECTORY_ENTRY_EXPORT.symbols
        except pefile.PEFormatError:
            log.error('%s not a pe, skipping...' % basename)
            continue

        # Generate hashes as a list of tuples
        entries = []
        for exp in symbols:

            if exp.name is None:
                continue

            entries.append(('Standard ROR 0x7', basename,
                            bytes(exp.name).decode('ascii'),
                            gen_standard_hash(exp.name, 0x7)))
            entries.append(('Standard ROR 0xd', basename,
                            bytes(exp.name).decode('ascii'),
                            gen_standard_hash(exp.name, 0xd)))
            entries.append(('Metasploit ROR 0xd', basename,
                            bytes(exp.name).decode('ascii'),
                            gen_metasploit_hash(basename, exp.name, 0xd)))
            entries.append(('CRC32', basename, bytes(exp.name).decode('ascii'),
                            gen_crc32_hash(exp.name)))
            # I've seen this twist as well where the null byte
            # is part of the computation for crc32
            entries.append(('CRC32', basename,
                            (bytes(exp.name + b'\\x00')).decode('ascii'),
                            gen_crc32_hash(bytes(exp.name + b'\x00'))))
            entries.append(('JSHash', basename,
                            bytes(exp.name).decode('ascii'),
                            gen_js_hash(exp.name)))
            entries.append(('Carberp', basename,
                            bytes(exp.name).decode('ascii'),
                            gen_carberp_hash(exp.name)))

        if len(entries) == 0:
            log.info('No export entries were found')
            continue

        log.info('Found %s export entries...' % len(symbols))
        log.info('Adding %s hashes to database...' % len(entries))

        start = datetime.datetime.now()

        conn = sqlite3.connect(args.database_name)
        cursor = conn.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS apihashes
            (Algorithm text, Module text, Function text, Hash int)
            """)
        cursor.executemany("INSERT INTO apihashes (Algorithm, Module, "
                           "Function, Hash) VALUES (?, ?, ?, ?)",
                           entries)
        conn.commit()
        cursor.close()
        conn.close()
        end = datetime.datetime.now()

        log.info('Inserted %s new entries in %s...' %
                 (len(entries), end - start))

    print('Complete! Any computed hashes saved to %s' % args.database_name)


if __name__ == '__main__':
    main()
