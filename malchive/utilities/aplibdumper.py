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
# There are a few capabilities out there like this that exist such as
# aplib-ripper.
#
# However, I didn't see anything that met the following requirements:
#   * Python 3 support.
#   * Processing any content compressed using aPLib (not just PEs).
#   * Contains some form of validation against the headers advertised
#     CRC32 and size values.
#   * Creates pretty tables for output ;)
#

import os
import io
import sys
import hashlib
import struct
import yara
import logging
import argparse
from tabulate import tabulate
from malchive.helpers import apLib

__version__ = "1.0.0"
__author__ = "Jason Batchelor"

log = logging.getLogger(__name__)


class YaraScanner:
    """
    Uses YARA to identify potential embedded aPLib content, then parses
    and decompresses.

    :ivar list results: List of tuples for each entry, indicating;
    uncompressed md5, offset, uncompressed size, uncompressed
    crc32 and uncompressed data.
    """

    def __init__(self, data):

        """
        Initialize class instance.

        :param bytes data: The stream of bytes to be processed.
        """

        self.results = []
        self.data = data

        try:
            rule = '''
/*
00004700  41 50 33 32 18 00 00 00  66 65 01 00 0d 15 c5 77  |AP32....fe.....w|
00004710  00 88 02 00 b8 d7 c1 5d  4d 38 5a 90 38 03 66 02  |.......]M8Z.8.f.|

Offset | Size | Context
--------------------------------
0x0     DWORD   Magic header
0x4     DWORD   Second magic header
0x8     DWORD   Payload size compressed
0xC     DWORD   CRC32 compressed data
0x10    DWORD   Payload size uncompressed
0x14    DWORD   CRC32 uncompressed data
0x18    Varies  APLib compressed data

*/
rule aPLib_header
{
    strings:
        $apLib = { 41 50 33 32 18 00 00 00 }

    condition:
        for any p in (1..#apLib):
            // ensure size compressed data is less than size of file
            (filesize > uint32(@apLib[p] + 0x8) and
            // ensure size decompressed is greater than size compressed
            // this may not be true for really small payloads due to
            // compression overhead, but im willing to accept that
            uint32(@apLib[p] + 0x8) < uint32(@apLib[p] + 0x10))
}
'''
            self.rules = yara.compile(source=rule)
        except yara.SyntaxError as e:
            log.error(f"Exception while compiling YARA rule: {e}")
            sys.exit(1)

    def callback(self, data):
        """
        Parse, extract, and decompress aPLib content.
        """

        for offset, rule_name, rule_match in data.get("strings"):

            match_buffer = self.data[offset:]
            compressed_size = struct.unpack('I', match_buffer[0x8:0xc])[0]
            # fwiw
            # compressed_crc32 = struct.unpack('I', match_buffer[0xc:0x10])[0]
            uncompressed_size = struct.unpack('I', match_buffer[0x10:0x14])[0]
            uncompressed_crc32 = struct.unpack('I', match_buffer[0x14:0x18])[0]
            compressed_data = match_buffer[0x18: 0x18 + compressed_size]

            try:
                r = io.BytesIO(compressed_data)
                uncompressed_data = apLib.Decompress(r, False).do()
                self.results.append((
                    hashlib.md5(uncompressed_data).hexdigest(),
                    offset,
                    uncompressed_size,
                    uncompressed_crc32,
                    uncompressed_data
                ))
            except Exception as e:
                log.error("Exception decompressing payload: %s"
                          "\n\toffset => 0x%x"
                          "\n\tcompressed size => %s bytes"
                          "\n\textracted compressed => %s bytes"
                          % (e, offset, compressed_size, len(compressed_data)))

        return yara.CALLBACK_CONTINUE

    def match(self):
        """
        Run rule on input data and execute callback if match occurs.
        """
        self.rules.match(data=self.data, callback=self.callback)


def write_files(target_dir, f_data, f_md5):
    if target_dir != '.':
        try:
            os.makedirs(target_dir)
        except OSError:
            if not os.path.isdir(target_dir):
                log.error('Could not create %s. Exiting...' % target_dir)
                sys.exit(2)
    with open('%s/%s.aplib' % (target_dir, f_md5), 'wb') as f:
        f.write(f_data)


def initialize_parser():
    parser = argparse.ArgumentParser(
        description='Extracts, decompresses, and dumps embedded payloads '
                    'compressed using aPLib to disk using the MD5 of the '
                    'decompressed data as the filename. This is done by '
                    'evaluating an embedded structure that precedes aPLib'
                    ' compressed content.')
    parser.add_argument('infile', metavar='FILE', nargs='*',
                        help='Full path to the file(s) to be processed.')
    parser.add_argument('-v', '--verbose', action='store_true', default=False,
                        help='Output additional information when processing '
                             '(mostly for debugging purposes).')
    parser.add_argument('-t', '--target-directory', type=str, default='.',
                        help='Target directory to write files. '
                             'Defaults to executing directory.')
    parser.add_argument('-s', '--suppress-write', action='store_true',
                        help='Prevent results from being written to disk. '
                             'Opting instead for just a table view of the '
                             'results.')

    return parser


def main():
    import binascii

    p = initialize_parser()
    args = p.parse_args()

    root = logging.getLogger()
    logging.basicConfig()
    if args.verbose:
        root.setLevel(logging.DEBUG)
    else:
        root.setLevel(logging.WARNING)

    if len(args.infile) == 0:
        p.print_help()
        sys.exit(2)

    target_dir = args.target_directory
    if not args.suppress_write and target_dir != '.':
        log.info('Writing to directory: %s' % target_dir)

    for fname in args.infile:
        results = []

        basename = os.path.basename(fname)
        log.info('Processing file %s...' % basename)
        if not os.path.isfile(fname):
            log.warning('Failed to find file %s. Skipping...' % fname)
            continue

        with open(fname, 'rb') as f:
            scanner = YaraScanner(f.read())
            scanner.match()

        log.info('Found %s compressed files in %s...' % (len(scanner.results),
                                                         basename))

        if len(scanner.results) == 0:
            continue

        for uncomp_md5, offset, uncomp_size, uncomp_crc32, uncomp_data in \
                scanner.results:

            h = binascii.crc32(uncomp_data)
            if h > 0x7FFFFFFF:
                h -= 0x100000000 & 0xffffffff
            if h != uncomp_crc32:
                log.debug('Reported CRC32 and actual CRC32 of '
                          'decompressed data is different!'
                          '\n\tOffset => 0x%x'
                          '\n\tReported CRC32=> 0x%x'
                          '\n\tActual CRC32> 0x%x'
                          '\n\tReported Size=> %s bytes'
                          '\n\tActual Size=> %s bytes' %
                          (offset,
                           uncomp_crc32,
                           h,
                           uncomp_size,
                           len(uncomp_data)))

            results.append((uncomp_md5, len(uncomp_data),
                            '0x%x' % offset, '0x%x' % h))

            if not args.suppress_write:
                write_files(target_dir, uncomp_data, uncomp_md5)

        if len(results) > 0:
            print(tabulate(results,
                           headers=["MD5", "Size", "Offset", "CRC32"],
                           tablefmt="grid"))


if __name__ == '__main__':
    main()
