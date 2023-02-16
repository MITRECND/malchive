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

import argparse
import logging
import struct

__version__ = "1.0.0"
__author__ = "Marcus Eddy & Jason Batchelor"


log = logging.getLogger(__name__)


class ExtractIt:

    def __init__(self, buff):
        """
        Initialize decoder instance.

        :param bytes buff: The stream of bytes to be processed.
        """

        self.key = 0
        self.buff = bytearray(buff)
        self.decoded_payload = bytearray()
        self.payload = self.decode_payload(self.buff)

    def decode_payload(self, buff):
        """
        Find Xor Key and Decode Payload
        """

        beacon_magic = [
                b'\x90\x90',
                b'\x0f\x1f',
                b'\x66\x90',
                b'\x4d\x5a',
                ]

        ff_start = buff[:100].find(b'\xff\xff\xff')
        if ff_start > 1:
            log.info('Encrypted payload marker found!')

            buff = buff[ff_start+3:]

            _t, size = struct.unpack('II', buff[0x0:0x8])
            size ^= _t

            dec = buff[0x8:]
            key = buff[:0x4]

            if size > len(dec):
                log.info('Bad size of %s bytes returned for payload %s bytes' %
                         (size, len(dec)))
                return

            self.key = struct.unpack('>I', key)[0]

            decoded = self.rolling_xor_long(dec, key, size)
            if decoded[:2] in beacon_magic:
                self.decoded_payload = decoded
            else:
                log.info('Beacon PE data was not found in decrypted data.')

    @staticmethod
    def rolling_xor_long(dec, key, size):
        for i in range(0, size):
            dec[i] ^= key[i % len(key)]
            key[i % len(key)] ^= dec[i]

        return dec


def initialize_parser():
    parser = argparse.ArgumentParser(
        description='Process candidate. Prints results in JSON format.')
    parser.add_argument('candidates', metavar='FILE',
                        nargs='*', help='candidate file(s).')
    parser.add_argument('-v', '--verbose', action='store_true',
                        default=False,
                        help='Output additional information when processing '
                             '(mostly for debugging purposes).')
    parser.add_argument('-w', '--write', action='store_true',
                        default=False,
                        help='Write retrieved payloads to disk '
                             'using [MD5.beacon] as the filename.')
    parser.add_argument('-t', '--target-directory', type=str, default='.',
                        help='Target directory to write files. Defaults to '
                             'executing directory.')
    return parser


def main():
    import sys
    import os
    import json
    import hashlib

    p = initialize_parser()
    args = p.parse_args()

    root = logging.getLogger()
    logging.basicConfig()
    if args.verbose:
        root.setLevel(logging.DEBUG)
    else:
        root.setLevel(logging.WARNING)

    directory = args.target_directory
    if directory != '.':
        if not os.path.isdir(directory):
            log.error('Could not create %s. Exiting...'
                      % directory)
            sys.exit(2)

    for filename in args.candidates:

        log.info('Processing file %s...' % filename)

        if not os.path.isfile(filename):
            log.warning('Failed to find file %s' % filename)
            continue

        f = open(filename, 'rb')
        stream = f.read()

        d = ExtractIt(stream)

        if len(d.decoded_payload) == 0:
            log.info('Payload not a Cobalt Beacon.')
            continue

        config_dict = {
            'Input Sha256': hashlib.sha256(stream).hexdigest(),
            'Input': filename,
            'Output Sha256': hashlib.sha256(d.decoded_payload).hexdigest(),
            'XOR Key': hex(d.key)
        }

        if args.write and len(d.decoded_payload):
            md5 = hashlib.md5(d.decoded_payload).hexdigest()
            fname = '%s/%s.beacon' % (directory, md5)
            with open(fname, 'wb') as f:
                f.write(d.decoded_payload)
            log.info('%s written to disk!' % fname)

        try:
            print((json.dumps(config_dict, indent=4, sort_keys=False)))
        except UnicodeDecodeError:
            log.warning('There was a Unicode decoding error when '
                        'processing %s' % os.path.basename(filename))
            continue


if __name__ == '__main__':
    main()
