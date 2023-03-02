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
from typing import List
from malchive.helpers import BinDataHelper

__version__ = "1.1.0"
__author__ = "Jason Batchelor"

log = logging.getLogger(__name__)


class GenericXor(BinDataHelper.LiteCrypt):

    def __init__(self,
                 key: list = None,
                 count: int = 0,
                 skip_nulls: bool = False,
                 skip_key: bool = False,
                 skip_strict: bool = False,
                 *args,
                 **kwargs):

        self.key: List[int] = []
        self.key_count: int = 0
        self.skip_nulls: bool = False
        self.skip_key: bool = False
        self.skip_strict: bool = False

        if not isinstance(key, list):
            raise TypeError('Key sequence must be passed as a list.')
        if not all(k < 256 for k in key):
            raise ValueError('Key sequence must contain values within '
                             'byte range (0x00 - 0xff).')
        if count > 256:
            raise ValueError('Count must be within byte range (0x00 - 0xff).')

        self.key = key
        self.key_count = count
        self.skip_nulls = skip_nulls
        self.skip_key = skip_key
        self.skip_strict = skip_strict

        log.info('Proceeding using key: [%s]' %
                 ', '.join(hex(x) for x in self.key))

        super().__init__(*args, **kwargs)

    def run_crypt(self):
        """
        Run a generic xor on supplied data.

        :return: processed data
        :rtype: bytearray
        """

        counter = 0
        decoded = bytearray()

        for i in range(self.offset, self.total_size):

            k = self.key[counter % len(self.key)]
            byte = self.buff[i]

            if (self.skip_nulls and byte == 0x00) or \
                    (self.skip_key and byte == k):
                decoded.append(byte)
                if self.skip_strict:
                    continue
            else:
                decoded.append(byte ^ k & 0xff)

            k = k + self.key_count & 0xff
            self.key[counter % len(self.key)] = k
            counter += 1

        return decoded


def initialize_parser():

    description = 'Process data stream and xor each byte by ' \
                  'the supplied key. Numeric values may be provided ' \
                  'as regular integers or hexadecimal with the \'0x\' prefix.'

    parser = BinDataHelper.generic_args(description)

    parser.add_argument('key', type=BinDataHelper.autokey,
                        help='Single or multibyte key value. '
                             'May be supplied as an integer or '
                             'as a hex value with the \'0x\' prefix.')
    parser.add_argument('-c', '--count',
                        type=BinDataHelper.autoint,
                        default=0,
                        help='Interval to increment key value on each byte '
                             'iteration. Range of 0x00 - 0xff.')
    parser.add_argument('-sn', '--skip-nulls',
                        action='store_true',
                        default=False,
                        help='When processing the buffer, skip all null '
                             '(\'0x00\') bytes.')
    parser.add_argument('-sk', '--skip-key',
                        action='store_true',
                        default=False,
                        help='Skip bytes that match the supplied key value.')
    parser.add_argument('--skip-strict',
                        action='store_true',
                        default=False,
                        help='Do not increment or modify key in any way if a '
                        'skip condition is satisfied.')

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

    buff = args.infile.buffer.read()

    s = GenericXor(
        key=args.key,
        count=args.count,
        skip_nulls=args.skip_nulls,
        skip_key=args.skip_key,
        skip_strict=args.skip_strict,
        buff=buff,
        offset=args.offset,
        size=args.size,
    )

    return_data = s.run_crypt()

    sys.stdout.buffer.write(return_data)


if __name__ == '__main__':
    main()
