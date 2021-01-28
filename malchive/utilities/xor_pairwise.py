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
from malchive.helpers import BinDataHelper

__version__ = "1.0.0"
__author__ = "Jason Batchelor"

log = logging.getLogger(__name__)


class PairwiseXor(BinDataHelper.LiteCrypt):

    def __init__(self,
                 key: int = 0,
                 incrementing: bool = False,
                 *args,
                 **kwargs):

        self.key: int = 0
        self.incrementing: bool = False

        if 0x00 <= key <= 0xff:
            self.key = key
        else:
            raise ValueError('Key must be between 0x00 and 0xff.')

        self.incrementing = incrementing

        super().__init__(*args, **kwargs)

    def run_crypt(self):
        """
        Run pairwise xor on supplied data.

        :return: processed data
        :rtype: bytearray
        """

        data = bytearray(self.buff[self.offset:self.total_size])

        if self.total_size % 2 != 0:
            raise ValueError('Total size of processed bytes must '
                             'be even length for pairwise decode.')

        if self.incrementing:
            data[0] ^= self.key
            for i in range(0, len(data) - 1, 1):
                data[i + 1] ^= data[i]
        else:
            for i in range(len(data) - 1, 0, -1):
                data[i] ^= data[i - 1]
            data[0] ^= self.key
        return data


def initialize_parser():

    description = 'Instead of a standard single byte xor operation, ' \
                  'xor end byte with previous byte and continue in a ' \
                  'decrementing fashion until the final byte is ' \
                  'reached at the beginning.'

    parser = BinDataHelper.generic_args(description)

    parser.add_argument('-r', '--reverse',
                        action='store_true',
                        default=False,
                        help='Reverse the process, applying pairwise '
                             'at the beginning rather than the end.')
    parser.add_argument('-k', '--pw-xor-key',
                        type=BinDataHelper.autoint,
                        default=0,
                        help='Key to use to start or end the XOR '
                             '(depending on if \'r\' is used). '
                             'Must be 0x00-0xff. Defaults to 0x00.')

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

    s = PairwiseXor(
        key=args.pw_xor_key,
        incrementing=args.reverse,
        buff=buff,
        offset=args.offset,
        size=args.size,
    )

    return_data = s.run_crypt()

    sys.stdout.buffer.write(return_data)


if __name__ == '__main__':
    main()
