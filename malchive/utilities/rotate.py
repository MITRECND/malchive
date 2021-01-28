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


class GenericRotate(BinDataHelper.LiteCrypt):

    def __init__(self,
                 count: int = 0,
                 right: bool = False,
                 *args,
                 **kwargs):

        self.count: int = 0
        self.right: bool = False

        # Only rotating single bytes
        count = count % 8
        if right:
            log.debug('Modifying count to align with right rotation...')
            count = 8 - count

        self.count = count
        self.right = right

        super().__init__(*args, **kwargs)

    def run_crypt(self):
        """
        Perform bitwise rotation of supplied BYTE N times.

        :return: processed data
        :rtype: bytearray
        """

        rotated = bytearray()

        for i in range(self.offset, self.total_size):
            byte = self.buff[i]
            rotated.append(
                (byte << self.count | byte >> (8 - self.count))
                & 0xff)

        return rotated


def initialize_parser():

    description = 'Process data stream and rotate each byte. ' \
                  'Numeric values may be provided ' \
                  'as regular integers or hexadecimal with the \'0x\' prefix.'

    parser = BinDataHelper.generic_args(description)

    parser.add_argument('count', type=BinDataHelper.autoint,
                        help='Number of times to perform rotation. '
                             'Defaults to the left.')
    parser.add_argument('-r', '--right', action='store_true',
                        default=False,
                        help='Override default rotation direction, and '
                             'instead rotate bits to the right.')

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

    s = GenericRotate(
        count=args.count,
        right=args.right,
        buff=buff,
        offset=args.offset,
        size=args.size,
    )

    return_data = s.run_crypt()

    sys.stdout.buffer.write(return_data)


if __name__ == '__main__':
    main()
