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


class GenericByteflip(BinDataHelper.LiteCrypt):

    def run_crypt(self):
        """
        Swap bytes of supplied data.

        :return: processed data
        :rtype: bytearray
        """

        if self.total_size % 2 != 0:
            raise ValueError('Total size of processed bytes must be even'
                             'length for byteflip.')

        flipped = bytearray()

        for i in range(self.offset, self.total_size, 2):
            flipped.append(self.buff[i + 1])
            flipped.append(self.buff[i])

        return flipped


def initialize_parser():

    description = 'Process data stream and swap each byte. ' \
                  'Numeric values may be provided ' \
                  'as regular integers or hexadecimal with the \'0x\' prefix.'

    parser = BinDataHelper.generic_args(description)

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

    s = GenericByteflip(
        buff=buff,
        offset=args.offset,
        size=args.size,
    )

    return_data = s.run_crypt()

    sys.stdout.buffer.write(return_data)


if __name__ == '__main__':
    main()
