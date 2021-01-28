#!/usr/bin/env python
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

import logging
import argparse
import binascii

__version__ = "1.0.0"
__author__ = "Jason Batchelor"

log = logging.getLogger(__name__)


class LiteCrypt():
    """
    LiteCrypt object.
    """

    def __init__(
            self,
            buff: bytearray = bytearray(),
            offset: int = 0,
            size: int = -1,
            **kwargs
    ):

        self.buff: bytearray = bytearray()
        self.offset: int = 0
        self.total_size: int = 0
        self.buff = buff

        if offset > len(buff) or offset < 0:
            raise IndexError('Invalid start position supplied. Exceeds '
                             'range of supplied buffer.')
        self.offset = offset

        if size == -1:
            total_size = len(buff)
        else:
            total_size = size + offset
            if total_size > len(buff) or total_size < offset:
                raise IndexError('Invalid size position supplied. '
                                 'Exceeds range of supplied parameters.')

        self.total_size = total_size

    def run_crypt(self):
        """
        Should be overridden.
        Apply the example crypto method.

        :return: processed data
        :rtype: bytearray
        """

        log.warning('Method should be overridden!')

        return bytearray()


def autokey(x):
    # Ensure we pad the key if necessary with an extra 0
    key = '%x' % autoint(x)
    if len(key) % 2 != 0:
        key = '0' + key
    key = [x for x in binascii.unhexlify(key)]
    return key


def autoint(x):

    if x.startswith('0x'):
        x = int(x, 16)
    else:
        x = int(x)
    return x


def generic_args(info='BinDataHelper Default Parser Description'):

    parser = argparse.ArgumentParser(
        description=info)
    parser.add_argument('-v', '--verbose',
                        action='store_true',
                        default=False,
                        help='Output additional information when processing '
                             '(mostly for debugging purposes).')
    parser.add_argument('infile',
                        type=argparse.FileType('r'),
                        default='-',
                        help='Data stream to process. '
                             '(stdin, denoted by a \'-\').')
    parser.add_argument('-o', '--offset',
                        type=autoint,
                        default=0,
                        help='Starting point within the supplied buffer to '
                             'begin processing.')
    parser.add_argument('-s', '--size',
                        type=autoint,
                        default=-1,
                        help='The total number of bytes to process. Defaults '
                             'to size of supplied data.')

    return parser
