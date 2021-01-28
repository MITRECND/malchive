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
import re
import sys
import struct
import logging
import argparse
import hashlib
from tabulate import tabulate

__version__ = "1.0.0"
__author__ = "Jason Batchelor"

log = logging.getLogger(__name__)


def getcab(buff):
    """
    Return a dictionary of information about cabs such as; size, offset, MD5,
    and the cab buffer.

    :param bytes buff: File to look for cabs.

    :return: Dictionary containing cab information.
    :rtype: dict
    """

    hidden_cab_regex = b'(.{4})\x00\x00\x00\x00(.{4})\x00\x00\x00\x00' \
                       b'(.{4})\x00\x00\x00\x00\x03\x01' \
                       b'(.{2})(.{2}).\x00.{2}\x00\x00'
    matches = re.finditer(hidden_cab_regex, buff, re.DOTALL)
    cabs = {}
    counter = 0

    for m in matches:
        cabsize = struct.unpack('<I', m.group(2))[0]
        if struct.unpack('<I', m.group(1))[0] != 0x4d534346 and \
                (0 < cabsize < len(buff)) and \
                struct.unpack('<I', m.group(3))[0] > 0 and \
                struct.unpack('<H', m.group(4))[0] > 0 and \
                struct.unpack('<H', m.group(5))[0] > 0:
            start = m.start(0) + 4
            cab = b'\x4d\x53\x43\x46' + buff[start:start + (cabsize - 4)]
            cabs['Object_%s' % counter] = {'buff': cab,
                                           'size': cabsize,
                                           'offset': m.start(0) + 4,
                                           'md5': hashlib.md5(cab).hexdigest()
                                           }
            counter += 1

    return cabs


def initialize_parser():
    parser = argparse.ArgumentParser(
        description='Search for hidden CAB files inside binary.')
    parser.add_argument('infile', metavar='FILE', nargs='*',
                        help='Full path to the file to be processed.')
    parser.add_argument('-t', '--target-directory', type=str, default='.',
                        help='Target directory to write files. \
                        Defaults to executing directory.')
    parser.add_argument('-s', '--suppress-write', action='store_true',
                        help='Prevent results from being written to '
                             'disk. Opting instead for just a table view '
                             'of the results.')
    parser.add_argument('-v', '--verbose', action='store_true', default=False,
                        help='Output additional information when processing '
                             '(mostly for debugging purposes).')
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

    if len(args.infile) == 0:
        p.print_help()
        sys.exit(2)

    target_dir = args.target_directory
    for fname in args.infile:
        results = []
        cabinfo = {}

        basename = os.path.basename(fname)

        if not os.path.isfile(fname):
            log.warning('Failed to find file %s. Skipping...' % fname)
            continue

        with open(fname, 'rb') as f:
            data = f.read()

        cabinfo = getcab(data)

        print('Found %s hidden cab(s) in %s...' % (len(cabinfo), basename))
        if not args.suppress_write and target_dir != '.':
            log.info('Writing to directory: %s' % target_dir)

        for k, v in list(cabinfo.items()):
            results.append((v['md5'], v['size'], v['offset']))

            if not args.suppress_write:
                if target_dir != '.':
                    try:
                        os.makedirs(target_dir)
                    except OSError:
                        if not os.path.isdir(target_dir):
                            log.error('Could not create %s. Exiting...'
                                      % target_dir)
                            sys.exit(2)
                with open('%s/%s' % (target_dir, v['md5']), 'wb') as f:
                    f.write(v['buff'])

        if len(results) > 0:
            print(tabulate(results,
                           headers=["MD5", "Size", "Offset"],
                           tablefmt="grid"))


if __name__ == '__main__':
    main()
