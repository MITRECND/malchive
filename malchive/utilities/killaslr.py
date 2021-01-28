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
import logging
import argparse
import pefile

__version__ = "1.0.0"
__author__ = "Jason Batchelor"

log = logging.getLogger(__name__)

# Reference:
# http://msdn.microsoft.com/en-us/library/windows/desktop/ms680339(v=vs.85).aspx
dynamicbase_flag = 0x0040


def patch_aslr(pe):
    """
    Disable ASLR protection from a binary.

    :param pefile.PE pe: A pe object passed from the pefile project.

    :return: List of stream containing the data.
    :rtype: pefile.PE
    """
    pe.OPTIONAL_HEADER.DllCharacteristics ^= dynamicbase_flag
    return pe


def initialize_parser():
    parser = argparse.ArgumentParser(
        description='Patch provided PE to disable ASLR. '
                    'Write new PE with \'noaslr\' prefix.')
    parser.add_argument('infile', metavar='FILE', nargs='*',
                        help='Full path to the file(s) to be processed.')
    parser.add_argument('-o', '--overwrite', action='store_true',
                        default=False,
                        help='Patch existing file instead of creating a '
                             'new one.')
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

    for fname in args.infile:

        basename = os.path.basename(fname)
        log.info('Patching %s...' % basename)

        if not os.path.isfile(fname):
            log.warning('Failed to find file %s. Skipping...' % fname)
            continue

        with open(fname, 'rb') as f:
            stream = f.read()

        try:
            pe = pefile.PE(data=stream)
        except pefile.PEFormatError:
            log.warning('%s not a pe, skipping...' % basename)
            continue

        if pe.OPTIONAL_HEADER.DllCharacteristics & dynamicbase_flag:
            pe = patch_aslr(pe)

            if args.overwrite:
                outname = basename
            else:
                outname = basename + '.noaslr'
            pe.write(outname)
            print('Patched file written as %s...' % outname)

        else:
            print('%s was not found to have ASLR enabled...' % basename)


if __name__ == '__main__':
    main()
