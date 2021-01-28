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
import base64
import logging
import argparse
import hashlib
from tabulate import tabulate

__version__ = "1.0.0"
__author__ = "Jason Batchelor"

log = logging.getLogger(__name__)


def get_b64_encoded_streams(buff, modifier=0):
    """
    Decode embedded Base64 blobs.

    :param bytes buff: Encoded candidate stream to search.
    :return: Base64 decoded results.
    :rtype: list
    """

    b64_blobs = []
    # Reference: Seems to reliably detect with minimal FPs
    # https://github.com/ctxis/CAPE/blob/master/lib/cuckoo/common/office/olevba.py#L444
    b64_rex = re.compile(
        rb'(?:[A-Za-z0-9+/]{4}){1,}(?:[A-Za-z0-9+/]{2}'
        rb'[AEIMQUYcgkosw048]=|[A-Za-z0-9+/][AQgw]==)?'
    )

    for m in b64_rex.findall(buff):
        if len(m) < modifier:
            continue
        log.debug('Possible Base64 match... %s bytes' % len(m))
        try:
            d = base64.b64decode(m, validate=True)
            b64_blobs.append(d)
        except Exception:
            log.debug('Error when trying to decode Base64 content.')
            pass

    return b64_blobs


def initialize_parser():
    parser = argparse.ArgumentParser(
        description='Parse provided files and extract and decode candidate '
                    'Base64 data streams.')
    parser.add_argument('infile', metavar='FILE', nargs='*',
                        help='Full path to the file(s) to be processed.')
    parser.add_argument('-v', '--verbose', action='store_true',
                        default=False,
                        help='Output additional information when processing '
                             '(mostly for debugging purposes).')
    parser.add_argument('-s', '--suppress-write', action='store_true',
                        help='Prevent results from being written to disk. '
                             'Opting instead for just a table view of the '
                             'results.')
    parser.add_argument('-t', '--target-directory', type=str, default='.',
                        help='Target directory to write files. Defaults to '
                             'executing directory.')
    parser.add_argument('-m', '--modifier', type=int, default=500,
                        help='Amount of Base64 characters encountered before '
                             'a string is recognized (default is 500).')

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

    b64_content = []
    target_dir = args.target_directory
    for fname in args.infile:

        basename = os.path.basename(fname)

        if not os.path.isfile(fname):
            log.warning('Failed to find file %s. Skipping...' % fname)
            continue

        with open(fname, 'rb') as f:
            stream = f.read()

        decodes = get_b64_encoded_streams(stream, args.modifier)

        log.info('Found %s candiates in %s...' % (len(decodes), basename))

        if not args.suppress_write and target_dir != '.':
            log.info('Writing to directory: %s' % target_dir)

        for d in decodes:
            _md5 = hashlib.md5(d).hexdigest()
            b64_content.append((basename, len(d), _md5))

            if not args.suppress_write:
                if target_dir != '.':
                    try:
                        os.makedirs(target_dir)
                    except OSError:
                        if not os.path.isdir(target_dir):
                            log.error('Could not create %s. Exiting...'
                                      % target_dir)
                            sys.exit(2)
                with open('%s/%s' % (target_dir, _md5), 'wb') as f:
                    f.write(d)

    if len(b64_content) > 0:
        print(tabulate(b64_content,
                       headers=["Filename", "Size", "MD5"],
                       tablefmt="grid"))


if __name__ == '__main__':
    main()
