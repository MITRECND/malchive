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

import argparse
import pefile
import logging
import re
import base64
import zlib

__version__ = "1.0.0"
__author__ = "Jason Batchelor"

log = logging.getLogger(__name__)


class GetConfig:

    def __init__(self, buff):
        """
        Initialize decoder instance.

        :param bytes buff: The stream of bytes to be processed.
        """

        self.buff = buff
        self.elements = []

        try:
            pe = pefile.PE(data=self.buff)
            self.decode_config(pe)
        except pefile.PEFormatError:
            log.debug('Supplied file must be a valid PE!')

    def decode_config(self, pe):

        unicode_candidates = self.find_unicode()
        elements = self.find_decode_suspect_data(unicode_candidates)
        self.elements = elements

    def find_unicode(self, modifier=4):
        """
        Find unicode characters within supplied data.
        """
        wide = []
        matches = re.finditer(b'([\x20-\x7e]\x00){' +
                              str(modifier).encode('ascii') + b',}', self.buff)

        if matches:
            for m in matches:
                wide.append(m.group(0).decode('utf-16'))
        return wide

    def find_decode_suspect_data(self, candidates):
        """
        From a list of candidate strings, try to decode using b64 + DEFLATE.
        """
        elements = []
        # Reference: Seems to reliably detect with minimal FPs
        # https://github.com/ctxis/CAPE/blob/master/lib/cuckoo/common/office/olevba.py#L444
        b64_rex = re.compile(
            r'(?:[A-Za-z0-9+/]{4}){1,}(?:[A-Za-z0-9+/]{2}'
            r'[AEIMQUYcgkosw048]=|[A-Za-z0-9+/][AQgw]==)?'
        )

        for c in candidates:
            if b64_rex.match(c):
                try:
                    b64 = base64.b64decode(c, validate=True)
                    deflate = zlib.decompress(b64, -15)
                    e = deflate.decode('ascii')
                    log.info('Candidate found! %s' % c)
                    elements.append(e)
                except Exception:
                    pass

        return sorted(set(elements))


def initialize_parser():
    parser = argparse.ArgumentParser(
        description='Process candidate. Prints results in JSON format.')
    parser.add_argument('candidates', metavar='FILE',
                        nargs='*', help='candidate file(s).')
    parser.add_argument('-v', '--verbose', action='store_true',
                        default=False,
                        help='Output additional information when processing '
                             '(mostly for debugging purposes).')
    return parser


def main():
    import os
    import json
    import datetime
    import hashlib

    p = initialize_parser()
    args = p.parse_args()

    root = logging.getLogger()
    logging.basicConfig()
    if args.verbose:
        root.setLevel(logging.DEBUG)
    else:
        root.setLevel(logging.WARNING)

    # Iterate through list of files in bulk.
    for filename in args.candidates:

        log.info('Processing file %s...' % filename)

        if not os.path.isfile(filename):
            log.warning('Failed to find file %s' % filename)
            continue

        f = open(filename, 'rb')
        stream = f.read()

        try:
            pe = pefile.PE(data=stream)
            timestamp = datetime.datetime.utcfromtimestamp(
                pe.FILE_HEADER.TimeDateStamp)
        except pefile.PEFormatError:
            log.warning('%s not a pe, skipping...' % f.name)
            continue

        d = GetConfig(stream)

        config_dict = {
            'Compile Time': '%s UTC' % timestamp,
            'MD5': hashlib.md5(stream).hexdigest(),
            'Decoded Elements': d.elements,
        }

        try:
            print(json.dumps(config_dict, indent=4, sort_keys=False))
        except UnicodeDecodeError:
            log.warning('There was a Unicode decoding error when '
                        'processing %s' % os.path.basename(filename))
            continue


if __name__ == '__main__':
    main()
