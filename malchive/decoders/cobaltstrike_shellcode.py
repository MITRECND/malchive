#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2020 The MITRE Corporation. All rights reserved.
#
# MITRE Proprietary - Internal Use Only
# TLP:Red and NDA Restrictions may apply.
# For redistribution, specific permission is needed.
#   Contact: infosec@mitre.org
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

import argparse
import logging

__version__ = "1.0.0"
__author__ = "Marcus Eddy"


log = logging.getLogger(__name__)


class ExtractIt:

    def __init__(self, buff, filename):
        """
        Initialize decoder instance.

        :param bytes buff: The stream of bytes to be processed.
        """

        self.buff = buff
        self.decoded_payload = ''
        self.decoded_payload_filename = filename+'.decoded'
        try:
            self.payload = self.decode_payload(self.buff)
        except Exception as e:
            log.warning("Error!")
            log.info(str(e))

    def decode_payload(self, buff):
        """
        Find Xor Key and Decode Payload

        :param bytes buff: file input

        :rtype: string
        """
        log.info("Looking for Marker...")
        ff_start = buff.find(b'\x00\x00\x00\x00\xfc\xe8')
        if ff_start > 1:
            log.info('FC E8 Marker Found!')
            log.info(ff_start + 4)

            buff = buff[ff_start+4:]

            dec = bytearray(buff[0x4:])
            key = bytearray(buff[:0x4])
            log.info('Start Key: %s' % key)

            self.decoded_payload = self.sliding_xor(key, dec)
            if self.decoded_payload[:100].find(
                    b'\x54\x68\x69\x73\x20\x70\x72\x6f\x67\x72\x61\x6d'):
                log.info('Writing File to Disk')
                fh = open(self.decoded_payload_filename, 'wb')
                fh.write(self.decoded_payload)
                fh.close()
        else:
            log.info('No Marker found!')

    @staticmethod
    def sliding_xor(key, dec):
        for i in range(0, len(dec), 4):
            for k in range(0, len(key)):
                dec[i+k] ^= key[k]
                key[k] ^= dec[i+k]
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
    return parser


def main():
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

    for filename in args.candidates:

        log.info('Processing file %s...' % filename)

        if not os.path.isfile(filename):
            log.warning('Failed to find file %s' % filename)
            continue

        f = open(filename, 'rb')
        stream = f.read()

        d = ExtractIt(stream, filename)
        
        if len(d.decoded_payload) == 0:
            log.warning('Decryption failure. Skipping %s...' % filename)
            continue

        config_dict = {
            'Input MD5': hashlib.md5(stream).hexdigest(),
            'Input': filename,
            'Output MD5': hashlib.md5(d.decoded_payload).hexdigest(),
            'Output': d.decoded_payload_filename,
        }

        try:
            print((json.dumps(config_dict, indent=4, sort_keys=False)))
        except UnicodeDecodeError:
            log.warning('There was a Unicode decoding error when '
                        'processing %s' % os.path.basename(filename))
            continue


if __name__ == '__main__':
    main()
