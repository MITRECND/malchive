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

import logging
import struct
import hashlib
import requests
from malchive.helpers import discovery
from string import ascii_letters, digits
from random import sample, random

__version__ = "1.0.0"
__author__ = "Jason Batchelor"

log = logging.getLogger(__name__)

MAX_PAYLOAD_SIZE = 200000


# tested using metasploit v4.17.15-dev-
class MeterpreterReverseShell(discovery.Discover):

    def tickle_socket(self, co, timeout):
        """
        Probe the server for data and make a determination based on
        send/recv traffic.
        """

        payload = bytearray()
        s = self.connect(co, timeout)

        # size of incoming payload
        data = s.recv(4)
        size = struct.unpack('I', data)[0]
        log.info('Response received! Waiting for %s byte payload'
                 '...' % size)

        if size > MAX_PAYLOAD_SIZE:
            log.info('Payload size exceeded maximum.')
            return co

        while len(payload) < size:
            data = s.recv(size)
            if not data:
                break
            payload += data

        if self.check_payload:
            co.details['payload'] = payload
            co.success = True

        return co

    def tickle_http(self, co, timeout):

        location = self.gen_msf_uri()
        url = f"{co.protocol}://{co.ip}:{co.port}/{location}"

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                          'AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/79.0.3945.117 Safari/537.36'
        }

        log.info('Making attempt using: %s' % url)
        resp = requests.get(url, allow_redirects=True,
                            headers=headers, timeout=timeout)

        if resp.status_code == 200:
            payload = resp.content
            if self.check_payload(payload):
                co.details['payload'] = payload
                co.success = True

        return co

    def checksum8(self, string: str) -> int:
        """
        Calculate the 8-bit checksum for the given string. Taken from:
            https://www.veil-framework.com/veil-framework-2-4-0-reverse-http/
        """
        return sum([ord(char) for char in string]) % 0x100

    def gen_msf_uri(self) -> str:
        """
        Generate a MSF compatible URI. Taken from:
            https://www.veil-framework.com/veil-framework-2-4-0-reverse-http/
        """
        charset = ascii_letters + digits
        msf_uri = ''
        for x in range(64):
            uri = ''.join(sample(charset, 3))
            r = ''.join(sorted(list(charset), key=lambda *args: random()))

            for char in r:
                # URI_CHECKSUM_INITW (Windows)
                if self.checksum8(uri + char) == 92:
                    msf_uri = uri + char
        return msf_uri

    def check_payload(self, payload):

        parameters = [
            b'core_channel_open',
            b'core_channel_write',
            b'core_channel_close',
            b'core_channel_read',
            b'core_channel_seek',
        ]

        if payload.startswith(b'MZ') and \
           all(p in payload for p in parameters):
            return True
        else:
            return False

    def write_payload(self, payload, directory='.'):
        """
        Write the retrieved payload to disk.
        """

        md5 = hashlib.md5(payload).hexdigest()
        fname = '%s/%s.msf' % (directory, md5)
        with open(fname, 'wb') as f:
            f.write(payload)
        log.info('%s written to disk!' % fname)


def initialize_parser():
    parser = discovery.generic_args()
    parser.add_argument('-w', '--write', action='store_true',
                        default=False,
                        help='Write retrieved meterpreter payloads to disk '
                             'using [MD5.msf] as the filename.')
    parser.add_argument('-t', '--target-directory', type=str, default='.',
                        help='Target directory to write files. Defaults to '
                             'executing directory.')
    return parser


def main():

    import os
    import sys

    p = initialize_parser()
    args = p.parse_args()

    root = logging.getLogger()
    logging.basicConfig()
    if args.verbose:
        root.setLevel(logging.DEBUG)
    else:
        root.setLevel(logging.WARNING)

    directory = args.target_directory
    if directory != '.':
        if not os.path.isdir(directory):
            log.error('Could not create %s. Exiting...'
                      % directory)
            sys.exit(2)

    d = MeterpreterReverseShell(
        ips=args.ipaddress,
        ports=args.port,
        domains=args.domain,
        timeout=args.timeout,
        protocols=args.protocol,
        )
    d.run()

    for co in d.results:
        if co.success:
            print('Successfully discovered candidate! [%s] %s:%s' %
                  (co.protocol, co.ip, co.port))
            if args.write and 'payload' in co.details.keys():
                d.write_payload(co.details['payload'], directory)


if __name__ == '__main__':
    main()
