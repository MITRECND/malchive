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
import camellia
import argparse
from malchive.helpers import discovery
from random import choice, randint
from string import digits

__version__ = "1.0.0"
__author__ = "Jason Batchelor"

log = logging.getLogger(__name__)


class SecurePoisonIvy(discovery.Discover):

    def __init__(self,
                 key: str = None,
                 *args,
                 **kwargs):

        self.key: str = ''
        self.parse_key(key)
        log.debug('Using supplied key: \'%s\'' % key)
        self.challenge_response = bytearray()
        super().__init__(*args, **kwargs)

    def parse_key(self, key):

        key_size = 32

        if len(key) > key_size:
            raise argparse.ArgumentError(
                        None,
                        'The supplied key is too long!'
                    )

        if len(key) == 0:
            raise argparse.ArgumentError(
                        None,
                        'Need to supply a key!'
                    )

        if len(key) < key_size:
            key += '\x00' * (key_size - len(key))

        self.key = key

    def craft_payload(self):
        """
        Craft an SPIVY packet mimicking the beginning of the challenge
        request/response chain. Save the expected response.
        """

        junk_size = randint(1, 16)

        junk_data = bytearray(
            [
                choice([i for i in range(0, 256)])
                for i in range(0, junk_size)
            ])

        challenge_request = bytes(
            [
                choice([i for i in range(0, 256)])
                for i in range(0, 256)
            ])

        payload = \
            struct.pack('B', junk_size) + \
            junk_data + \
            struct.pack('B', (junk_size*2 & 0xff)) + \
            challenge_request

        c = camellia.CamelliaCipher(bytes(self.key.encode('utf-8')),
                                    mode=camellia.MODE_ECB)
        self.challenge_response = c.encrypt(challenge_request)

        return payload

    def validate_response(self, response):
        """
        We can just take the last 0x100 bytes from the challenge
        response and compare rather than parsing the packet.
        """

        return self.challenge_response == response[-0x100:]

    def tickle_http(self, co, timeout=5):
        """
        Probe the server for data and make a determination based on
        request/response.
        """

        payload = self.craft_payload()

        # informed by observations of traffic, we fuzz here
        cookie_id = ''.join(
            [
                choice(digits)
                for i in range(0, 17)
            ])

        # informed by observations of traffic, we fuzz here again
        uri_string = ''.join(
            [
                choice(digits)
                for i in range(0, 16)
            ])

        url = f"{co.protocol}://{co.ip}:{co.port}/{uri_string}"
        http_data = f"POST {url} HTTP/1.1\r\n" \
                    f"Cookie: id={cookie_id}\r\n" \
                    f"Content-Length: {str(len(payload))}\r\n" \
                    f"\r\n"

        http_request = http_data.encode('utf-8') + payload

        # SPIVY 'technically' just uses HTTP over a TCP socket and
        # does not have an 'Accept-Encoding' header. Components of
        # the requests library force this downstream...
        s = self.connect(co, timeout)
        s.sendall(http_request)
        response = s.recv(512)

        if len(response) > 0x100:
            if self.validate_response(response):
                co.success = True
                log.info('Positive match for SPIVY controller!')
            else:
                log.info('Retrieved data not an SPIVY challenge response.')
        else:
            log.info('Retrieved data too short for SPIVY response.')

        return co

    def tickle_socket(self, co, timeout=5):
        """
        Probe the server for data and make a determination based on
        send/recv traffic.
        """

        s = self.connect(co, timeout)
        payload = self.craft_payload()
        s.send(payload)
        response = s.recv(512)

        if len(response) > 0x100:
            if self.validate_response(response):
                co.success = True
                log.info('Positive match for SPIVY controller!')
            else:
                log.info('Retrieved data not an SPIVY challenge response.')
        else:
            log.info('Retrieved data too short for SPIVY response.')

        return co


def initialize_parser():
    parser = discovery.generic_args()

    parser.add_argument('-k', '--key', default='admin',
                        help='The key used to crypt traffic. Default: admin')

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

    d = SecurePoisonIvy(
        key=args.key,
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


if __name__ == '__main__':
    main()
