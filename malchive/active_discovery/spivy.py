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
#
import asyncio
import logging
import struct
from malchive.helpers import discovery
from random import choice, randint
from string import digits
from async_timeout import timeout

__version__ = "2.0.0"
__author__ = "Jason Batchelor"

log = logging.getLogger(__name__)


class SecurePoisonIvy(discovery.Discover):

    def __init__(self,
                 key: str = None,
                 *args,
                 **kwargs):

        self.payload = self.craft_payload()
        # informed by observations of traffic, we fuzz here
        self.cookie_id = ''.join(
            [
                choice(digits)
                for i in range(0, 17)
            ])

        # informed by observations of traffic, we fuzz here again
        self.uri_string = ''.join(
            [
                choice(digits)
                for i in range(0, 16)
            ])

        super().__init__(*args, **kwargs)

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

        challenge_request = bytes(b'\x00' * 0x100)

        payload = \
            struct.pack('B', junk_size) + \
            junk_data + \
            struct.pack('B', (junk_size*2 & 0xff)) + \
            challenge_request

        return payload

    async def tickle_tcp(self, co):
        """
        Probe the server for data and make a determination based on
        request/response.
        """

        # SPIVY 'technically' just uses HTTP over a TCP socket and
        # does not have an 'Accept-Encoding' header.
        url = f"{co.protocol}://{co.ip}:{co.port}/{self.uri_string}"
        http_data = f"POST {url} HTTP/1.1\r\n" \
                    f"Cookie: id={self.cookie_id}\r\n" \
                    f"Content-Length: {str(len(self.payload))}\r\n" \
                    f"\r\n"

        http_request = http_data.encode('utf-8') + self.payload

        try:
            async with timeout(self.timeout):
                reader, writer = await asyncio.open_connection(co.ip, co.port)
                writer.write(http_request)
                await writer.drain()

                response = await reader.read(0x200)
                writer.close()
                await writer.wait_closed()

                if await self.eval_response(response):
                    co.success = True

        except asyncio.TimeoutError:
            log.debug('Failure: TimeoutError: %s:%s:%s' %
                      (co.protocol, co.ip, co.port))

        except ConnectionRefusedError:
            log.debug('Failure: ConnectionRefusedError: %s:%s:%s' %
                      (co.protocol, co.ip, co.port))

        except Exception as e:
            log.debug('General failure: %s: %s:%s:%s' %
                      (str(e), co.protocol, co.ip, co.port))

        return co

    async def eval_response(self, response):

        buff = bytearray(response)

        if len(buff) > 0x100:
            if self.validate_response(response):
                log.info('Positive match for SPIVY controller!')
                return True
            else:
                log.info('Retrieved data not an SPIVY challenge response.')
        else:
            log.info('Retrieved data too short for SPIVY response.')

        return False

    def validate_response(self, response):
        """
        We can just take the last 0x100 bytes from the challenge
        response and compare rather than parsing the packet.
        """
        crypted = response[-0x100:]
        # check that not all values are the same
        if all(v == crypted[0] for v in crypted):
            return False
        # return if chunks of 0x10 repeat
        return (len([True for i in range(0x10, len(crypted), 0x10)
                     if crypted[:0x10] == crypted[i:i+0x10]])) == 0xf


def initialize_parser():
    parser = discovery.generic_args()
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
        ips=args.ipaddress,
        ports=args.port,
        domains=args.domain,
        timeout=args.timeout,
        protocols=args.protocol,
        )

    comms = discovery.create_comms(
            d.protocols,
            d.ips,
            d.ports
            )

    results = []
    asyncio.run(d.run(comms, results))

    for co in results:
        if co.success:
            print('Successfully discovered candidate! [%s] %s:%s' %
                  (co.protocol, co.ip, co.port))


if __name__ == '__main__':
    main()
