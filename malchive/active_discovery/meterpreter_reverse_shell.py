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
import aiohttp
import asyncio
import logging
import struct
import hashlib
from malchive.helpers import discovery
from string import ascii_letters, digits
from random import sample, randint
from async_timeout import timeout

__version__ = "2.0.0"
__author__ = "Jason Batchelor"

log = logging.getLogger(__name__)


# Tested using metasploit v6.0.47 and v4.17.15.
#
# Designed to look for cleartext transmission of the following...
# * windows/meterpreter/reverse_tcp
# * windows/meterpreter/reverse_http
# * windows/meterpreter/reverse_https
class MeterpreterReverseShell(discovery.Discover):

    max_payload_size = 200000

    def __init__(self,
                 *args,
                 **kwargs):
        self.location = self.gen_msf_uri()
        super().__init__(*args, **kwargs)

    async def tickle_tcp(self, co):

        response = b''

        try:
            async with timeout(self.timeout):
                reader, writer = await asyncio.open_connection(co.ip, co.port)

                # size of incoming payload
                data = await reader.read(0x4)
                size = struct.unpack('I', data)[0]
                log.info('Response received! Waiting for %s byte payload'
                         '...' % size)

                if size > self.max_payload_size:
                    log.info('Payload size exceeded maximum.')
                    return co

                response = await reader.read(size)

                if response.startswith(b'MZ'):
                    co.payload = response
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

    async def tickle_http(self, co):

        stage_two = b''
        url = f"{co.protocol}://{co.ip}:{co.port}/{self.location}"

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                          'AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/79.0.3945.117 Safari/537.36'
        }

        log.info('Making attempt using: %s' % url)

        conn = aiohttp.TCPConnector()
        async with aiohttp.ClientSession(connector=conn) as session:
            try:
                async with timeout(self.timeout):
                    stage_two = await self.get_stage_two(
                                                         url,
                                                         headers,
                                                         session
                                                        )

            except aiohttp.ClientConnectionError as e:
                log.debug('Failure: ClientConnectionError %s: %s:%s:%s' %
                          (str(e), co.protocol, co.ip, co.port))

            except asyncio.TimeoutError:
                log.debug('Failure: TimeoutError: %s:%s:%s' %
                          (co.protocol, co.ip, co.port))

            except aiohttp.TooManyRedirects:
                log.debug('Failure: TooManyRedirects: %s:%s:%s' %
                          (co.protocol, co.ip, co.port))

            except Exception as e:
                log.debug('General failure: %s: %s:%s:%s' %
                          (str(e), co.protocol, co.ip, co.port))

        if len(stage_two):
            co.payload = stage_two
            co.success = True

        return co

    async def get_stage_two(self, url, headers, session):

        payload = b''
        async with session.get(url,
                               headers=headers,
                               read_bufsize=self.max_payload_size,
                               verify_ssl=False
                               ) as resp:

            if resp.status_code == 200:
                payload = await resp.content.read(0x2)
                if payload.startswith(b'MZ'):
                    payload += resp.content.read()
                else:
                    return payload

                if len(payload) > self.max_payload_size:
                    log.info('Payload size exceeded maximum.')

        return payload

    def checksum8(self, string: str) -> int:
        """
        Calculate the 8-bit checksum for the given string. Taken from:
            https://www.veil-framework.com/veil-framework-2-4-0-reverse-http/
        """
        return sum([ord(char) for char in string]) % 0x100

    def gen_msf_uri(self, MIN_URI_LENGTH=26) -> str:
        """
            Generate a MSF compatible URI. Taken from:
            https://www.veil-framework.com/veil-framework-2-4-0-reverse-http/
        """
        charset = ascii_letters + digits
        msf_uri = ''

        while True:
            uri = ''.join(sample(charset, MIN_URI_LENGTH))
            r = uri[randint(0, len(uri)-1)]

            # URI_CHECKSUM_INITW (Windows)
            if self.checksum8(uri + r) == 92:
                msf_uri = uri + r
                break

        return msf_uri

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
            if args.write and len(co.payload) != 0:
                d.write_payload(co.payload, directory)


if __name__ == '__main__':
    main()
