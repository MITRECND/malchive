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
import aiohttp
import asyncio
from async_timeout import timeout
from malchive.helpers import discovery

__version__ = "2.0.0"
__author__ = "First Last"

log = logging.getLogger(__name__)


class ExampleTemplate(discovery.Discover):

    def __init__(self,
                 *args,
                 **kwargs):
        # any overrides, or busy work that needs to be done
        # pre-scan can be done here...
        self.magic_request = b'GET / HTTP/1.1\r\n\r\n'
        self.magic_response = b'HTTP/1.1 200 OK'

        super().__init__(*args, **kwargs)

    async def tickle_http(self, co):
        """
        Probe the server for data and make a determination based on
        request/response.
        """

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64) '
                          'AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/34.0.1847.116 Safari/537.36'
        }

        url = f"{co.protocol}://{co.ip}:{co.port}"

        log.info('Making attempt using: %s' % url)

        conn = aiohttp.TCPConnector()
        async with aiohttp.ClientSession(connector=conn) as session:
            try:
                async with timeout(self.timeout):
                    async with session.get(url,
                                           headers=headers,
                                           read_bufsize=10000,
                                           verify_ssl=False
                                           ) as resp:
                        if resp.status == 200:
                            co.success = True

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

        return co

    async def tickle_tcp(self, co):
        """
        Probe the server for data and make a determination based on
        send/recv traffic.
        """

        try:
            async with timeout(self.timeout):
                reader, writer = await asyncio.open_connection(co.ip, co.port)

                writer.write(self.magic_request)
                data = await reader.read(len(self.magic_response))

                if data == self.magic_response:
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

    d = ExampleTemplate(
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
