#!/usr/bin/env python
# -*- coding: utf-8 -*-
import aiohttp
import asyncio
import logging
from malchive.helpers import discovery
from async_timeout import timeout

__version__ = "1.0.0"

log = logging.getLogger(__name__)


class ShadowPadController(discovery.Discover):

    # Reference: SASCon - https://youtu.be/YCwyc6SctYs?t=1360
    fake_not_found = b'Page not found\x0d\x0a'

    async def tickle_http(self, co):

        verdict = False
        url = f"{co.protocol}://{co.ip}:{co.port}/"

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
                    verdict = await self.get_resp_verdict(
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

        if verdict:
            co.success = True

        return co

    async def get_resp_verdict(self, url, headers, session):

        async with session.get(url,
                               headers=headers,
                               read_bufsize=len(self.fake_not_found),
                               verify_ssl=False
                               ) as resp:

            # Ensure the headers we care about exist
            if 'content-length' not in resp.headers or \
               'Server' not in resp.headers:
                log.info('Response headers did not have content-length.')
                return False

            # Check if the length of our content
            if int(resp.headers['content-length']) != len(self.fake_not_found):
                log.info('Response content size mismatch. %s bytes'
                         % resp.headers['content-length'])
                return False

            # Check content, status code, and server name
            if resp.status == 404 and \
               resp.headers['server'] == 'nginx':
                payload = await resp.content.read()
                if payload == self.fake_not_found:
                    return True
        return False


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

    d = ShadowPadController(
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
