#!/usr/bin/env python
# -*- coding: utf-8 -*-
import aiohttp
import asyncio
import logging
import hashlib
from malchive.helpers import discovery
from malchive.decoders import cobaltstrike_payload
from string import ascii_letters, digits
from random import sample, randint
from async_timeout import timeout

__version__ = "1.0.0"

log = logging.getLogger(__name__)


# very similar to Meterpreter script, just validating CS beacon payloads...
class CobaltStrikeBeacon(discovery.Discover):

    max_payload_size = 300000

    def __init__(self,
                 *args,
                 **kwargs):
        self.location = self.gen_msf_uri()
        super().__init__(*args, **kwargs)

    async def tickle_http(self, co):

        beacon = bytearray()
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
                    beacon = await self.get_beacon(
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

        if len(beacon):
            co.payload = beacon
            co.success = True

        return co

    async def get_beacon(self, url, headers, session):

        decoded = bytearray()
        async with session.get(url,
                               headers=headers,
                               read_bufsize=self.max_payload_size,
                               verify_ssl=False
                               ) as resp:

            if 'content-length' not in resp.headers:
                return decoded

            if 'content-type' not in resp.headers:
                return decoded

            if int(resp.headers['content-length']) > self.max_payload_size:
                return decoded

            if resp.status == 200:
                payload = await resp.content.read(0x10)

                if not payload.isascii() and len(payload) != 0:
                    payload += await resp.content.read()
                else:
                    return decoded

                try:
                    decoded = self.check_payload(payload)
                except Exception as e:
                    log.warning('Failure encountered when checking payload '
                                'with %s. Error: %s' % (url, str(e)))
        return decoded

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

    def check_payload(self, payload):

        d = cobaltstrike_payload.ExtractIt(payload)
        return d.decoded_payload

    def write_payload(self, payload, directory='.'):
        """
        Write the retrieved payload to disk.
        """

        md5 = hashlib.md5(payload).hexdigest()
        fname = '%s/%s.beacon' % (directory, md5)
        with open(fname, 'wb') as f:
            f.write(payload)
        log.info('%s written to disk!' % fname)


def initialize_parser():
    parser = discovery.generic_args()
    parser.add_argument('-w', '--write', action='store_true',
                        default=False,
                        help='Write retrieved meterpreter payloads to disk '
                             'using [MD5.beacon] as the filename.')
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

    d = CobaltStrikeBeacon(
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
