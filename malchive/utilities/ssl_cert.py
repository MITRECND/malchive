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
# -----------------
#
import asyncio
import logging
import ssl
import json
import hashlib
from malchive.helpers import discovery
from async_timeout import timeout

__version__ = "2.1.0"
__author__ = "Marcus Eddy"
__contributors__ = "Jason Batchelor"

log = logging.getLogger(__name__)


class SSLInfo(discovery.Discover):

    def __init__(self,
                 sni_host: str = "",
                 *args,
                 **kwargs):

        self.sni_host: str = sni_host
        if len(self.sni_host):
            log.debug('Using SNI hostname: \'%s\'' % self.sni_host)
        super().__init__(*args, **kwargs)

    async def tickle_tcp(self, co):
        """
        Probe the server for data and make a determination based on
        send/recv traffic.
        """

        log.info('Checking: %s:%s' % (co.ip, co.port))

        try:
            async with timeout(self.timeout):
                reader, writer = await asyncio.open_connection(co.ip, co.port)
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.set_ciphers('DEFAULT:@SECLEVEL=1')
                await writer.start_tls(
                                       context,
                                       server_hostname=self.sni_host
                                      )

                obj = writer.get_extra_info('ssl_object')
                der_cert_bin = obj.getpeercert(True)

                meta = {
                    'Query': '%s:%s' % (co.ip, co.port),
                    'SNI': '%s' % self.sni_host,
                }

                co.details = meta
                co.payload = der_cert_bin
                co.success = True

        except asyncio.TimeoutError:
            log.debug('Failure: TimeoutError: %s:%s:%s' %
                      (co.protocol, co.ip, co.port))
        except ConnectionResetError:
            log.debug('Failure: ConnectionResetError: %s:%s:%s' %
                      (co.protocol, co.ip, co.port))
        except Exception as e:
            log.debug('General failure: %s: %s:%s:%s' %
                      (str(e), co.protocol, co.ip, co.port))

        return co


def initialize_parser():
    import argparse

    parser = argparse.ArgumentParser(
        description='Retrieve hashes of SSL certificates.')

    parser.add_argument('-i', '--ipaddress', nargs='*',
                        help='One or more IP addresses to scan. To provide a '
                             'range, use CIDR notation.')
    parser.add_argument('-d', '--domain', nargs='*',
                        help='One or more domains to scan.')
    parser.add_argument('-p', '--port', nargs='*',
                        help='Range of ports to test per host. May be '
                             'specified as a series of integers (80 443 8080)'
                             ', a range (80-9000), or both.')
    parser.add_argument('--timeout', nargs='?', default=5, type=int,
                        help='How long (in seconds) to wait before timeout '
                             'for each connection attempt. Defaults to five '
                             'seconds.')
    parser.add_argument('--sni-host', nargs='?', type=str,
                        default="",
                        help='Apply the given domain as an SNI parameter '
                        'for all domain related requests (when given). '
                        'The provided domain is used when initiating '
                        'a TLS/SSL handshake. This is required for some '
                        'providers hosting multiple TLS enabled IPs off a '
                        'single domain.')
    parser.add_argument('-w', '--write', action='store_true',
                        default=False,
                        help='Write retrieved DER to disk '
                             'using [MD5.der] as the filename.')
    parser.add_argument('-t', '--target-directory', type=str, default='.',
                        help='Target directory to write files. Defaults to '
                             'executing directory.')
    parser.add_argument('-v', '--verbose', action='store_true',
                        default=False,
                        help='Output additional information when processing '
                             '(mostly for debugging purposes).')

    return parser


def main():
    import sys
    import os

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

    d = SSLInfo(
        sni_host=args.sni_host,
        ips=args.ipaddress,
        ports=args.port,
        domains=args.domain,
        timeout=args.timeout,
        protocols=['tcp'],
        )

    comms = discovery.create_comms(
            d.protocols,
            d.ips,
            d.ports
            )

    results = []
    asyncio.run(d.run(comms, results))

    for co in results:
        if len(co.payload) > 0:
            thumb_sha256 = hashlib.sha256(co.payload).hexdigest()
            if co.success:
                success = {
                            'Cert Sha256': thumb_sha256,
                            'Details': co.details
                          }

                jo = json.dumps(success, indent=4)
                print(jo)
            if args.write:
                fname = '%s/%s.der' % (directory, thumb_sha256)
                with open(fname, 'wb') as f:
                    f.write(co.payload)
                log.info('%s written to disk!' % fname)


if __name__ == '__main__':
    main()
