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
import socket
import json
import hashlib
from malchive.helpers import discovery

__version__ = "2.0.0"
__author__ = "Marcus Eddy"
__contributors__ = "Jason Batchelor"

log = logging.getLogger(__name__)


class SSLInfo(discovery.Discover):

    # TODO: make async
    async def tickle_tcp(self, co):
        """
        Probe the server for data and make a determination based on
        send/recv traffic.
        """

        log.info('Checking: %s:%s' % (co.ip, co.port))
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        wrapped_s = ssl.wrap_socket(sock)

        try:
            wrapped_s.connect((co.ip, co.port))
        except ConnectionRefusedError:
            log.warning('No SSL info found!')
            return co

        der_cert_bin = wrapped_s.getpeercert(True)
        thumb_md5 = hashlib.md5(der_cert_bin).hexdigest()
        thumb_sha1 = hashlib.sha1(der_cert_bin).hexdigest()
        thumb_sha256 = hashlib.sha256(der_cert_bin).hexdigest()

        meta = {
            'Query': '%s:%s' % (co.ip, co.port),
            'MD5': thumb_md5,
            'SHA1': thumb_sha1,
            'SHA256': thumb_sha256,
        }

        co.details['meta'] = meta
        co.details['payload'] = der_cert_bin
        co.success = True
        return co

    def write_payload(self, payload, directory='.'):
        """
        Write the retrieved payload to disk.
        """

        sha256 = hashlib.sha256(payload).hexdigest()
        fname = '%s/%s.der' % (directory, sha256)
        with open(fname, 'wb') as f:
            f.write(payload)
        log.info('%s written to disk!' % fname)


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
        if co.success and 'meta' in co.details.keys():
            jo = json.dumps(co.details['meta'], indent=4)
            print(jo)
        if args.write and 'payload' in co.details.keys():
            d.write_payload(co.details['payload'], directory)


if __name__ == '__main__':
    main()
