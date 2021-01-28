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
import ssl
import socket
import json
import hashlib
from malchive.helpers import discovery

__version__ = "1.0.0"
__author__ = "Marcus Eddy"
__contributors__ = "Jason Batchelor"

log = logging.getLogger(__name__)


class SSLInfo(discovery.Discover):

    def tickle_socket(self, co, timeout):
        """
        Probe the server for data and make a determination based on
        send/recv traffic.
        """

        log.info('Checking: %s:%s' % (co.ip, co.port))
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
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

        co.details = {
            'Query': '%s:%s' % (co.ip, co.port),
            'MD5': thumb_md5,
            'SHA1': thumb_sha1,
            'SHA256': thumb_sha256,
        }

        co.success = True
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
    parser.add_argument('-v', '--verbose', action='store_true',
                        default=False,
                        help='Output additional information when processing '
                             '(mostly for debugging purposes).')

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

    d = SSLInfo(
        ips=args.ipaddress,
        ports=args.port,
        domains=args.domain,
        timeout=args.timeout,
        protocols=['tcp'],
    )
    d.run()

    for co in d.results:
        if co.success:
            jo = json.dumps(co.details, indent=4)
            print(jo)


if __name__ == '__main__':
    main()
