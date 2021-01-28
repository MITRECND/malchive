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
import requests
from malchive.helpers import discovery

__version__ = "1.0.0"
__author__ = "First Last"

log = logging.getLogger(__name__)


class ExampleTemplate(discovery.Discover):

    def tickle_http(self, co, timeout):
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
        r = requests.get(url, headers=headers, timeout=timeout)

        if r.status_code == 200:
            co.success = True

        return co

    def tickle_socket(self, co, timeout=5):
        """
        Probe the server for data and make a determination based on
        send/recv traffic.
        """

        s = self.connect(co, timeout)

        data = s.recv(0x100)
        if len(data):
            # if we validated the response, great set success to true
            co.success = True
            # details is a dictionary where we can capture
            # any additional items of interest if desired
            co.details['size'] = len(data)
        else:
            log.info('Retrieved data did not match desired parameters.')

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
    d.run()

    for co in d.results:
        if co.success:
            print('Successfully discovered candidate! [%s] %s:%s' %
                  (co.protocol, co.ip, co.port))


if __name__ == '__main__':
    main()
