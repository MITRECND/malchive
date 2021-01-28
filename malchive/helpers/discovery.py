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

import socket
import logging
import argparse
import ipaddress
from typing import List
from validators import domain as valid_domain

__version__ = "1.0.0"
__author__ = "Jason Batchelor"

log = logging.getLogger(__name__)


class CommObject():
    """
    Communication object.
    """

    def __init__(
        self,
        success: bool = False,
        ip: str = None,
        port: int = None,
        protocol: str = None,
        details: dict = {},
        **kwargs
    ):

        self.success = success
        self.ip = ip
        self.port = port
        self.protocol = protocol
        self.details = details


class Discover():
    """
    Discover object.
    """

    results: list = []
    supported_protocols: list = ['http', 'https', 'tcp', 'udp', 'all']

    def __init__(
        self,
        ips: list = None,
        ports: list = None,
        domains: list = None,
        timeout: int = 5,
        protocols: list = None,
        **kwargs
    ):

        self.ips: List[str] = []
        self.ports: List[int] = []
        self.comms: List[CommObject] = []

        self.parse_ips(ips)
        self.parse_ports(ports)
        self.parse_domains(domains)

        self.ips = sorted(set(self.ips))
        self.protocols = self.parse_protocols(protocols)

        self.comms = self.create_comms()
        self.timeout = timeout

    def connect(self, co, timeout):
        """
        See if you can connect.
        """

        if co.protocol == 'udp':
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        s.settimeout(timeout)
        s.connect((co.ip, co.port))

        return s

    def run(self):

        for co in self.comms:

            try:
                if co.protocol.startswith('http'):
                    co = self.tickle_http(co, self.timeout)
                else:
                    co = self.tickle_socket(co, self.timeout)
            except Exception as e:
                log.debug('Failure: %s: %s:%s:%s' %
                          (e, co.protocol, co.ip, co.port))

            self.results.append(co)

    def tickle_http(self, co, timeout):
        """
        Should be overridden.
        Probe the server for data and make a determination based on
        request/response traffic.
        """

        log.warning('HTTP is not supported! [%s] %s:%s' %
                    (co.protocol, co.ip, co.port))

        return co

    def tickle_socket(self, co, timeout):
        """
        Should be overridden.
        Probe the server for data and make a determination based on
        send/recv traffic.
        """

        log.warning('TCP/UDP is not supported! [%s] %s:%s' %
                    (co.protocol, co.ip, co.port))
        return co

    def create_comms(self):
        """
        Create comm objects for each attempt.
        """

        commsl = []
        for proto in self.protocols:
            for ip in self.ips:
                for port in self.ports:
                    commsl.append(CommObject(ip=ip, port=port,
                                             protocol=proto))

        return commsl

    def parse_protocols(self, protocols):

        protosl = []
        if not protocols:
            self.ports = protosl
            raise argparse.ArgumentError(
                        None,
                        'A protocol argument must be supplied.'
                    )

        protosl = sorted(set(protocols))
        if 'all' in protosl:
            protosl = self.supported_protocols
            protosl.remove('all')
        return protosl

    def parse_ports(self, ports):

        portsl = []

        if not ports:
            self.ports = portsl
            raise argparse.ArgumentError(
                        None,
                        'A port argument must be supplied.'
                    )

        for entry in ports:

            if "-" in entry and entry.count('-') == 1:
                start, end = entry.split("-")

                try:
                    start = int(start)
                    end = int(end)
                except ValueError:
                    raise argparse.ArgumentTypeError(
                        'Error when trying to convert range values %s to int.'
                        % entry)

                if start > end:
                    raise argparse.ArgumentError(
                        None,
                        'Start value must be more than end value...'
                    )

                if (start >= 0) and (end <= 65535):
                    portsl.extend(range(start, end))
                else:
                    raise argparse.ArgumentError(
                        None,
                        'Port value must be between 0-65535.'
                    )
            else:
                try:
                    v = int(entry)
                except ValueError:
                    raise argparse.ArgumentTypeError(
                        'Error when trying to convert value %s to int.'
                        % entry)
                if v <= 65535:
                    portsl.append(v)
                else:
                    raise argparse.ArgumentError(
                        None,
                        'Port value must be between 0-65535'
                    )

        self.ports = portsl

    def parse_ips(self, ips):

        ipsl = []

        if not ips:
            self.ips = ipsl
            return

        for ip in ips:

            cidr = True if '/' in ip else False

            if cidr:
                try:
                    ipsl.extend([str(i)
                                 for i in ipaddress.ip_network(ip).hosts()])
                except ValueError as e:
                    log.error(
                        'There was a problem processing IP address input '
                        'using %s. Error: %s. Skipping...' % (ip, e))
                    continue
            else:
                try:
                    ipsl.append(str(ipaddress.ip_address(ip)))
                except ValueError as e:
                    log.error(
                        'There was a problem processing IP address input '
                        'using %s. Error: %s. Skipping...' % (ip, e))
                    continue

        self.ips.extend(ipsl)

    def parse_domains(self, domains):

        ipsl = []

        if not domains:
            return

        for d in domains:

            if not valid_domain(d):
                log.error('There was a problem validating domain input '
                          'using %s. Skipping...' % d)
                continue

            # note this does NOT support ipv6 translation
            try:
                hostname, aliaslist, ipaddrlist = socket.gethostbyname_ex(d)
            except socket.gaierror:
                log.error('Could not resolve domain %s. Skipping...' % d)
                continue

            ipsl.extend(ipaddrlist)

        self.ips.extend(ipsl)


def generic_args(info='Scan for candidate controllers.'):

    parser = argparse.ArgumentParser(
        description=info)

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
    parser.add_argument('--protocol', nargs='*',
                        choices=Discover.supported_protocols,
                        help='Choose the protocol(s) for the request.')
    parser.add_argument('-v', '--verbose', action='store_true',
                        default=False,
                        help='Output additional information when processing '
                             '(mostly for debugging purposes).')
    return parser
