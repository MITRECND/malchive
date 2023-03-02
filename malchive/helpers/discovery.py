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
import socket
import logging
import argparse
import netaddr
from typing import List
from validators import domain as valid_domain
from async_timeout import timeout

__version__ = "2.0.0"
__author__ = "Jason Batchelor"

log = logging.getLogger(__name__)


class CommObject():
    """
    Communication object.
    """

    def __init__(
        self,
        ip: str,
        port: int,
        protocol: str,
        success: bool = False,
        payload: bytearray = bytearray(),
        details: dict = {},
        **kwargs
    ) -> None:

        self.success = success
        self.ip = ip
        self.port = port
        self.protocol = protocol
        self.payload = payload
        self.details = details


class Discover():
    """
    Discover object.
    """

    supported_protocols: list = ['http', 'https', 'tcp', 'udp', 'all']

    def __init__(
        self,
        ips: list,
        ports: list,
        domains: list,
        timeout: int,
        protocols: list,
        max_semaphore: int = 5000,
        **kwargs
    ) -> None:

        self.ips: List[str] = []
        self.ports: List[int] = []

        self.parse_ips(ips)
        self.parse_ports(ports)
        self.parse_domains(domains)
        self.timeout = timeout
        self.protocols = self.parse_protocols(protocols)
        self.max_semaphore = max_semaphore

    async def run(self, comms, results):

        tasks = []
        # Max number of concurrent tasks for asyncio, set with caution
        sem = asyncio.Semaphore(self.max_semaphore)

        total_tasks = get_comms_count(self.protocols, self.ips, self.ports)
        if total_tasks == 0:
            log.warning('No tasks to perform!')
            return

        try:
            for co in comms:
                tasks.append(asyncio.ensure_future(self.bound_tickle(sem, co)))

            log.debug('Awaiting %s tasks...' % total_tasks)
            counter = 0
            for fut in asyncio.as_completed(tasks):
                results.append(await fut)
                counter += 1
                if counter % 100 == 0:
                    log.debug('%s/%s tasks complete.' % (counter, total_tasks))
            log.debug('All tasks complete.')

        except Exception as e:
            log.debug('Critical Failure: %s' % str(e))

    async def bound_tickle(self, sem, co):
        async with sem:
            if co.protocol.startswith('http'):
                return await self.tickle_http(co)
            elif co.protocol == 'udp':
                return await self.tickle_udp(co)
            else:
                return await self.tickle_tcp(co)

    async def tickle_http(self, co):
        """
        Should be overridden.
        Probe the server for data and make a determination based on
        request/response traffic.
        """
        try:
            # including in the overridden function to emphasize
            # the importance of setting a task timer
            async with timeout(self.timeout):
                log.warning('HTTP(s) is not supported! [%s] %s:%s' %
                            (co.protocol, co.ip, co.port))
        except asyncio.TimeoutError:
            log.debug('Failure: TimeoutError: %s:%s:%s' %
                      (co.protocol, co.ip, co.port))

        return co

    async def tickle_udp(self, co):
        """
        Should be overridden.
        Probe the server for data and make a determination based on
        send/recv traffic.
        """
        try:
            async with timeout(self.timeout):
                log.warning('UDP is not supported! [%s] %s:%s' %
                            (co.protocol, co.ip, co.port))
        except asyncio.TimeoutError:
            log.debug('Failure: TimeoutError: %s:%s:%s' %
                      (co.protocol, co.ip, co.port))

        return co

    async def tickle_tcp(self, co):
        """
        Should be overridden.
        Probe the server for data and make a determination based on
        send/recv traffic.
        """
        try:
            async with timeout(self.timeout):
                log.warning('TCP is not supported! [%s] %s:%s' %
                            (co.protocol, co.ip, co.port))
        except asyncio.TimeoutError:
            log.debug('Failure: TimeoutError: %s:%s:%s' %
                      (co.protocol, co.ip, co.port))

        return co

    def parse_protocols(self, protocols):

        protosl = []
        if not protocols:
            raise argparse.ArgumentError(
                        None,
                        'A protocol argument must be supplied.'
                    )

        if not set(protocols).issubset(self.supported_protocols):
            raise argparse.ArgumentError(
                        None,
                        'You must supply a supported protocol.'
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

        if not ips:
            self.ips = []
            return

        for ip in ips:

            try:
                ipaddr = netaddr.IPNetwork(ip)
                if ipaddr.version == 4:
                    self.ips.append(ipaddr)
            except netaddr.core.AddrFormatError as e:
                log.error('There was a problem processing IP address input '
                          'using %s. Error: %s. Skipping...' % (ip, e))
                continue

    def parse_domains(self, domains):

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

            for ip in ipaddrlist:
                try:
                    ipaddr = netaddr.IPNetwork(ip)
                    if ipaddr.version == 4:
                        self.ips.append(netaddr.IPNetwork(ipaddr))
                except netaddr.core.AddrFormatError as e:
                    log.error('There was a problem processing IP address '
                              'input using %s. Error: %s. Skipping...'
                              % (ip, e))
                    continue


def get_comms_count(protocols, ips, ports):
    """
    Simply return how many comms objects there will be.
    """

    ipsum = 0
    for i in ips:
        if i.version == 4:
            if i.size >= 4:
                ipsum += netaddr.IPRange(i.first + 1, i.last - 1).size
            else:
                ipsum += netaddr.IPRange(i.first, i.last).size

    return len(protocols) * ipsum * len(ports)


def create_comms(protocols, ipnet, ports):
    """
    Create comm objects for each attempt.
    """

    for proto in protocols:
        for ipaddr in ipnet:
            for ip in ipaddr.iter_hosts():
                for port in ports:
                    yield CommObject(ip=str(ip), port=port,
                                     protocol=proto)


def generic_args(info='Scan for candidate controllers.'):

    parser = argparse.ArgumentParser(
        description=info)

    parser.add_argument('-i', '--ipaddress', nargs='*',
                        help='One or more IPv4 addresses to scan. To '
                             'provide a range, use CIDR notation.')
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
