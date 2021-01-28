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

import re
import tld
import logging
import argparse
import validators
from struct import unpack
from operator import itemgetter

__version__ = "1.1.0"
__author__ = "Jason Batchelor"
__contributors__ = "Marcus Eddy"

log = logging.getLogger(__name__)


class Superstrings:
    """
    Using supplied parameters, iterate over buffer to recover
    strings of interest.
    """

    def __init__(self, buff, offset=0, size=-1, stringmodifier=3):
        """
        Initialize generic instance.

        :param bytes buff: The stream of bytes to be processed.
        :param int,optional offset: Amount of bytes to skip into supplied
        buffer before processing. Defaults to zero.
        :param int,optional size: Amount of bytes to process. Defaults to
        end of supplied buffer.
        :param int,optional stringmodifier: number of characters recovered
        before item is considered a string
        """

        self.buff = buff

        if offset > len(buff) or offset < 0:
            raise IndexError('Invalid start position supplied. '
                             'Exceeds range of supplied buffer.')
        self.offset = offset

        if size == -1:
            total_size = len(buff)
        else:
            total_size = size + offset
            if total_size > len(buff) or total_size < offset:
                raise IndexError('Invalid size position supplied. '
                                 'Exceeds range of supplied parameters.')
        self.total_size = total_size

        self.stringmodifier = stringmodifier

    def find_ascii(self):
        """
        Find ascii printables within supplied data.

        :return: list of tuples with parameters of hex offset, type, string
        :rtype: list
        """
        ascii = []
        matches = re.finditer(b'([\x20-\x7e]{' + str(
            self.stringmodifier).encode('ascii') + b',})',
                              self.buff[self.offset:self.total_size])
        if matches:
            for m in matches:
                ascii.append((m.start(0), '(ascii)', m.group(0)))

        return ascii

    # TODO: What about foreign character matches?
    # Right now its just english unicode ascii ranges...
    def find_unicode(self):
        """
        Find unicode characters within supplied data.

        :return: list of tuples with parameters of hex offset, type, string
        :rtype: list
        """
        wide = []
        matches = re.finditer(b'([\x20-\x7e]\x00){' + str(
            self.stringmodifier).encode('ascii') + b',}',
                              self.buff[self.offset:self.total_size])
        if matches:
            for m in matches:
                wide.append((m.start(0), '(unicode)',
                             m.group(0).replace(b'\0', b'')))

        return wide

    def find_stack_strings(self):
        """
        Find stack string characters within supplied data.

        :return: list of tuples with parameters of hex offset, type, string
        :rtype: list
        """

        # ascii printables
        # echo -ne '\xc6\x45\x00\x4d' | ndisasm -u -
        # 00000000  C645004D          mov byte [ebp+0x0],0x4d
        #
        # echo -ne '\xc6\x44\x24\x24\x4d' | ndisasm -u -
        # 00000000  C64424244D        mov byte [esp+0x24],0x4d
        #
        # echo -ne '\xc6\x85\x44\x00\x00\x00\x4d' | ndisasm -u -
        # 00000000  C685440000004D    mov byte [ebp+0x44],0x4d
        #
        # echo -ne '\xc6\x05\x44\x00\x00\x00\x4d' | ndisasm -u -
        # 00000000  C605440000004D    mov byte [0x44],0x4d
        #
        # unicode printables
        # echo -ne '\xc7\x44\x24\x50\x02\x7f\x00\x00' | ndisasm -u -
        # 00000000  C7442450027F0000  mov dword [esp+0x50],0x7f02
        #
        # stack 16
        # echo -ne '\x66\xC7\x45\xC8\x31\x30' | ndisasm -u -
        # 00000000  66C745C83130      mov word [ebp-0x38],0x3031
        #
        # stack 32
        # echo -ne '\xC7\x45\xF0\x73\x74\x6F\x6D' | ndisasm -u -
        # 00000000  C745F073746F6D    mov dword [ebp-0x10],0x6d6f7473
        #

        stack_regex = [b'\xc6\x45.([\x20-\x7e])',
                       b'\xc6\x44.{2}([\x20-\x7e])',
                       b'\xc6\x85.{4}([\x20-\x7e])',
                       b'\xc6\x05.{4}([\x20-\x7e])',
                       b'\xc7\x44.{2}([\x00-\xd7][\x20-\xff]\x00\x00)',
                       b'\xc7\x45.([\x20-\x7e]\x00|[\x20-\x7e]{2,4}'
                       b'|[\x20-\x7e]{3}\x00)',
                       b'\xc7\x44.{2}([\x20-\x7e]\x00|[\x20-\x7e]{2,4}'
                       b'|[\x20-\x7e]{3}\x00)',
                       b'\xc7\x85.{2}\xff\xff([\x20-\x7e]{2,4})', ]
        stack = []

        for r in stack_regex:
            matches = re.finditer(r, self.buff[self.offset:self.total_size],
                                  re.DOTALL)
            if matches:
                first_match = 0
                last_match = 0
                stack_string = bytearray()
                for m in matches:
                    match_start = m.start(0)
                    match_char_len = len(m.group(1))

                    # encompass other languages used as stack strings
                    if match_char_len == 4 and \
                            m.group(1).endswith(b'\x00\x00'):
                        try:
                            match_char = '\\u' + '%x' % \
                                         unpack('I', m.group(1))[0]
                            match_char = \
                                bytes(match_char, 'utf-8').decode(
                                    'unicode_escape').encode('utf-8')
                        except (UnicodeDecodeError, UnicodeEncodeError):
                            log.debug('Detection at offset %x not a valid '
                                      'unicode string.' % match_start)
                            continue
                    elif match_char_len > 1:
                        match_char = m.group(1).rstrip(b'\x00')
                    # single byte ascii
                    else:
                        match_char = m.group(1)

                    # Start a new stack string and end the previous
                    if match_start - last_match > 15:
                        if 0 < len(stack_string) >= self.stringmodifier:
                            log.debug('End string %s' %
                                      stack_string.decode("utf-8"))
                            stack.append((first_match, '(stack)',
                                          stack_string))
                        stack_string = bytearray(match_char)
                        first_match = match_start
                    # In the middle of a known stack string
                    elif match_start - last_match <= 15:
                        stack_string.extend(match_char)
                    last_match = match_start

                # Catch the last stack string
                if 0 < len(stack_string) >= self.stringmodifier:
                    stack.append((first_match, '(stack)', stack_string))

        return stack


def get_iocs(candidate):
    """
    Determine if candidate string DIRECTLY corresponds to indicator regex,
    and return the type and value of the first match.

    This means long paragraphs are not expected to have each candidate
    examined and enumerated. A candidate string is evaluated, in the given
    order, to determine if it contains regex that lends it to an ioc. If it
    does, extract the candidate grouping and return the first match.

    This is not intended to give a full and accurate accounting, it is merely
    to facilitate rapid triage of a binary prior to ADDITIONAL analysis.
    """

    m_url = re.search(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*(),]|'
                      r'(?:%[0-9a-fA-F][0-9a-fA-F]))+', candidate)
    if m_url:
        url = m_url.group(0)
        if validators.url(url):
            return 'url', url, m_url.start(0)

    # must have a tld in fld
    m_domain = re.search(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])\.'
                         r'[.a-zA-Z]{2,}', candidate)
    if m_domain:
        domain = m_domain.group(0)
        t = domain.rsplit('.', 1)[-1]
        if tld.is_tld(t) and validators.domain(domain):
            return 'domain', domain, m_domain.start(0)
        else:
            log.info('Failed to validate: %s', domain)

    # ref:
    # https://nbviewer.jupyter.org/github/rasbt/python_reference/blob/master/tutorials/useful_regex.ipynb
    m_ipv4 = re.search(r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', candidate)  # noqa:E501
    if m_ipv4:
        ipv4 = m_ipv4.group(0)
        if validators.ipv4(ipv4):
            return 'ipv4', ipv4, m_ipv4.start(0)

    # ref:
    # https://nbviewer.jupyter.org/github/rasbt/python_reference/blob/master/tutorials/useful_regex.ipynb
    m_ipv6 = re.search(r'((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?', candidate)  # noqa:E501

    if m_ipv6:
        ipv6 = m_ipv6.group(0)
        if validators.ipv6(ipv6):
            return 'ipv6', ipv6, m_ipv6.start(0)

    m_email = re.search(r'(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]'
                        r'+\.[a-zA-Z0-9-.]+$)', candidate)
    if m_email:
        email = m_email.group(0)
        if validators.email(email):
            return 'email', email, m_email.start(0)

    m_filename = re.search(r'\b([A-Za-z0-9-_.]{1,255}\.'
                           r'(exe|dll|bat|sys|htm|html|cfg|gz|tar|rpm|7z|'
                           r'js|jar|jpg|png|vb|scr|pif|chm|zip|rar|cab|'
                           r'pdf|doc|docx|ppt|pptx|py|pyc|txt|msg|csv|wps|'
                           r'xls|xlsx|swf|gif|pps|xml|vcxproj|sln|pl|msi|tmp'
                           r'c|cpp|cs|h|java|lua|class|sh|bak)'
                           r')\b', candidate)
    if m_filename:
        fname = m_filename.group(0)
        return 'filename', fname, m_filename.start(0)

    return 'unknown', candidate, 0


def autoint(x):
    if x.startswith('0x'):
        x = int(x, 16)
    else:
        x = int(x)
    return x


def initialize_parser():
    parser = argparse.ArgumentParser(
        description='Process data stream and recover desired strings. Numeric '
                    'values may be provided as regular integers or hexadecimal'
                    ' with the \'0x\' prefix. String types may be specified '
                    'and combined to filter results. By default all strings '
                    'recovered will be displayed. Assembled strings are best '
                    'effort using regular expressions on byte patterns.')
    parser.add_argument('-v', '--verbose', action='store_true',
                        default=False,
                        help='Output additional information when processing '
                             '(mostly for debugging purposes).')
    parser.add_argument('infile', type=argparse.FileType('r'), default='-',
                        help='Data stream to search '
                             '(stdin, denoted by a \'-\').')
    parser.add_argument('-a', '--ascii', action='store_true', default=False,
                        help='Specify to search for normal single byte '
                             'ascii printables.')
    parser.add_argument('-u', '--unicode', action='store_true', default=False,
                        help='Specify to search for wide unicode characters.')
    parser.add_argument('-ss', '--stack-strings', action='store_true',
                        default=False,
                        help='Specify to search for stack strings.')
    parser.add_argument('-o', '--offset', type=autoint, default=0,
                        help='Starting point within the supplied buffer '
                             'to begin processing.')
    parser.add_argument('-s', '--size', type=autoint, default=-1,
                        help='The total number of bytes to process. '
                             'Defaults to size of supplied data.')
    parser.add_argument('-i', '--indicators', action='store_true',
                        default=False,
                        help='Print only strings contextualized '
                             'through indicator regex.')
    parser.add_argument('-m', '--modifier', type=int, default=3,
                        help='Number of consecutive printable characters '
                             'encountered before a string is recognized '
                             '(default is 3).')

    return parser


def find_strings(options):

    buff = options.infile.buffer.read()
    s = Superstrings(buff, options.offset, options.size, options.modifier)

    show_all = not (options.stack_strings or options.unicode or options.ascii)
    results = []

    if show_all:
        log.info('Checking for all types of strings...')
        results.extend(s.find_ascii())
        results.extend(s.find_unicode())
        results.extend(s.find_stack_strings())
    else:
        if options.stack_strings:
            log.info('Checking for stack strings...')
            results.extend(s.find_stack_strings())
        if options.unicode:
            log.info('Checking for unicode strings...')
            results.extend(s.find_unicode())
        if options.ascii:
            log.info('Checking for ascii strings...')
            results.extend(s.find_ascii())

    for offset, strtype, value in sorted(results, key=itemgetter(0)):
        value = value.decode("utf-8")
        if options.indicators:
            context, ioc, start = get_iocs(value)
            if context == 'unknown':
                continue
            print('0x%x' % (offset + start), strtype, context, ioc)
        else:
            print('0x%x' % offset, strtype, value)


def main():
    p = initialize_parser()
    args = p.parse_args()

    root = logging.getLogger()
    logging.basicConfig()
    if args.verbose:
        root.setLevel(logging.DEBUG)
    else:
        root.setLevel(logging.WARNING)

    find_strings(args)


if __name__ == '__main__':
    main()
