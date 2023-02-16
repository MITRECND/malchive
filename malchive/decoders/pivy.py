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

import argparse
import logging
import struct
import binascii

__version__ = "1.0.0"
__author__ = "Jason Batchelor"

log = logging.getLogger(__name__)


# A re-imagining of a PivyParser, credit to the following
# resource for the enums:
# https://github.com/botherder/volatility/blob/master/contrib/plugins/malware/poisonivy.py
#
class PivyParser:
    """
    Class that helps map and parse Poison Ivy config elements.

    :ivar int size: Indicates how large the current data value in the
    config is.
    :ivar int window: Indicates how large the total section is minus the two
    byte symbol value.
    :ivar str key: The key that corresponds with the symbol.
    :ivar str,list value: The return data for the specific symbol.
    :ivar dict symbols: Dictionary with symbol mappings to functions that
    process the data as required.
    """

    def __init__(self):

        symbol_mapping = {
            0x12d: self.copy_dest_file,
            0x145: self.get_password,
            0x165: self.get_persist_active_setup_guid,
            0x190: self.get_callback_info,
            0x2c1: self.get_proxy_config,
            0x2c5: self.get_callback_info,
            0x3f6: self.get_persist_active_setup,
            0x3f7: self.copy_dest_dir,
            0x3f8: self.get_melt,
            0x3f9: self.get_inject_persist,
            0x3fa: self.get_keylogger,
            0x3fb: self.get_mutex,
            0x40f: self.get_active_setup,
            0x418: self.get_browser_key,
            0x441: self.get_inject_into_browser,
            0x442: self.get_inject_proc_name,
            0x456: self.get_persist_active_setup_key,
            0xaf4: self.get_use_proxy,
            0xaf5: self.get_proxy_persist,
            0xafa: self.get_server_id,
            0xbf9: self.get_server_group,
            0xd08: self.get_inject,
            0xd09: self.get_autorun_persist,
            0xd12: self.get_copy_as_ads,
            0xe12: self.get_persist_hklm_run_name,
        }

        self.size = 0
        self.window = 0
        self.symbols = symbol_mapping
        self.key = ''
        self.value = ''

    def _extract_value(self, d):
        self.size = struct.unpack('<H', d[0x0:0x2])[0]
        # size bytes, plus actual size of the value
        self.window = self.size + 0x2
        v = d[0x2:0x2 + self.size]
        return v

    @staticmethod
    def _get_string(v):
        try:
            v = v.decode('ascii').rstrip('\x00')
        except UnicodeDecodeError:
            value = binascii.hexlify(v).decode('ascii')
            log.debug('Could not decode value with bytes %s' % value)
            v = 'UNDETERMINED'
        return v

    @staticmethod
    def _get_protocol_type(p):
        if p == 0x0:
            return 'Direct'
        if p == 0x1:
            return 'SOCKS Proxy'
        if p == 0x2:
            return 'HTTP Proxy'
        if p == 0x6:
            return 'SPIVY HTTP'
        if p == 0xb:
            return 'SPIVY 2.0'
        log.debug('Unknown protocol value 0x%x' % p)
        return 'Unknown'

    def copy_dest_file(self, d, s):
        value = self._extract_value(d)
        self.value = self._get_string(value)
        self.key = 'CopyDestFile'

    def get_password(self, d, s):
        value = self._extract_value(d)
        self.value = self._get_string(value)
        self.key = 'Password'

    def get_persist_active_setup_guid(self, d, s):
        value = self._extract_value(d)
        self.value = self._get_string(value)
        self.key = 'PersistActiveSetupGUID'

    def get_callback_info(self, d, s):
        values = []
        i = 0
        callback_block = self._extract_value(d)

        while i < len(callback_block):
            callback_info = {}
            size = callback_block[i]

            if size == 0x0:
                break

            callback = callback_block[i + 0x1:
                                      i + 0x1 + size]

            callback_info['callback'] = self._get_string(callback)
            i += size

            if len(callback_block) != i + 0x1:
                p = callback_block[i + 0x1]
                callback_info['protocol'] = self._get_protocol_type(p)
                callback_info['port'] = struct.unpack(
                    '<H', callback_block[i + 0x2: i + 0x4])[0]
                i += 0x4
            else:
                i += 0x1
            values.append(callback_info)

        self.value = values
        if s == 0x190:
            self.key = 'Callbacks'
        else:
            self.key = 'CallbackIfProxy'

    def get_persist_active_setup(self, d, s):
        self.value = True if self._extract_value(d) else False
        self.key = 'PersistActiveSetupOn'

    def copy_dest_dir(self, d, s):
        self.value = True if self._extract_value(d) else False
        self.key = 'CopyDestDir'

    def get_proxy_config(self, d, s):
        v = struct.unpack('<I', self._extract_value(d))[0]
        v = (v ^ 0x80000000) - 0x80000000
        self.value = True if v >= 0 else False
        self.key = 'ProxyCfgPresent'

    def get_melt(self, d, s):
        self.value = True if self._extract_value(d) else False
        self.key = 'Melt'

    def get_inject_persist(self, d, s):
        self.value = True if self._extract_value(d) else False
        self.key = 'InjectPersist'

    def get_keylogger(self, d, s):
        self.value = True if self._extract_value(d) else False
        self.key = 'Keylogger'

    def get_mutex(self, d, s):
        value = self._extract_value(d)
        self.value = self._get_string(value)
        self.key = 'Mutex'

    def get_active_setup(self, d, s):
        value = self._extract_value(d)
        self.value = self._get_string(value)
        self.key = 'PersistActiveSetupName'

    def get_browser_key(self, d, s):
        value = self._extract_value(d)
        self.value = self._get_string(value)
        self.key = 'DefaultBrowserKey'

    def get_inject_into_browser(self, d, s):
        self.value = True if self._extract_value(d) else False
        self.key = 'InjectIntoDefaultBrowser'

    def get_inject_proc_name(self, d, s):
        value = self._extract_value(d)
        self.value = self._get_string(value)
        self.key = 'InjectProcName'

    def get_persist_active_setup_key(self, d, s):
        value = self._extract_value(d)
        self.value = self._get_string(value)
        self.key = 'PersistActiveSetupKeyPart'

    def get_use_proxy(self, d, s):
        self.value = True if self._extract_value(d) else False
        self.key = 'UseProxy'

    def get_proxy_persist(self, d, s):
        self.value = True if self._extract_value(d) else False
        self.key = 'ProxyNoPersist'

    def get_server_id(self, d, s):
        value = self._extract_value(d)
        self.value = self._get_string(value)
        self.key = 'ServerId'

    def get_server_group(self, d, s):
        value = self._extract_value(d)
        self.value = self._get_string(value)
        self.key = 'ServerGroup'

    def get_inject(self, d, s):
        self.value = True if self._extract_value(d) else False
        self.key = 'Inject'

    def get_autorun_persist(self, d, s):
        self.value = True if self._extract_value(d) else False
        self.key = 'PersistAutoRun'

    def get_persist_hklm_run_name(self, d, s):
        value = self._extract_value(d)
        self.value = self._get_string(value)
        self.key = 'PersistHKLMRunName'

    def get_copy_as_ads(self, d, s):
        self.value = True if self._extract_value(d) else False
        self.key = 'CopyAsADS'

    def unknown_symbol(self, d, s):
        self._extract_value(d)
        self.key = 'Unknown'
        log.debug('Unknown symbol identified! 0x%x' % s)


class GetConfig:
    """
    Gets specific configuration IoCs from the malware.

    :ivar dict elements: Dictionary representing various configuration
    elements that were recovered.
    """

    def __init__(self, buff):
        """
        Initialize decoder instance.

        :param bytes buff: The stream of bytes representing the first stage.
        """
        self.buff = buff
        self.elements = {}
        self.parse_config()

    def parse_config(self):
        """
        Parse out Poison Ivy config elements.
        """

        '''
        ; final return from function executing next plugin
        ; followed by config
        ;
        seg000:00004198 58  pop     eax
        seg000:00004199 61  popa
        seg000:0000419A C9  leave
        seg000:0000419B C3  retn
        '''

        # seems to be the first element of all configs
        offset = self.buff.rfind(b'\x0f\x04\x08\x00')
        if offset < 0:
            log.debug('Could not find config offset!')
            return

        log.debug('Config offset recovered at 0x%x' % offset)
        config = self.buff[offset:]

        # Iterate by two each time (size of pivy enums is a WORD).
        # Let the PivyParser class do the lifting on interpretation...
        i = 0
        p = PivyParser()
        while i + 0x2 < len(config):
            symbol = struct.unpack('<H', config[i:i + 0x2])[0]
            if symbol == 0x0:
                break
            log.debug('Trying symbol 0x%x' % symbol)
            p.symbols.get(symbol, p.unknown_symbol)(config[i + 0x2:], symbol)
            if p.key != 'Unknown':
                log.debug('Found %s key with value %s' % (p.key, p.value))
                log.debug('Relative config offset 0x%x' % i)
                self.elements[p.key] = p.value
            i += p.window + 0x2


def initialize_parser():
    parser = argparse.ArgumentParser(
        description='Process candidate. Prints results in JSON format.')
    parser.add_argument('candidates', metavar='FILE', nargs='*',
                        help='candidate file(s).')
    parser.add_argument('-v', '--verbose', action='store_true', default=False,
                        help='Output additional information when processing '
                             '(mostly for debugging purposes).')
    return parser


def main():
    import os
    import json
    import hashlib

    p = initialize_parser()
    args = p.parse_args()

    root = logging.getLogger()
    logging.basicConfig()
    if args.verbose:
        root.setLevel(logging.DEBUG)
    else:
        root.setLevel(logging.WARNING)

    # Iterate through list of files in bulk.
    for filename in args.candidates:

        log.info('Processing file %s...' % filename)

        if not os.path.isfile(filename):
            log.warning('Failed to find file %s' % filename)
            continue

        f = open(filename, 'rb')
        log.info('Reading file %s...' % filename)
        stream = f.read()

        d = GetConfig(stream)

        config_dict = {
            'SHA256': hashlib.sha256(stream).hexdigest(),
            'Config': d.elements,
        }

        try:
            print(json.dumps(config_dict, indent=4, sort_keys=False))
        except UnicodeDecodeError:
            log.warning('There was a Unicode decoding error when processing %s'
                        % os.path.basename(filename))
            continue


if __name__ == '__main__':
    main()
