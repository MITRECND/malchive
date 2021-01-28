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
import pefile
import logging
import re
import struct

__version__ = "1.0.0"
__author__ = "First Last"

log = logging.getLogger(__name__)

# Function or class that does the heavy lifting. It is important to
# consider how you expect other people to interface with the program
# while you are developing it. They will likely be importing it directly
# into other frameworks.
#
# In some cases, it might make more sense to develop as a class instead
# of a single method. For example, if you have a config with a lot of
# data variables you are parsing out, it might make more sense to
# 'group' those. Either way, documentation is key.


class GetConfig:
    """
    Gets specific configuration IoCs from the malware.

    :ivar list callbacks: Example callback domains or IP address.
    :ivar int key: Example key used to encode callback data.
    :ivar int port: Example port used for callback communication.
    """

    def __init__(self, buff):
        """
        Initialize decoder instance.

        :param bytes buff: The stream of bytes to be processed.
        """

        self.callbacks = []
        self.port = 0
        self.key = 0
        self.buff = buff
        self.config = bytearray()

        try:
            pe = pefile.PE(data=self.buff)
            self.decode_config(pe)
        except pefile.PEFormatError:
            log.debug('Supplied file must be a valid PE!')

        if len(self.config):
            self.parse_config()
        else:
            log.debug('Could not find config!')

    def decode_config(self, pe):
        """
        Description of what the method does.

        :param bytes buff: Something describing your parameters.

        :return: Something describing what you're returning.
        :rtype: dict
        """

        config_regex = b'MALWARE CONFIG'
        m = re.search(config_regex, self.buff, re.DOTALL)
        if m:
            # Feel free to use debug statements liberally to help troubleshoot,
            # they will only show if the logger is setup to show them
            # (-v in main)
            log.debug('Getting something now...')
            offset = m.end()
            # example config is always 0x800 bytes large
            self.config = bytearray(self.buff[offset:offset+0x800])

        if len(self.config):
            # As with debug, these can be used to notify/troubleshoot issues.
            # Only shown with -v when invoked from main.
            log.info('We got something!')
            self.parse_config()
        else:
            # Something irrecoverable happened and we cannot proceed.
            # Shown by default.
            log.error('Something bad happened!')

    def parse_config(self):

        self.port = struct.unpack('I', self.config[0x0:0x4])[0]
        callbacks = self.config[0x4:].rstrip(b'\x00').split(b'|')

        for callback in callbacks:
            try:
                self.callbacks.append(callback.decode('ascii'))
            except UnicodeDecodeError:
                # Warnings that something Isn't right the user should know.
                # These will show by default.
                log.warning('Got something I didn\'t expect')

        return


def initialize_parser():
    parser = argparse.ArgumentParser(
        description='Process candidate. Prints results in JSON format.')
    parser.add_argument('candidates', metavar='FILE',
                        nargs='*', help='candidate file(s).')
    parser.add_argument('-v', '--verbose', action='store_true',
                        default=False,
                        help='Output additional information when processing '
                             '(mostly for debugging purposes).')
    return parser


# Code supporting standalone operations. This sequence will
# iterate through a list of supplied files and generate IoCs for output
# in a JSONified format. Files found not to meet criteria for processing
# should not impede runtime. Errors should be output to console using the
# logger module.
def main():
    # local imports
    import os
    import json
    import datetime
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
        stream = f.read()

        # In some cases it helps to check if the file is a PE upfront.
        try:
            pe = pefile.PE(data=stream)
            timestamp = datetime.datetime.utcfromtimestamp(
                pe.FILE_HEADER.TimeDateStamp)
        except pefile.PEFormatError:
            log.warning('%s not a pe, skipping...' % f.name)
            continue

        d = GetConfig(stream)

        config_dict = {
            'Compile Time': '%s UTC' % timestamp,
            'MD5': hashlib.md5(stream).hexdigest(),
            'Callbacks': d.callbacks,
        }

        try:
            print(json.dumps(config_dict, indent=4, sort_keys=False))
        except UnicodeDecodeError:
            log.warning('There was a Unicode decoding error when '
                        'processing %s' % os.path.basename(filename))
            continue


if __name__ == '__main__':
    main()
