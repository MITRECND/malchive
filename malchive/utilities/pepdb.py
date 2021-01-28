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

import os
import sys
import logging
import argparse
import pefile
import operator
import binascii
import struct
from tabulate import tabulate
from datetime import datetime

__version__ = "1.0.0"
__author__ = "Jason Batchelor"

log = logging.getLogger(__name__)


class PDBInfo:
    """
    Gets specific info from PE DIRECTORY_ENTRY_DEBUG directory

    :ivar list results: List of tuples representing debug info in
    the following order; timestamp, signature, age, pdb path, guid.
    """

    def __init__(self, buff):
        """
        Initialize PDBInfo.

        :param bytes buff: The stream of bytes to be processed. Must be a PE.
        """

        self.results = []
        self.buff = buff

        try:
            pe = pefile.PE(data=self.buff)
        except pefile.PEFormatError:
            log.debug('Supplied file must be a valid PE!')
            return

        if not hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
            log.debug('No debug info present.')
            return

        self.get_debug_dir_info(pe)

    def get_debug_dir_info(self, pe):
        """
        Retrieves debug information from the Debug directory.

        :param pefile.PE pe: pefile object.
        """

        for debugdata in pe.DIRECTORY_ENTRY_DEBUG:

            timestamp = getattr(debugdata.struct, 'TimeDateStamp', None)
            if timestamp is not None:
                timestamp = datetime.utcfromtimestamp(timestamp).__str__()
            else:
                log.debug('No timestamp entry was present.')

            dbg_type = getattr(debugdata.struct, 'Type', 0)
            # Reference:
            # https://github.com/dotnet/corefx/blob/master/src/System.Reflection.Metadata/specs/PE-COFF.md#codeview-debug-directory-entry-type-2
            if dbg_type != 2:
                log.debug('Type is not a CodeView Debug Directory Entry')
                continue

            if debugdata.entry is None:
                log.debug('No debug entry data found.')
                continue

            entry = debugdata.entry
            signature, age, pdb_path, guid = self.get_entry_info(entry)
            self.results.append((timestamp, signature, age, pdb_path, guid))

    @staticmethod
    def get_entry_info(entry):
        """
        Process an entry from the debug directory and return metadata.
        """

        age = getattr(entry, 'Age', None)
        if age is None:
            log.debug('Age entry not found.')

        pdb_path = getattr(entry, 'PdbFileName', None)
        if pdb_path is not None:
            try:
                pdb_path = entry.PdbFileName.rstrip(b'\x00').decode('utf-8')
            except UnicodeDecodeError:
                pdb_path = None
                log.warning('There was an error decoding unicode '
                            'information from debug data.')
        else:
            log.debug('No PdbFileName entry found.')

        signature = getattr(entry, 'CvSignature', None)
        if signature is not None:
            signature = struct.pack('I', entry.CvSignature).decode('ascii')
        else:
            log.debug('No signature entry found.')

        try:
            guid = '{' + \
                   binascii.hexlify(
                       struct.pack('>I', entry.Signature_Data1)
                   ).decode('ascii') + \
                   '-' + \
                   binascii.hexlify(
                       struct.pack('>H', entry.Signature_Data2)
                   ).decode('ascii') + \
                   '-' + \
                   binascii.hexlify(
                       struct.pack('>H', entry.Signature_Data3)
                   ).decode('ascii') + \
                   '-' + \
                   binascii.hexlify(
                       entry.Signature_Data4[:2]
                   ).decode('ascii') + \
                   '-' + \
                   binascii.hexlify(
                       entry.Signature_Data4[2:]
                   ).decode('ascii') + \
                   '}'

        except UnicodeDecodeError as e:
            guid = ''
            log.warning('Error while getting GUID information. '
                        'Exception: %s', e)

        return signature, age, pdb_path, guid


def initialize_parser():
    parser = argparse.ArgumentParser(
        description='Take a series of provided files and print the extracted'
                    ' PDB CodeView info from them.')
    parser.add_argument('infile', metavar='FILE', nargs='*',
                        help='Full path to the file to be processed.')
    parser.add_argument('-v', '--verbose', action='store_true', default=False,
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

    if len(args.infile) == 0:
        p.print_help()
        sys.exit(2)

    results = []
    for fname in args.infile:

        basename = os.path.basename(fname)

        log.info('Processing file %s' % basename)

        if not os.path.isfile(fname):
            log.warning('Failed to find file %s. Skipping...' % fname)
            continue

        with open(fname, 'rb') as f:
            stream = f.read()

        try:
            pefile.PE(data=stream)
        except pefile.PEFormatError:
            log.warning('%s not a pe, skipping...' % basename)
            continue

        try:
            dbg = PDBInfo(stream)
        except Exception as e:
            log.warning('Could not process %s. Make sure you are running the '
                        'latest version of pefile. '
                        'Exception %s' % (basename, e))
            continue

        for d in dbg.results:
            results.append(((basename,) + d))

    results = sorted(results, key=operator.itemgetter(1, 0))

    table_header = ["Filename", "Debug Timestamp", "Signature",
                    "Revisions", "Path", "GUID"]

    if len(results) > 0:
        print(tabulate(results, headers=table_header, tablefmt="grid"))
    else:
        print('No debug information found!')


if __name__ == '__main__':
    main()
