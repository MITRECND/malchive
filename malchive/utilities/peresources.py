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
import hashlib
from tabulate import tabulate

__version__ = "1.0.0"
__author__ = "Jason Batchelor"

log = logging.getLogger(__name__)

resource_types = {
    1: 'RT_CURSOR',
    2: 'RT_BITMAP',
    3: 'RT_ICON',
    4: 'RT_MENU',
    5: 'RT_DIALOG',
    6: 'RT_STRING',
    7: 'RT_FONTDIR',
    8: 'RT_FONT',
    9: 'RT_ACCELERATOR',
    10: 'RT_RCDATA',
    11: 'RT_MESSAGETABLE',
    12: 'RT_GROUP_CURSOR',
    14: 'RT_GROUP_ICON',
    16: 'RT_VERSION',
    17: 'RT_DLGINCLUDE',
    19: 'RT_PLUGPLAY',
    20: 'RT_VXD',
    21: 'RT_ANICURSOR',
    22: 'RT_ANIICON',
    23: 'RT_HTML',
    24: 'RT_MANIFEST',
}


def get_pe_resources(pe):
    """
    Get resources from a Windows PE file.

    :param pefile.PE pe: A pe object passed from the pefile project.

    :return: List of tuples containing resource directory name, id,
    entry name, entry id, size, and binary data.
    :rtype: list
    """

    rsrcs = []

    for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        res_dir_name = '%s' % rsrc.name if rsrc.name is not None else '-'
        res_id = resource_types.get(rsrc.id, '-')

        entry_id, entry_name = ['-'] * 2
        entry_data = bytearray()
        entry_size = 0

        if len(rsrc.directory.entries) == 0:
            rsrcs.append((res_dir_name, res_id, entry_name,
                          entry_id, entry_size, entry_data))

        for entry in rsrc.directory.entries:
            offset = entry.directory.entries[0].data.struct.OffsetToData
            entry_size = entry.directory.entries[0].data.struct.Size
            entry_data = bytearray(pe.get_memory_mapped_image()
                                   [offset:offset + entry_size])
            entry_id = '%s' % entry.id if entry.id is not None else '-'
            entry_name = '%s' % entry.name if entry.name is not None else '-'
            rsrcs.append((res_dir_name, res_id, entry_name,
                          entry_id, entry_size, entry_data))

    return rsrcs


def initialize_parser():
    parser = argparse.ArgumentParser(
        description='Dump embedded resources to disk. '
                    'Entries with \'-\' are unlabeled.')
    parser.add_argument('infile', metavar='FILE', nargs='*',
                        help='Full path to the file(s) to be processed.')
    parser.add_argument('-w', '--write', action='store_true',
                        help='Write the file(s) to disk. Creates a directory '
                             'with MD5 hash and \'_rsrc\' prefix of the '
                             'provided sample and extracts payloads there.')
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

    for fname in args.infile:

        basename = os.path.basename(fname)

        if not os.path.isfile(fname):
            log.warning('Failed to find file %s. Skipping...' % fname)
            continue

        with open(fname, 'rb') as f:
            stream = f.read()

        try:
            pe = pefile.PE(data=stream)
        except pefile.PEFormatError:
            log.warning('%s not a pe, skipping...' % basename)
            continue

        try:
            resources = get_pe_resources(pe)
        except (AttributeError, ValueError) as e:
            log.error('%s' % e)
            continue

        print('Found %s resources in %s...' % (len(resources), basename))
        if len(resources) == 0:
            continue

        results = []
        target_dir = '%s_rsrc' % hashlib.md5(stream).hexdigest()
        if args.write:
            try:
                os.makedirs(target_dir, exist_ok=True)
            except OSError:
                if not os.path.isdir(target_dir):
                    log.error('Could not create %s' % target_dir)

        for res_dir, res_type, e_name, e_id, e_size, e_data in resources:
            md5 = hashlib.md5(e_data).hexdigest()
            results.append((md5, res_dir, res_type, e_name, e_id, e_size))

            name = '%s/%s.bin' % (target_dir, md5)
            if args.write:
                with open(name, 'wb+') as f:
                    f.write(e_data)
                log.info('%s written to disk.' % name)

        if len(results) > 0:
            print(tabulate(results,
                           headers=["MD5", "Directory", "Type",
                                    "Name", "ID", "Size"],
                           tablefmt="grid"))


if __name__ == '__main__':
    main()
