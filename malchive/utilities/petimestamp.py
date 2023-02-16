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
from tabulate import tabulate
from datetime import datetime

__version__ = "1.0.0"
__author__ = "Jason Batchelor"

log = logging.getLogger(__name__)


# Reference:
# https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#export-directory-table
def get_export_timestamp(pefile_object):
    """
    Retrieves timestamps from the export directory, if available.

    :param pefile.PE pefile_object: pefile object.
    :return: Value representing recovered timestamp from PE
    export directory (if present)
    :rtype: int
    """

    timestamp = 0
    if hasattr(pefile_object, 'DIRECTORY_ENTRY_EXPORT'):
        exportdata = pefile_object.DIRECTORY_ENTRY_EXPORT
        timestamp = getattr(exportdata.struct, 'TimeDateStamp', 0)
    return timestamp


# Reference:
# https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#resource-directory-table
def get_resource_timestamp(pefile_object):
    """
    Retrieves timestamps from resource directory entries, if available.

    :param pefile.PE pefile_object: pefile object.
    :return: Recovered timestamp from PE resource table entry (if present)
    :rtype: int
    """

    timestamp = 0
    if hasattr(pefile_object, 'DIRECTORY_ENTRY_RESOURCE'):
        resourcedata = pefile_object.DIRECTORY_ENTRY_RESOURCE
        timestamp = getattr(resourcedata.struct, 'TimeDateStamp', 0)
    return timestamp


# Reference:
# https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#load-configuration-layout
def get_load_config_timestamp(pefile_object):
    """
    Retrieves the timestamp from the Load Configuration directory.

    :param pefile.PE pefile_object: pefile object.
    :return: Recovered timestamps from PE load config (if any).
    None if there aren't.
    :rtype: int
    """

    timestamp = 0
    if hasattr(pefile_object, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
        loadconfigdata = pefile_object.DIRECTORY_ENTRY_LOAD_CONFIG
        timestamp = getattr(loadconfigdata.struct, 'TimeDateStamp', 0)
    return timestamp


# Code for import timestamps and delay load import
# timestamps informed by log2timeline project:
# Log2Timeline:
# https://github.com/log2timeline/plaso/blob/master/plaso/parsers/pe.py
# Reference:
# https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#import-directory-table
def get_import_timestamp(pefile_object):
    """
    Retrieves the timestamp from the Import Table directory.

    :param pefile.PE pefile_object: pefile object.
    :return: Recovered timestamps from PE imports (if any) as a list of
    tuples such that [(dllname, timestamp)].
    :rtype: list
    """

    import_timestamps = []
    if not hasattr(pefile_object, 'DIRECTORY_ENTRY_IMPORT'):
        return import_timestamps

    for importdata in pefile_object.DIRECTORY_ENTRY_IMPORT:
        dll_name = getattr(importdata, 'dll', '')
        try:
            dll_name = dll_name.decode('ascii')
        except UnicodeDecodeError:
            dll_name = dll_name.decode('ascii', errors='replace')
        if not dll_name:
            dll_name = '<NO DLL NAME>'

        timestamp = getattr(importdata.struct, 'TimeDateStamp', 0)
        if timestamp:
            import_timestamps.append((dll_name, timestamp))
    return import_timestamps


# Reference:
# https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#delay-load-import-tables-image-only
def get_delay_loaded_timestamp(pefile_object):
    """
    Retrieves the timestamp from the Delay Load Import Table directory.

    :param pefile.PE pefile_object: pefile object.
    :return: Recovered timestamps from PE imports (if any) as a list
    of tuples such that [(dllname, timestamp)].
    :rtype: list
    """

    delay_import_timestamps = []
    if not hasattr(pefile_object, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
        return delay_import_timestamps

    for delayloaddata in pefile_object.DIRECTORY_ENTRY_DELAY_IMPORT:
        dll_name = delayloaddata.dll
        try:
            dll_name = dll_name.decode('ascii')
        except UnicodeDecodeError:
            dll_name = dll_name.decode('ascii', errors='replace')

        timestamp = getattr(delayloaddata.struct, 'dwTimeStamp', 0)
        if timestamp:
            delay_import_timestamps.append((dll_name, timestamp))
    return delay_import_timestamps


# Reference:
# https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#debug-directory-image-only
def get_debug_dir_timestamp(pefile_object):
    """
    Retrieves the timestamp from the Debug directory.

    :param pefile.PE pefile_object: pefile object.
    :return: List of recovered timestamps from PE Debug directory (if any).
    None if there aren't.
    :rtype: list
    """

    timestamps = []
    if not hasattr(pefile_object, 'DIRECTORY_ENTRY_DEBUG'):
        return timestamps
    for debugdata in pefile_object.DIRECTORY_ENTRY_DEBUG:
        timestamp = getattr(debugdata.struct, 'TimeDateStamp', 0)
        if timestamp:
            timestamps.append(timestamp)
    return timestamps


def initialize_parser():
    parser = argparse.ArgumentParser(
        description='Take a series of provided files and print the '
                    'extracted timestamps from each PE; '
                    'such as the compile, resource, '
                    'load config, debug, and export timestamps.')
    parser.add_argument('infile', metavar='FILE', nargs='*',
                        help='Full path to the file to be processed.')
    parser.add_argument('-v', '--verbose', action='store_true', default=False,
                        help='Output additional information when processing '
                             '(mostly for debugging purposes).')
    parser.add_argument('-b', '--brief', action='store_true', default=False,
                        help='Just print the \'compile time\' only and '
                             'not the other timestamp fields.')
    parser.add_argument('-x', '--extended', action='store_true', default=False,
                        help='Also print timestamps from the \'import\' and '
                             'the \'delay load\' directory tables. '
                             'Useful in limited cases since these timestamps '
                             'are created only when the image is bound.')

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

        compile_timestamp = datetime.utcfromtimestamp(
            pe.FILE_HEADER.TimeDateStamp)
        if args.brief:
            results.append((basename, datetime.utcfromtimestamp(
                pe.FILE_HEADER.TimeDateStamp)))
            continue

        export_timestamp = get_export_timestamp(pe)
        if export_timestamp:
            export_timestamp = datetime.utcfromtimestamp(
                export_timestamp).__str__()
        else:
            export_timestamp = ''

        resource_timestamp = get_resource_timestamp(pe)
        if resource_timestamp:
            resource_timestamp = datetime.utcfromtimestamp(
                resource_timestamp).__str__()
        else:
            resource_timestamp = ''

        load_config_timestamp = get_load_config_timestamp(pe)
        if load_config_timestamp:
            load_config_timestamp = datetime.utcfromtimestamp(
                load_config_timestamp).__str__()
        else:
            load_config_timestamp = ''

        debug_timestamp = ''
        for timestamp in get_debug_dir_timestamp(pe):
            timestamp = datetime.utcfromtimestamp(
                timestamp).__str__()
            debug_timestamp += '%s\n' % timestamp

        if args.extended:

            import_timestamp = ''
            for dllname, timestamp in get_import_timestamp(pe):
                timestamp = datetime.utcfromtimestamp(
                    timestamp).__str__()
                import_timestamp += '%s - %s\n' % (dllname, timestamp)

            delay_load_import_timestamp = ''
            for dllname, timestamp in get_delay_loaded_timestamp(pe):
                timestamp = datetime.utcfromtimestamp(
                    timestamp).__str__()
                delay_load_import_timestamp += '%s - %s\n' % \
                                               (dllname, timestamp)

            results.append((basename, compile_timestamp,
                            resource_timestamp, load_config_timestamp,
                            debug_timestamp, export_timestamp,
                            import_timestamp, delay_load_import_timestamp))
        else:
            results.append((basename, compile_timestamp,
                            resource_timestamp, load_config_timestamp,
                            debug_timestamp, export_timestamp))

    results = sorted(results, key=operator.itemgetter(1, 0))

    table_header = ["Filename", "Compile Timestamp"]
    if not args.brief:
        table_header.extend(["Resource Timestamp", "Load Config Timestamp",
                             "Debug Timestamp(s)", "Export Timestamp"])
    if args.extended:
        table_header.extend(["Import Timestamp(s)",
                             "Delay Load Import Timestamp(s)"])

    print(tabulate(results, headers=table_header, tablefmt="grid"))


if __name__ == '__main__':
    main()
