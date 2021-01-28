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
import argparse
from struct import unpack_from

__version__ = "1.0.0"
__author__ = "Jason Batchelor"

log = logging.getLogger(__name__)

s_image_file_header = 0x18
s_image_section_header = 0x28
s_data_directory_entry = 0x8
s_import_descriptor = 0x14

IMAGE_FILE_MACHINE_I386 = 0x14c
IMAGE_FILE_MACHINE_IA64 = 0x200
IMAGE_FILE_MACHINE_AMD64 = 0x8664


# Traditional PE modules like pefile and lief don't take kindly to
# the way Cobalt PEs present on disk. So we have to do the heavy lifting...
#
# References:
# https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
# https://www.ired.team/miscellaneous-reversing-forensics/pe-file-header-parser-in-c++
def malleable_fixup(buff):

    import_section = 0
    e_magic = buff[0x0:0x2]
    e_lfanew = unpack_from('I', buff[0x3c:])[0]

    if not e_magic.startswith(b'MZ'):
        log.debug('Invalid e_magic value, aborting...')
        return None

    if e_lfanew >= len(buff):
        log.debug('Invalid e_lfanew value, aborting...')
        return None

    p_image_nt_headers = e_lfanew
    if not buff[p_image_nt_headers:].startswith(b'PE'):
        log.debug('Invalid PE header, aborting...')
        return None

    machine = unpack_from('H', buff[p_image_nt_headers + 0x4:])[0]
    if machine == IMAGE_FILE_MACHINE_I386:
        log.debug('Proceeding with x86 image...')
    elif machine == IMAGE_FILE_MACHINE_IA64 or \
            machine == IMAGE_FILE_MACHINE_AMD64:
        log.debug('Proceeding with x64 image...')
    else:
        log.debug('Unknown image type 0x%x, aborting...')
        return None

    num_sections = unpack_from('H', buff[p_image_nt_headers + 0x6:])[0]
    size_optional_header = \
        unpack_from('H', buff[p_image_nt_headers + 0x14:])[0]
    p_section_table = \
        p_image_nt_headers + s_image_file_header + size_optional_header
    p_image_optional_header = p_image_nt_headers + s_image_file_header
    if machine == IMAGE_FILE_MACHINE_I386:
        number_rva_and_sizes = \
            unpack_from('I', buff[p_image_optional_header + 0x5c:])[0]
    else:
        number_rva_and_sizes = \
            unpack_from('I', buff[p_image_optional_header + 0x6c:])[0]
    size_data_directories = number_rva_and_sizes * s_data_directory_entry
    p_data_directories = \
        p_image_optional_header + size_optional_header - size_data_directories

    # import table is the second entry
    import_dir_rva = \
        unpack_from('I', buff[p_data_directories + s_data_directory_entry:])[0]

    # here we make an assumption on the first byte of the first section
    # name being a '.'. this is not mandatory but its a safe bet given
    # past observations.
    key = buff[p_section_table] ^ 0x2e
    if key == 0x0:
        log.debug('Key was found to be a null value. Aborting...')
        return None

    log.debug('Proceeding with key value 0x%x' % key)

    for i in range(0, num_sections):
        # section name exactly eight bytes for executables
        for n in range(0, 0x8):
            if buff[p_section_table + n] == 0x0:
                continue
            buff[p_section_table + n] ^= key

        section_va = unpack_from('I', buff[p_section_table + 0xc:])[0]
        section_va_size = unpack_from('I', buff[p_section_table + 0x8:])[0]

        try:
            log.debug('Recovered section at 0x%x : %s' %
                      (p_section_table,
                       buff[p_section_table:p_section_table + 0x8]
                       .decode('ascii')))
        except UnicodeDecodeError:
            log.error('String conversion error when parsing section names.')
            return None

        if import_dir_rva >= section_va and \
           import_dir_rva <= section_va + section_va_size:
            import_section = p_section_table
            import_section_va = section_va
            log.debug('Found import section 0x%x' % import_section)

        p_section_table += s_image_section_header

    if import_section == 0:
        log.debug('Could not find import section!')
        return None

    import_offset = unpack_from('I', buff[import_section + 0x14:])[0]

    import_descriptor = import_offset + (import_dir_rva - import_section_va)

    while True:
        module_name_rva = unpack_from('I', buff[import_descriptor + 0xc:])[0]
        p_module_name = import_offset + (module_name_rva - import_section_va)

        s = p_module_name
        while True:
            buff[s] ^= key
            if buff[s] == 0x0:
                break
            s += 1

        try:
            log.debug('Recovered module at 0x%x : %s' %
                      (p_module_name,
                       buff[p_module_name:s].decode('ascii')))
        except UnicodeDecodeError:
            log.error('String conversion error when parsing module names.')
            return None

        import_lookup_table_rva = \
            unpack_from('I', buff[import_descriptor + 0x0:])[0]
        p_import_lookup_table = \
            import_offset + (import_lookup_table_rva - import_section_va)

        while True:

            if machine == IMAGE_FILE_MACHINE_I386:
                flag = 0x80000000
                thunk_data = \
                    unpack_from('I', buff[p_import_lookup_table:
                                          p_import_lookup_table + 0x4])[0]
                p_import_lookup_table += 0x4
            else:
                flag = 0x8000000000000000
                thunk_data = \
                    unpack_from('Q', buff[p_import_lookup_table:
                                          p_import_lookup_table + 0x8])[0]
                p_import_lookup_table += 0x8

            if thunk_data == 0:
                break

            if not thunk_data & flag:
                p_wfunc_name = \
                    import_offset + (thunk_data - import_section_va + 2)

                s = p_wfunc_name
                while True:
                    buff[s] ^= key
                    if buff[s] == 0x0:
                        break
                    s += 1

                try:
                    log.debug('Recovered function at 0x%x : %s' %
                              (p_wfunc_name,
                               buff[p_wfunc_name:s].decode('ascii')))
                except UnicodeDecodeError:
                    log.error('String conversion error when '
                              'parsing function names.')
                    return None

        import_descriptor += s_import_descriptor

        # Reference:
        # https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-idata-section
        # The last directory entry is empty (filled with null values)
        import_dir_data = buff[import_descriptor:
                               import_descriptor+s_import_descriptor]
        if all(v == 0x0 for v in import_dir_data):
            break

    return buff


def initialize_parser():
    parser = argparse.ArgumentParser(
        description='Patch provided PE to restore section, module, '
                    'and function names obfuscated by Cobalt Strike '
                    'malleable stager. Write new PE with \'.patched\' '
                    'prefix.')
    parser.add_argument('infile', metavar='FILE', nargs='*',
                        help='Full path to the file(s) to be processed.')
    parser.add_argument('-o', '--overwrite', action='store_true',
                        default=False,
                        help='Patch existing file instead of creating a '
                             'new one.')
    parser.add_argument('-v', '--verbose', action='store_true', default=False,
                        help='Output additional information when processing '
                             '(mostly for debugging purposes).')

    return parser


def main():

    import os
    import sys

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
        log.info('Processing %s...' % basename)

        if not os.path.isfile(fname):
            log.warning('Failed to find file %s. Skipping...' % fname)
            continue

        with open(fname, 'rb') as f:
            stream = bytearray(f.read())

        fixed = malleable_fixup(stream)

        if fixed is None:
            log.debug('Failed to process %s. Skipping...' % fname)
            continue

        if args.overwrite:
            outname = basename
        else:
            outname = basename + '.patched'

        with open(outname, 'wb') as f:
            f.write(fixed)
        print('Patched file written as %s...' % outname)


if __name__ == '__main__':
    main()
