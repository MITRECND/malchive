#!/usr/bin/python

import sys
import struct
import re
import binascii
import logging
import argparse

__version__ = "1.0.0"

log = logging.getLogger(__name__)


def get_guids(buff):

    results = []
    storage_signature = b'\x42\x53\x4A\x42'  # 'BSBJ'
    guid_signature = b'\x23\x47\x55\x49\x44\x00\x00\x00'  # '#GUID\x00\x00'

    storage_offsets = re.finditer(storage_signature, buff)

    for match in storage_offsets:

        guid_offset = buff[match.start():].find(guid_signature) - 0x8

        if guid_offset == -1:
            log.warning('GUID offset mismatch at 0x%x.' % guid_offset)
            continue

        iOffset, iSize = struct.unpack_from('II', buff[match.start() +
                                                       guid_offset:])
        gLocation = iOffset + match.start()
        raw_guid = bytearray(buff[gLocation: gLocation + iSize])

        guid = \
            '{' + \
            binascii.hexlify(
                raw_guid[0x0:0x4][::-1]
                ).decode('ascii') + \
            '-' + \
            binascii.hexlify(
                raw_guid[0x4:0x6][::-1]
                ).decode('ascii') + \
            '-' + \
            binascii.hexlify(
                raw_guid[0x6:0x8][::-1]
                ).decode('ascii') + \
            '-' + \
            binascii.hexlify(
                raw_guid[0x8:0xa]
                ).decode('ascii') + \
            '-' + \
            binascii.hexlify(
                raw_guid[0xa:]
                ).decode('ascii') + \
            '}'

        raw_ascii = binascii.hexlify(raw_guid).decode('ascii')
        results.append((gLocation, raw_ascii, guid))
    return results


def initialize_parser():
    parser = argparse.ArgumentParser(
        description='Fetch embedded .NET GUIDs within a binary stream.'
                    ' Like a process dump for example.')
    parser.add_argument('infile', metavar='FILE', nargs='*',
                        help='Full path to the file(s) to be processed.')
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
            stream = f.read()

        results = get_guids(stream)

        if len(results) == 0:
            log.info('No results for %s' % basename)
            continue

        i = 1
        parent = {
                  'Sha256': hashlib.sha256(stream).hexdigest()
                 }
        for res in results:
            child = {
                     'offset': hex(res[0]),
                     'raw_data': res[1],
                     'guid': res[2]
                    }
            parent['result_%s' % i] = child
            i += 1

        try:
            print(json.dumps(parent, indent=4, sort_keys=False))
        except UnicodeDecodeError:
            log.warning('There was a Unicode decoding error when '
                        'processing %s' % os.path.basename(basename))
            continue


if __name__ == '__main__':
    main()
