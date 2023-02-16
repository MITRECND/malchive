#!/usr/bin/env python
import re
import argparse
import logging
import pefile
from struct import unpack_from

__version__ = "1.0.0"

log = logging.getLogger(__name__)


def carve_pe_files(data, include_start=False):

    results = []

    matches = re.finditer(b'MZ', data, flags=0)
    pe_size = 0
    for m in matches:
        if m.start() == 0 and not include_start:
            continue

        if m.start() + 0x40 > len(data):
            continue

        e_lfanew = unpack_from('I', data[m.start() + 0x3c:])[0]
        if m.start() + e_lfanew + 0x2 > len(data):
            continue

        if not data[m.start() + e_lfanew:].startswith(b'PE'):
            continue

        log.info('Embedded PE content detected at 0x%x!' % m.start())
        try:
            pe = pefile.PE(data=data[m.start():])
            pe_size = pe.sections[-1].PointerToRawData + pe.sections[-1].SizeOfRawData
        except Exception as e:
            log.error('PEFile could not load detected PE. Error: %s' % e)
            continue

        if m.start() + pe_size > len(data):
            log.warning('Expressed PE size at 0x%x larger than file. '
                        'Incomplete result.' % m.start())

        results.append((m.start(), data[m.start():m.start() + pe_size]))

    return results


def initialize_parser():
    parser = argparse.ArgumentParser(
        description='Checks for embedded PE files within candidate. Writes result(s) to disk.')
    parser.add_argument('candidates', metavar='FILE', nargs='*',
                        help='candidate file(s).')
    parser.add_argument('--include-start', action='store_true', default=False,
                        help='For PE files that themselves have embedded PEs, this option will '
                             'include the beginnnig PE file among the carved payloads.')
    parser.add_argument('-v', '--verbose', action='store_true', default=False,
                        help='Output additional information when processing '
                             '(mostly for debugging purposes).')
    return parser


def main():
    import os
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
    for candidate in args.candidates:

        filename = os.path.basename(candidate)
        log.info('Processing file %s...' % filename)

        if not os.path.isfile(candidate):
            log.warning('Failed to find file %s' % candidate)
            continue

        results = []
        with open(candidate, 'rb') as f:
            results = carve_pe_files(f.read(), args.include_start)

        if len(results) == 0:
            print('No embedded PE files found within %s' % filename)
            continue

        print('Found %s embedded PE file(s) within %s' % (len(results), filename))
        for o, r in results:
            sha256 = hashlib.sha256(r).hexdigest()
            out_name = 'pe_0x%x_%s' % (o, sha256)
            with open(out_name, 'wb') as f:
                f.write(r)
            print('Processed %s and written as %s' % (filename, out_name))


if __name__ == '__main__':
    main()
