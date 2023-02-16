#!/usr/bin/env python

import os
import sys
import logging
import argparse
import pefile
import hashlib
import tlsh

__version__ = "1.0.0"

log = logging.getLogger(__name__)


class HashInfo:
    """
    Return hashes based on supplied buffer such as;
    sha, md5, imphash, etc..
    """

    def __init__(self, buff):
        """
        Initialize HashInfo.

        :param bytes buff: The stream of bytes to be processed.
        """

        self.buff = buff
        self.imphash = self.get_imphash()
        self.sha256 = hashlib.sha256(self.buff).hexdigest()
        self.sha1 = hashlib.sha1(self.buff).hexdigest()
        self.md5 = hashlib.md5(self.buff).hexdigest()
        self.tlsh = tlsh.hash(self.buff).lower()

    def get_imphash(self):

        imphash = ""
        try:
            pe = pefile.PE(data=self.buff)
            imphash = pe.get_imphash()
        except pefile.PEFormatError:
            log.info('Data is not a pe...')
        return imphash


def initialize_parser():
    parser = argparse.ArgumentParser(
        description='Get various hashes on supplied filename.')
    parser.add_argument('infile', metavar='FILE', nargs='*',
                        help='Full path to the file(s) to be processed.')
    parser.add_argument('-v', '--verbose', action='store_true', default=False,
                        help='Output additional information when processing '
                             '(mostly for debugging purposes).')

    return parser


def main():
    import json

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

        hi = HashInfo(stream)

        hashDict = {
                'Name': basename,
                'ImpHash': "N/A" if len(hi.imphash) == 0 else hi.imphash,
                'SHA256': hi.sha256,
                'SHA1': hi.sha1,
                'MD5': hi.md5,
                'TLSH': hi.tlsh
                }

        try:
            print(json.dumps(hashDict, indent=4, sort_keys=False))
        except UnicodeDecodeError:
            log.warning('There was a Unicode decoding error when processing %s'
                        % fname)
            continue


if __name__ == '__main__':
    main()
