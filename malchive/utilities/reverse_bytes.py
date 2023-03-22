#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import logging
import argparse

__version__ = "1.0.0"

log = logging.getLogger(__name__)


def initialize_parser():
    parser = argparse.ArgumentParser(
        description='Reverse data stream and write to STDOUT. That\'s it.')
    parser.add_argument('infile', type=argparse.FileType('r'), default='-',
                        help='Data stream to process '
                             '(stdin, denoted by a \'-\').')
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

    stream = bytearray(args.infile.buffer.read())
    stream.reverse()
    sys.stdout.buffer.write(stream)


if __name__ == '__main__':
    main()
