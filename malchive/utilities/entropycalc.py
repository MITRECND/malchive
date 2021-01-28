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
import hashlib
import operator
import math
from collections import Counter
from tabulate import tabulate

__version__ = "1.0.0"
__author__ = "Jason Batchelor"

log = logging.getLogger(__name__)


# Reference:
# https://stackoverflow.com/questions/15450192/fastest-way-to-compute-entropy-in-python
def entropy(data, unit='natural'):
    """
    Compute and return the entropy of a stream of data.

    :param bytearray data: Stream to compute entropy on.
    :param str,optional unit: Passed to math.log calculation.
    Default is natural.

    :return: Entropy calculation
    :rtype: float
    """
    base = {
        'shannon': 2.,
        'natural': math.exp(1),
        'hartley': 10.
    }

    if len(data) <= 1:
        return 0

    counts = Counter()

    for d in data:
        counts[d] += 1

    probs = [float(c) / len(data) for c in list(counts.values())]
    probs = [p for p in probs if p > 0.]

    ent = 0

    for p in probs:
        if p > 0.:
            ent -= p * math.log(p, base[unit])

    return ent


def autoint(x):
    if x.startswith('0x'):
        x = int(x, 16)
    else:
        x = int(x)
    return x


def initialize_parser():
    parser = argparse.ArgumentParser(
        description='Take a series of provided files and print the entropy, '
                    'alongside other information like the filename and MD5.')
    parser.add_argument('infile', metavar='FILE', nargs='*',
                        help='Full path to the file to be processed.')
    parser.add_argument('-o', '--offset', type=autoint, default=0,
                        help='Starting point within the supplied buffer to '
                             'begin processing.')
    parser.add_argument('-s', '--size', type=autoint, default=-1,
                        help='The total number of bytes to process. Defaults '
                             'to size of supplied data.')
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
        size = args.size
        offset = args.offset

        if not os.path.isfile(fname):
            log.warning('Failed to find file %s. Skipping...' % fname)
            continue

        with open(fname, 'rb') as f:
            stream = f.read()

        if offset > len(stream) or offset < 0:
            log.error('Invalid start position supplied. Exceeds range of '
                      'supplied buffer. Skipping...')
            continue

        if size == -1:
            total_size = len(stream)
        else:
            total_size = size + offset
            if total_size > len(stream) or total_size < offset:
                log.error('Invalid size position supplied. Exceeds range of '
                          'supplied buffer. Skipping...')
                continue

        stream = stream[offset:total_size]

        md5 = hashlib.md5(stream).hexdigest()
        ent = entropy(stream, 'shannon')

        results.append((md5, basename, ent))

    results = sorted(results, key=operator.itemgetter(2, 1, 0))
    if len(results) > 0:
        print(tabulate(results, headers=["MD5", "Filename", "Entropy"],
                       tablefmt="grid"))


if __name__ == '__main__':
    main()
