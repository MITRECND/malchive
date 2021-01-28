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
import re
import sys
import struct
import sqlite3
import logging
import argparse
import operator
import datetime
from tabulate import tabulate

__version__ = "1.0.0"
__author__ = "Jason Batchelor"

log = logging.getLogger(__name__)

SQLITE_MAX_VARIABLE_NUMBER = 999


def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for x in range(0, len(l), n):
        yield l[x:x + n]


def initialize_parser():
    parser = argparse.ArgumentParser(
        description='Searches supplied shellcode binary for any API hash '
                    'matches. Results are displayed as a table denoting '
                    'function and hash matches.')
    parser.add_argument('file', metavar='FILE',
                        help='Binary file containing shellcode.')
    parser.add_argument('-db', '--database-name', type=str, default=None,
                        help='Name of the database to reference for hashes. '
                             'Will search the data directory located '
                             'in the same path as the executing script unless '
                             'an alternate name is provided '
                             '(default: data/apihashes.db).')
    parser.add_argument('-v', '--verbose', action='store_true', default=False,
                        help='Output additional information when processing '
                             '(mostly for debugging purposes).')

    return parser


def main():

    p = initialize_parser()
    args = p.parse_args()
    logging.basicConfig()

    root = logging.getLogger()
    logging.basicConfig()
    if args.verbose:
        root.setLevel(logging.DEBUG)
    else:
        root.setLevel(logging.WARNING)

    database = args.database_name
    if database is None:
        database = os.path.dirname(os.path.abspath(__file__)) + \
                   '/data/apihashes.db'
    else:
        database = args.database_name

    sc = args.file
    if not os.path.isfile(database):
        log.error('Failed to find hash database %s, exiting...' % database)
        sys.exit(2)

    if not os.path.isfile(sc):
        log.error('Failed to find provided shellcode file %s, exiting...' % sc)
        sys.exit(2)

    buff = ''
    with open(sc, 'rb') as f:
        buff = f.read()

        if len(buff) < 4:
            log.error('Supplied file must be at least four bytes. Exiting...')
            sys.exit(2)

        f.close()

    log.info('Processing %s...' % os.path.basename(sc))

    i = 0
    candidates = []
    start = datetime.datetime.now()
    while i < len(buff) - 3:
        candidates.append(struct.unpack('<I', buff[i:i + 4])[0])
        i += 1

    num_candidates = len(candidates)
    candidates = list(chunks(candidates, SQLITE_MAX_VARIABLE_NUMBER))
    conn = sqlite3.connect(database)
    cursor = conn.cursor()

    rows = []
    for c in candidates:
        cursor.execute(
            "SELECT * FROM apihashes WHERE Hash IN ({0})"
            .format(', '.join('?' for _ in c)), c)
        result = cursor.fetchall()
        if len(result) != 0:
            rows.extend(result)

    cursor.close()
    conn.close()

    # deduplication of results
    rows = set(rows)

    results = []
    # change format of hash, and locate all recovered offsets
    for alg, lib, func, hash in rows:
        search = struct.pack("<I", hash)
        # find all the offsets for each match
        offsets = '\n'.join([hex(m.start())
                             for m in re.finditer(re.escape(search), buff,
                                                  re.DOTALL)])
        results.append([alg, lib, func, hex(hash), offsets])

    results = sorted(results, key=operator.itemgetter(0, 1, 2, 4))

    if len(results) > 0:
        print(tabulate(results,
                       headers=["Algorithm", "Library", "Function",
                                "Hash", "Offset(s)"],
                       tablefmt="grid"))
    else:
        print('No results were found in %s.' % sc)
    end = datetime.datetime.now()
    log.info('Processed %s candidate(s) in %s...' %
             (num_candidates, end - start))


if __name__ == '__main__':
    main()
