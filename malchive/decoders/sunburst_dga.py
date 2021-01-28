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

import argparse
import logging
import binascii
import base64
import zlib

__version__ = "1.0.0"
__author__ = "Jason Batchelor"

log = logging.getLogger(__name__)

GUID_SIZE = 16


def sunburst_unzip(s):
    b64 = base64.b64decode(s)
    return zlib.decompress(b64, -15)


# rq3gsalt6u1iyfzop572d49bnx8cvmkewhj
sub_table = \
    sunburst_unzip(b'Kyo0Ti9OzCkxKzXMrEyryi8wNTdKMbFMyquwSC7LzU4tz8gCAA==')

# 0_-.
sub_table2 = \
    sunburst_unzip(b'M4jX1QMA')

# ph2eifo3n5utg1j8d94qrvbmk0sal76c
sub_table3 = \
    sunburst_unzip(b'K8gwSs1MyzfOMy0tSTfMskixNCksKkvKzTYoTswxN0sGAA==')


# implementation guidance
# https://blog.prevasio.com/2020/12/sunburst-backdoor-part-ii-dga-list-of.html
def sunburst_cipher_decode(data):
    encoded = bytearray(data.encode('ascii'))
    decoded = bytearray()

    i = 0
    while i < len(encoded):
        n = sub_table2.find(encoded[i])
        if n < 0:
            decoded.append(sub_table[(sub_table.find(encoded[i]) - 4)
                                     % len(sub_table)])
        elif i + 1 < len(encoded):
            n = sub_table.find(encoded[i + 1])
            decoded.append(sub_table2[n % 4])
            i += 1
        i += 1
    return decoded


def sunburst_cipher_decode_base32(data):

    encoded = bytearray(data.encode('ascii'))
    decoded = bytearray()
    decoded_len = len(encoded) * 5 // 8

    bit_buff = (sub_table3.find(encoded[0]) | sub_table3.find(encoded[1]) << 5)
    if len(encoded) < 3:
        decoded.append(bit_buff & 0xff)
        return decoded

    bits_in_buff = 10
    curr_idx = 2
    for i in range(0, decoded_len):
        decoded.append(bit_buff & 0xff)
        bit_buff >>= 8
        bits_in_buff -= 8
        while bits_in_buff < 8 and curr_idx < len(encoded):
            bit_buff |= (sub_table3.find(encoded[curr_idx]) << bits_in_buff)
            curr_idx += 1
            bits_in_buff += 5
    return decoded


def get_decoded_guid(data):

    decoded = sunburst_cipher_decode_base32(data)

    key = decoded[0]
    for i in range(1, len(decoded)):
        decoded[i] ^= key

    guid = binascii.hexlify(decoded[1:(GUID_SIZE//2) + 1])
    return guid


def process_dga_file(data, fname):

    results = []
    for line in data:
        data = line.rstrip().split(".")[0]
        if len(data) > GUID_SIZE:
            guid = get_decoded_guid(data[:16])
            candidate = data[16:]

            if candidate.startswith('00'):
                decoded = sunburst_cipher_decode_base32(candidate[2:])
            else:
                decoded = sunburst_cipher_decode(candidate)
            results.append((
                fname,
                line.rstrip(),
                guid.decode('ascii').upper(),
                decoded.decode('ascii')))
    return results


def initialize_parser():
    parser = argparse.ArgumentParser(
        description='Process list of SUNBURST DGA domains. The list must be'
                    ' full domain queries separated by newlines. Default '
                    'output in csv.')
    parser.add_argument('candidates',
                        metavar='FILE',
                        nargs='*',
                        help='candidate file(s).')
    parser.add_argument('-v', '--verbose',
                        action='store_true',
                        default=False,
                        help='Output additional information when processing '
                             '(mostly for debugging purposes).')
    parser.add_argument('-t', '--table',
                        action='store_true',
                        default=False,
                        help='Show results in a table.')
    parser.add_argument('-u', '--unique',
                        action='store_true',
                        default=False,
                        help='Show only results unique to decoded GUID and'
                             ' try to assemble original name.')

    return parser


def main():

    import os
    from tabulate import tabulate
    import operator

    p = initialize_parser()
    args = p.parse_args()

    root = logging.getLogger()
    logging.basicConfig()
    if args.verbose:
        root.setLevel(logging.DEBUG)
    else:
        root.setLevel(logging.WARNING)

    dga_decode = []
    collapse = {}
    for filename in args.candidates:

        log.info('Processing file %s...' % filename)
        basename = os.path.basename(filename)

        if not os.path.isfile(filename):
            log.warning('Failed to find file %s' % filename)
            continue

        f = open(filename, 'r')
        stream = f.readlines()

        dga_decode.extend(process_dga_file(stream, basename))

    if len(dga_decode) == 0:
        print('No decodes found!')

    # remove duplicates
    dga_decode = [t for t in (set(tuple(i) for i in dga_decode))]
    # sort by guid
    dga_decode = sorted(dga_decode, key=operator.itemgetter(2))

    if args.unique:
        unique = []
        for filename, encoded, guid, decoded in dga_decode:
            unique.append((guid, decoded))
        unique = [t for t in (set(tuple(i) for i in unique))]

        for guid, decoded in unique:
            if guid not in collapse.keys():
                collapse[guid] = decoded
            else:
                # try to make a good guess on where the decoded data
                # should be placed based on the size
                if len(decoded) > len(collapse[guid]):
                    collapse[guid] = decoded + collapse[guid]
                else:
                    collapse[guid] += decoded

        dga_decode = [(k, v) for k, v in collapse.items()]

    if args.table:
        if args.unique:
            print(tabulate(dga_decode,
                           headers=["Guid", "Decoded"],
                           tablefmt="grid"))
        else:
            print(tabulate(dga_decode,
                           headers=["Filename", "Encoded", "Guid", "Decoded"],
                           tablefmt="grid"))
    else:
        if args.unique:
            for guid, decoded in dga_decode:
                print('%s,%s' % (guid, decoded))
        else:
            for filename, encoded, guid, decoded in dga_decode:
                print('%s,%s,%s,%s' % (filename, encoded, guid, decoded))


if __name__ == '__main__':
    main()
