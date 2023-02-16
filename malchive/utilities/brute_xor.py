#!/usr/bin/python

import logging
import binascii
import argparse
from operator import itemgetter
from tabulate import tabulate
from malchive.helpers.crypt_plaintexts import plaintexts

__version__ = "1.0.0"

log = logging.getLogger(__name__)


def hamming_distance(x, y):

    xor_bytes = bytearray()
    for i in range(0, len(x)):
        xor_bytes.append(x[i] ^ y[i])
    bin_str = ''.join(format(byte, '08b') for byte in xor_bytes)
    return bin_str.count('1')


def get_key_sizes(buff, max_key_size=25):

    results = []
    top_n_avg_hd = []
    for key_size in range(2, max_key_size):
        t, avg_hd, n_avg_hd = 0, 0, 0
        c = 1
        for i in range(0, len(buff), key_size):
            if i + (key_size * 2) > len(buff):
                break
            s1 = buff[i:i + key_size]
            s2 = buff[i + key_size:i + (key_size * 2)]
            c += 1
            t += hamming_distance(s1, s2)
        avg_hd = t / c
        n_avg_hd = avg_hd / key_size
        results.append((key_size, avg_hd, n_avg_hd))

    log.info('Top Normalized Average Hamming Distances...')
    for k, hd, nhd in sorted(results, key=itemgetter(2))[:5]:
        log.info("Key Size: {:3d}\tAvg HD: {:5.2f}"
                 "\tNAvg HD: {:f}".format(k, hd, nhd))
        top_n_avg_hd.append(k)
    return top_n_avg_hd


def check_repeat(x, k):

    if k*4 < len(x):
        # for small key sizes, do some
        # extra checks
        return x[:k] == x[k:k*2] and \
               x[k:k*2] == x[k*2:k*3] and \
               x[k*2:k*3] == x[k*3:k*4]
    elif k*2 < len(x):
        return x[:k] == x[k:k*2]
    elif k < len(x):
        # if buffer is larger than key*2,
        # still try to compare the difference
        c = k*2 - len(x)
        return x[:k-c] == x[k:k*2-c]

    # candidate key needs to be
    # bigger than the plaintext
    return False


def derive_key(crypt_offset, key_size, key_data):

    key = bytearray()
    pos = key_size - (crypt_offset % key_size)
    key = key_data[pos:key_size] + key_data[:pos]
    if len(key) != key_size:
        log.info('Failed to derive all key bytes')

    # check if key is repeated
    # happens for key sizes that are multiples
    # of the true size
    temp = (key + key).find(key, 1, -1)
    if temp != -1:
        key = key[:temp]
    return key


def brute_key(buff, pt, key_sizes):

    key = bytearray()
    pl = len(pt)

    # crypt derivation
    for d in range(0, len(pt)):
        chunks = [buff[i+d:i+d+pl]
                  for i in range(0, len(buff), pl)
                  if len(buff[i+d:i+d+pl]) == pl]

        c = 0
        for chunk in chunks:
            offset = c * pl + d
            x = bytearray()
            for b in range(0, len(chunk)):
                x.append(chunk[b] ^ pt[b % len(pt)])
            for k in key_sizes:
                if check_repeat(x, k):
                    key = derive_key(offset, k, x)
                    return key
            c += 1

    return key


def hunt_xor_key(buff,
                 offset=0,
                 sample_size=1024,
                 myplaintexts=plaintexts):

    results = []

    if offset > len(buff) or offset < 0:
        raise IndexError('Invalid start position supplied. Exceeds '
                         'range of supplied buffer.')

    total_size = offset + sample_size
    if total_size > len(buff) or total_size < offset:
        raise IndexError('Invalid size position supplied. '
                         'Exceeds range of supplied parameters.')

    sample_space = buff[offset:offset + sample_size]
    key_sizes = get_key_sizes(sample_space)
    for name, pts in myplaintexts.items():
        for pt in pts:
            key = brute_key(buff[offset:], pt, key_sizes)
            if len(key) and key.count(b'\x00') != len(key):
                results.append((name, key))
                break
    return results


def autoint(x):

    if x.startswith('0x'):
        x = int(x, 16)
    else:
        x = int(x)
    return x


def initialize_parser():
    parser = argparse.ArgumentParser(
        description='Process candidate and attempt to brute force an'
                    ' XOR key using hamming distance, coincidence '
                    ' index, and known plaintext. Prints results'
                    ' in table format. Key is computed based on'
                    ' the start of the offset specified.')
    parser.add_argument('candidates', metavar='FILE', nargs='*',
                        help='candidate file(s).')
    parser.add_argument('-o', '--offset',
                        type=autoint,
                        default=0,
                        help='Starting point within the supplied buffer to '
                             'begin sampling the data. Should represent '
                             'a rough idea where the XOR\'d data starts. '
                             'Defaults to start of file.')
    parser.add_argument('-s', '--sample-size',
                        type=autoint,
                        default=1024,
                        help='The total number of bytes to sample for '
                             'candidate key size. This should comprise '
                             'an area you know to be encrypted with '
                             'XOR. Defaults to 1024.')
    parser.add_argument('-v', '--verbose', action='store_true', default=False,
                        help='Output additional information when processing '
                             '(mostly for debugging purposes).')
    return parser


def main():
    import os

    p = initialize_parser()
    args = p.parse_args()

    root = logging.getLogger()
    logging.basicConfig()
    if args.verbose:
        root.setLevel(logging.DEBUG)
    else:
        root.setLevel(logging.WARNING)

    results = []
    # Iterate through list of files in bulk.
    for filename in args.candidates:

        log.info('Processing file %s...' % filename)
        entries = []
        key_ascii = "-"
        key_hex = "-"

        if not os.path.isfile(filename):
            log.warning('Failed to find file %s' % filename)
            continue

        with open(filename, 'rb') as f:
            entries.extend(hunt_xor_key(f.read(),
                                        args.offset,
                                        args.sample_size))

        if len(entries) == 0:
            log.info('No matches found for %s' % filename)
            continue

        for name, key in entries:
            if key.isascii():
                key_ascii = key.decode('ascii')
            key_hex = "0x%s" % binascii.hexlify(key).decode('ascii')
            results.append((os.path.basename(filename), name,
                            key_ascii, key_hex, len(key)))

    if len(results) > 0:
        print(tabulate(results,
                       headers=["File", "Pattern", "Ascii XOR Key",
                                "Hex XOR Key", "Size"],
                       tablefmt="grid"))


if __name__ == '__main__':
    main()
