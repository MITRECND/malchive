#!/usr/bin/python

import argparse
import logging

__version__ = "1.0.0"

log = logging.getLogger(__name__)

# Reference:
# https://blog.xorhex.com/blog/mustangpandaplugx-1/
# Reference sample:
# https://www.virustotal.com/gui/file/589e87d4ac0a2c350e98642ac53f4940fcfec38226c16509da21bb551a8f8a36


class ExtractBinFile:
    """
    Carve and extract RZStreet encrypted PE file.

    :ivar bytearray decrypted: Decrypted data stream.
    :ivar list key: Multibyte key value used to decrypt.
    """

    def __init__(self, data):
        self.buff = data
        self.key = []
        self.decrypted = bytearray()

        if self.get_rz_payload():
            log.debug('Payload extraction success!')

    def get_rz_payload(self):

        dec = bytearray()
        offset = self.buff.find(b'\x00')
        if offset > 0x100:
            log.debug('Null offset to large to be RZStreet.')
            return False

        crypted = self.buff[offset + 1:]
        self.key = bytearray(self.buff[:offset])

        for i in range(0, len(crypted)):
            dec.append(crypted[i] ^ self.key[i % len(self.key)])

        if dec.startswith(b'\x4d\x5a\xe8\x00\x00\x00\x00\x5b'):
            self.decrypted = dec
            return True
        else:
            log.debug('Decrypted content did not match RZStreet PIC')
            return False


def initialize_parser():
    parser = argparse.ArgumentParser(
        description='Process candidate. Prints results in table format.')
    parser.add_argument('candidates', metavar='FILE', nargs='*',
                        help='candidate file(s).')
    parser.add_argument('-v', '--verbose', action='store_true', default=False,
                        help='Output additional information when processing '
                             '(mostly for debugging purposes).')
    parser.add_argument('-w', '--write', action='store_true',
                        help='Write the file(s) to disk with MD5 hash '
                             'and \'_rz\' prefix of the provided sample.')
    return parser


def main():
    import os
    import hashlib
    import binascii
    import json

    p = initialize_parser()
    args = p.parse_args()

    root = logging.getLogger()
    logging.basicConfig()
    if args.verbose:
        root.setLevel(logging.DEBUG)
    else:
        root.setLevel(logging.WARNING)

    # Iterate through list of files in bulk.
    for filename in args.candidates:

        log.info('Processing file %s...' % filename)

        if not os.path.isfile(filename):
            log.warning('Failed to find file %s' % filename)
            continue

        with open(filename, 'rb') as f:
            rz = ExtractBinFile(f.read())

        if len(rz.decrypted) == 0:
            log.info('No decrypted content found in candidate.')
            continue

        sha256 = hashlib.sha256(rz.buff).hexdigest()
        results = {
            'Sha256': sha256,
            'XOR Key': '0x%s' % binascii.hexlify(rz.key).decode('ascii'),
            'Decrypted Sha256': hashlib.sha256(rz.decrypted).hexdigest(),
            'Decrypted Size': len(rz.decrypted),
        }

        if args.write:
            with open('%s_rz' % sha256, 'wb') as f:
                f.write(rz.decrypted)

        try:
            print(json.dumps(results, indent=4, sort_keys=False))
        except UnicodeDecodeError:
            log.warning('There was a Unicode decoding error when '
                        'processing %s' % os.path.basename(filename))


if __name__ == '__main__':
    main()
