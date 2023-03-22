#!/usr/bin/python

import argparse
import logging
import struct
import re

__version__ = "1.0.0"

log = logging.getLogger(__name__)

# Reference:
# https://github.com/MythicAgents/Apollo
# Reference sample:
# https://www.virustotal.com/gui/file/f78628c0ecca360a4c9d33f67bf394955c8b89929e9ca611e2f2dbe6e170ece5


class GetConfig:

    def __init__(self, buff):
        """
        Initialize decoder instance.

        :param bytes buff: The stream of bytes to be processed.
        """

        self.buff = buff
        self.elements = []
        self.parse_config()

    def parse_config(self):

        parameters = {
                      'callback_interval': "",
                      'callback_jitter': "",
                      'callback_port': "",
                      'callback_host': "",
                      'post_uri': "",
                      'encrypted_exchange_check': "",
                      'proxy_host': "",
                      'proxy_port': "",
                      'proxy_user': "",
                      'proxy_pass': "",
                      'killdate': "",
                      'User-Agent': "",
                      }

        pRex = []
        for k, v in parameters.items():
            pRex.append(k.encode('utf-16').strip(b'\xFF\xFE'))

        r = re.compile(
                       pRex[0] + b"(.*?)" +
                       pRex[1] + b"(.*?)" +
                       pRex[2] + b"(.*?)" +
                       pRex[3] + b"(.*?)" +
                       pRex[4] + b"(.*?)" +
                       pRex[5] + b"(.*?)" +
                       pRex[6] + b"(.*?)" +
                       pRex[7] + b"(.*?)" +
                       pRex[8] + b"(.*?)" +
                       pRex[9] + b"(.*?)" +
                       pRex[10] + b"(.*?)" +
                       pRex[11] + b"(.*?)" +
                       b'\x00\x00'
                      )

        m = re.search(r, self.buff)
        if not m:
            log.debug('No match on config regex...')
            return

        for index in range(1, m.lastindex + 1):

            data = m.group(index)
            size = struct.unpack_from('>H', data)[0]

            value = data[0x2:0x2 + size].decode('utf-8').replace('\x00', '')
            key = pRex[index - 1].decode('utf-8').replace('\x00', '')
            parameters[key] = value

        self.elements = parameters


def initialize_parser():
    parser = argparse.ArgumentParser(
        description='Process candidate. Prints results in JSON format.')
    parser.add_argument('candidates', metavar='FILE',
                        nargs='*', help='candidate file(s).')
    parser.add_argument('-v', '--verbose', action='store_true',
                        default=False,
                        help='Output additional information when processing '
                             '(mostly for debugging purposes).')
    return parser


def main():
    import os
    import json
    import hashlib
    import pefile

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

        f = open(filename, 'rb')
        stream = f.read()

        try:
            pefile.PE(data=stream)
        except pefile.PEFormatError:
            log.warning('%s not a pe, skipping...' % f.name)
            continue

        d = GetConfig(stream)

        config_dict = {
            'Sha256': hashlib.sha256(stream).hexdigest(),
            'Config': d.elements
        }

        try:
            print(json.dumps(config_dict, indent=4, sort_keys=False))
        except UnicodeDecodeError:
            log.warning('There was a Unicode decoding error when '
                        'processing %s' % os.path.basename(filename))
            continue


if __name__ == '__main__':
    main()
