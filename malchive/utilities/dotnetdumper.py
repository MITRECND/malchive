#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2019 Wesley Shields. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

import argparse
import logging
import os
import struct
import sys

import yara


__version__ = "1.0.0"
__author__ = "Wesley Shields"
__contributor__ = "Mike Goffin"

log = logging.getLogger(__name__)

# It is really important you read this!
# Documentation on the manifest resource file format:
# http://www.ntcore.com/files/manifestres.htm


class YaraScanner:
    """
    Uses YARA to identify potential embedded .NET content

    :ivar list results: List of tuples for each entry, indicating the given
    filename by the class and data.
    """

    RSRC_MAGIC = 0xBEEFCACE

    def __init__(self, filename, data):
        self.filename = filename
        self.results = []
        self.metadata = {}
        self.data = data

        try:
            rule = 'import "dotnet" rule a { condition: false }'
            self.rules = yara.compile(source=rule)
        except yara.SyntaxError as e:
            log.error(f"Exception while compiling dotnet rule: {e}")
            log.error("Do you have the YARA dotnet module compiled in?")
            sys.exit(1)

    def parse_manifest_resource(self, rsrc, rsrc_length):
        # We must have at least 12 bytes to start parsing...
        if rsrc_length < 12:
            return

        name_len = struct.unpack("<I", rsrc[8:12])[0]
        # Skip the version field (4 extra bytes)
        offset = name_len + 16
        if offset >= rsrc_length:
            return

        (num_rsrcs, num_types) = struct.unpack("<II", rsrc[offset:offset + 8])
        type_offset = offset + 8
        i = 0
        while i < num_types:
            i += 1
            # We don't actually care what these bytes are but we have to find
            # the first one with the high bit unset, which is the last one.
            type_byte = \
                struct.unpack("B", rsrc[type_offset:type_offset + 1])[0]
            type_offset += 1
            if type_byte & 0x80:
                break

        # Skip over: padding bytes, hashes, name offsets. This brings us to the
        # data section offset. This value is the base offset for all resources.
        offset = type_offset + (8 - type_offset % 8) + (num_rsrcs * 8)
        data_section_offset = \
            struct.unpack("<I", rsrc[offset:offset + 4])[0]
        offset += 4

        # Skip the resource names. The first byte is the length of the name.
        # But grab the offsets after each name. These offsets are added to the
        # data_section_offset above.
        i = 0
        data_offsets = []
        while i < num_rsrcs:
            name_len = struct.unpack("B", rsrc[offset:offset + 1])[0]
            offset += 1 + name_len
            data_offset = struct.unpack("<I", rsrc[offset:offset + 4])[0]
            data_offsets.append(data_offset)
            offset += 4
            i += 1

        # The data_section_offset plus each of the data_offsets gives us the
        # location of each resource. The first byte there is a type index, then
        # there is a dword for the length, then the data.
        for data_offset in data_offsets:
            final_offset = data_section_offset + data_offset + 1
            if final_offset + 4 >= rsrc_length:
                break
            data_len = \
                struct.unpack("<I", rsrc[final_offset:final_offset + 4])[0]
            final_offset += 4

            yield rsrc[final_offset:final_offset + data_len]

    def add_to_result(self, _type, data: bytes) -> None:
        filename = f"{self.filename}.{_type}_bin_{len(self.results)}"
        self.results.append((filename, data))

    def modules_callback(self, data):
        self.metadata = data
        for rsrc_dict in data.get("resources", []):
            rsrc_offset = rsrc_dict["offset"]
            rsrc_length = rsrc_dict["length"]

            # Check if this is a manifest resource, or if it's the variant that
            # is a generic encrypted, compressed blob.
            if rsrc_length < 4:
                log.info(f"Resource at {rsrc_offset:0x} too small to parse.")
                continue

            rsrc = self.data[rsrc_offset:rsrc_offset + rsrc_length]
            magic = struct.unpack("<I", rsrc[:4])[0]
            if magic == self.RSRC_MAGIC:
                for r in self.parse_manifest_resource(rsrc, rsrc_length):
                    if r is not None:
                        self.add_to_result('rsrc', r)
            else:
                self.add_to_result('rsrc', rsrc)

        for stream in data.get("streams", []):
            stream_data = \
                self.data[stream['offset']:stream['offset'] + stream['size']]
            stream_name = \
                str(stream['name']).replace('\'', '').replace('b#', '#')
            self.add_to_result(f'stream_{stream_name}', stream_data)

        return yara.CALLBACK_CONTINUE

    def match(self):
        self.rules.match(data=self.data,
                         modules_callback=self.modules_callback)


def initialize_parser():
    parser = argparse.ArgumentParser(
        description="Dump netz resources and streams to file.")
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Output additional information when processing.",
    )
    parser.add_argument(
        "infile",
        metavar="FILE",
        nargs="*",
        help="Full path to the file to be processed.",
    )
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
        sys.exit(1)

    for filename in args.infile:
        log.info(f"Retrieving {filename} resources and streams...")
        if not os.path.isfile(filename):
            log.warning("Failed to find file {filename}. Skipping...")
            continue

        with open(filename, "rb") as f:
            scanner = YaraScanner(filename, f.read())
            scanner.match()

        for filename, data in scanner.results:
            print(f"Writing {filename} ({len(data)})")
            with open(filename, "wb") as f:
                f.write(data)


if __name__ == "__main__":
    main()
