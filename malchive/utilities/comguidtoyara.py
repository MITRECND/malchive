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

import re
import os
import sys
import struct
import binascii
import logging
import argparse
import progressbar
from datetime import datetime
from Registry import Registry

__version__ = "1.0.0"
__author__ = "Jason Batchelor"

log = logging.getLogger(__name__)


def iid_text_to_bin(iid):
    """
    Process an IID and convert to a YARA compliant search string.

    Below describes the GUID structure used to describe an identifier
    for a MAPI interface:

    https://msdn.microsoft.com/en-us/library/office/cc815892.aspx

    :param str iid: Name of the IID to convert

    :return: bin_yara
    :rtype: str
    """

    # remove begin and end brackets
    guid = re.sub('[{}-]', '', iid)
    # convert to binary representation
    bin_struc = struct.unpack("IHH8B", binascii.a2b_hex(guid))
    bin_str = '%.8X%.4X%.4X%s' % \
              (bin_struc[0], bin_struc[1], bin_struc[2],
               (''.join('{:02X}'.format(x) for x in bin_struc[3:])))
    # create YARA compliant search string
    bin_yara = '{ ' + ' '.join(a + b for a, b in
                               zip(bin_str[::2], bin_str[1::2])) + ' }'

    return bin_yara


def enumerate_com_interfaces(reg_keys, show_bar=False):
    """
    Iterate through registry keys and retrieve unique interface identifiers
    and their name.

    :param list reg_keys: List of registry key objects from python-registry
    module.
    :param bool show_bar: Show progressbar as subfiles are identified.
    :param bytes buff: File to look for subfiles.

    :return: com
    :rtype: dict
    """

    total_iters = 0
    counter = 0
    com = {}

    for key in reg_keys:
        total_iters += len(key.subkeys())

    if show_bar:
        print('Processing %s results...' % total_iters)
        bar = progressbar.ProgressBar(redirect_stdout=True,
                                      max_value=total_iters)

    for key in reg_keys:
        for subkey in key.subkeys():
            for v in list(subkey.values()):

                # Per MS documentation, Interface names must start with the
                # 'I' prefix, so we limit our values here as well.
                # Not doing so can lead to some crazy names and conflicting
                # results!
                # https://docs.microsoft.com/en-us/dotnet/standard/design-guidelines/names-of-classes-structs-and-interfaces
                if v.value_type() == Registry.RegSZ \
                        and v.name() == '(default)' \
                        and v.value().startswith('I'):

                    bin_guid = iid_text_to_bin(subkey.name())

                    # Names with special characters/spaces are truncated
                    stop_chars = ['_', '<', '[', ' ']
                    index = min(v.value().find(i)
                                if i in v.value()
                                else
                                len(v.value())
                                for i in stop_chars)
                    value = v.value()[:index]

                    if value not in com:
                        com[value] = [bin_guid]

                    elif bin_guid not in com[value]:
                        com[value].append(bin_guid)

            if show_bar:
                bar.update(counter)
            counter += 1

    if show_bar:
        bar.finish()

    return com


def initialize_parser():
    parser = argparse.ArgumentParser(
        description="Crawls windows registry to hunt for and convert IIDs for "
                    "COM interfaces to binary YARA signatures. The submitted "
                    "hives must be from HKLM\\SOFTWARE. Make copies of "
                    "these files off an active Windows OS using the command "
                    "'reg save HKLM\\SOFTWARE hklm_sft.hiv' when running as "
                    "administrator.")
    parser.add_argument('hive', metavar='FILE', nargs='*',
                        help='Full path to the registry hive to be processed.')
    parser.add_argument('-o', '--output-filename', type=str,
                        default='com_interface_ids.yara',
                        help='Filename to write YARA signatures '
                             'to (default: com_interface_ids.yara)')
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

    if len(args.hive) == 0:
        p.print_help()
        sys.exit(2)

    keys = []
    for hive in args.hive:

        print('Collecting IIDs from %s...' % hive)

        if not os.path.isfile(hive):
            log.warning('Failed to find file %s. Skipping...' % hive)
            continue

        try:
            reg = Registry.Registry(hive)
        except Registry.RegistryParse.ParseException:
            log.warning('Error parsing %s. Skipping...' % hive)
            continue

        try:
            keys.append(reg.open("Classes\\Interface"))
        except Registry.RegistryKeyNotFoundException:
            log.warning("Couldn't find 'Classes\\Interface' key in %s." % hive)

        try:
            keys.append(reg.open("Classes\\Wow6432Node\\Interface"))
        except Registry.RegistryKeyNotFoundException:
            log.warning("Couldn't find 'Classes\\Wow6432Node\\Interface\\ "
                        "key in %s." % hive)

    com_signatures = enumerate_com_interfaces(keys, True)

    counter = 0
    total_rules = len(com_signatures)
    print('Generating %s YARA signatures...' % total_rules)

    bar = progressbar.ProgressBar(redirect_stdout=True, max_value=total_rules)
    yara_rule = '// %s\n// COM IID YARA sig collection.\n// ' \
                'Autogenerated on %s\n\n' % (__author__, datetime.now())
    for name, rules in com_signatures.items():
        yara_rule += 'rule %s\n{\n\t' \
                     'strings:' % name
        if len(rules) > 1:
            for i in range(0, len(rules)):
                yara_rule += '\n\t\t$%s_%s = %s' % (name, i, rules[i])
        else:
            yara_rule += '\n\t\t$%s = %s' % (name, rules[0])

        yara_rule += '\n\tcondition:\n\t\tany of them\n}\n'

        bar.update(counter)
        counter += 1
    bar.finish()

    print('Writing YARA rules to %s' % args.output_filename)
    with open(args.output_filename, 'w') as f:
        f.write(yara_rule)
        f.close()


if __name__ == '__main__':
    main()
