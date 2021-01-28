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
import json
import logging
import argparse
import binascii
import pefile
import hashlib
import difflib
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_16, CS_MODE_32, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

__version__ = "1.0.0"
__author__ = "Jason Batchelor"

log = logging.getLogger(__name__)

# Reference:
# https://wiki.osdev.org/X86-64_Instruction_Encoding#Legacy_Prefixes
MAX_PREFIX_SIZE = 4


def _to_yara_hex_string(b, wildcards=None):
    """
    Generate a YARA compliant hex string that is consumable by YARA.
    """
    b = binascii.hexlify(b).decode('utf-8')
    hex_string = ' '.join(a + b for a, b in zip(b[::2], b[1::2]))

    if wildcards is None:
        return hex_string

    hex_list = hex_string.split(' ')
    for offset, size in wildcards:
        # get rid of unnecessary ??'s at the end
        if offset + size == len(hex_list):
            hex_list = hex_list[:offset]
            break
        for i in range(offset, offset + size):
            if i == offset:
                hex_list[i] = '[%s]' % size
            else:
                hex_list[i] = '??'

    # remove ??s now that we've identified them
    hex_list = list(filter('??'.__ne__, hex_list))
    # aesthetically '??' instead of '[1]' seems like a better output
    hex_list = ['??' if x == '[1]' else x for x in hex_list]

    return ' '.join(hex_list)


def _get_opcode_length(op):
    """
    Get length of operand bytes.
    """
    while not op[-1]:
        # encountered bug for the following
        # 00 04 31      add     byte ptr [rcx + rsi], al
        if len(op) == 1:
            break
        op.pop()
    return len(op)


def generate_yara_rule(rule, name):
    """
    Print a compliant YARA rule using supplied data.

    :param str rule: YARA compliant hex string sequence.
    :param str name: Name of the rule.

    :return: str yara_syntax: Created YARA rule.
    :rtype: str
    """

    meta = ''

    meta_filename = '%s/.gensig.json' % Path.home()
    if os.path.isfile(meta_filename):
        try:
            with open(meta_filename) as f:
                meta_json = json.load(f)
            meta = 'meta:\n'
            for k in meta_json:
                meta += '        %s = \"%s\"\n' % (k, meta_json[k])
            meta += '\n    '
        except json.JSONDecodeError:
            log.error('JSON in %s not valid!' % meta_filename)

    yara_syntax = 'rule %s\n{\n    ' \
                  '%s' \
                  'strings:\n        ' \
                  '$code = %s\n\n    ' \
                  'condition:\n        ' \
                  '$code\n}\n' % (name, meta, rule)

    return yara_syntax


def generate_mnemonic(buff, mode):
    """
    Return a mnemonic only result of the byte sequence.

    :param bytes buff: Complete data stream.
    :param int mode: Capstone hardware mode.

    :return: YARA compliant hex string sequence.
    :rtype: str
    """

    md = Cs(CS_ARCH_X86, mode)
    md.detail = True
    mnemonic_tracker = []

    for insn in md.disasm(buff, 0x0):
        op_len = _get_opcode_length(insn.opcode)
        offset = insn.address + op_len

        r_size = len(insn.bytes) - op_len
        mnemonic_tracker.append((offset, r_size))

    hex_bytes = '{ ' + _to_yara_hex_string(buff, mnemonic_tracker) + ' }'
    return hex_bytes


def generate_pic(buff, mode):
    """
    Return a position independent result of the byte sequence.

    :param bytes buff: Complete data stream.
    :param int mode: Capstone hardware mode.

    :return: YARA compliant hex string sequence.
    :rtype: str
    """

    md = Cs(CS_ARCH_X86, mode)
    md.detail = True

    relative_tracker = []
    relative = False
    offset = 0

    for insn in md.disasm(buff, 0x0):

        if relative:
            r_size = insn.address - offset
            relative_tracker.append((offset, r_size))
            relative = False

        if insn.op_count(X86_OP_IMM) == 1 or insn.op_count(X86_OP_MEM) == 1:

            offset = insn.address + _get_opcode_length(insn.opcode)
            relative = True

            if insn.modrm > 0:
                offset += 1
            if insn.rex > 0:
                offset += 1
            if insn.sib > 0:
                offset += 1

            offset += MAX_PREFIX_SIZE - insn.prefix.count(0x0)

            continue

    if relative:
        r_size = len(buff) - offset
        relative_tracker.append((offset, r_size))

    hex_bytes = '{ ' + _to_yara_hex_string(buff, relative_tracker) + ' }'
    return hex_bytes


def gen_ndiff(a, b):
    """
    Return a binary diff result of the byte sequence as a YARA signature.

    :param list a: First buffer representing code block as hexlified bytes.
    :param list b: Second buffer representing code block as hexlified bytes.

    :return: YARA compliant hex string sequence.
    :rtype: str
    """

    diff = difflib.ndiff(a, b)

    commons = []
    start = 0
    end = 0
    start_code = None
    end_code = None
    for d in diff:
        code = d[0:2]
        seq = d[2:]
        if code == '  ':

            if start > 0 and start == end and len(commons) > 0:
                commons.append('[%s]' % start)
            if start > 0 and end == 0 and len(commons) > 0:
                commons.append('[%s-%s]' % (end, start))
            if 0 < start != end > 0 and len(commons) > 0:
                commons.append('[%s-%s]' % (start, end))

            start = 0
            end = 0
            commons.append(seq)

        if code == '- ' and start == 0:
            start_code = '- '
            end_code = '+ '
        elif code == '+ ' and start == 0:
            start_code = '+ '
            end_code = '- '

        if code == start_code:
            start += 1
        if code == end_code:
            end += 1

    return '{ ' + ' '.join(commons) + ' }'


def show_asm(buff, mode, base):
    """
    Return the given byte sequence as assembly under the given hardware mode.

    :param bytes buff: Complete data stream.
    :param int mode: Capstone hardware mode.
    :param int base: Base address from which to start.

    :return: Assembly code representation.
    :rtype: str
    """

    md = Cs(CS_ARCH_X86, mode)
    md.detail = True

    ret = ''
    for insn in md.disasm(buff, base):
        b = binascii.hexlify(insn.bytes).decode('utf-8')
        b = ' '.join(a + b for a, b in zip(b[::2], b[1::2]))
        if len(b) > 18:
            b = b[:18] + '+'
        ret += "{0:10} {1:20} {2:10} {3:10}\n".format(
            '%08x:' % insn.address, b, insn.mnemonic, insn.op_str)
    ret += '*/\n'

    return ret


def generate_strict(buff):
    """
    Return a literal interpretation of bytes as a YARA compliant hex string.

    :param bytes buff: Complete data stream.

    :return: YARA compliant hex string sequence.
    :rtype: str
    """

    hex_bytes = '{ ' + _to_yara_hex_string(buff) + ' }'
    return hex_bytes


def autoint(x):
    if x.startswith('0x'):
        x = int(x, 16)
    else:
        x = int(x)
    return x


def initialize_parser():
    parser = argparse.ArgumentParser(
        description='Generate YARA signature for x86 architectures based on '
                    'data passed. \nNumeric values may be provided as regular '
                    'integers or hexadecimal \nwith the \'0x\' prefix. \n\n'
                    'You can optionally create a file .gensig.json in your '
                    '\nhome directory with JSON data that can serve as a '
                    'template for \nrule \'meta\'.',
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-f', '--files', nargs='+', required=True,
                        help='Name of file(s) to process.')
    parser.add_argument('-s', '--start-offset', nargs='+', type=autoint,
                        default=[0],
                        help='Starting point within the supplied buffer to '
                             'begin processing. One or more offsets may\n'
                             'be provided, and are processed sequentially '
                             'with respect the list of files. For virtual\n'
                             'address offsets, please see the '
                             '--force-virtual-address flag.')
    parser.add_argument('-e', '--end-offset', nargs='+', type=autoint,
                        default=[0],
                        help='End point to stop processing. Multiple offsets '
                             'are processed in sequence with\n the list of '
                             'files. If this is not provided, it will default '
                             'to the length of the data\n minus the start '
                             'offset.')
    parser.add_argument('-g', '--generator', type=str,
                        choices=['strict', 'pic', 'mnem', 'bdiff'],
                        default='strict',
                        help='Choose how the signatures is generated from '
                             'the supplied bytes. Defaults to \'strict\'.\n'
                             '\n* Strict - Literal interpretation of bytes to '
                             'generate signature.'
                             '\n* PIC - Position Independent Code (PIC) mode '
                             'attempts to wildcard immediate and memory type '
                             'operands.'
                             '\n* Mnemonic (mnem) - Only show bytes that '
                             'reflect the represented mnemonic instruction.'
                             '\n* Bindiff (bdiff) - Compute a diff on two '
                             'binary streams and produce a YARA compliant '
                             'regex.')
    parser.add_argument('-m', '--mode', type=int, choices=[16, 32, 64],
                        default=32,
                        help='The hardware mode to use when creating the '
                             'signature. Relevant in PIC and Mnemonic modes\n'
                             '(Default: 32-bit).')
    parser.add_argument('-r', '--rule-name', type=str, default='',
                        help='The name of the rule you wish to create. '
                             'Default is [generator]_code_[yara_string_md5]')
    parser.add_argument('-va', '--force-virtual-address', action='store_true',
                        default=False,
                        help='Force interpretation of the provided offset '
                             'to be the a virtual address.')
    parser.add_argument('--suppress-asm', action='store_true', default=False,
                        help='Suppress automatically generated assembly code.')
    parser.add_argument('-w', '--write', action='store_true', default=False,
                        help='Write to disk using the rule name along '
                             'with the .yara file extension.')
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

    bindiffs = []
    # some input checks for bindiffs
    if args.generator == 'bdiff':
        if len(args.start_offset) % 2 != 0 and args.start_offset[0] != 0 or \
           len(args.end_offset) % 2 != 0 and args.end_offset[0] or \
           len(args.files) % 2 != 0:
            log.error('You must specify all file and offset arguments '
                      'for bdiff in pairs of two.')
            sys.exit(2)

    for i in range(0, len(args.files)):

        filename = args.files[i]
        log.info('Processing candidate %s...' % filename)

        if not os.path.isfile(filename):
            log.error('Failed to find file %s' % filename)
            continue

        f = open(filename, 'rb')
        stream = f.read()

        if args.start_offset[0] == 0:
            start_offset = 0
        else:
            start_offset = args.start_offset[i]

        if args.end_offset[0] == 0:
            end_offset = len(stream) - start_offset
        else:
            end_offset = args.end_offset[i]

        # get the base address before doing any necessary conversion
        # to the offset
        base_address = start_offset
        if args.force_virtual_address:
            try:
                pe = pefile.PE(data=stream)
                start_offset = pe.get_offset_from_rva(
                    start_offset - pe.OPTIONAL_HEADER.ImageBase)
                end_offset = pe.get_offset_from_rva(
                    end_offset - pe.OPTIONAL_HEADER.ImageBase)
                log.info('Processing using provided virtual address...')
            except pefile.PEFormatError:
                log.error('Invalid virtual address provided! Exiting...')
                sys.exit(2)
        else:
            log.info('Processing as raw binary data...')

        if start_offset >= end_offset or \
                end_offset > len(stream) or \
                start_offset > len(stream):
            log.error('Invalid offset provided. '
                      'Please check your offset parameters.')
            continue

        buff = stream[start_offset:end_offset]

        mode = 0
        if args.mode == 16:
            mode = CS_MODE_16
        elif args.mode == 32:
            mode = CS_MODE_32
        elif args.mode == 64:
            mode = CS_MODE_64

        if not args.suppress_asm:
            yara_syntax = '/*\nCandidate: %s\n---\n' % \
                          hashlib.md5(stream).hexdigest() \
                          + show_asm(buff, mode, base_address)
        else:
            yara_syntax = '// Candidate: %s\n' % \
                          hashlib.md5(stream).hexdigest()

        if args.generator == 'strict':
            rule = generate_strict(buff)
        elif args.generator == 'pic':
            rule = generate_pic(buff, mode)
        elif args.generator == 'bdiff':
            s = binascii.hexlify(buff).decode('utf-8')
            s = [s[i:i + 2] for i in range(0, len(s), 2)]
            bindiffs.append((s, yara_syntax))
            if len(bindiffs) == 2:
                # bindiff based on pairs
                rule = gen_ndiff(bindiffs[0][0], bindiffs[1][0])
                # show asm from both pairs
                yara_syntax = bindiffs[0][1] + bindiffs[1][1]
                bindiffs = []
            else:
                continue
        else:
            rule = generate_mnemonic(buff, mode)

        if len(args.rule_name) == 0:
            name = '%s_code_%s' % \
                   (args.generator,
                    hashlib.md5(rule.encode('utf-8')).hexdigest())
        else:
            name = args.rule_name

        yara_syntax += generate_yara_rule(rule, name)

        print(yara_syntax)
        if args.write:
            fname = '%s.yara' % name
            with open(fname, 'w+') as f:
                f.write(yara_syntax)
            log.info('%s written to disk.' % fname)


if __name__ == '__main__':
    main()
