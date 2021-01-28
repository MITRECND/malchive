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

import camellia
import socket
import struct
from random import choice, randint

__version__ = "1.0.0"
__author__ = "Jason Batchelor"


# Simple test illustrating who one might emulate the initial
# negotiation for SPIVY.


HOST = '10.10.10.1'
PORT = 8080
PASSWORD = 'admin'

key_size = 32


def fake_challenge_response(request, key=PASSWORD):

    if len(key) < key_size:
        key += '\x00' * (key_size - len(key))

    junk_size = randint(1, 16)

    junk_data = bytearray(
            [
                choice([i for i in range(0, 256)])
                for i in range(0, junk_size)
            ])

    challenge_request = request[-0x100:]

    c = camellia.CamelliaCipher(bytes(key.encode('utf-8')),
                                mode=camellia.MODE_ECB)

    challenge_response = c.encrypt(challenge_request)

    payload = \
        struct.pack('B', junk_size) + \
        junk_data + \
        struct.pack('B', (junk_size*2 & 0xff)) + \
        challenge_response

    return payload


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        while True:
            data = conn.recv(1024)
            resp = fake_challenge_response(data)
            if not data:
                break
            conn.sendall(resp)
