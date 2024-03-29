plaintexts = {
    'DosModeHeader': [
        # Beginning DOS header
        bytearray(b'\x4d\x5a\x90\x00\x03\x00\x00\x00\x04\x00'
                  b'\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00'
                  b'\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00'
                  b'\x00\x00'),
        # DOSMODE text
        bytearray(b'\x54\x68\x69\x73\x20\x70\x72\x6f\x67\x72'
                  b'\x61\x6d\x20\x63\x61\x6e\x6e\x6f\x74\x20'
                  b'\x62\x65\x20\x72\x75\x6e\x20\x69\x6e\x20'
                  b'\x44\x4f\x53\x20\x6d\x6f'),
        # WIN32 text
        bytearray(b'\x54\x68\x69\x73\x20\x70\x72\x6f\x67\x72'
                  b'\x61\x6d\x20\x6d\x75\x73\x74\x20\x62\x65'
                  b'\x20\x72\x75\x6e\x20\x75\x6e\x64\x65\x72'
                  b'\x20\x57\x69\x6e\x33\x32')
        ],
}
