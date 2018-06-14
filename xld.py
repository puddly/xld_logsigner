#!/usr/bin/env python3

import sys
import copy
import struct
import argparse


LOGCHECKER_MIN_VERSION = '20121027'
ENCODING_TABLE = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._='
MAGIC_CONSTANTS = [0x99036946, 0xe99db8e7, 0xe3ae2fa7, 0xa339740, 0xf06eb6a9, 0x92ff9b65, 0x28f7873, 0x9070e316]
MAGIC_INITIAL_STATE = 0x48853afc6479b873
DIGEST_LENGTH = 64 + len('\nVersion=0001')
WEIRD_SHA256_IV = [0x1d95e3a4, 0x06520ef5, 0x3a9cfb75, 0x6104bcae, 0x09ceda82, 0xba55e60b, 0xeaec16c6, 0xeb19af15]


class AlmostSHA256(object):
    __author__ = 'Thomas Dixon'
    __license__ = 'MIT'

    _k = (0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
          0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
          0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
          0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
          0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
          0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
          0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
          0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
          0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
          0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
          0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
          0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
          0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
          0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
          0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
          0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2)

    # Non-standard initial state
    _h = WEIRD_SHA256_IV

    def __init__(self, m=None):
        self._buffer = b''
        self._counter = 0

        if m is not None:
            self.update(m)

    def _rotate_right(self, x, y):
        return ((x >> y) | (x << (32 - y))) & 0xFFFFFFFF

    def _sha256_process(self, data):
        state = [0] * 64
        state[0:16] = struct.unpack('!16L', data)

        for i in range(16, 64):
            s0 = self._rotate_right(state[i - 15], 7) ^ self._rotate_right(state[i - 15], 18) ^ (state[i - 15] >> 3)
            s1 = self._rotate_right(state[i - 2], 17) ^ self._rotate_right(state[i - 2], 19) ^ (state[i - 2] >> 10)

            state[i] = (state[i - 16] + s0 + state[i - 7] + s1) & 0xFFFFFFFF

        a, b, c, d, e, f, g, h = self._h

        for i in range(64):
            s0 = self._rotate_right(a, 2) ^ self._rotate_right(a, 13) ^ self._rotate_right(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = s0 + maj

            s1 = self._rotate_right(e, 6) ^ self._rotate_right(e, 11) ^ self._rotate_right(e, 25)
            ch = (e & f) ^ ((~e) & g)
            t1 = h + s1 + ch + self._k[i] + state[i]

            h = g
            g = f
            f = e
            e = (d + t1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xFFFFFFFF

        self._h = [(x + y) & 0xFFFFFFFF for x, y in zip(self._h, [a, b, c, d, e, f, g, h])]

    def update(self, m):
        self._buffer += m
        self._counter += len(m)

        while len(self._buffer) >= 64:
            self._sha256_process(self._buffer[:64])
            self._buffer = self._buffer[64:]

    def digest(self):
        mdi = self._counter & 0x3F
        length = struct.pack('!Q', self._counter << 3)

        if mdi < 56:
            padlen = 55 - mdi
        else:
            padlen = 119 - mdi

        r = copy.deepcopy(self)
        r.update(b'\x80' + (b'\x00' * padlen) + length)

        return b''.join([struct.pack('!L', i) for i in r._h[:8]])

    def hexdigest(self):
        return self.digest().hex()


def bit_concat32(high, low):
    return ((high << 32) & 0xFFFFFFFFFFFFFFFF) | low


def byte_swap(bits, n):
    n = n & (1 << bits) - 1
    return int.from_bytes(n.to_bytes(bits // 8, 'little')[::-1], 'little')


def LODWORD(n):
    return n & 0x00000000FFFFFFFF


def HIDWORD(n):
    return n >> 32


def set_LODWORD(n, v):
    return (n & 0xFFFFFFFF00000000) | (v & 0xFFFFFFFF)


def set_HIDWORD(n, v):
    return (n & 0x00000000FFFFFFFF) | ((v & 0xFFFFFFFF) << 32)


def ROTATE_LEFT32(n, k):
    return ((n << k) & 0xFFFFFFFF) | (n >> (32 - k))


def scramble(data):
    previous = MAGIC_INITIAL_STATE
    mod_current = 0

    output = b''

    for size in range(DIGEST_LENGTH, 0, -8):
        current = 0

        needs_padding = (size < 8)  # We will always need padding in the end

        if not needs_padding:
            offset = DIGEST_LENGTH - size
            chunk1 = struct.unpack('<I', data[offset:offset + 4])[0]
            chunk2 = struct.unpack('<I', data[offset + 4:offset + 8])[0]

            current = previous ^ bit_concat32(byte_swap(32, chunk2), byte_swap(32, chunk1))
        else:
            current = byte_swap(64, bit_concat32(mod_current, HIDWORD(mod_current)))

        for i in range(4):
            for j in range(2):
                current = set_HIDWORD(current, HIDWORD(current) ^ current)

                a = (MAGIC_CONSTANTS[4*j + 0] + HIDWORD(current)) & 0xFFFFFFFF
                b = a
                a = ROTATE_LEFT32(a, 1)
                c = (b - 1 + a) & 0xFFFFFFFF
                d = c
                c = ROTATE_LEFT32(c, 4)

                current = set_LODWORD(current, d ^ c ^ current)

                e = (MAGIC_CONSTANTS[4*j + 1] + current) & 0xFFFFFFFF
                f = e
                e = ROTATE_LEFT32(e, 2)
                g = (f + 1 + e) & 0xFFFFFFFF
                h = g
                g = ROTATE_LEFT32(g, 8)
                i = (MAGIC_CONSTANTS[4*j + 2] + (h ^ g)) & 0xFFFFFFFF
                p = i
                i = ROTATE_LEFT32(i, 1)
                k = (i - p) & 0xFFFFFFFF
                q = k
                k = ROTATE_LEFT32(k, 16)

                current = set_HIDWORD(current, HIDWORD(current) ^ (current | q) ^ k)

                m = (MAGIC_CONSTANTS[4*j + 3] + HIDWORD(current)) & 0xFFFFFFFF
                n = m
                m = ROTATE_LEFT32(m, 2)

                current = set_LODWORD(current, ((n + 1 + m) ^ current) & 0xFFFFFFFF)

        previous = current
        mod_current = byte_swap(64, (current << 32) | HIDWORD(current))

        if needs_padding:
            remaining = bytearray(data[len(output):])

            for i in range(size):
                remaining[i] ^= mod_current & 0xFF
                mod_current >>= 8

            output += remaining
            break

        output += struct.pack('<Q', mod_current)

    return output


def encode(data):
    counter = 0
    last_digit = 0
    output = ''

    for c in data:
        t = 6 - counter
        digit = c

        counter += 2
        output += ENCODING_TABLE[(digit >> counter) | (last_digit << t) & 0b111111]
        last_digit = digit

        if counter == 6:
            counter = 0
            output += ENCODING_TABLE[last_digit & 0b111111]

    if counter:
        output += ENCODING_TABLE[(last_digit << (6 - counter)) & 0b111111]

    return output


def extract_info(data):
    version = data.splitlines()[0]

    if not version.startswith('X Lossless Decoder version'):
        version = None
    else:
        version = version.split()[4]

    if '\n-----BEGIN XLD SIGNATURE-----\n' not in data:
        signature = None
    else:
        data, signature_parts = data.split('\n-----BEGIN XLD SIGNATURE-----\n', 1)
        signature = signature_parts.split('\n-----END XLD SIGNATURE-----\n')[0].strip()

    return data, version, signature


def xld_verify(data):
    data, version, old_signature = extract_info(data)

    hashed_data = (AlmostSHA256(data.encode('utf-8')).hexdigest() + '\nVersion=0001').encode('ascii')
    scrambled_data = scramble(hashed_data)
    signature = encode(scrambled_data)

    return data, version, old_signature, signature


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Verifies and resigns XLD logs')
    parser.add_argument('file', metavar='FILE', help='path to the log file')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--verify', action='store_true', help='verify a log')
    group.add_argument('--sign', action='store_true', help='sign or fix an existing log')

    args = parser.parse_args()

    if args.file == '-':
        handle = sys.stdin
    else:
        handle = open(args.file, 'rb')

    data, version, old_signature, actual_signature = xld_verify(handle.read().decode('utf-8'))
    handle.close()

    if args.sign:
        if version <= LOGCHECKER_MIN_VERSION:
            raise ValueError('XLD version was too old to be signed')

        print(data)
        print('-----BEGIN XLD SIGNATURE-----')
        print(actual_signature)
        print('-----END XLD SIGNATURE-----')

    if args.verify:
        if old_signature is None:
            print('Not a log file')
            sys.exit(1)
        elif old_signature != actual_signature:
            print('Malformed')
            sys.exit(1)
        elif version <= LOGCHECKER_MIN_VERSION:
            print('Forged')
            sys.exit(1)
        else:
            print('OK')
