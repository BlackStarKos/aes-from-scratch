"""AES-128 written from scratch (FIPS 197), plus a small authenticated file format.

Layers, bottom to top:
  1. block cipher   expandKey / encryptBlock / decryptBlock          (FIPS 197)
  2. mode           CBC with a random IV and PKCS#7 padding          (NIST SP 800-38A)
  3. container      PBKDF2-HMAC-SHA256 keys + HMAC-SHA256 tag        (encrypt-then-MAC)
  4. helpers        text, files (use this for video), pictures

Learning project. Pure Python, not constant-time, never audited: do not use it to protect real data.
"""

import base64
import hashlib
import hmac
import os
import struct

# ---------------------------------------------------------------------------
# Look-up tables (from the first version, kept as hex strings)
# ---------------------------------------------------------------------------
# sub bytes for encryption
subBytes_Box =        [['63','7c','77','7b','f2','6b','6f','c5','30','01','67','2b','fe','d7','ab','76'],
                        ['ca','82','c9','7d','fa','59','47','f0','ad','d4','a2','af','9c','a4','72','c0'],
                        ['b7','fd','93','26','36','3f','f7','cc','34','a5','e5','f1','71','d8','31','15'],
                        ['04','c7','23','c3','18','96','05','9a','07','12','80','e2','eb','27','b2','75'],
                        ['09','83','2c','1a','1b','6e','5a','a0','52','3b','d6','b3','29','e3','2f','84'],
                        ['53','d1','00','ed','20','fc','b1','5b','6a','cb','be','39','4a','4c','58','cf'],
                        ['d0','ef','aa','fb','43','4d','33','85','45','f9','02','7f','50','3c','9f','a8'],
                        ['51','a3','40','8f','92','9d','38','f5','bc','b6','da','21','10','ff','f3','d2'],
                        ['cd','0c','13','ec','5f','97','44','17','c4','a7','7e','3d','64','5d','19','73'],
                        ['60','81','4f','dc','22','2a','90','88','46','ee','b8','14','de','5e','0b','db'],
                        ['e0','32','3a','0a','49','06','24','5c','c2','d3','ac','62','91','95','e4','79'],
                        ['e7','c8','37','6d','8d','d5','4e','a9','6c','56','f4','ea','65','7a','ae','08'],
                        ['ba','78','25','2e','1c','a6','b4','c6','e8','dd','74','1f','4b','bd','8b','8a'],
                        ['70','3e','b5','66','48','03','f6','0e','61','35','57','b9','86','c1','1d','9e'],
                        ['e1','f8','98','11','69','d9','8e','94','9b','1e','87','e9','ce','55','28','df'],
                        ['8c','a1','89','0d','bf','e6','42','68','41','99','2d','0f','b0','54','bb','16']]

# inv sub bytes for decryption
invSubBytes_Box =     [['52','09','6a','d5','30','36','a5','38','bf','40','a3','9e','81','f3','d7','fb'],
                        ['7c','e3','39','82','9b','2f','ff','87','34','8e','43','44','c4','de','e9','cb'],
                        ['54','7b','94','32','a6','c2','23','3d','ee','4c','95','0b','42','fa','c3','4e'],
                        ['08','2e','a1','66','28','d9','24','b2','76','5b','a2','49','6d','8b','d1','25'],
                        ['72','f8','f6','64','86','68','98','16','d4','a4','5c','cc','5d','65','b6','92'],
                        ['6c','70','48','50','fd','ed','b9','da','5e','15','46','57','a7','8d','9d','84'],
                        ['90','d8','ab','00','8c','bc','d3','0a','f7','e4','58','05','b8','b3','45','06'],
                        ['d0','2c','1e','8f','ca','3f','0f','02','c1','af','bd','03','01','13','8a','6b'],
                        ['3a','91','11','41','4f','67','dc','ea','97','f2','cf','ce','f0','b4','e6','73'],
                        ['96','ac','74','22','e7','ad','35','85','e2','f9','37','e8','1c','75','df','6e'],
                        ['47','f1','1a','71','1d','29','c5','89','6f','b7','62','0e','aa','18','be','1b'],
                        ['fc','56','3e','4b','c6','d2','79','20','9a','db','c0','fe','78','cd','5a','f4'],
                        ['1f','dd','a8','33','88','07','c7','31','b1','12','10','59','27','80','ec','5f'],
                        ['60','51','7f','a9','19','b5','4a','0d','2d','e5','7a','9f','93','c9','9c','ef'],
                        ['a0','e0','3b','4d','ae','2a','f5','b0','c8','eb','bb','3c','83','53','99','61'],
                        ['17','2b','04','7e','ba','77','d6','26','e1','69','14','63','55','21','0c','7d']]

# MixColumns matrix for encryption
GF =                  [['02','03','01','01'],
                        ['01','02','03','01'],
                        ['01','01','02','03'],
                        ['03','01','01','02']]

# inverse MixColumns matrix for decryption
invGF =               [['0e','0b','0d','09'],
                        ['09','0e','0b','0d'],
                        ['0d','09','0e','0b'],
                        ['0b','0d','09','0e']]

# round constants (only the first byte of each row is non-zero)
RCON =                [['01','00','00','00'],
                        ['02','00','00','00'],
                        ['04','00','00','00'],
                        ['08','00','00','00'],
                        ['10','00','00','00'],
                        ['20','00','00','00'],
                        ['40','00','00','00'],
                        ['80','00','00','00'],
                        ['1b','00','00','00'],
                        ['36','00','00','00']]

# Flat integer versions, built once at import. The tables above are never modified.
SBOX = [int(v, 16) for row in subBytes_Box for v in row]
INV_SBOX = [int(v, 16) for row in invSubBytes_Box for v in row]
RCON_BYTES = [int(row[0], 16) for row in RCON]


# ---------------------------------------------------------------------------
# GF(2^8) arithmetic
# ---------------------------------------------------------------------------
def x0x(a, b):
    """Multiply two bytes in GF(2^8), reducing by x^8+x^4+x^3+x+1 (0x11B = 283)."""
    total = 0
    while b:
        if b & 1:
            total ^= a
        b >>= 1
        a <<= 1
        if a >= 256:
            a ^= 283
    return total


_MUL = {c: [x0x(v, c) for v in range(256)] for c in (1, 2, 3, 9, 11, 13, 14)}


def _mixRows(matrix):
    return tuple(tuple(_MUL[int(v, 16)] for v in row) for row in matrix)


_MIX = {'e': _mixRows(GF), 'd': _mixRows(invGF)}

# ShiftRows as an index permutation of the 16-byte state.
_SHIFT = {'e': [r + 4 * ((c + r) % 4) for c in range(4) for r in range(4)],
          'd': [r + 4 * ((c - r) % 4) for c in range(4) for r in range(4)]}


# ---------------------------------------------------------------------------
# Block cipher (FIPS 197)
#
# The state is a flat list of 16 ints in input order. Byte n sits at row n % 4,
# column n // 4 (FIPS 197 section 3.4), so a column is 4 consecutive bytes.
# ---------------------------------------------------------------------------
def subBytes(state, mode):
    box = SBOX if mode == 'e' else INV_SBOX
    return [box[b] for b in state]


def shiftRows(state, mode):
    return [state[i] for i in _SHIFT[mode]]


def mixColumns(state, mode):
    rows = _MIX[mode]
    out = []
    for c in range(0, 16, 4):
        a0, a1, a2, a3 = state[c], state[c + 1], state[c + 2], state[c + 3]
        for t0, t1, t2, t3 in rows:
            out.append(t0[a0] ^ t1[a1] ^ t2[a2] ^ t3[a3])
    return out


def addRoundKey(state, roundKey):
    return [a ^ b for a, b in zip(state, roundKey)]


def expandKey(key):
    """16-byte key -> 11 round keys of 16 ints each (FIPS 197 section 5.2)."""
    if len(key) != 16:
        raise ValueError("AES-128 needs a 16-byte key")
    words = [list(key[4 * i:4 * i + 4]) for i in range(4)]
    for i in range(4, 44):
        temp = list(words[i - 1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]                 # RotWord
            temp = [SBOX[b] for b in temp]             # SubWord
            temp[0] ^= RCON_BYTES[i // 4 - 1]
        words.append([a ^ b for a, b in zip(words[i - 4], temp)])
    return [[b for w in words[4 * r:4 * r + 4] for b in w] for r in range(11)]


def encryptBlock(block, roundKeys):
    state = addRoundKey(list(block), roundKeys[0])
    for rnd in range(1, 10):
        state = addRoundKey(mixColumns(shiftRows(subBytes(state, 'e'), 'e'), 'e'), roundKeys[rnd])
    return addRoundKey(shiftRows(subBytes(state, 'e'), 'e'), roundKeys[10])   # last round: no MixColumns


def decryptBlock(block, roundKeys):
    state = addRoundKey(list(block), roundKeys[10])
    for rnd in range(9, 0, -1):
        state = mixColumns(addRoundKey(subBytes(shiftRows(state, 'd'), 'd'), roundKeys[rnd]), 'd')
    return addRoundKey(subBytes(shiftRows(state, 'd'), 'd'), roundKeys[0])


# ---------------------------------------------------------------------------
# CBC mode with PKCS#7 padding
# ---------------------------------------------------------------------------
def pkcs7Pad(data):
    n = 16 - len(data) % 16
    return bytes(data) + bytes([n]) * n


def pkcs7Unpad(data):
    if not data or len(data) % 16:
        raise ValueError("bad padding")
    n = data[-1]
    if n < 1 or n > 16 or data[-n:] != bytes([n]) * n:
        raise ValueError("bad padding")
    return data[:-n]


def cbcEncryptRaw(roundKeys, iv, data):
    """CBC over whole blocks, no padding (used directly by the NIST test vectors)."""
    if len(iv) != 16 or len(data) % 16:
        raise ValueError("IV must be 16 bytes and data a multiple of 16 bytes")
    out = bytearray()
    prev = list(iv)
    for i in range(0, len(data), 16):
        prev = encryptBlock([a ^ b for a, b in zip(data[i:i + 16], prev)], roundKeys)
        out += bytes(prev)
    return bytes(out)


def cbcDecryptRaw(roundKeys, iv, data):
    if len(iv) != 16 or len(data) % 16:
        raise ValueError("IV must be 16 bytes and data a multiple of 16 bytes")
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(decryptBlock(block, roundKeys), prev))
        prev = block
    return bytes(out)


def cbcEncrypt(key, iv, plaintext):
    return cbcEncryptRaw(expandKey(key), iv, pkcs7Pad(plaintext))


def cbcDecrypt(key, iv, ciphertext):
    return pkcs7Unpad(cbcDecryptRaw(expandKey(key), iv, ciphertext))


# ---------------------------------------------------------------------------
# Container: password -> keys, encrypt-then-MAC
#
#   "AESK" | version 1 | iterations (4, big-endian) | salt (16) | IV (16) | ciphertext | HMAC-SHA256 tag (32)
#
# The tag covers the header and the ciphertext, and is checked before anything is decrypted.
# ---------------------------------------------------------------------------
MAGIC = b"AESK"
VERSION = 1
SALT_LEN = 16
IV_LEN = 16
TAG_LEN = 32
HEADER_LEN = len(MAGIC) + 1 + 4 + SALT_LEN + IV_LEN
DEFAULT_ITERATIONS = 600_000        # OWASP guidance for PBKDF2-HMAC-SHA256
MAX_ITERATIONS = 10_000_000         # refuse absurd values from an untrusted header


def deriveKeys(password, salt, iterations):
    """PBKDF2 -> (16-byte AES key, 32-byte HMAC key); the two keys are independent."""
    material = hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen=48)
    return material[:16], material[16:]


def seal(password, plaintext, iterations=DEFAULT_ITERATIONS):
    salt, iv = os.urandom(SALT_LEN), os.urandom(IV_LEN)
    encKey, macKey = deriveKeys(password, salt, iterations)
    header = MAGIC + bytes([VERSION]) + iterations.to_bytes(4, "big") + salt + iv
    body = cbcEncrypt(encKey, iv, plaintext)
    return header + body + hmac.new(macKey, header + body, hashlib.sha256).digest()


def unseal(password, blob):
    if len(blob) < HEADER_LEN + 16 + TAG_LEN or (len(blob) - HEADER_LEN - TAG_LEN) % 16:
        raise ValueError("not an AES container (bad length)")
    if blob[:4] != MAGIC or blob[4] != VERSION:
        raise ValueError("not an AES container (bad header)")
    iterations = int.from_bytes(blob[5:9], "big")
    if not 1 <= iterations <= MAX_ITERATIONS:
        raise ValueError("not an AES container (bad iteration count)")
    salt = blob[9:9 + SALT_LEN]
    iv = blob[9 + SALT_LEN:HEADER_LEN]
    body, tag = blob[HEADER_LEN:-TAG_LEN], blob[-TAG_LEN:]
    encKey, macKey = deriveKeys(password, salt, iterations)
    expected = hmac.new(macKey, blob[:-TAG_LEN], hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("authentication failed: wrong password or the data was modified")
    return cbcDecrypt(encKey, iv, body)


# ---------------------------------------------------------------------------
# Text, files, pictures
# ---------------------------------------------------------------------------
_PIC_MAGIC = b"PIC1"


class AES:
    def __init__(self, password, iterations=DEFAULT_ITERATIONS):
        if isinstance(password, str):
            password = password.encode("utf-8")
        if not password:
            raise ValueError("password must not be empty")
        if not 1 <= iterations <= MAX_ITERATIONS:
            raise ValueError("iterations out of range")
        self.password = bytes(password)
        self.iterations = iterations

    def encryptBytes(self, data):
        return seal(self.password, data, self.iterations)

    def decryptBytes(self, blob):
        return unseal(self.password, blob)

    def encryptText(self, inFile, outFile):
        """UTF-8 text file -> base64 text file."""
        with open(inFile, encoding="utf-8", newline="") as f:
            blob = self.encryptBytes(f.read().encode("utf-8"))
        with open(outFile, "w", encoding="ascii") as f:
            f.write(base64.b64encode(blob).decode("ascii"))

    def decryptText(self, inFile, outFile):
        with open(inFile, encoding="ascii") as f:
            blob = base64.b64decode(f.read())
        with open(outFile, "w", encoding="utf-8", newline="") as f:
            f.write(self.decryptBytes(blob).decode("utf-8"))

    def encryptFile(self, inPath, outPath):
        """Encrypt any file byte-for-byte. Lossless, so the result always decrypts to the identical file."""
        with open(inPath, "rb") as f:
            blob = self.encryptBytes(f.read())
        with open(outPath, "wb") as f:
            f.write(blob)

    def decryptFile(self, inPath, outPath):
        with open(inPath, "rb") as f:
            data = self.decryptBytes(f.read())
        with open(outPath, "wb") as f:
            f.write(data)

    # Video is a file: encrypting the compressed bytes is lossless and far smaller than decoded frames.
    encryptVideo = encryptFile
    decryptVideo = decryptFile

    def encryptPicture(self, inPath, outPath):
        """Image -> PNG of pure noise (the encrypted container, stored as pixels). Output must be .png."""
        import cv2
        import numpy
        if not outPath.lower().endswith(".png"):
            raise ValueError("output must be a .png (lossless); JPEG would destroy the ciphertext")
        img = cv2.imread(inPath, cv2.IMREAD_UNCHANGED)
        if img is None:
            raise ValueError("cannot read image: " + inPath)
        if img.dtype != numpy.uint8:
            raise ValueError("only 8-bit images are supported")
        h, w = img.shape[:2]
        channels = 1 if img.ndim == 2 else img.shape[2]
        blob = self.encryptBytes(_PIC_MAGIC + struct.pack(">IIB", h, w, channels) + img.tobytes())

        stream = len(blob).to_bytes(8, "big") + blob        # length prefix so the random padding can be dropped
        width = max(w, 64)
        rows = -(-len(stream) // (3 * width))
        stream += os.urandom(rows * 3 * width - len(stream))
        noise = numpy.frombuffer(bytearray(stream), dtype=numpy.uint8).reshape(rows, width, 3)
        if not cv2.imwrite(outPath, noise):
            raise OSError("could not write " + outPath)

    def decryptPicture(self, inPath, outPath):
        import cv2
        import numpy
        img = cv2.imread(inPath, cv2.IMREAD_UNCHANGED)
        if img is None or img.dtype != numpy.uint8 or img.ndim != 3 or img.shape[2] != 3:
            raise ValueError("not an encrypted picture")
        stream = img.tobytes()
        n = int.from_bytes(stream[:8], "big")
        if n > len(stream) - 8:
            raise ValueError("not an encrypted picture (bad length)")
        plain = self.decryptBytes(stream[8:8 + n])
        if plain[:4] != _PIC_MAGIC or len(plain) < 13:
            raise ValueError("not an encrypted picture (bad header)")
        h, w, channels = struct.unpack(">IIB", plain[4:13])
        pixels = plain[13:]
        if len(pixels) != h * w * channels:
            raise ValueError("not an encrypted picture (size mismatch)")
        shape = (h, w) if channels == 1 else (h, w, channels)
        if not cv2.imwrite(outPath, numpy.frombuffer(pixels, dtype=numpy.uint8).reshape(shape)):
            raise OSError("could not write " + outPath)
