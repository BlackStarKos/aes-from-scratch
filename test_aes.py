"""Run with:  python -m unittest -v test_aes

Known-answer tests come from FIPS 197 and NIST SP 800-38A. If the `cryptography` package is installed,
the cipher is also cross-checked against it on random inputs (skipped otherwise).
Picture tests need numpy + opencv-python (skipped otherwise).
"""
import math
import os
import random
import tempfile
import unittest

import AES_Class as A

try:
    import cv2
    import numpy
except ImportError:
    cv2 = numpy = None

try:
    from cryptography.hazmat.primitives import padding as refPadding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    Cipher = None

h = bytes.fromhex
FAST = 1000          # PBKDF2 iterations for tests (production default is 600,000)


class BlockCipher(unittest.TestCase):
    def test_fips197_appendix_b(self):
        rk = A.expandKey(h("2b7e151628aed2a6abf7158809cf4f3c"))
        pt, ct = h("3243f6a8885a308d313198a2e0370734"), h("3925841d02dc09fbdc118597196a0b32")
        self.assertEqual(bytes(A.encryptBlock(pt, rk)), ct)
        self.assertEqual(bytes(A.decryptBlock(ct, rk)), pt)

    def test_fips197_appendix_c1(self):
        rk = A.expandKey(h("000102030405060708090a0b0c0d0e0f"))
        pt, ct = h("00112233445566778899aabbccddeeff"), h("69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(bytes(A.encryptBlock(pt, rk)), ct)
        self.assertEqual(bytes(A.decryptBlock(ct, rk)), pt)

    def test_key_expansion_appendix_a1(self):
        rk = A.expandKey(h("2b7e151628aed2a6abf7158809cf4f3c"))
        self.assertEqual(len(rk), 11)
        self.assertEqual(bytes(rk[1]).hex(), "a0fafe1788542cb123a339392a6c7605")
        self.assertEqual(bytes(rk[10]).hex(), "d014f9a8c9ee2589e13f0cc8b6630ca6")

    def test_gf_multiplication_examples_from_fips197(self):
        self.assertEqual(A.x0x(0x57, 0x83), 0xC1)
        self.assertEqual(A.x0x(0x57, 0x13), 0xFE)

    def test_sbox_matches_first_principles(self):
        def inverse(b):
            return 0 if b == 0 else next(c for c in range(1, 256) if A.x0x(b, c) == 1)

        def affine(b):
            out = 0
            for i in range(8):
                bit = sum((b >> ((i + k) % 8)) & 1 for k in (0, 4, 5, 6, 7)) + (0x63 >> i) & 1
                out |= (bit & 1) << i
            return out

        self.assertEqual(A.SBOX, [affine(inverse(b)) for b in range(256)])
        self.assertEqual([A.INV_SBOX[A.SBOX[b]] for b in range(256)], list(range(256)))

    def test_wrong_key_length_rejected(self):
        with self.assertRaises(ValueError):
            A.expandKey(b"short")

    def test_tables_are_never_mutated(self):
        # Version 1 converted the global RCON table in place, so a second AES object crashed.
        before = [row[:] for row in A.RCON]
        first = A.expandKey(b"0123456789abcdef")
        second = A.expandKey(b"0123456789abcdef")
        self.assertEqual(first, second)
        self.assertEqual(A.RCON, before)
        A.AES("one", iterations=FAST), A.AES("two", iterations=FAST)

    def test_round_trip_random_blocks(self):
        rng = random.Random(1)
        for _ in range(50):
            rk = A.expandKey(bytes(rng.randrange(256) for _ in range(16)))
            blk = bytes(rng.randrange(256) for _ in range(16))
            self.assertEqual(bytes(A.decryptBlock(A.encryptBlock(blk, rk), rk)), blk)

    @unittest.skipIf(Cipher is None, "cryptography not installed")
    def test_matches_reference_library_ecb(self):
        rng = random.Random(2)
        for _ in range(30):
            key = bytes(rng.randrange(256) for _ in range(16))
            blk = bytes(rng.randrange(256) for _ in range(16))
            enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
            self.assertEqual(bytes(A.encryptBlock(blk, A.expandKey(key))), enc.update(blk) + enc.finalize())


class Cbc(unittest.TestCase):
    KEY = h("2b7e151628aed2a6abf7158809cf4f3c")
    IV = h("000102030405060708090a0b0c0d0e0f")
    PT = h("6bc1bee22e409f96e93d7e117393172a" "ae2d8a571e03ac9c9eb76fac45af8e51"
           "30c81c46a35ce411e5fbc1191a0a52ef" "f69f2445df4f9b17ad2b417be66c3710")
    CT = h("7649abac8119b246cee98e9b12e9197d" "5086cb9b507219ee95db113a917678b2"
           "73bed6b8e3c1743b7116e69e22229516" "3ff1caa1681fac09120eca307586e1a7")

    def test_nist_sp800_38a_f21_encrypt(self):
        self.assertEqual(A.cbcEncryptRaw(A.expandKey(self.KEY), self.IV, self.PT), self.CT)

    def test_nist_sp800_38a_f22_decrypt(self):
        self.assertEqual(A.cbcDecryptRaw(A.expandKey(self.KEY), self.IV, self.CT), self.PT)

    def test_pkcs7_round_trip_every_length(self):
        for n in range(0, 50):
            data = bytes(range(n))
            padded = A.pkcs7Pad(data)
            self.assertEqual(len(padded) % 16, 0)
            self.assertGreater(len(padded), n)              # a full block is added when n is already a multiple of 16
            self.assertEqual(A.pkcs7Unpad(padded), data)

    def test_pkcs7_rejects_bad_padding(self):
        for bad in (b"", b"x" * 15, b"x" * 15 + b"\x00", b"x" * 15 + b"\x11", b"x" * 14 + b"\x01\x02"):
            with self.assertRaises(ValueError):
                A.pkcs7Unpad(bad)

    def test_same_plaintext_blocks_give_different_ciphertext_blocks(self):
        ct = A.cbcEncryptRaw(A.expandKey(self.KEY), self.IV, b"A" * 64)
        self.assertEqual(len({ct[i:i + 16] for i in range(0, 64, 16)}), 4)

    @unittest.skipIf(Cipher is None, "cryptography not installed")
    def test_padded_cbc_matches_reference_library(self):
        rng = random.Random(3)
        for n in (0, 1, 15, 16, 17, 100, 1000):
            key, iv = os.urandom(16), os.urandom(16)
            data = bytes(rng.randrange(256) for _ in range(n))
            padder = refPadding.PKCS7(128).padder()
            enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
            ref = enc.update(padder.update(data) + padder.finalize()) + enc.finalize()
            self.assertEqual(A.cbcEncrypt(key, iv, data), ref)
            self.assertEqual(A.cbcDecrypt(key, iv, ref), data)


class Container(unittest.TestCase):
    def setUp(self):
        self.aes = A.AES("correct horse battery staple", iterations=FAST)

    def test_round_trip_various_lengths(self):
        for n in (0, 1, 15, 16, 17, 255, 1000):
            data = os.urandom(n)
            self.assertEqual(self.aes.decryptBytes(self.aes.encryptBytes(data)), data)

    def test_encrypting_twice_gives_different_output(self):
        a, b = self.aes.encryptBytes(b"same data"), self.aes.encryptBytes(b"same data")
        self.assertNotEqual(a, b)
        self.assertNotEqual(a[9:25], b[9:25])              # salt
        self.assertNotEqual(a[25:41], b[25:41])            # IV

    def test_overhead_is_header_padding_and_tag(self):
        blob = self.aes.encryptBytes(b"x" * 20)
        self.assertEqual(len(blob), A.HEADER_LEN + 32 + A.TAG_LEN)

    def test_wrong_password_rejected(self):
        blob = self.aes.encryptBytes(b"secret")
        with self.assertRaises(ValueError):
            A.AES("wrong password", iterations=FAST).decryptBytes(blob)

    def test_flipping_any_single_byte_is_detected(self):
        blob = self.aes.encryptBytes(b"twenty bytes of data")
        for i in range(len(blob)):
            bad = bytearray(blob)
            bad[i] ^= 0x01
            with self.assertRaises(ValueError, msg="byte %d" % i):
                self.aes.decryptBytes(bytes(bad))

    def test_truncation_and_garbage_rejected(self):
        blob = self.aes.encryptBytes(b"secret")
        for bad in (blob[:-1], blob[:-16], blob[:10], b"", b"\x00" * 200):
            with self.assertRaises(ValueError):
                self.aes.decryptBytes(bad)

    def test_absurd_iteration_count_in_header_rejected(self):
        bad = bytearray(self.aes.encryptBytes(b"secret"))
        bad[5:9] = (2 ** 32 - 1).to_bytes(4, "big")
        with self.assertRaises(ValueError):
            self.aes.decryptBytes(bytes(bad))

    def test_empty_password_rejected(self):
        with self.assertRaises(ValueError):
            A.AES("")


class Files(unittest.TestCase):
    def setUp(self):
        self.aes = A.AES("pw", iterations=FAST)
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def path(self, name):
        return os.path.join(self.dir.name, name)

    def test_text_round_trip_is_exact_including_unicode_and_newlines(self):
        text = "This is the day we've been waiting for.\r\nüñíçødé ✓\n\n  trailing spaces   "
        with open(self.path("in.txt"), "w", encoding="utf-8", newline="") as f:
            f.write(text)
        self.aes.encryptText(self.path("in.txt"), self.path("enc.txt"))
        self.aes.decryptText(self.path("enc.txt"), self.path("out.txt"))
        with open(self.path("out.txt"), encoding="utf-8", newline="") as f:
            self.assertEqual(f.read(), text)

    def test_file_round_trip_is_byte_identical(self):
        for n in (0, 1, 16, 100_000):
            data = os.urandom(n)
            with open(self.path("in.bin"), "wb") as f:
                f.write(data)
            self.aes.encryptFile(self.path("in.bin"), self.path("enc.aes"))
            self.aes.decryptFile(self.path("enc.aes"), self.path("out.bin"))
            with open(self.path("out.bin"), "rb") as f:
                self.assertEqual(f.read(), data)

    @unittest.skipIf(cv2 is None, "opencv/numpy not installed")
    def test_video_round_trip_is_byte_identical(self):
        # Version 1 re-encoded encrypted frames with a lossy codec, which destroyed them.
        frames = numpy.random.default_rng(0).integers(0, 256, (12, 48, 64, 3), dtype=numpy.uint8)
        writer = cv2.VideoWriter(self.path("in.mp4"), cv2.VideoWriter_fourcc(*"mp4v"), 10, (64, 48))
        for frame in frames:
            writer.write(frame)
        writer.release()
        self.assertGreater(os.path.getsize(self.path("in.mp4")), 0)
        self.aes.encryptVideo(self.path("in.mp4"), self.path("video.aes"))
        self.aes.decryptVideo(self.path("video.aes"), self.path("out.mp4"))
        with open(self.path("in.mp4"), "rb") as a, open(self.path("out.mp4"), "rb") as b:
            self.assertEqual(a.read(), b.read())
        self.assertTrue(cv2.VideoCapture(self.path("out.mp4")).read()[0])   # still a playable video


@unittest.skipIf(cv2 is None, "opencv/numpy not installed")
class Pictures(unittest.TestCase):
    def setUp(self):
        self.aes = A.AES("pw", iterations=FAST)
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def path(self, name):
        return os.path.join(self.dir.name, name)

    def roundTrip(self, image):
        cv2.imwrite(self.path("in.png"), image)
        original = cv2.imread(self.path("in.png"), cv2.IMREAD_UNCHANGED)
        self.aes.encryptPicture(self.path("in.png"), self.path("enc.png"))
        self.aes.decryptPicture(self.path("enc.png"), self.path("out.png"))
        restored = cv2.imread(self.path("out.png"), cv2.IMREAD_UNCHANGED)
        self.assertEqual(original.shape, restored.shape)
        self.assertTrue(numpy.array_equal(original, restored))

    def test_round_trip_exact_for_gray_colour_alpha_and_odd_sizes(self):
        rng = numpy.random.default_rng(5)
        for shape in ((1, 1), (5, 7), (33, 17, 3), (60, 100, 3), (20, 30, 4), (40, 50)):
            self.roundTrip(rng.integers(0, 256, shape, dtype=numpy.uint8))

    def test_flat_image_encrypts_to_noise_with_no_repeated_blocks(self):
        # In ECB mode a flat image leaves the same 16-byte block repeated everywhere; CBC + IV must not.
        cv2.imwrite(self.path("flat.png"), numpy.full((64, 64, 3), 32, dtype=numpy.uint8))
        self.aes.encryptPicture(self.path("flat.png"), self.path("enc.png"))
        data = cv2.imread(self.path("enc.png"), cv2.IMREAD_UNCHANGED).tobytes()[8 + A.HEADER_LEN:]
        blocks = [data[i:i + 16] for i in range(0, len(data) - 16, 16)]
        self.assertEqual(len(set(blocks)), len(blocks))
        counts = [data.count(bytes([v])) for v in range(256)]
        entropy = -sum(c / len(data) * math.log2(c / len(data)) for c in counts if c)
        self.assertGreater(entropy, 7.9)

    def test_tampered_picture_is_rejected(self):
        cv2.imwrite(self.path("in.png"), numpy.random.default_rng(6).integers(0, 256, (5, 7, 3), dtype=numpy.uint8))
        self.aes.encryptPicture(self.path("in.png"), self.path("enc.png"))
        enc = cv2.imread(self.path("enc.png"), cv2.IMREAD_UNCHANGED)
        enc[0, 10, 0] ^= 1
        cv2.imwrite(self.path("bad.png"), enc)
        with self.assertRaises(ValueError):
            self.aes.decryptPicture(self.path("bad.png"), self.path("out.png"))

    def test_wrong_password_is_rejected(self):
        cv2.imwrite(self.path("in.png"), numpy.zeros((8, 8, 3), dtype=numpy.uint8))
        self.aes.encryptPicture(self.path("in.png"), self.path("enc.png"))
        with self.assertRaises(ValueError):
            A.AES("nope", iterations=FAST).decryptPicture(self.path("enc.png"), self.path("out.png"))

    def test_lossy_output_format_is_refused(self):
        cv2.imwrite(self.path("in.png"), numpy.zeros((8, 8, 3), dtype=numpy.uint8))
        with self.assertRaises(ValueError):
            self.aes.encryptPicture(self.path("in.png"), self.path("enc.jpg"))

    def test_non_picture_is_refused(self):
        cv2.imwrite(self.path("plain.png"), numpy.zeros((8, 8, 3), dtype=numpy.uint8))
        with self.assertRaises(ValueError):
            self.aes.decryptPicture(self.path("plain.png"), self.path("out.png"))


if __name__ == "__main__":
    unittest.main()
