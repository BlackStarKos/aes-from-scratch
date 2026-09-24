"""Draws docs/ecb_vs_cbc.png: the same picture encrypted with the same AES block cipher in ECB and in CBC.

ECB is here only to show why it is unsafe. Nothing else in the project uses it.
"""
import os

import cv2
import numpy

import AES_Class as A

W, H = 320, 240


def testPicture():
    img = numpy.full((H, W, 3), 40, dtype=numpy.uint8)
    cv2.rectangle(img, (20, 150), (300, 215), (60, 160, 60), -1)
    cv2.circle(img, (250, 70), 45, (40, 140, 240), -1)
    cv2.putText(img, "AES", (25, 125), cv2.FONT_HERSHEY_DUPLEX, 3.6, (255, 255, 255), 8)
    return img


def ecbEncrypt(roundKeys, data):                    # INSECURE: identical plaintext blocks -> identical ciphertext blocks
    return b"".join(bytes(A.encryptBlock(data[i:i + 16], roundKeys)) for i in range(0, len(data), 16))


def label(img, text):
    out = cv2.copyMakeBorder(img, 34, 0, 0, 0, cv2.BORDER_CONSTANT, value=(255, 255, 255))
    cv2.putText(out, text, (8, 24), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 0, 0), 1, cv2.LINE_AA)
    return out


def main():
    picture = testPicture()
    raw = picture.tobytes()                          # 320*240*3 bytes, a multiple of 16
    roundKeys = A.expandKey(os.urandom(16))
    ecb = numpy.frombuffer(ecbEncrypt(roundKeys, raw), dtype=numpy.uint8).reshape(H, W, 3)
    cbc = numpy.frombuffer(A.cbcEncryptRaw(roundKeys, os.urandom(16), raw), dtype=numpy.uint8).reshape(H, W, 3)
    figure = numpy.hstack([label(picture, "original"), label(ecb, "AES-ECB (insecure)"), label(cbc, "AES-CBC, random IV")])
    os.makedirs("docs", exist_ok=True)
    cv2.imwrite(os.path.join("docs", "ecb_vs_cbc.png"), figure)
    print("wrote docs/ecb_vs_cbc.png")


if __name__ == "__main__":
    main()
