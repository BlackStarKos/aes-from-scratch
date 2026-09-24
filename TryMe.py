"""Command-line front end for AES_Class.

  python TryMe.py encrypt-picture photo.png photo_encrypted.png
  python TryMe.py decrypt-picture photo_encrypted.png photo_decrypted.png
  python TryMe.py encrypt-video   clip.mp4 clip.aes
  python TryMe.py decrypt-video   clip.aes clip_decrypted.mp4
  python TryMe.py encrypt-text    message.txt message.enc.txt
  python TryMe.py decrypt-text    message.enc.txt message_decrypted.txt

The password is asked for interactively. AES_PASSWORD skips the prompt for scripted runs
(environment variables can leak, so don't use that for anything real).
"""
import argparse
import getpass
import os
import sys
import time

from AES_Class import AES

COMMANDS = {
    "encrypt-picture": "encryptPicture", "decrypt-picture": "decryptPicture",
    "encrypt-video": "encryptVideo", "decrypt-video": "decryptVideo",
    "encrypt-text": "encryptText", "decrypt-text": "decryptText",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=sorted(COMMANDS))
    parser.add_argument("source")
    parser.add_argument("destination")
    args = parser.parse_args()

    password = os.environ.get("AES_PASSWORD")
    if password is None:
        password = getpass.getpass("Password: ")
        if args.command.startswith("encrypt") and getpass.getpass("Repeat password: ") != password:
            sys.exit("Passwords do not match.")

    start = time.perf_counter()
    try:
        getattr(AES(password), COMMANDS[args.command])(args.source, args.destination)
    except (ValueError, OSError) as error:
        sys.exit("Error: %s" % error)
    print("%s -> %s  (%.1f s)" % (args.source, args.destination, time.perf_counter() - start))


if __name__ == "__main__":
    main()
