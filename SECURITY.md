# Security policy

This repository is a learning implementation of AES-128. It is not constant-time, it has not been
audited, and it must not be used to protect real data. Use a vetted library such as
[`cryptography`](https://cryptography.io/) for that.

## Reporting a problem

If you find a correctness or security bug, for example a known-answer test that should fail but
passes, a padding or MAC check that can be bypassed, or a key or IV handling mistake, please report
it privately through GitHub's private vulnerability reporting on this repository
(Security tab, "Report a vulnerability"). Include a minimal reproducer. I aim to acknowledge reports
within 7 days.

## Scope

In scope: the cipher core (`expandKey`, `encryptBlock`, `decryptBlock`), CBC mode, PKCS#7 padding,
the PBKDF2 and HMAC-SHA256 container format, and the text, file and picture round-trips.

Out of scope: timing side channels (documented and accepted for a pure-Python learning project) and
denial of service through very large inputs.

## Supply chain

The cipher and its tests use only the Python standard library. Continuous integration runs the test
suite on Python 3.11 to 3.13 with no third-party packages, plus one job that cross-checks against a
pinned release of `cryptography`. GitHub Actions are pinned to commit SHAs, Dependabot proposes
updates, secret scanning and push protection are on, and `main` only accepts changes through a pull
request with a green build.
