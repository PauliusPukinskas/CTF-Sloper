# Hash format identification

Use `scripts/hash_identifier.py` to classify likely hash families before choosing a CTF workflow. It does not crack hashes, submit them to external services, or claim that digest length proves a specific algorithm.

## Inspect one value

Quote values containing `$` so the shell does not expand them:

```bash
python3 scripts/hash_identifier.py \
  '5d41402abc4b2a76b9719d911017c592'

python3 scripts/hash_identifier.py \
  '$2b$12$abcdefghijklmnopqrstuuBqP9h55QQb9xv0aFZBmm7jyV8J5QAmA'
```

The report includes the detected encoding, compatible algorithms, confidence, and a warning when the result is ambiguous.

## Inspect a file or stdin

Put one value on each line. Blank lines and lines beginning with `#` are ignored.

```bash
python3 scripts/hash_identifier.py --file hashes.txt
cat hashes.txt | python3 scripts/hash_identifier.py
```

Use the Make targets for the same file-based workflow:

```bash
make hash-identify HASH_FILE=hashes.txt
make hash-identify-json HASH_FILE=hashes.txt
```

## JSON output

```bash
python3 scripts/hash_identifier.py --json --file hashes.txt
```

JSON output is useful for challenge notes, scripts, or importing guesses into another local tool.

## Optional base64 classification

Base64 is too broad to classify safely by default because arbitrary binary data can have the same decoded length as a digest. Enable it explicitly:

```bash
python3 scripts/hash_identifier.py --allow-base64 'XUFAKrxLKna5cZ2REBfFkg=='
```

Base64 matches are always reported with low confidence.

## Recognized families

The identifier understands common raw hexadecimal digest lengths and explicit markers for formats including:

* MD4, MD5, NTLM, and LM
* SHA-1, SHA-2, SHA-3, RIPEMD, BLAKE2, and Whirlpool
* bcrypt, Argon2, scrypt, and PBKDF2
* md5crypt, sha256crypt, sha512crypt, Apache md5crypt, and phpass
* LDAP SHA and salted SHA
* MySQL legacy and MySQL 4.1+ formats

## Interpretation rules

A format marker such as `$2b$` or `$argon2id$` provides a strong family identification. A raw 32-character hexadecimal value is inherently ambiguous and may be MD5, MD4, NTLM, LM, or another format with the same size.

Use surrounding challenge context, source system, salt structure, known plaintext hints, and verification against a candidate value before selecting a final algorithm.
