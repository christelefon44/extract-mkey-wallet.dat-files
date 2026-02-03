#!/usr/bin/env python3
# Batch-capable mkey extractor from Bitcoin Core wallet.dat
# Accepts single file, folder (looks for wallet.dat), or wildcard patterns (*.dat)
# 2026 version — proper varint parsing

import sys
import base64
import struct
import os
import glob

try:
    import bsddb3.db as bdb
except ImportError:
    print("Warning: using pure-python bsddb fallback (install bsddb3 for better performance)", file=sys.stderr)
    from bsddb3 import db as bdb  # pip install bsddb3

def read_compact_size(data, pos):
    val = data[pos]
    pos += 1
    if val < 253:
        return val, pos
    elif val == 253:
        val, = struct.unpack_from("<H", data, pos)
        pos += 2
        return val, pos
    elif val == 254:
        val, = struct.unpack_from("<I", data, pos)
        pos += 4
        return val, pos
    elif val == 255:
        val, = struct.unpack_from("<Q", data, pos)
        pos += 8
        return val, pos
    raise ValueError("Invalid compact size")

def extract_mkey(wallet_path):
    """Returns (base64_blob, breakdown_lines) or (None, error_message)"""
    if not os.path.isfile(wallet_path):
        return None, f"Not a file: {wallet_path}"

    try:
        db_env = bdb.DBEnv()
        db_env.open(os.path.dirname(wallet_path) or '.',
                    bdb.DB_CREATE | bdb.DB_INIT_MPOOL | bdb.DB_PRIVATE | bdb.DB_THREAD)
        db = bdb.DB(db_env)
        db.open(wallet_path, "main", bdb.DB_BTREE, bdb.DB_RDONLY)

        mkey_data = None
        mkey_nid = None
        for key, value in db.items():
            if key.startswith(b'\x04mkey'):
                if len(key) >= 9:
                    mkey_nid = struct.unpack("<I", key[5:9])[0]
                mkey_data = value
                break

        db.close()
        db_env.close()

        if not mkey_data:
            return None, "No mkey found (wallet not encrypted or not legacy format?)"

        pos = 0
        enc_len, pos = read_compact_size(mkey_data, pos)
        enc_master_key = mkey_data[pos:pos + enc_len]
        pos += enc_len

        salt_len, pos = read_compact_size(mkey_data, pos)
        salt = mkey_data[pos:pos + salt_len]
        pos += salt_len

        method, = struct.unpack_from("<I", mkey_data, pos)
        pos += 4

        iter_count, = struct.unpack_from("<I", mkey_data, pos)
        pos += 4

        other = b''
        if pos < len(mkey_data):
            other_len, pos = read_compact_size(mkey_data, pos)
            other = mkey_data[pos:pos + other_len]

        blob = enc_master_key + salt + struct.pack("<II", method, iter_count)
        blob_b64 = base64.b64encode(blob).decode('ascii')

        lines = []
        if mkey_nid is not None:
            lines.append(f"  mkey nID                      : {mkey_nid}")
        lines.extend([
            f"  Encrypted master key ({len(enc_master_key)} bytes): {enc_master_key.hex()}",
            f"  Salt ({len(salt)} bytes)                 : {salt.hex()}",
            f"  Derivation method              : {method}  (0 = EVP_BytesToKey usually)",
            f"  Iteration count                : {iter_count}",
            f"  Other derivation params ({len(other)} bytes): {other.hex() or '(empty)'}"
        ])

        return blob_b64, lines

    except Exception as e:
        return None, f"Error: {str(e)}"


# ────────────────────────────────────────────────
# Main logic – handle single file, folder or pattern

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <path_or_pattern>")
    print("Examples:")
    print("  Single file     :  python script.py wallet.dat")
    print("  All in folder   :  python script.py old_wallets/")
    print("  Wildcard        :  python script.py backups/*.dat")
    print("  Recursive       :  python script.py 'archive/**/wallet.dat'")
    sys.exit(1)

input_arg = sys.argv[1]

# Collect files to process
if os.path.isfile(input_arg):
    files = [input_arg]
elif os.path.isdir(input_arg):
    files = glob.glob(os.path.join(input_arg, "*"))
    if not files:  # fallback: look recursively
        files = glob.glob(os.path.join(input_arg, "**", "*"), recursive=True)
elif '*' in input_arg or '?' in input_arg:
    files = glob.glob(input_arg, recursive=True)
else:
    print(f"Path not found: {input_arg}")
    sys.exit(1)

if not files:
    print("No matching wallet.dat files found.")
    sys.exit(0)

print(f"Found {len(files)} file(s)\n")

for filepath in sorted(files):
    print(f"Processing: {filepath}")
    blob, result = extract_mkey(filepath)

    if blob:
        print("\nEncrypted mkey (BTCRecover compatible base64):")
        print(blob)
        print("\nBreakdown:")
        for line in result:
            print(line)
    else:
        print("→", result)

    print("-" * 60 + "\n")

print("Done.")
