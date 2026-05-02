#!/usr/bin/env python3

# Blockchain Chain of Custody - Track 1

# -------
# Imports
# -------

import os
import sys
import uuid
import struct
import hashlib
from Crypto.Cipher import AES
from datetime import datetime, timezone

# ---------
# Constants
# ---------

# fixed byte sizes used by the binary block format
PREV_HASH_SIZE = 32
TIMESTAMP_SIZE = 8
CASE_ID_SIZE = 32
ITEM_ID_SIZE = 32
STATE_SIZE = 12
CREATOR_SIZE = 12
OWNER_SIZE = 12
DATA_LENGTH_SIZE = 4

# valid block states
STATE_INITIAL = "INITIAL"
STATE_CHECKEDIN = "CHECKEDIN"
STATE_CHECKEDOUT = "CHECKEDOUT"
STATE_DISPOSED = "DISPOSED"
STATE_DESTROYED = "DESTROYED"
STATE_RELEASED = "RELEASED"

# passwords
PASSWORD_CREATOR = os.environ.get("BCHOC_PASSWORD_CREATOR", "C67C")
PASSWORD_POLICE = os.environ.get("BCHOC_PASSWORD_POLICE", "P80P")
PASSWORD_LAWYER = os.environ.get("BCHOC_PASSWORD_LAWYER", "L76L")
PASSWORD_ANALYST = os.environ.get("BCHOC_PASSWORD_ANALYST", "A65A")
PASSWORD_EXECUTIVE = os.environ.get("BCHOC_PASSWORD_EXECUTIVE", "E69E")

# owner role based on which valid owner password was used
PASSWORD_TO_OWNER = {
    PASSWORD_POLICE: "POLICE",
    PASSWORD_LAWYER: "LAWYER",
    PASSWORD_ANALYST: "ANALYST",
    PASSWORD_EXECUTIVE: "EXECUTIVE"
}

# AES key
AES_KEY = b"R0chLi4uLi4uLi4="

# binary layout for the fixed portion of each block
BLOCK_STRUCT_FORMAT = "32s d 32s 32s 12s 12s 12s I"
BLOCK_STRUCT = struct.Struct(BLOCK_STRUCT_FORMAT)

# ------------------
# File Path Handling
# ------------------

def get_blockchain_path():
    return os.environ.get("BCHOC_FILE_PATH", "blockchain.dat")

# ----------------------------
# Padding and Encoding Helpers
# ----------------------------

def pad_bytes(value: str, length: int) -> bytes:
    # fixed-width text fields need to be null-padded to the correct length
    b = value.encode()
    return b.ljust(length, b'\x00')[:length]

def strip_padding(value: bytes) -> str:
    # remove null padding when displaying stored fields
    return value.rstrip(b'\x00').decode()

def format_timestamp(timestamp):
     # print timestamps in utc using the Z suffix
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat().replace("+00:00", "Z")

# ------------------------
# UUID and Item ID Helpers
# ------------------------

def validate_case_id(case_id):
    # case IDs must be valid UUID strings
    try:
        uuid.UUID(case_id)
        return True
    except ValueError:
        return False


def validate_item_id(item_id):
    # item IDs are stored as 4-byte unsigned integers
    try:
        value = int(item_id)
        return 0 <= value <= 0xFFFFFFFF
    except ValueError:
        return False

def aes_encrypt_block(plain_bytes):
    # encrypt exactly one AES block using ECB mode
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    return cipher.encrypt(plain_bytes)


def aes_decrypt_block(cipher_bytes):
    # decrypt exactly one AES block using ECB mode
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    return cipher.decrypt(cipher_bytes)


def store_case_id(case_id):
    # convert UUID to raw bytes, encrypt it, then store encrypted bytes as hex text
    plain = uuid.UUID(case_id).bytes
    encrypted = aes_encrypt_block(plain)
    return encrypted.hex().encode()


def store_item_id(item_id):
    # pack item ID into 4 bytes, pad to 16 bytes, encrypt, and store as hex text
    plain = struct.pack("I", int(item_id)) + (b'\x00' * 12)
    encrypted = aes_encrypt_block(plain)
    return encrypted.hex().encode()


def load_case_id(stored_case_id):
    # reverse store_case_id for display when decryption is allowed
    encrypted = bytes.fromhex(stored_case_id.decode())
    plain = aes_decrypt_block(encrypted)
    return str(uuid.UUID(bytes=plain))


def load_item_id(stored_item_id):
    # reverse store_item_id and return the original item number as text
    encrypted = bytes.fromhex(stored_item_id.decode())
    plain = aes_decrypt_block(encrypted)
    return str(struct.unpack("I", plain[:4])[0])

# ----------------
# Password Helpers
# ----------------

def is_creator_password(password):
    # creator password is required for add and remove
    return password == PASSWORD_CREATOR

def is_owner_password(password):
    # owner passwords are used for checkout and checkin
    return password in PASSWORD_TO_OWNER

def owner_from_password(password):
    # convert a valid owner password into the padded owner role field
    if password not in PASSWORD_TO_OWNER:
        return None
    return pad_bytes(PASSWORD_TO_OWNER[password], OWNER_SIZE)

# -------------
# Initial Block
# -------------

def create_initial_block():
    # the first block anchors the chain and does not represent real evidence
    prev_hash = b'\x00' * 32
    timestamp = 0.0
    case_id = b"0" * 32
    item_id = b"0" * 32
    state = pad_bytes(STATE_INITIAL, STATE_SIZE)
    creator = b'\x00' * CREATOR_SIZE
    owner = b'\x00' * OWNER_SIZE
    data = b"Initial block\0"
    data_length = len(data)

    return {
        "prev_hash": prev_hash,
        "timestamp": timestamp,
        "case_id": case_id,
        "item_id": item_id,
        "state": state,
        "creator": creator,
        "owner": owner,
        "data_length": data_length,
        "data": data
    }

# --------------------------
# Binary Packing / Unpacking
# --------------------------

def pack_block(block):
    # pack the fixed fields first, then append the variable-length data field
    header = BLOCK_STRUCT.pack(
        block["prev_hash"],
        block["timestamp"],
        block["case_id"],
        block["item_id"],
        block["state"],
        block["creator"],
        block["owner"],
        block["data_length"]
    )
    return header + block["data"]

def unpack_block(header, data):
    # convert raw bytes from the file back into the dictionary format used in code
    (
        prev_hash,
        timestamp,
        case_id,
        item_id,
        state,
        creator,
        owner,
        data_length
    ) = BLOCK_STRUCT.unpack(header)

    return {
        "prev_hash": prev_hash,
        "timestamp": timestamp,
        "case_id": case_id,
        "item_id": item_id,
        "state": state,
        "creator": creator,
        "owner": owner,
        "data_length": data_length,
        "data": data
    }

# ---------------
# Hashing Helper
# ---------------

def hash_block(block):
    # block hashes are based on the full packed binary version of the block
    return hashlib.sha256(pack_block(block)).digest()

# ------------------------------------
# Blockchain File Read / Write Helpers
# ------------------------------------

def blockchain_exists(path):
    # simple file existence check before reading or creating the chain
    return os.path.exists(path)

def write_block(path, block):
    # append one packed block to the binary blockchain file
    with open(path, "ab") as f:
        f.write(pack_block(block))

def read_blocks(path):
    # read the binary file one block at a time
    blocks = []

    if not blockchain_exists(path):
        return blocks

    with open(path, "rb") as f:
        while True:
            # each block starts with a fixed-size header
            header = f.read(BLOCK_STRUCT.size)

            if header == b"":
                break

            if len(header) != BLOCK_STRUCT.size:
                print("Invalid blockchain file")
                sys.exit(1)

            # the header tells us how many extra data bytes follow
            data_length = BLOCK_STRUCT.unpack(header)[7]
            data = f.read(data_length)

            if len(data) != data_length:
                print("Invalid blockchain file")
                sys.exit(1)

            blocks.append(unpack_block(header, data))

    return blocks

# -------------------------
# Blockchain Search Helpers
# -------------------------

def get_last_block(blocks):
    # the newest block is always at the end of the file
    if len(blocks) == 0:
        return None
    return blocks[-1]

def get_latest_block_for_item(blocks, item_id):
    # scan the chain and keep the most recent block for this item
    latest = None

    for block in blocks:
        if block["item_id"] == item_id:
            latest = block

    return latest

def get_blocks_for_item(blocks, stored_item_id):
    # return all blocks associated with one encrypted item id
    return [block for block in blocks if block["item_id"] == stored_item_id]


def get_blocks_for_case(blocks, stored_case_id):
    # return all blocks associated with one encrypted case id
    return [block for block in blocks if block["case_id"] == stored_case_id]

# ------------------------
# State Transition Helpers
# ------------------------

def get_state(block):
    # state is stored as padded bytes, so strip it before comparing
    return strip_padding(block["state"])

def is_removed_state(state):
    # these states mean the item is no longer active in custody
    return state in [STATE_DISPOSED, STATE_DESTROYED, STATE_RELEASED]

# -------------
# Command: init
# -------------

def cmd_init(args):
    if len(args) != 0:
        exit_error("Invalid arguments")

    # create the blockchain file if needed, otherwise check the first block
    path = get_blockchain_path()

    if not blockchain_exists(path):
        block = create_initial_block()
        write_block(path, block)
        print("Blockchain file not found. Created INITIAL block.")
    else:
        blocks = read_blocks(path)

        # an existing file should still contain a readable initial block
        if len(blocks) == 0:
            print("Blockchain file found but INITIAL block is missing.")
            sys.exit(1)

        first_block = blocks[0]

        # the first block must be the INITIAL block
        if first_block["state"].rstrip(b'\x00') != STATE_INITIAL.encode():
            print("Blockchain file found but INITIAL block is invalid.")
            sys.exit(1)

        print("Blockchain file found with INITIAL block.")

# ------------
# Command: add
# ------------

def cmd_add(args):
    # collect command-line values for adding one or more evidence items
    case_id = None
    item_ids = []
    creator = None
    password = None

    i = 0
    while i < len(args):
        if args[i] == "-c" and i + 1 < len(args):
            case_id = args[i + 1]
            i += 2
        elif args[i] == "-i" and i + 1 < len(args):
            item_ids.append(args[i + 1])
            i += 2
        elif args[i] == "-g" and i + 1 < len(args):
            creator = args[i + 1]
            i += 2
        elif args[i] == "-p" and i + 1 < len(args):
            password = args[i + 1]
            i += 2
        else:
            exit_error("Invalid arguments")

    # check required fields before changing the blockchain
    if case_id is None:
        exit_error("Missing case ID")

    if len(item_ids) == 0:
        exit_error("Missing item ID")

    if creator is None:
        exit_error("Missing creator")

    if password is None or not is_creator_password(password):
        exit_error("Invalid password")

    if not validate_case_id(case_id):
        exit_error("Invalid case ID")

    for item_id in item_ids:
        if not validate_item_id(item_id):
            exit_error("Invalid item ID")

    path = get_blockchain_path()

    # add can create the chain if init was not called first
    if not blockchain_exists(path):
        write_block(path, create_initial_block())

    blocks = read_blocks(path)

    for item_id in item_ids:
        stored_item_id = store_item_id(item_id)

        # item ids should only be added once
        if get_latest_block_for_item(blocks, stored_item_id) is not None:
            exit_error("Duplicate item ID")

        last_block = get_last_block(blocks)
        prev_hash = hash_block(last_block)

        # normal add blocks do not use the data field
        data = b""

        new_block = {
            "prev_hash": prev_hash,
            "timestamp": datetime.now(timezone.utc).timestamp(),
            "case_id": store_case_id(case_id),
            "item_id": stored_item_id,
            "state": pad_bytes(STATE_CHECKEDIN, STATE_SIZE),
            "creator": pad_bytes(creator, CREATOR_SIZE),
            "owner": b'\x00' * OWNER_SIZE,
            "data_length": len(data),
            "data": data
        }

        write_block(path, new_block)
        blocks.append(new_block)

        print(f"Added item: {item_id}")
        print("Status: CHECKEDIN")
        print(f"Time of action: {format_timestamp(new_block['timestamp'])}")


# ------------------
# Command: checkout
# ------------------

def cmd_checkout(args):
    # checkout needs an item id and a role password
    item_id = None
    password = None

    i = 0
    while i < len(args):
        if args[i] == "-i" and i + 1 < len(args):
            item_id = args[i + 1]
            i += 2
        elif args[i] == "-p" and i + 1 < len(args):
            password = args[i + 1]
            i += 2
        else:
            exit_error("Invalid arguments")

    if item_id is None:
        exit_error("Missing item ID")

    if password is None or not is_owner_password(password):
        exit_error("Invalid password")

    if not validate_item_id(item_id):
        exit_error("Invalid item ID")

    path = get_blockchain_path()
    blocks = read_blocks(path)

    # find the current state of this item
    stored_item_id = store_item_id(item_id)
    latest_block = get_latest_block_for_item(blocks, stored_item_id)

    if latest_block is None:
        exit_error("Item does not exist")

    latest_state = get_state(latest_block)

    # checkout is only valid from CHECKEDIN
    if latest_state != STATE_CHECKEDIN:
        exit_error("Item is not checked in")

    last_block = get_last_block(blocks)
    data = b""

    # most fields carry forward from the previous item block
    new_block = {
        "prev_hash": hash_block(last_block),
        "timestamp": datetime.now(timezone.utc).timestamp(),
        "case_id": latest_block["case_id"],
        "item_id": latest_block["item_id"],
        "state": pad_bytes(STATE_CHECKEDOUT, STATE_SIZE),
        "creator": latest_block["creator"],
        "owner": owner_from_password(password),
        "data_length": len(data),
        "data": data
    }

    write_block(path, new_block)

    print(f"Case: {load_case_id(new_block['case_id'])}")
    print(f"Checked out item: {item_id}")
    print("Status: CHECKEDOUT")
    print(f"Time of action: {format_timestamp(new_block['timestamp'])}")


# ----------------
# Command: checkin
# ----------------

def cmd_checkin(args):
    # checkin mirrors checkout but requires the item to already be checked out
    item_id = None
    password = None

    i = 0
    while i < len(args):
        if args[i] == "-i" and i + 1 < len(args):
            item_id = args[i + 1]
            i += 2
        elif args[i] == "-p" and i + 1 < len(args):
            password = args[i + 1]
            i += 2
        else:
            exit_error("Invalid arguments")

    if item_id is None:
        exit_error("Missing item ID")

    if password is None or not is_owner_password(password):
        exit_error("Invalid password")

    if not validate_item_id(item_id):
        exit_error("Invalid item ID")

    path = get_blockchain_path()
    blocks = read_blocks(path)

    # look up the latest custody record for the item
    stored_item_id = store_item_id(item_id)
    latest_block = get_latest_block_for_item(blocks, stored_item_id)

    if latest_block is None:
        exit_error("Item does not exist")

    latest_state = get_state(latest_block)

    # checkin is only valid from CHECKEDOUT
    if latest_state != STATE_CHECKEDOUT:
        exit_error("Item is not checked out")

    last_block = get_last_block(blocks)
    data = b""

    new_block = {
        "prev_hash": hash_block(last_block),
        "timestamp": datetime.now(timezone.utc).timestamp(),
        "case_id": latest_block["case_id"],
        "item_id": latest_block["item_id"],
        "state": pad_bytes(STATE_CHECKEDIN, STATE_SIZE),
        "creator": latest_block["creator"],
        "owner": owner_from_password(password),
        "data_length": len(data),
        "data": data
    }

    write_block(path, new_block)

    print(f"Case: {load_case_id(new_block['case_id'])}")
    print(f"Checked in item: {item_id}")
    print("Status: CHECKEDIN")
    print(f"Time of action: {format_timestamp(new_block['timestamp'])}")

# ---------------
# Command: remove
# ---------------

def cmd_remove(args):
    # remove closes out an item with a final reason state
    item_id = None
    reason = None
    password = None
    owner_info = None

    i = 0
    while i < len(args):
        if args[i] == "-i" and i + 1 < len(args):
            item_id = args[i + 1]
            i += 2
        elif args[i] in ["-y", "--why"] and i + 1 < len(args):
            reason = args[i + 1]
            i += 2
        elif args[i] == "-p" and i + 1 < len(args):
            password = args[i + 1]
            i += 2
        elif args[i] == "-o" and i + 1 < len(args):
            owner_info = args[i + 1]
            i += 2
        else:
            exit_error("Invalid arguments")

    if item_id is None:
        exit_error("Missing item ID")

    if reason is None:
        exit_error("Missing removal reason")

    if password is None or not is_creator_password(password):
        exit_error("Invalid password")

    if not validate_item_id(item_id):
        exit_error("Invalid item ID")

    if reason not in [STATE_DISPOSED, STATE_DESTROYED, STATE_RELEASED]:
        exit_error("Invalid removal reason")

    if reason == STATE_RELEASED and owner_info is None:
        exit_error("Missing owner information")

    if reason != STATE_RELEASED and owner_info is not None:
        exit_error("Owner information only allowed for RELEASED")

    path = get_blockchain_path()
    blocks = read_blocks(path)

    # remove uses the latest item block as the base snapshot
    stored_item_id = store_item_id(item_id)
    latest_block = get_latest_block_for_item(blocks, stored_item_id)

    if latest_block is None:
        exit_error("Item does not exist")

    latest_state = get_state(latest_block)

    # removed items must currently be checked in
    if latest_state != STATE_CHECKEDIN:
        exit_error("Item is not checked in")

    # data is only used for RELEASED owner information
    if reason == STATE_RELEASED:
        data = owner_info.encode()
    else:
        data = b""

    last_block = get_last_block(blocks)

    new_block = {
        "prev_hash": hash_block(last_block),
        "timestamp": datetime.now(timezone.utc).timestamp(),
        "case_id": latest_block["case_id"],
        "item_id": latest_block["item_id"],
        "state": pad_bytes(reason, STATE_SIZE),
        "creator": latest_block["creator"],
        "owner": latest_block["owner"],
        "data_length": len(data),
        "data": data
    }

    write_block(path, new_block)

    print(f"Case: {load_case_id(new_block['case_id'])}")
    print(f"Removed item: {item_id}")
    print(f"Status: {reason}")
    print(f"Time of action: {format_timestamp(new_block['timestamp'])}")

# -------------------
# Command: show cases
# -------------------

def cmd_show_cases(args):
    # show all unique case IDs that appear in the chain
    password = None

    i = 0
    while i < len(args):
        if args[i] == "-p" and i + 1 < len(args):
            password = args[i + 1]
            i += 2
        else:
            exit_error("Invalid arguments")

    if password is not None and not is_owner_password(password):
        exit_error("Invalid password")

    path = get_blockchain_path()
    blocks = read_blocks(path)

    seen_cases = set()

    for block in blocks:
        if get_state(block) == STATE_INITIAL:
            continue

        seen_cases.add(block["case_id"])

    show_decrypted = password is not None and is_owner_password(password)

    if show_decrypted:
        cases = sorted(load_case_id(stored_case_id) for stored_case_id in seen_cases)
    else:
        cases = sorted(stored_case_id.decode() for stored_case_id in seen_cases)

    for case in cases:
        print(case)

# -------------------
# Command: show items
# -------------------

def cmd_show_items(args):
    # show all unique item IDs for a specific case
    case_id = None
    password = None

    i = 0
    while i < len(args):
        if args[i] == "-c" and i + 1 < len(args):
            case_id = args[i + 1]
            i += 2
        elif args[i] == "-p" and i + 1 < len(args):
            password = args[i + 1]
            i += 2
        else:
            exit_error("Invalid arguments")

    if case_id is None:
        exit_error("Missing case ID")

    if not validate_case_id(case_id):
        exit_error("Invalid case ID")

    if password is not None and not is_owner_password(password):
        exit_error("Invalid password")

    path = get_blockchain_path()
    blocks = read_blocks(path)

    stored_case_id = store_case_id(case_id)
    seen_items = set()

    for block in blocks:
        if get_state(block) == STATE_INITIAL:
            continue

        if block["case_id"] == stored_case_id:
            seen_items.add(block["item_id"])

    show_decrypted = password is not None and is_owner_password(password)

    if show_decrypted:
        items = sorted(int(load_item_id(stored_item_id)) for stored_item_id in seen_items)

        for item in items:
            print(item)
    else:
        items = sorted(stored_item_id.decode() for stored_item_id in seen_items)

        for item in items:
            print(item)

# ---------------------
# Command: show history
# ---------------------

def cmd_show_history(args):
    # show custody history, optionally filtered by case or item
    case_id = None
    item_id = None
    num_entries = None
    reverse = False
    password = None

    i = 0
    while i < len(args):
        if args[i] == "-c" and i + 1 < len(args):
            case_id = args[i + 1]
            i += 2
        elif args[i] == "-i" and i + 1 < len(args):
            item_id = args[i + 1]
            i += 2
        elif args[i] == "-n" and i + 1 < len(args):
            try:
                num_entries = int(args[i + 1])
            except ValueError:
                exit_error("Invalid number of entries")

            if num_entries < 0:
                exit_error("Invalid number of entries")

            i += 2
        elif args[i] in ["-r", "--reverse"]:
            reverse = True
            i += 1
        elif args[i] == "-p" and i + 1 < len(args):
            password = args[i + 1]
            i += 2
        else:
            exit_error("Invalid arguments")

    if case_id is not None and not validate_case_id(case_id):
        exit_error("Invalid case ID")

    if item_id is not None and not validate_item_id(item_id):
        exit_error("Invalid item ID")

    if password is not None and not is_owner_password(password):
        exit_error("Invalid password")

    path = get_blockchain_path()
    blocks = read_blocks(path)

    # initial block is only the chain anchor, not item history
    history = [block for block in blocks if get_state(block) != STATE_INITIAL]

    if case_id is not None:
        history = get_blocks_for_case(history, store_case_id(case_id))

    if item_id is not None:
        history = get_blocks_for_item(history, store_item_id(item_id))

    if reverse:
        history = list(reversed(history))

    if num_entries is not None:
        history = history[:num_entries]

    # without a valid password, show encrypted IDs instead of decrypted IDs
    show_decrypted = password is not None and is_owner_password(password)

    for block in history:
        if show_decrypted:
            case_display = load_case_id(block["case_id"])
            item_display = load_item_id(block["item_id"])
        else:
            case_display = block["case_id"].decode()
            item_display = block["item_id"].decode()

        print(f"Case: {case_display}")
        print(f"Item: {item_display}")
        print(f"Action: {get_state(block)}")
        print(f"Time: {format_timestamp(block['timestamp'])}")
        print()

# ----------------
# Command: summary
# ----------------

def cmd_summary(args):
    # count the activity recorded for a specific case
    case_id = None

    i = 0
    while i < len(args):
        if args[i] == "-c" and i + 1 < len(args):
            case_id = args[i + 1]
            i += 2
        else:
            exit_error("Invalid arguments")

    if case_id is None:
        exit_error("Missing case ID")

    if not validate_case_id(case_id):
        exit_error("Invalid case ID")

    path = get_blockchain_path()
    blocks = read_blocks(path)

    stored_case_id = store_case_id(case_id)

    unique_items = set()
    counts = {
        STATE_CHECKEDIN: 0,
        STATE_CHECKEDOUT: 0,
        STATE_DISPOSED: 0,
        STATE_DESTROYED: 0,
        STATE_RELEASED: 0
    }

    for block in blocks:
        if get_state(block) == STATE_INITIAL:
            continue

        if block["case_id"] != stored_case_id:
            continue

        unique_items.add(block["item_id"])

        state = get_state(block)
        if state in counts:
            counts[state] += 1

    print(f"Case Summary for Case ID: {case_id}")
    print(f"Total Evidence Items: {len(unique_items)}")
    print(f"Checked In: {counts[STATE_CHECKEDIN]}")
    print(f"Checked Out: {counts[STATE_CHECKEDOUT]}")
    print(f"Disposed: {counts[STATE_DISPOSED]}")
    print(f"Destroyed: {counts[STATE_DESTROYED]}")
    print(f"Released: {counts[STATE_RELEASED]}")

# ---------------
# Command: verify
# ---------------

def cmd_verify(args):
    # verify chain integrity and item state transitions
    if len(args) != 0:
        exit_error("Invalid arguments")

    path = get_blockchain_path()
    blocks = read_blocks(path)

    print(f"Transactions in blockchain: {len(blocks)}")

    if len(blocks) == 0:
        print("State of blockchain: ERROR")
        print("Bad block: INITIAL")
        print("Initial block not found.")
        sys.exit(1)

    first_block = blocks[0]

    # the chain must begin with the expected initial block
    if first_block["prev_hash"] != b'\x00' * PREV_HASH_SIZE or get_state(first_block) != STATE_INITIAL:
        print("State of blockchain: ERROR")
        print("Bad block: INITIAL")
        print("Invalid initial block.")
        sys.exit(1)

    # each block should point to the hash of the block immediately before it
    for i in range(1, len(blocks)):
        expected_prev_hash = hash_block(blocks[i - 1])

        if blocks[i]["prev_hash"] != expected_prev_hash:
            print("State of blockchain: ERROR")
            print(f"Bad block: {hash_block(blocks[i]).hex()}")
            print(f"Parent block: {blocks[i]['prev_hash'].hex()}")
            print("Parent block does not match previous block.")
            sys.exit(1)

    # duplicate parent hashes would mean two blocks claim the same parent
    seen_parent_hashes = set()

    for i in range(1, len(blocks)):
        parent_hash = blocks[i]["prev_hash"]

        if parent_hash in seen_parent_hashes:
            print("State of blockchain: ERROR")
            print(f"Bad block: {hash_block(blocks[i]).hex()}")
            print(f"Parent block: {parent_hash.hex()}")
            print("Two blocks were found with the same parent.")
            sys.exit(1)

        seen_parent_hashes.add(parent_hash)

    # replay item states to make sure each action is legal
    item_states = {}
    removed_items = set()

    for block in blocks:
        state = get_state(block)

        if state == STATE_INITIAL:
            continue

        item_id = block["item_id"]

        # once removed, an item should not receive more custody actions
        if item_id in removed_items:
            print("State of blockchain: ERROR")
            print(f"Bad block: {hash_block(block).hex()}")
            print("Item checked out or checked in after removal from chain.")
            sys.exit(1)

        # the first real block for an item should be its add/CHECKEDIN block
        if item_id not in item_states:
            if state != STATE_CHECKEDIN:
                print("State of blockchain: ERROR")
                print(f"Bad block: {hash_block(block).hex()}")
                print("Item action occurred before add.")
                sys.exit(1)

            item_states[item_id] = state
            continue

        previous_state = item_states[item_id]

        if state == STATE_CHECKEDIN:
            if previous_state != STATE_CHECKEDOUT:
                print("State of blockchain: ERROR")
                print(f"Bad block: {hash_block(block).hex()}")
                print("Invalid checkin transition.")
                sys.exit(1)

        elif state == STATE_CHECKEDOUT:
            if previous_state != STATE_CHECKEDIN:
                print("State of blockchain: ERROR")
                print(f"Bad block: {hash_block(block).hex()}")
                print("Invalid checkout transition.")
                sys.exit(1)

        elif state in [STATE_DISPOSED, STATE_DESTROYED, STATE_RELEASED]:
            if previous_state != STATE_CHECKEDIN:
                print("State of blockchain: ERROR")
                print(f"Bad block: {hash_block(block).hex()}")
                print("Invalid remove transition.")
                sys.exit(1)

            removed_items.add(item_id)

        else:
            print("State of blockchain: ERROR")
            print(f"Bad block: {hash_block(block).hex()}")
            print("Invalid block state.")
            sys.exit(1)

        item_states[item_id] = state

    print("State of blockchain: CLEAN")

# --------------
# Error Handling
# --------------

def exit_error(message):
    # print a simple error and return a nonzero exit code
    print(message)
    sys.exit(1)

# -----
# Main
# -----

def main():
    # route the first command-line word to the correct handler
    if len(sys.argv) < 2:
        print("No command provided")
        sys.exit(1)

    command = sys.argv[1]

    if command == "init":
        cmd_init(sys.argv[2:])
    elif command == "add":
        cmd_add(sys.argv[2:])
    elif command == "checkout":
        cmd_checkout(sys.argv[2:])
    elif command == "checkin":
        cmd_checkin(sys.argv[2:])
    elif command == "remove":
        cmd_remove(sys.argv[2:])
    elif command == "show":
        if len(sys.argv) >= 3 and sys.argv[2] == "history":
            cmd_show_history(sys.argv[3:])
        elif len(sys.argv) >= 3 and sys.argv[2] == "cases":
            cmd_show_cases(sys.argv[3:])
        elif len(sys.argv) >= 3 and sys.argv[2] == "items":
            cmd_show_items(sys.argv[3:])
        else:
            exit_error("Unknown show command")
    elif command == "summary":
        cmd_summary(sys.argv[2:])
    elif command == "verify":
        cmd_verify(sys.argv[2:])
    else:
        exit_error("Unknown command")

if __name__ == "__main__":
    main()