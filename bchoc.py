#!/usr/bin/env python3

# ============================================================
# bchoc.py
# Blockchain Chain of Custody - Track 1
# ============================================================
# Purpose:
#   Implement a command-line chain of custody system using a
#   binary blockchain file.
#
# Required executable:
#   ./bchoc
#
# Main commands:
#   init
#   add
#   checkout
#   checkin
#   remove
#   show cases
#   show items
#   show history
#   verify
#   summary
# ============================================================


# ============================================================
# Imports
# ============================================================
# Import only the modules needed for:
#   - command-line parsing
#   - binary struct packing/unpacking
#   - hashing
#   - timestamps
#   - UUID validation
#   - environment variables
#   - program exit codes

import os
import sys
import uuid
import struct
import hashlib
from datetime import datetime, timezone


# ============================================================
# Constants
# ============================================================
# Define field sizes:
#   PREV_HASH_SIZE = 32
#   TIMESTAMP_SIZE = 8
#   CASE_ID_SIZE = 32
#   ITEM_ID_SIZE = 32
#   STATE_SIZE = 12
#   CREATOR_SIZE = 12
#   OWNER_SIZE = 12
#   DATA_LENGTH_SIZE = 4
#
# Define valid states:
#   INITIAL
#   CHECKEDIN
#   CHECKEDOUT
#   DISPOSED
#   DESTROYED
#   RELEASED
#
# Define passwords:
#   Creator password = C67C
#   Police password = P80P
#   Lawyer password = L76L
#   Analyst password = A65A
#   Executive password = E69E
#
# Define password-to-owner mapping:
#   P80P -> POLICE
#   L76L -> LAWYER
#   A65A -> ANALYST
#   E69E -> EXECUTIVE
#
# Define AES key:
#   AES_KEY = b"R0chLi4uLi4uLi4="
#
# Define struct format string for fixed block fields.
# The project recommends:
#   "32s d 32s 32s 12s 12s 12s I"

# Field sizes
PREV_HASH_SIZE = 32
TIMESTAMP_SIZE = 8
CASE_ID_SIZE = 32
ITEM_ID_SIZE = 32
STATE_SIZE = 12
CREATOR_SIZE = 12
OWNER_SIZE = 12
DATA_LENGTH_SIZE = 4

# States
STATE_INITIAL = "INITIAL"
STATE_CHECKEDIN = "CHECKEDIN"
STATE_CHECKEDOUT = "CHECKEDOUT"
STATE_DISPOSED = "DISPOSED"
STATE_DESTROYED = "DESTROYED"
STATE_RELEASED = "RELEASED"

# Passwords
PASSWORD_CREATOR = "C67C"
PASSWORD_POLICE = "P80P"
PASSWORD_LAWYER = "L76L"
PASSWORD_ANALYST = "A65A"
PASSWORD_EXECUTIVE = "E69E"

# Password → owner mapping
PASSWORD_TO_OWNER = {
    PASSWORD_POLICE: "POLICE",
    PASSWORD_LAWYER: "LAWYER",
    PASSWORD_ANALYST: "ANALYST",
    PASSWORD_EXECUTIVE: "EXECUTIVE"
}

# AES key (used later)
AES_KEY = b"R0chLi4uLi4uLi4="

# Struct format (fixed header)
BLOCK_STRUCT_FORMAT = "32s d 32s 32s 12s 12s 12s I"
BLOCK_STRUCT = struct.Struct(BLOCK_STRUCT_FORMAT)

# ============================================================
# File Path Handling
# ============================================================
# Create a helper function to determine the blockchain file path.
#
# Important:
#   First check BCHOC_FILE_PATH environment variable.
#   If it exists, use that.
#   Otherwise, use a reasonable local default path.
#
# This is required for Gradescope/autograding.

def get_blockchain_path():
    return os.environ.get("BCHOC_FILE_PATH", "blockchain.dat")

# ============================================================
# Padding and Encoding Helpers
# ============================================================
# Create helper functions for:
#   - converting strings to bytes
#   - null-padding fixed-width fields
#   - stripping null bytes when displaying fields
#   - validating max byte lengths
#
# Fields that need padding:
#   state: 12 bytes
#   creator: 12 bytes
#   owner: 12 bytes
#
# Remember:
#   add owner = 12 null bytes
#   creator comes from -g
#   checkout/checkin owner comes from password role
#   remove owner is inherited from latest item block

def pad_bytes(value: str, length: int) -> bytes:
    b = value.encode()
    return b.ljust(length, b'\x00')[:length]

def strip_padding(value: bytes) -> str:
    return value.rstrip(b'\x00').decode()

# ============================================================
# UUID and Item ID Helpers
# ============================================================
# Create helper functions for:
#   - validating case_id is a UUID
#   - validating item_id is a 4-byte integer
#   - converting case_id into the required encrypted/stored form
#   - converting item_id into the required encrypted/stored form
#
# Important:
#   Case ID and Item ID must be encrypted using AES ECB
#   before being stored in the binary file.
#
# Also create helpers for decrypting them when a valid password
# is provided for show/history output.

def validate_case_id(case_id):
    try:
        uuid.UUID(case_id)
        return True
    except ValueError:
        return False


def validate_item_id(item_id):
    try:
        value = int(item_id)
        return 0 <= value <= 0xFFFFFFFF
    except ValueError:
        return False
    
def store_case_id(case_id):
    return uuid.UUID(case_id).hex.encode()

def store_item_id(item_id):
    return int(item_id).to_bytes(4, byteorder="big").rjust(ITEM_ID_SIZE, b'\x00')

# ============================================================
# Password Helpers
# ============================================================
# Create helper functions for:
#   - checking creator password
#   - checking owner passwords
#   - checking whether a password is valid at all
#   - converting owner password to owner role bytes
#
# Rules:
#   add/remove require creator password C67C
#   checkout/checkin require one of the owner passwords
#   show commands require one of the owner passwords
#   invalid passwords should print an error and exit nonzero

def is_creator_password(password):
    return password == PASSWORD_CREATOR


def is_owner_password(password):
    return password in PASSWORD_TO_OWNER


def owner_from_password(password):
    if password not in PASSWORD_TO_OWNER:
        return None
    return pad_bytes(PASSWORD_TO_OWNER[password], OWNER_SIZE)


# ============================================================
# Block Representation
# ============================================================
# Decide how to represent a block internally.
#
# Possible simple approach:
#   Use a dictionary with keys:
#     prev_hash
#     timestamp
#     case_id
#     item_id
#     state
#     creator
#     owner
#     data_length
#     data
#
# Or:
#   Use a small class/dataclass later if desired.
#
# Each block must contain all fields, because every block is a
# complete snapshot of that evidence item.


# ============================================================
# Genesis / Initial Block
# ============================================================
# Create helper function to build the INITIAL block.
#
# Required values:
#   prev_hash = 32 zero bytes
#   timestamp = 0
#   case_id = b"0" * 32
#   item_id = b"0" * 32
#   state = INITIAL padded to 12 bytes
#   creator = 12 null bytes
#   owner = 12 null bytes
#   data_length = 14
#   data = b"Initial block\0"
#
# The init command uses this block.

def create_initial_block():
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

# ============================================================
# Binary Packing / Unpacking
# ============================================================
# Create functions to:
#   - pack a block into binary bytes
#   - unpack binary bytes into a block object/dictionary
#
# Important:
#   The fixed-size header is packed using the struct format.
#   The variable-length data field comes after the fixed fields.
#
# Reading blocks:
#   Read fixed header first.
#   Use data_length to know how many additional bytes to read.
#
# Writing blocks:
#   Pack fixed fields.
#   Append data bytes.

def pack_block(block):
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

# ============================================================
# Hashing Helpers
# ============================================================
# Create helper function to calculate the SHA-256 hash of a block.
#
# Important:
#   Each new block stores the hash of the previous block.
#   verify must recompute hashes to detect tampering.
#
# Decide exactly which bytes are included in the block hash:
#   likely the full packed block bytes.

def hash_block(block):
    return hashlib.sha256(pack_block(block)).digest()


# ============================================================
# Blockchain File Read / Write Helpers
# ============================================================
# Create functions to:
#   - check if blockchain file exists
#   - read all blocks from the blockchain file
#   - append one block to the blockchain file
#   - create the file with the initial block
#
# Important:
#   All blockchain data must be binary.
#   Do not use JSON, CSV, or plain text storage.

def blockchain_exists(path):
    return os.path.exists(path)


def write_block(path, block):
    with open(path, "ab") as f:
        f.write(pack_block(block))

def read_blocks(path):
    blocks = []

    if not blockchain_exists(path):
        return blocks

    with open(path, "rb") as f:
        while True:
            header = f.read(BLOCK_STRUCT.size)

            if header == b"":
                break

            if len(header) != BLOCK_STRUCT.size:
                print("Invalid blockchain file")
                sys.exit(1)

            data_length = BLOCK_STRUCT.unpack(header)[7]
            data = f.read(data_length)

            if len(data) != data_length:
                print("Invalid blockchain file")
                sys.exit(1)

            blocks.append(unpack_block(header, data))

    return blocks

# ============================================================
# Blockchain Search Helpers
# ============================================================
# Create helper functions for:
#   - finding the latest block for an item_id
#   - finding all blocks for an item_id
#   - finding all blocks for a case_id
#   - checking whether an item already exists
#   - checking whether an item has been removed
#   - getting all unique cases
#   - getting all items for a case
#
# These helpers will be used by add, checkout, checkin, remove,
# show, summary, and verify.

def get_last_block(blocks):
    if len(blocks) == 0:
        return None
    return blocks[-1]


def get_latest_block_for_item(blocks, item_id):
    latest = None

    for block in blocks:
        if block["item_id"] == item_id:
            latest = block

    return latest

# ============================================================
# State Transition Helpers
# ============================================================
# Create helper functions that enforce valid transitions.
#
# Rules:
#   add creates CHECKEDIN
#   checkout only allowed if latest state is CHECKEDIN
#   checkin only allowed if latest state is CHECKEDOUT
#   remove only allowed if latest state is CHECKEDIN
#   no actions allowed after DISPOSED, DESTROYED, or RELEASED
#
# Invalid operations should exit nonzero.


# ============================================================
# Command: init
# ============================================================
# Behavior:
#   If blockchain file does not exist:
#       create file
#       write INITIAL block
#       print success message
#
#   If blockchain file exists:
#       verify that INITIAL block exists
#       print success message
#
#   If file exists but INITIAL block is invalid:
#       print error
#       exit nonzero

def cmd_init():
    path = get_blockchain_path()

    if not blockchain_exists(path):
        block = create_initial_block()
        write_block(path, block)
        print("Blockchain file not found. Created INITIAL block.")
    else:
        blocks = read_blocks(path)

        if len(blocks) == 0:
            print("Blockchain file found but INITIAL block is missing.")
            sys.exit(1)

        first_block = blocks[0]

        if first_block["state"].rstrip(b'\x00') != STATE_INITIAL.encode():
            print("Blockchain file found but INITIAL block is invalid.")
            sys.exit(1)

        print("Blockchain file found with INITIAL block.")

# ============================================================
# Command: add
# ============================================================
# Required syntax:
#   bchoc add -c case_id -i item_id [-i item_id ...] -g creator -p password
#
# Behavior:
#   Ensure blockchain file exists or create INITIAL block if needed.
#   Validate creator password C67C.
#   Validate case_id UUID.
#   Validate each item_id.
#   Reject duplicate item_id.
#   For each item:
#       create CHECKEDIN block
#       creator = value from -g
#       owner = 12 null bytes
#       data = empty
#       data_length = 0
#       prev_hash = hash of previous block
#       append block
#       print expected output

def cmd_add(args):
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

    if not blockchain_exists(path):
        write_block(path, create_initial_block())

    blocks = read_blocks(path)

    for item_id in item_ids:
        stored_item_id = store_item_id(item_id)

        if get_latest_block_for_item(blocks, stored_item_id) is not None:
            exit_error("Duplicate item ID")

        last_block = get_last_block(blocks)
        prev_hash = hash_block(last_block)

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
        print(f"Time of action: {datetime.fromtimestamp(new_block['timestamp'], timezone.utc).isoformat().replace('+00:00', 'Z')}")


# ============================================================
# Command: checkout
# ============================================================
# Required syntax:
#   bchoc checkout -i item_id -p password
#
# Behavior:
#   Validate owner password.
#   Find latest block for item.
#   Item must already exist.
#   Latest state must be CHECKEDIN.
#   Create CHECKEDOUT block.
#   Carry forward case_id, item_id, creator.
#   owner = role determined by password.
#   data = empty.
#   Append block.
#   Print expected output.


# ============================================================
# Command: checkin
# ============================================================
# Required syntax:
#   bchoc checkin -i item_id -p password
#
# Behavior:
#   Validate owner password.
#   Find latest block for item.
#   Item must already exist.
#   Latest state must be CHECKEDOUT.
#   Create CHECKEDIN block.
#   Carry forward case_id, item_id, creator.
#   owner = role determined by password.
#   data = empty.
#   Append block.
#   Print expected output.


# ============================================================
# Command: remove
# ============================================================
# Required syntax:
#   bchoc remove -i item_id -y reason -p password
#
# Optional:
#   -o owner information, only for RELEASED
#
# Behavior:
#   Validate creator password C67C.
#   Find latest block for item.
#   Item must already exist.
#   Latest state must be CHECKEDIN.
#   Reason must be DISPOSED, DESTROYED, or RELEASED.
#   If reason is RELEASED, store -o text in data field.
#   If reason is not RELEASED, data is empty.
#   Carry forward case_id, item_id, creator, owner.
#   State becomes reason.
#   Append block.
#   Print expected output.


# ============================================================
# Command: show cases
# ============================================================
# Required syntax:
#   bchoc show cases
#
# Behavior:
#   Read blockchain.
#   Find all unique case IDs.
#   Display them in expected format.
#
# Need to consider password behavior if required by tests/spec.


# ============================================================
# Command: show items
# ============================================================
# Required syntax:
#   bchoc show items -c case_id
#
# Behavior:
#   Validate case_id.
#   Read blockchain.
#   Find all unique item IDs for the given case.
#   Display them in expected format.
#
# Need to consider password behavior if required by tests/spec.


# ============================================================
# Command: show history
# ============================================================
# Required syntax:
#   bchoc show history [-c case_id] [-i item_id] [-n num_entries] [-r] -p password
#
# Behavior:
#   Read blockchain.
#   Filter by case_id if provided.
#   Filter by item_id if provided.
#   Default order is oldest first.
#   If -r is used, show newest first.
#   If -n is used, limit number of entries.
#
# Password behavior:
#   With valid password, show decrypted case_id and item_id.
#   Without valid password or no password, encrypted values may be shown,
#   depending on exact command/test expectations.


# ============================================================
# Command: summary
# ============================================================
# Required syntax:
#   bchoc summary -c case_id
#
# Behavior:
#   Iterate through blocks for the case.
#   Count unique item IDs.
#   Count blocks/states:
#       CHECKEDIN
#       CHECKEDOUT
#       DISPOSED
#       DESTROYED
#       RELEASED
#   Print in expected format.


# ============================================================
# Command: verify
# ============================================================
# Required syntax:
#   bchoc verify
#
# Behavior:
#   Read all blocks.
#   Verify INITIAL block.
#   Verify hash links.
#   Verify no duplicate parent issue.
#   Verify block contents match checksum.
#   Verify item state transitions.
#
# Should detect errors such as:
#   missing parent block
#   duplicate parent block
#   invalid initial block
#   checksum mismatch
#   duplicate item add
#   double checkin
#   double checkout
#   remove before add
#   action after remove
#
# On success:
#   print transaction count
#   print CLEAN
#
# On failure:
#   print transaction count
#   print ERROR
#   print bad block information
#   exit nonzero


# ============================================================
# Argument Parsing
# ============================================================
# Create command-line parser.
#
# Recognize command patterns:
#   init
#   add
#   checkout
#   checkin
#   remove
#   show cases
#   show items
#   show history
#   verify
#   summary
#
# Keep parsing simple and predictable.
# Can use argparse subcommands or manual parsing.


# ============================================================
# Error Handling
# ============================================================
# Create helper for errors:
#   print message
#   sys.exit(1)
#
# Success should exit 0.
#
# The exact error message is usually less important than
# the nonzero exit code, but clear messages help debugging.

def exit_error(message):
    print(message)
    sys.exit(1)


# ============================================================
# Main Entry Point
# ============================================================
# main():
#   parse arguments
#   dispatch to the correct command handler
#
# if __name__ == "__main__":
#   main()

def main():
    if len(sys.argv) < 2:
        print("No command provided")
        sys.exit(1)

    command = sys.argv[1]

    if command == "init":
        cmd_init()
    elif command == "add":
        cmd_add(sys.argv[2:])
    else:
        exit_error("Unknown command")


if __name__ == "__main__":
    main()