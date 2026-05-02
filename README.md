Blockchain Chain of Custody - Track 1

Group 6

Group Members:
Adrian Hernandez [1227811262]
Liam Nolan [1229483439]
Luke Humbert [1229294445]
Vinnie Kumar [1226867709]
Violet Stinson [1228552639]

Project Description:
This program implements a digital chain of custody system using a binary blockchain file. Each action involving evidence is stored as a block in the chain. The program supports initializing the blockchain, adding evidence items, checking items in and out, removing items, viewing cases/items/history, generating a case summary, and verifying the integrity of the blockchain.

How the Program Works:
The executable is called bchoc. The Makefile creates this executable from bchoc.py when make is run.

The blockchain file location is determined using the BCHOC_FILE_PATH environment variable. If that variable is not set, the program uses blockchain.dat in the current directory.

Each block is stored in binary format using the required struct layout:
32s d 32s 32s 12s 12s 12s I

Each block contains:
- previous block hash
- timestamp
- encrypted case ID
- encrypted item ID
- state
- creator
- owner
- data length
- data

The case ID and item ID are encrypted using AES ECB mode before being stored. The program uses SHA-256 hashes to link each block to the previous block. The verify command recalculates these hashes and checks item state transitions to detect invalid chains.

Supported Commands:
./bchoc init
./bchoc add -c case_id -i item_id [-i item_id ...] -g creator -p password
./bchoc checkout -i item_id -p password
./bchoc checkin -i item_id -p password
./bchoc remove -i item_id -y reason -p password [-o owner]
./bchoc show cases [-p password]
./bchoc show items -c case_id [-p password]
./bchoc show history [-c case_id] [-i item_id] [-n num_entries] [-r] [-p password]
./bchoc summary -c case_id
./bchoc verify

Dependencies:
This project uses PyCryptodome for AES encryption. The required package is listed in the packages file:
python3-pycryptodome

Build Instructions:
Run:
make

This creates the executable:
./bchoc

Example Usage:
make
./bchoc init
./bchoc add -c c84e339e-5c0f-4f4d-84c5-bb79a3c1d2a2 -i 100 -g Adrian -p C67C
./bchoc checkout -i 100 -p A65A
./bchoc checkin -i 100 -p P80P
./bchoc verify

Generative AI Acknowledgment:
Portions of the code in this project were generated with assistance from ChatGPT, an AI tool developed by OpenAI.

Reference:
OpenAI. (2024). ChatGPT [Large language model].
openai.com/chatgpt

Estimated percentage of code influenced by Generative AI:
[65]%

Generative AI was used to help plan the project structure, explain the assignment requirements, debug implementation issues, review code behavior, and suggest improvements for command parsing, blockchain validation, and README wording. The code was reviewed, edited, tested, and adjusted by our group.