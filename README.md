# Cryptographic Key Generator

This Python script facilitates the generation and handling of cryptographic keys, particularly for blockchain and cryptocurrency applications. It supports multiple networks by generating Ethereum and Avalanche compatible keys, with options for mnemonic-based or random private key generation.

## Features

- Generate Ethereum and P-Chain addresses.
- Encode private keys with base58 and a checksum.
- Support for mnemonic-based key derivation.
- Compatible with various network HRPs (Human Readable Parts).

## Requirements

- Python 3.x
- `eth_keys`
- `bip_utils`
- `binascii`
- `hashlib`
- `base58`
- `os`

## Installation

Before running the script, ensure that all dependencies are installed:

```bash
pip install eth-keys bip-utils base58
