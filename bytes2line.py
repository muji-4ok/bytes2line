#!/usr/bin/env -S python

import re
import logging

from argparse import ArgumentParser
from pathlib import Path

from search import ByteSymbolSearcher

logging.basicConfig(level=logging.INFO)


def hex_replace_func(match):
    return f'{match.group(1):>02}'


def hex_str_to_bytes(s: str) -> bytes:
    s = re.sub(r'0x([0-9a-fA-F]{1,2})', hex_replace_func, s)
    return bytes.fromhex(s)


def parse_args():
    parser = ArgumentParser(
        description='Script for determining program symbols by instruction bytes')

    parser.add_argument('path',
                        help='Directory of ELF files or a single ELF file',
                        type=Path)
    parser.add_argument('target',
                        help='Bytes to search for in hex or "-", which means server mode',
                        type=str)
    parser.add_argument('-e', '--file-extension', required=False,
                        default='debug', type=str, help='Extenstion of ELF files')

    return parser.parse_args()


def main():
    args = parse_args()

    path: Path = args.path
    extension = args.file_extension
    target = args.target

    if not path.exists():
        raise RuntimeError(f'Supplied path = {path} does not exist')

    symbol_searcher = ByteSymbolSearcher()

    if path.is_dir():
        for file_path in path.glob(f'**/*.{extension}'):
            symbol_searcher.add_elf_file(file_path)
    else:
        symbol_searcher.add_elf_file(path)

    if target == '-':
        print('Reading inputs')

        while True:
            try:
                hex_input = input('>>> ').strip()
            except KeyboardInterrupt:
                print('Interrupt received. Stopping')
                break

            if not hex_input:
                continue

            try:
                target_bytes = hex_str_to_bytes(hex_input)
            except ValueError as e:
                print(f'Failed to parse hex string. Error = {e}')
                continue

            try:
                symbol_searcher.print_symbols(target_bytes)
            except KeyboardInterrupt:
                print('Printing interrupted')
    else:
        target_bytes = hex_str_to_bytes(target)
        symbol_searcher.print_symbols(target_bytes)


if __name__ == '__main__':
    main()
