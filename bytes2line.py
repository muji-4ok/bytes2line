#!/usr/bin/env -S python

import logging
import re
import os

from argparse import ArgumentParser
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from dwarf import decode_file_line, decode_funcname

logging.basicConfig(level=logging.INFO)


def hex_replace_func(match):
    return f'{match.group(1):>02}'


def hex_str_to_bytes(s: str) -> bytes:
    s = re.sub(r'0x([0-9a-fA-F]{1,2})', hex_replace_func, s)
    return bytes.fromhex(s)


def find_occurences(haystack: bytes, needle: bytes) -> list[int]:
    result = []
    start = 0

    while True:
        offset = haystack.find(needle, start)

        if offset == -1:
            break

        result.append(offset)
        start = offset + 1

    return result


def closest_symbol_name(symbols: dict[int, str], target_offset: int) -> str | None:
    best = None

    for offset in symbols.keys():
        if offset > target_offset:
            continue

        if best is None:
            best = offset
        elif target_offset - offset <= target_offset - best:
            best = offset

    return symbols[best] if best is not None else None


@dataclass
class SymbolMatch:
    name: str
    path: Path
    offset: int


@dataclass
class LineInfo:
    file: Path
    line: int
    func: str | None


class ElfFileSearcher:
    def __init__(self, path: Path):
        self._path = path
        self._elf = ELFFile.load_from_path(path)

        self._text_index = self._elf.get_section_index('.text')
        text_section = self._elf.get_section(self._text_index)

        self._text_file_start = text_section['sh_offset']
        text_size = text_section['sh_size']
        self._text_file_end = self._text_file_start + text_size
        self._text_code_offset = text_section['sh_addr']

        symbol_section = self._elf.get_section_by_name('.symtab')
        self._symbol_file_locations = self._build_symbols(symbol_section)

        self._has_dwarf = self._elf.has_dwarf_info()
        # NOTE(e-kutovoi): Load lazily
        self._dwarf = None

    def is_in_text_section(self, file_offset: int) -> bool:
        return self._text_file_start <= file_offset < self._text_file_end

    def find_symbol(self, file_offset: int) -> str | None:
        return closest_symbol_name(self._symbol_file_locations, file_offset)

    def get_line_info(self, file_offset: int) -> LineInfo | None:
        if not self._has_dwarf:
            return None

        address = file_offset - self._text_file_start + self._text_code_offset

        file, line = decode_file_line(self._get_dwarf(), address)

        if file is None:
            assert line is None
            return None

        func = decode_funcname(self._get_dwarf(), address)

        return LineInfo(Path(file), line, func)

    def _get_dwarf(self):
        if self._dwarf is None:
            logging.debug(f'Loading dwarf info for {self._path}')
            self._dwarf = self._elf.get_dwarf_info()

        return self._dwarf

    def _build_symbols(self, symbol_section: SymbolTableSection) -> dict[int, str]:
        result = {}

        for symbol in symbol_section.iter_symbols():
            value = symbol.entry['st_value']

            if symbol.entry['st_shndx'] != self._text_index:
                continue

            if symbol.entry['st_info']['type'] != 'STT_FUNC':
                continue

            if not symbol.name or symbol.name.startswith('.LC'):
                continue

            offset = value - self._text_code_offset + self._text_file_start
            result[offset] = symbol.name

        return result


class SymbolSearcher:
    _file_bytes: dict[Path, bytes]
    _elfs: dict[Path, ElfFileSearcher]

    def __init__(self):
        self._file_bytes = {}
        self._elfs = {}

    def add_elf_file(self, path: Path):
        logging.debug(f'Loading elf file {path}')

        with open(path, 'rb') as f:
            self._file_bytes[path] = f.read()

        self._elfs[path] = ElfFileSearcher(path)

    def find_symbols(self, target_bytes: bytes) -> list[SymbolMatch]:
        result = []

        for path, file_bytes in self._file_bytes.items():
            file_offsets = find_occurences(file_bytes, target_bytes)

            if not file_offsets:
                logging.debug(f'File {path} does not match {target_bytes}')
                continue

            for file_offset in file_offsets:
                elf = self._elfs[path]

                if not elf.is_in_text_section(file_offset):
                    continue

                maybe_symbol = elf.find_symbol(file_offset)

                if maybe_symbol is None:
                    logging.warning(
                        f'Target bytes contained in file {path} .text section, but could not be matched to a symbol')
                    continue

                result.append(SymbolMatch(maybe_symbol, path, file_offset))

        return result

    def print_symbols(self, target_bytes: bytes):
        symbols = self.find_symbols(target_bytes)
        symbols_per_file = defaultdict(list)

        for symbol in symbols:
            symbols_per_file[symbol.path].append(symbol)

        for path, symbols_in_path in symbols_per_file.items():
            self._print_file_header(path)
            self._print_symbols(symbols_in_path, self._elfs[path])
            print()

    def _print_file_header(self, path: Path):
        name_size = len(path.name)
        limited_path = self._fit_str_on_terminal(str(path.resolve()),
                                                 name_size + 4)
        print(f'{path.name}: ({limited_path})')

    def _fit_str_on_terminal(self, s: str, already_occupied_size: int):
        try:
            max_columns = os.get_terminal_size()[0]
        except OSError:
            max_columns = None

        if max_columns is not None:
            margin = already_occupied_size + 5

            if len(s) + margin > max_columns:
                limit = max_columns - margin
                return f'...{s[-limit:]}'
            else:
                return s
        else:
            return s

    def _print_symbols(self, symbols: list[SymbolMatch], elf: ElfFileSearcher):
        for s in symbols:
            line_info = elf.get_line_info(s.offset)

            if line_info is None:
                print(f'{s.offset:>08}: {s.name}')
            else:
                func = line_info.func if line_info.func is not None else '???'
                occupied_size = 14 + len(func) + len(str(line_info.line))
                limited_path = self._fit_str_on_terminal(str(line_info.file), occupied_size)
                print(f'{s.offset:>08}: {func} ({limited_path}:{line_info.line})')


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

    symbol_searcher = SymbolSearcher()

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

            symbol_searcher.print_symbols(target_bytes)
    else:
        target_bytes = hex_str_to_bytes(target)
        symbol_searcher.print_symbols(target_bytes)


if __name__ == '__main__':
    main()
