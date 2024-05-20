import logging
import os

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from elftools.elf.elffile import ELFFile, DWARFInfo
from elftools.elf.sections import SymbolTableSection

from dwarf import decode_file_line, decode_funcname


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

        self._text_file_start: int = text_section['sh_offset']
        text_size = text_section['sh_size']
        self._text_file_end: int = self._text_file_start + text_size
        self._text_code_offset: int = text_section['sh_addr']

        symbol_section = self._elf.get_section_by_name('.symtab')
        self._symbol_file_locations = self._build_symbols(symbol_section)

        self._has_dwarf = self._elf.has_dwarf_info()
        # NOTE(e-kutovoi): Load lazily
        self._dwarf = None

    def is_in_text_section(self, file_offset: int) -> bool:
        return self._text_file_start <= file_offset < self._text_file_end

    def find_symbol(self, file_offset: int) -> str | None:
        return closest_symbol_name(self._symbol_file_locations, file_offset)

    def get_line_info_from_file_offset(self, file_offset: int) -> LineInfo | None:
        return self.get_line_info_from_text_offset(file_offset - self._text_file_start)

    def get_line_info_from_text_offset(self, text_offset: int) -> LineInfo | None:
        if not self._has_dwarf:
            return None

        address = self._text_code_offset + text_offset

        file, line = decode_file_line(self._get_dwarf(), address)

        if file is None:
            assert line is None
            return None

        func = decode_funcname(self._get_dwarf(), address)

        return LineInfo(Path(file), line, func)

    def _get_dwarf(self) -> DWARFInfo:
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


class AddrSymbolSearcher:
    _elfs: dict[Path, ElfFileSearcher]

    def __init__(self):
        self._elfs = {}

    def add_elf_file(self, path: Path):
        path = path.resolve()
        logging.debug(f'Loading elf file {path}')
        self._elfs[path] = ElfFileSearcher(path)

    def get_line_info(self, text_offset: int, path: Path) -> LineInfo | None:
        if path not in self._elfs:
            logging.debug(f'Path = {path} not available')
            return None

        elf = self._elfs[path]
        return elf.get_line_info_from_text_offset(text_offset)


class ByteSymbolSearcher:
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
            _print_file_header(path)
            _print_symbols(symbols_in_path, self._elfs[path])
            print()


def _print_file_header(path: Path):
    name_size = len(path.name)
    limited_path = _fit_str_on_terminal(str(path.resolve()),
                                        name_size + 4)
    print(f'{path.name}: ({limited_path})')


def _fit_str_on_terminal(s: str, already_occupied_size: int):
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


def _print_symbols(symbols: list[SymbolMatch], elf: ElfFileSearcher):
    for s in symbols:
        line_info = elf.get_line_info_from_file_offset(s.offset)

        if line_info is None:
            print(f'{s.offset:>08}: {s.name}')
        else:
            func = line_info.func if line_info.func is not None else '???'
            occupied_size = 14 + len(func) + len(str(line_info.line))
            limited_path = _fit_str_on_terminal(str(line_info.file), occupied_size)
            print(f'{s.offset:>08}: {func} ({limited_path}:{line_info.line})')
