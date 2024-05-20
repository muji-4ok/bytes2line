#!/usr/bin/env -S python

import re
import logging
import socketserver
import socket

from argparse import ArgumentParser
from pathlib import Path
from threading import Lock

from search import AddrSymbolSearcher

logging.basicConfig(level=logging.DEBUG)

mutex = Lock()


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
    parser.add_argument('-b', '--bind',
                        help='Address to bind to',
                        default='0.0.0.0',
                        type=str)
    parser.add_argument('-p', '--port',
                        help='Port on which to listen',
                        default=14578,
                        type=int)
    parser.add_argument('-e', '--file-extension', required=False,
                        default='debug', type=str, help='Extenstion of ELF files')

    return parser.parse_args()


class ConnectionClosed(Exception):
    pass


class MyTCPHandler(socketserver.BaseRequestHandler):
    symbol_searcher: AddrSymbolSearcher

    def handle(self):
        with mutex:
            self.handle_locked()

    def handle_locked(self):
        self.request: socket.socket
        self.buffer = b''

        while True:
            try:
                path, text_offset = self.recv_input()
            except (ValueError, UnicodeDecodeError):
                logging.exception('Failed to parse request')
                self.send_fail()
                continue
            except ConnectionClosed:
                self.buffer = b''
                break

            line_info = MyTCPHandler.symbol_searcher.get_line_info(text_offset, path)

            print(path, text_offset)
            print('===>')
            print(line_info)

            if line_info is None:
                logging.info(f'{path=} does not contain {text_offset=}')
                self.send_fail()
                continue

            reply = f'{line_info.file}:{line_info.line}\n'

            self.request.sendall(reply.encode('ascii'))

    def send_fail(self):
        self.request.sendall('invalid_request\n'.encode('ascii'))

    def recv_input(self) -> tuple[Path, int]:
        message = self.recv_line()

        if message is None:
            raise ConnectionClosed()

        path, text_offset = message.strip().split()
        text_offset = int(text_offset, base=16)
        path = Path(path)

        if not path.is_absolute():
            raise ValueError(f'Path = {path} is not absolute')

        if not path.exists():
            raise ValueError(f'Path = {path} does not exist')

        return path, text_offset

    def recv_line(self) -> str | None:
        while True:
            newline_index = self.buffer.find(b'\n')

            if newline_index >= 0:
                before, after = self.buffer.split(b'\n')
                self.buffer = after
                return before.decode('ascii')

            recvd = self.request.recv(1024)

            if not recvd:
                return None

            self.buffer += recvd


class MyTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


def main():
    args = parse_args()

    path: Path = args.path
    extension = args.file_extension

    if not path.exists():
        raise RuntimeError(f'Supplied path = {path} does not exist')

    symbol_searcher = AddrSymbolSearcher()

    if path.is_dir():
        for file_path in path.glob(f'**/*.{extension}'):
            symbol_searcher.add_elf_file(file_path)
    else:
        symbol_searcher.add_elf_file(path)

    MyTCPHandler.symbol_searcher = symbol_searcher

    bind_addr = args.bind
    port = args.port

    print(f'Starting server on {bind_addr}:{port}')

    with MyTCPServer((bind_addr, port), MyTCPHandler) as server:
        server.serve_forever()


if __name__ == '__main__':
    main()
