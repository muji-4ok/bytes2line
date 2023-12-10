## Script for converting raw instruction bytes to source lines

(provided you have the ELF files with debug info)

Works with single files or with directories. Default is to search for `.debug` files, as I made with for EDK2

## Requirements

- Python 3.10+
- [pyelftools](https://github.com/eliben/pyelftools)

