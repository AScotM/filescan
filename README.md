File Structure Scanner

A Python CLI tool for inspecting file structure using entropy, byte distribution, and content heuristics. Supports both small and large files with efficient chunk-based analysis.

Features
SHA256 hashing
Entropy (global and per-chunk)
Byte frequency analysis
Binary/text detection
Printable and null byte ratios
Text metrics (lines, empty lines, average length)
Basic file signature hints
Optional MIME detection (python-magic)
JSON output
Usage
./scanner.py file.bin
./scanner.py --json file.bin
./scanner.py --show-chunks file.bin
Notes

Uses full read for small files and memory-mapped chunk scanning for large files.
Binary detection is heuristic.
