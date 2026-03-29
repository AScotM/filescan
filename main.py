#!/usr/bin/env python3

import argparse
import hashlib
import json
import math
import mmap
import sys
from collections import Counter
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import logging

logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class ChunkEntropy:
    offset: int
    size: int
    entropy: float


@dataclass
class FileReport:
    path: str
    exists: bool
    size: int
    sha256: Optional[str]
    is_binary: Optional[bool]
    printable_ratio: Optional[float]
    null_byte_ratio: Optional[float]
    entropy: Optional[float]
    unique_bytes: Optional[int]
    longest_byte_run: Optional[int]
    line_count: Optional[int]
    empty_line_count: Optional[int]
    avg_line_length: Optional[float]
    top_bytes: List[Dict[str, Any]]
    chunk_entropy: List[ChunkEntropy]
    notes: List[str]
    mime_type: Optional[str] = None


class FileStructureScanner:
    def __init__(
        self,
        chunk_size: int = 4096,
        max_top_bytes: int = 16,
        stream_threshold: int = 100 * 1024 * 1024,
        follow_symlinks: bool = True
    ) -> None:
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        if max_top_bytes <= 0:
            raise ValueError("max_top_bytes must be positive")
        if stream_threshold <= 0:
            raise ValueError("stream_threshold must be positive")

        self.chunk_size = chunk_size
        self.max_top_bytes = max_top_bytes
        self.stream_threshold = stream_threshold
        self.follow_symlinks = follow_symlinks
        self._magic_available = None

    def _check_magic(self) -> bool:
        if self._magic_available is None:
            try:
                import magic
                self._magic_available = True
            except ImportError:
                self._magic_available = False
        return self._magic_available

    def scan(self, path: str) -> FileReport:
        original_path = path
        target = Path(path)
        
        resolved_path = target
        if self.follow_symlinks:
            try:
                resolved_path = target.resolve()
            except (OSError, RuntimeError):
                resolved_path = target

        if not resolved_path.exists():
            return FileReport(
                path=original_path,
                exists=False,
                size=0,
                sha256=None,
                is_binary=None,
                printable_ratio=None,
                null_byte_ratio=None,
                entropy=None,
                unique_bytes=None,
                longest_byte_run=None,
                line_count=None,
                empty_line_count=None,
                avg_line_length=None,
                top_bytes=[],
                chunk_entropy=[],
                notes=["file does not exist"],
            )

        is_symlink = target.is_symlink()
        if is_symlink and not self.follow_symlinks:
            return FileReport(
                path=original_path,
                exists=True,
                size=0,
                sha256=None,
                is_binary=None,
                printable_ratio=None,
                null_byte_ratio=None,
                entropy=None,
                unique_bytes=None,
                longest_byte_run=None,
                line_count=None,
                empty_line_count=None,
                avg_line_length=None,
                top_bytes=[],
                chunk_entropy=[],
                notes=["symbolic link (not followed)"],
            )

        if not resolved_path.is_file():
            return FileReport(
                path=original_path,
                exists=True,
                size=0,
                sha256=None,
                is_binary=None,
                printable_ratio=None,
                null_byte_ratio=None,
                entropy=None,
                unique_bytes=None,
                longest_byte_run=None,
                line_count=None,
                empty_line_count=None,
                avg_line_length=None,
                top_bytes=[],
                chunk_entropy=[],
                notes=["path is not a regular file"],
            )

        size = resolved_path.stat().st_size
        
        if size > self.stream_threshold:
            return self._scan_large_file(original_path, str(resolved_path), size)
        else:
            return self._scan_small_file(original_path, str(resolved_path))

    def _scan_small_file(self, original_path: str, resolved_path: str) -> FileReport:
        target = Path(resolved_path)
        
        try:
            data = target.read_bytes()
        except MemoryError:
            return FileReport(
                path=original_path,
                exists=True,
                size=target.stat().st_size,
                sha256=None,
                is_binary=None,
                printable_ratio=None,
                null_byte_ratio=None,
                entropy=None,
                unique_bytes=None,
                longest_byte_run=None,
                line_count=None,
                empty_line_count=None,
                avg_line_length=None,
                top_bytes=[],
                chunk_entropy=[],
                notes=["file too large for memory, use streaming mode"],
            )
        
        size = len(data)
        notes: List[str] = []
        
        mime_type = self._detect_mime_type(resolved_path)
        sha256 = self._sha256_bytes(data) if data else None
        entropy = self._shannon_entropy(data) if data else 0.0
        unique_bytes = len(set(data)) if data else 0
        printable_ratio = self._printable_ratio(data) if data else 0.0
        null_byte_ratio = (data.count(0) / size) if size else 0.0
        is_binary = self._guess_binary(data, printable_ratio, null_byte_ratio) if data else False
        longest_run = self._longest_byte_run(data) if data else 0
        top_bytes = self._top_bytes(data) if data else []
        chunk_entropy = self._chunk_entropy(data) if data else []

        line_count = None
        empty_line_count = None
        avg_line_length = None

        if not is_binary and size > 0:
            text_metrics = self._text_metrics(data)
            line_count = text_metrics.get("line_count")
            empty_line_count = text_metrics.get("empty_line_count")
            avg_line_length = text_metrics.get("avg_line_length")

        self._add_notes(notes, size, entropy, null_byte_ratio, is_binary, data)

        return FileReport(
            path=original_path,
            exists=True,
            size=size,
            sha256=sha256,
            is_binary=is_binary,
            printable_ratio=printable_ratio if size > 0 else None,
            null_byte_ratio=null_byte_ratio if size > 0 else None,
            entropy=entropy if size > 0 else None,
            unique_bytes=unique_bytes if size > 0 else None,
            longest_byte_run=longest_run,
            line_count=line_count,
            empty_line_count=empty_line_count,
            avg_line_length=avg_line_length,
            top_bytes=top_bytes,
            chunk_entropy=chunk_entropy,
            notes=notes,
            mime_type=mime_type,
        )

    def _scan_large_file(self, original_path: str, resolved_path: str, size: int) -> FileReport:
        notes: List[str] = []
        mime_type = self._detect_mime_type(resolved_path)
        
        hasher = hashlib.sha256()
        byte_counts: Counter[int] = Counter()
        null_byte_count = 0
        printable_count = 0
        total_bytes_processed = 0
        longest_run = 0
        current_run = 0
        previous_byte: Optional[int] = None
        chunk_entropy_list: List[ChunkEntropy] = []
        
        try:
            with open(resolved_path, "rb") as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    for offset in range(0, size, self.chunk_size):
                        chunk = mm[offset:offset + self.chunk_size]
                        chunk_size = len(chunk)
                        total_bytes_processed += chunk_size
                        
                        hasher.update(chunk)
                        
                        chunk_entropy = self._shannon_entropy(chunk)
                        chunk_entropy_list.append(
                            ChunkEntropy(
                                offset=offset,
                                size=chunk_size,
                                entropy=chunk_entropy,
                            )
                        )
                        
                        byte_counts.update(chunk)
                        
                        null_byte_count += chunk.count(0)
                        
                        for byte in chunk:
                            if byte in (9, 10, 13) or 32 <= byte <= 126:
                                printable_count += 1
                        
                        for byte in chunk:
                            if byte == previous_byte:
                                current_run += 1
                                if current_run > longest_run:
                                    longest_run = current_run
                            else:
                                current_run = 1
                                previous_byte = byte
        except MemoryError:
            notes.append("memory mapping failed, file may be too large")
            return FileReport(
                path=original_path,
                exists=True,
                size=size,
                sha256=None,
                is_binary=None,
                printable_ratio=None,
                null_byte_ratio=None,
                entropy=None,
                unique_bytes=None,
                longest_byte_run=None,
                line_count=None,
                empty_line_count=None,
                avg_line_length=None,
                top_bytes=[],
                chunk_entropy=[],
                notes=notes,
                mime_type=mime_type,
            )
        
        sha256 = hasher.hexdigest()
        unique_bytes = len(byte_counts)
        
        printable_ratio = printable_count / total_bytes_processed if total_bytes_processed > 0 else 0.0
        null_byte_ratio = null_byte_count / total_bytes_processed if total_bytes_processed > 0 else 0.0
        
        total_entropy = self._shannon_entropy_from_counter(byte_counts, total_bytes_processed)
        
        is_binary_result = self._guess_binary_from_metrics(printable_ratio, null_byte_ratio) if total_bytes_processed > 0 else False
        
        top_bytes = self._top_bytes_from_counter(byte_counts, total_bytes_processed) if total_bytes_processed > 0 else []
        
        line_count = None
        empty_line_count = None
        avg_line_length = None
        
        if not is_binary_result and total_bytes_processed > 0:
            text_metrics = self._text_metrics_large_file(resolved_path)
            if text_metrics:
                line_count = text_metrics["line_count"]
                empty_line_count = text_metrics["empty_line_count"]
                avg_line_length = text_metrics["avg_line_length"]
        
        self._add_notes(notes, size, total_entropy, null_byte_ratio, is_binary_result, None)
        notes.append("processed using memory-mapped chunk scanning")
        
        longest_run_result = longest_run if longest_run > 0 else 0

        return FileReport(
            path=original_path,
            exists=True,
            size=size,
            sha256=sha256,
            is_binary=is_binary_result,
            printable_ratio=printable_ratio if total_bytes_processed > 0 else None,
            null_byte_ratio=null_byte_ratio if total_bytes_processed > 0 else None,
            entropy=total_entropy,
            unique_bytes=unique_bytes,
            longest_byte_run=longest_run_result,
            line_count=line_count,
            empty_line_count=empty_line_count,
            avg_line_length=avg_line_length,
            top_bytes=top_bytes,
            chunk_entropy=chunk_entropy_list,
            notes=notes,
            mime_type=mime_type,
        )

    def _detect_mime_type(self, path: str) -> Optional[str]:
        if not self._check_magic():
            return None
        try:
            import magic
            return magic.from_file(path, mime=True)
        except Exception:
            return None

    def _sha256_bytes(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def _shannon_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0

        counts = Counter(data)
        total = len(data)
        return self._shannon_entropy_from_counter(counts, total)

    def _shannon_entropy_from_counter(self, counts: Counter, total: int) -> float:
        if total == 0:
            return 0.0
        
        entropy = 0.0
        for count in counts.values():
            probability = count / total
            entropy -= probability * math.log2(probability)
        
        return min(entropy, 8.0)

    def _printable_ratio(self, data: bytes) -> float:
        if not data:
            return 0.0

        printable = 0
        for byte in data:
            if byte in (9, 10, 13) or 32 <= byte <= 126:
                printable += 1

        return printable / len(data)

    def _guess_binary(self, data: bytes, printable_ratio: Optional[float] = None, null_byte_ratio: Optional[float] = None) -> bool:
        if not data:
            return False
        
        if printable_ratio is None:
            printable_ratio = self._printable_ratio(data)
        
        if null_byte_ratio is None:
            null_byte_ratio = data.count(0) / len(data) if data else 0.0
        
        return self._guess_binary_from_metrics(printable_ratio, null_byte_ratio)

    def _guess_binary_from_metrics(self, printable_ratio: float, null_byte_ratio: float) -> bool:
        if null_byte_ratio > 0.005:
            return True
        
        if printable_ratio < 0.85:
            return True
        
        return False

    def _longest_byte_run(self, data: bytes) -> int:
        if not data:
            return 0

        longest = 1
        current = 1
        previous = data[0]

        for byte in data[1:]:
            if byte == previous:
                current += 1
                if current > longest:
                    longest = current
            else:
                current = 1
                previous = byte

        return longest

    def _top_bytes(self, data: bytes) -> List[Dict[str, Any]]:
        if not data:
            return []

        counts = Counter(data)
        total = len(data)
        return self._top_bytes_from_counter(counts, total)

    def _top_bytes_from_counter(self, counts: Counter, total: int) -> List[Dict[str, Any]]:
        if not counts or total == 0:
            return []

        items = counts.most_common(self.max_top_bytes)

        result: List[Dict[str, Any]] = []
        for byte_value, count in items:
            char_repr = self._byte_to_char(byte_value)
            result.append(
                {
                    "byte": byte_value,
                    "hex": f"0x{byte_value:02x}",
                    "char": char_repr,
                    "count": count,
                    "ratio": count / total,
                }
            )
        return result

    def _byte_to_char(self, byte_value: int) -> str:
        if 32 <= byte_value <= 126:
            return chr(byte_value)
        elif byte_value == 9:
            return "\\t"
        elif byte_value == 10:
            return "\\n"
        elif byte_value == 13:
            return "\\r"
        elif byte_value == 0:
            return "\\x00"
        else:
            return f"\\x{byte_value:02x}"

    def _chunk_entropy(self, data: bytes) -> List[ChunkEntropy]:
        if not data:
            return []

        result: List[ChunkEntropy] = []
        for offset in range(0, len(data), self.chunk_size):
            chunk = data[offset:offset + self.chunk_size]
            result.append(
                ChunkEntropy(
                    offset=offset,
                    size=len(chunk),
                    entropy=self._shannon_entropy(chunk),
                )
            )
        return result

    def _text_metrics(self, data: bytes) -> Dict[str, Any]:
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            return {
                "line_count": 0,
                "empty_line_count": 0,
                "avg_line_length": 0.0,
            }

        return self._compute_text_metrics(text)

    def _text_metrics_large_file(self, path: str) -> Optional[Dict[str, Any]]:
        try:
            line_count = 0
            empty_line_count = 0
            total_line_length = 0
            
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line_count += 1
                    stripped = line.strip()
                    if not stripped:
                        empty_line_count += 1
                    total_line_length += len(line.rstrip("\n\r"))
            
            if line_count == 0:
                return None
            
            return {
                "line_count": line_count,
                "empty_line_count": empty_line_count,
                "avg_line_length": total_line_length / line_count,
            }
        except Exception:
            return None

    def _compute_text_metrics(self, text: str) -> Dict[str, Any]:
        lines = text.splitlines()
        if not lines:
            return {
                "line_count": 0,
                "empty_line_count": 0,
                "avg_line_length": 0.0,
            }

        empty_line_count = sum(1 for line in lines if not line.strip())
        avg_line_length = sum(len(line) for line in lines) / len(lines)

        return {
            "line_count": len(lines),
            "empty_line_count": empty_line_count,
            "avg_line_length": avg_line_length,
        }

    def _add_notes(self, notes: List[str], size: int, entropy: float, null_byte_ratio: float, is_binary: bool, data: Optional[bytes]) -> None:
        if size == 0:
            notes.append("empty file")
            return
        
        if entropy >= 7.9:
            notes.append("very high entropy (possible compression/encryption)")
        elif entropy <= 1.0:
            notes.append("very low entropy (highly repetitive)")
        elif 1.0 < entropy < 3.0:
            notes.append("low entropy (structured data)")
        elif 6.0 < entropy < 7.9:
            notes.append("high entropy (random-like)")
        
        if null_byte_ratio > 0.01:
            notes.append("contains notable null bytes")
        elif 0.005 < null_byte_ratio <= 0.01:
            notes.append("contains moderate null bytes")
        
        if is_binary:
            notes.append("binary-like content")
        else:
            notes.append("text-like content")
        
        if data is not None:
            if data.startswith(b'\x1f\x8b'):
                notes.append("gzip compressed content detected")
            elif data.startswith(b'PK\x03\x04'):
                notes.append("ZIP archive detected")
            elif data.startswith(b'%PDF'):
                notes.append("PDF document detected")
            elif data.startswith(b'\x89PNG'):
                notes.append("PNG image detected")
            elif data.startswith(b'\xff\xd8\xff'):
                notes.append("JPEG image detected")


def format_size(num_bytes: int, binary_units: bool = True) -> str:
    if num_bytes == 0:
        return "0 B"
    
    if binary_units:
        units = ["B", "KiB", "MiB", "GiB", "TiB"]
        divisor = 1024.0
    else:
        units = ["B", "KB", "MB", "GB", "TB"]
        divisor = 1000.0
    
    value = float(num_bytes)
    
    for unit in units:
        if value < divisor or unit == units[-1]:
            return f"{value:.2f} {unit}"
        value /= divisor
    
    return f"{num_bytes} B"


def print_report(report: FileReport, show_chunks: bool = False, verbose: bool = False, max_chunks: int = 100) -> None:
    print(f"Path:               {report.path}")
    print(f"Exists:             {report.exists}")

    if not report.exists:
        if report.notes:
            print(f"Notes:              {', '.join(report.notes)}")
        return

    print(f"Size:               {report.size} bytes ({format_size(report.size)})")
    
    if report.sha256:
        print(f"SHA256:             {report.sha256}")
    else:
        print(f"SHA256:             N/A")
    
    if report.mime_type:
        print(f"MIME type:          {report.mime_type}")
    
    binary_status = "unknown"
    if report.is_binary is not None:
        binary_status = "yes" if report.is_binary else "no"
    print(f"Binary guess:       {binary_status}")
    
    if report.entropy is not None:
        print(f"Entropy:            {report.entropy:.4f}")
    else:
        print(f"Entropy:            N/A")
    
    if report.unique_bytes is not None:
        print(f"Unique bytes:       {report.unique_bytes}")
    else:
        print(f"Unique bytes:       N/A")
    
    if report.printable_ratio is not None:
        print(f"Printable ratio:    {report.printable_ratio:.4f}")
    else:
        print(f"Printable ratio:    N/A")
    
    if report.null_byte_ratio is not None:
        print(f"Null byte ratio:    {report.null_byte_ratio:.4f}")
    else:
        print(f"Null byte ratio:    N/A")
    
    if report.longest_byte_run is not None:
        print(f"Longest byte run:   {report.longest_byte_run}")

    if report.line_count is not None:
        print(f"Line count:         {report.line_count}")
        print(f"Empty lines:        {report.empty_line_count}")
        if report.avg_line_length is not None:
            print(f"Avg line length:    {report.avg_line_length:.2f}")

    if report.notes:
        print(f"Notes:              {', '.join(report.notes)}")

    if report.top_bytes:
        print("\nTop bytes:")
        for item in report.top_bytes:
            char_display = f"'{item['char']}'" if len(item['char']) == 1 else item['char']
            print(
                f"  {item['hex']:>4} ({char_display:>4})  "
                f"count={item['count']:>8}  "
                f"ratio={item['ratio']:.4f}"
            )

    if show_chunks and report.chunk_entropy:
        print("\nChunk entropy:")
        
        chunk_stats = [c.entropy for c in report.chunk_entropy]
        if chunk_stats:
            min_entropy = min(chunk_stats)
            max_entropy = max(chunk_stats)
            avg_entropy = sum(chunk_stats) / len(chunk_stats)
            print(f"  Range: {min_entropy:.4f} - {max_entropy:.4f}, Avg: {avg_entropy:.4f}")
            print()
        
        max_display = max_chunks if verbose else min(max_chunks, 20)
        display_chunks = report.chunk_entropy[:max_display]
        
        for chunk in display_chunks:
            print(
                f"  offset={chunk.offset:>10}  "
                f"size={chunk.size:>6}  "
                f"entropy={chunk.entropy:.4f}"
            )
        
        if len(report.chunk_entropy) > max_display:
            print(f"  ... and {len(report.chunk_entropy) - max_display} more chunks")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan file entropy and structural characteristics",
        epilog="""
Examples:
  %(prog)s file.txt
  %(prog)s --json large_file.bin
  %(prog)s --show-chunks --verbose encrypted.dat
        """
    )
    parser.add_argument("path", help="Path to file")
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=4096,
        help="Chunk size for entropy scan (default: 4096)",
    )
    parser.add_argument(
        "--top-bytes",
        type=int,
        default=16,
        help="Number of top bytes to display (default: 16)",
    )
    parser.add_argument(
        "--stream-threshold",
        type=int,
        default=100 * 1024 * 1024,
        help="Threshold in bytes for streaming mode (default: 100MB)",
    )
    parser.add_argument(
        "--no-follow-symlinks",
        action="store_true",
        help="Do not follow symbolic links",
    )
    parser.add_argument(
        "--show-chunks",
        action="store_true",
        help="Show per-chunk entropy results",
    )
    parser.add_argument(
        "--max-chunks",
        type=int,
        default=100,
        help="Maximum number of chunks to display (default: 100)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show more detailed output",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress non-critical output",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    
    if args.verbose:
        logger.setLevel(logging.INFO)

    try:
        scanner = FileStructureScanner(
            chunk_size=args.chunk_size,
            max_top_bytes=args.top_bytes,
            stream_threshold=args.stream_threshold,
            follow_symlinks=not args.no_follow_symlinks,
        )
        report = scanner.scan(args.path)

        if args.json:
            payload = asdict(report)
            print(json.dumps(payload, indent=2))
        else:
            print_report(
                report,
                show_chunks=args.show_chunks,
                verbose=args.verbose,
                max_chunks=args.max_chunks
            )

        if not report.exists:
            return 2
        elif report.is_binary is None:
            return 3
        elif report.notes and any("error" in note.lower() for note in report.notes):
            return 1
        else:
            return 0
            
    except KeyboardInterrupt:
        if not args.quiet:
            print("Interrupted", file=sys.stderr)
        return 130
    except PermissionError as exc:
        if not args.quiet:
            print(f"Permission denied: {exc}", file=sys.stderr)
        return 1
    except MemoryError:
        if not args.quiet:
            print("Memory error: file too large for available memory", file=sys.stderr)
        return 1
    except ValueError as exc:
        if not args.quiet:
            print(f"Invalid argument: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        if not args.quiet:
            print(f"Error: {exc}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
