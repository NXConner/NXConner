#!/usr/bin/env python3

import argparse
import concurrent.futures
import dataclasses
import fnmatch
import hashlib
import json
import mimetypes
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple, Callable

try:
    from tqdm import tqdm
except Exception:  # pragma: no cover
    tqdm = None  # type: ignore

# Optional dependencies
try:  # pragma: no cover
    import magic  # python-magic
except Exception:  # pragma: no cover
    magic = None  # type: ignore

try:  # pragma: no cover
    from PIL import Image
except Exception:  # pragma: no cover
    Image = None  # type: ignore

# You can optionally provide an NSFW classifier via nsfw_detector
# pip install nsfw-detector
# and download a model, then pass --nsfw-model-path
try:  # pragma: no cover
    from nsfw_detector import predict as nsfw_predict  # type: ignore
except Exception:  # pragma: no cover
    nsfw_predict = None  # type: ignore


DEFAULT_IMAGE_EXTENSIONS: Set[str] = {
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".bmp",
    ".webp",
    ".tiff",
    ".tif",
    ".heic",
    ".heif",
}

DEFAULT_VIDEO_EXTENSIONS: Set[str] = {
    ".mp4",
    ".mkv",
    ".avi",
    ".mov",
    ".wmv",
    ".flv",
    ".webm",
    ".mpeg",
    ".mpg",
    ".m4v",
}

DEFAULT_TEXT_EXTENSIONS: Set[str] = {
    ".txt",
    ".md",
    ".html",
    ".htm",
    ".json",
    ".xml",
    ".csv",
    ".srt",
    ".vtt",
}

# A non-exhaustive multi-language keyword list to match explicit content in filenames/paths or text
# Note: detection purpose only
DEFAULT_KEYWORDS: List[str] = [
    r"porn",
    r"porno",
    r"pornography",
    r"nsfw",
    r"xxx",
    r"x-rated",
    r"adult",
    r"explicit",
    r"hardcore",
    r"softcore",
    r"nude",
    r"nudity",
    r"naked",
    r"sex",
    r"sexual",
    r"xxx18",
    r"18\+",
    r"amateur",
    r"anal",
    r"bdsm",
    r"bondage",
    r"blowjob",
    r"boobs",
    r"breasts",
    r"camgirl",
    r"camsite",
    r"cock",
    r"cum",
    r"cumming",
    r"deepthroat",
    r"dildo",
    r"dp",
    r"erotic",
    r"erotica",
    r"facial",
    r"fetish",
    r"fisting",
    r"fuck",
    r"fucked",
    r"fucking",
    r"gangbang",
    r"handjob",
    r"hardon",
    r"hentai",
    r"hotgirl",
    r"hottie",
    r"incest",
    r"jk",
    r"jerkoff",
    r"lesbian",
    r"milf",
    r"masturbat",
    r"nsfw",
    r"orgasm",
    r"orgy",
    r"penis",
    r"pornhub",
    r"pussy",
    r"redtube",
    r"rule34",
    r"sextape",
    r"slut",
    r"strip",
    r"threesome",
    r"tit",
    r"tits",
    r"vagina",
    r"xhamster",
    r"xnxx",
    r"xvideos",
]

# Common archive formats for stashes
DEFAULT_ARCHIVE_EXTENSIONS: Set[str] = {
    ".zip",
    ".rar",
    ".7z",
    ".tar",
    ".gz",
    ".bz2",
    ".xz",
}


@dataclasses.dataclass
class ScanResult:
    path: str
    reasons: List[str]
    size_bytes: int
    mime_type: Optional[str] = None
    nsfw_score: Optional[float] = None


@dataclasses.dataclass
class ScannerConfig:
    roots: List[str]
    include_hidden: bool = True
    follow_symlinks: bool = False
    exclude_globs: List[str] = dataclasses.field(default_factory=list)
    include_exts: Set[str] = dataclasses.field(
        default_factory=lambda: DEFAULT_IMAGE_EXTENSIONS | DEFAULT_VIDEO_EXTENSIONS | DEFAULT_ARCHIVE_EXTENSIONS
    )
    text_exts: Set[str] = dataclasses.field(default_factory=lambda: DEFAULT_TEXT_EXTENSIONS)
    keywords: List[str] = dataclasses.field(default_factory=lambda: DEFAULT_KEYWORDS)
    keyword_regex: Optional[re.Pattern] = None
    max_text_bytes: int = 2_000_000  # 2 MB per file for content scan
    num_workers: int = max(4, (os.cpu_count() or 4))
    ripgrep: bool = True
    deep_image_classify: bool = False
    nsfw_model_path: Optional[str] = None
    nsfw_threshold: float = 0.85
    quarantine_dir: Optional[str] = None
    delete: bool = False
    apply: bool = False
    dry_run: bool = True
    report_json: Optional[str] = None
    report_csv: Optional[str] = None


def is_hidden(path: Path) -> bool:
    name = path.name
    return name.startswith(".") or name in {"Thumbs.db", "desktop.ini"}


def should_exclude(path: Path, exclude_globs: List[str]) -> bool:
    if not exclude_globs:
        return False
    path_str = str(path)
    for pattern in exclude_globs:
        if fnmatch.fnmatch(path_str, pattern):
            return True
    return False


def get_mime_type(path: Path) -> Optional[str]:
    if magic is not None:
        try:
            ms = magic.Magic(mime=True)
            return ms.from_file(str(path))
        except Exception:
            pass
    mime, _ = mimetypes.guess_type(str(path))
    return mime


def hash_file_quick(path: Path, chunk_size: int = 1_048_576) -> str:
    # SHA-1 quick hash for dedupe
    h = hashlib.sha1()
    try:
        with open(path, "rb") as f:
            while True:
                data = f.read(chunk_size)
                if not data:
                    break
                h.update(data)
    except Exception:
        return ""
    return h.hexdigest()


def compile_keyword_regex(keywords: List[str]) -> re.Pattern:
    escaped = [kw for kw in keywords if kw]
    # word-like boundaries where applicable, case-insensitive
    pattern = r"(" + r"|".join(escaped) + r")"
    return re.compile(pattern, flags=re.IGNORECASE)


def build_ripgrep_pattern(keywords: List[str]) -> str:
    # Combine keywords into a single alternation
    # Ripgrep uses Rust regex; most of our tokens are compatible
    return "|".join(keywords)


def list_files(roots: List[str], include_hidden: bool, follow_symlinks: bool, exclude_globs: List[str]) -> List[Path]:
    paths: List[Path] = []
    for root in roots:
        root_path = Path(root)
        if not root_path.exists():
            continue
        for dirpath, dirnames, filenames in os.walk(root_path, followlinks=follow_symlinks):
            current_dir = Path(dirpath)
            # Optionally filter out hidden directories quickly
            if not include_hidden:
                dirnames[:] = [d for d in dirnames if not d.startswith(".")]
            # Apply directory-level exclude globs
            if should_exclude(current_dir, exclude_globs):
                dirnames[:] = []
                continue
            for filename in filenames:
                file_path = current_dir / filename
                if not include_hidden and is_hidden(file_path):
                    continue
                if should_exclude(file_path, exclude_globs):
                    continue
                paths.append(file_path)
    return paths


def is_text_mime(mime: Optional[str], path: Path, text_exts: Set[str]) -> bool:
    if mime is None:
        return path.suffix.lower() in text_exts
    return mime.startswith("text/") or mime in {"application/json", "application/xml", "application/xhtml+xml"}


def scan_text_for_keywords(path: Path, regex: re.Pattern, max_bytes: int) -> bool:
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            text = data.decode("latin-1", errors="ignore")
    except Exception:
        return False
    return bool(regex.search(text))


def init_nsfw_model(model_path: str):  # pragma: no cover
    if nsfw_predict is None:
        raise RuntimeError("nsfw_detector not available. Install with: pip install nsfw-detector")
    return nsfw_predict.load_model(model_path)


def classify_image_nsfw(model, path: Path) -> Optional[float]:  # pragma: no cover
    try:
        preds = nsfw_predict.classify(model, [str(path)])
        # preds is a dict: {path: {'drawings': 0.001, 'hentai': 0.01, 'neutral': 0.2, 'porn': 0.7, 'sexy': 0.09}}
        entry = preds.get(str(path))
        if not entry:
            return None
        porn_score = float(entry.get("porn", 0.0))
        sexy_score = float(entry.get("sexy", 0.0))
        hentai_score = float(entry.get("hentai", 0.0))
        # Combine conservatively
        score = max(porn_score, 0.75 * sexy_score, 0.75 * hentai_score)
        return score
    except Exception:
        return None


def gather_candidates_with_ripgrep(roots: List[str], keywords: List[str]) -> Set[str]:
    if shutil.which("rg") is None:
        return set()
    pattern = build_ripgrep_pattern(keywords)
    candidates: Set[str] = set()
    rg_cmd = [
        "rg",
        "--ignore-case",
        "--no-messages",
        "--hidden",
        "--pcre2",
        "--with-filename",
        "--line-number",
        "--color=never",
        pattern,
    ] + roots
    try:
        proc = subprocess.run(rg_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False, text=True)
        if proc.returncode in (0, 1):
            for line in proc.stdout.splitlines():
                # Format: path:line:content
                # We only want the path
                if ":" in line:
                    path = line.split(":", 1)[0]
                    candidates.add(os.path.abspath(path))
    except Exception:
        pass
    return candidates


def action_on_path(path: Path, cfg: ScannerConfig) -> None:
    if not cfg.apply:
        return
    if cfg.delete:
        try:
            path.unlink(missing_ok=True)  # type: ignore[arg-type]
        except Exception:
            pass
        return
    if cfg.quarantine_dir:
        try:
            qdir = Path(cfg.quarantine_dir)
            qdir.mkdir(parents=True, exist_ok=True)
            target = qdir / path.name
            # Avoid collisions
            if target.exists():
                stem = target.stem
                suffix = target.suffix
                i = 1
                while True:
                    candidate = qdir / f"{stem}_{i}{suffix}"
                    if not candidate.exists():
                        target = candidate
                        break
                    i += 1
            shutil.move(str(path), str(target))
        except Exception:
            pass


def scan_one_file(path: Path, cfg: ScannerConfig, keyword_re: re.Pattern, nsfw_model) -> Optional[ScanResult]:
    reasons: List[str] = []
    size_bytes = 0
    try:
        size_bytes = path.stat().st_size
    except Exception:
        pass

    suffix = path.suffix.lower()

    # Filename/path keyword match
    if keyword_re.search(str(path)):
        reasons.append("name_keyword")

    # Extension-based heuristics
    if suffix in cfg.include_exts:
        reasons.append("extension")

    mime = get_mime_type(path)

    # Text content scan
    if is_text_mime(mime, path, cfg.text_exts):
        if scan_text_for_keywords(path, keyword_re, cfg.max_text_bytes):
            reasons.append("content_keyword")

    # Deep image classification (optional)
    if cfg.deep_image_classify and suffix in DEFAULT_IMAGE_EXTENSIONS and nsfw_model is not None:
        score = classify_image_nsfw(nsfw_model, path)
        if score is not None:
            if score >= cfg.nsfw_threshold:
                reasons.append("nsfw_image")
            nsfw_score = score
        else:
            nsfw_score = None
    else:
        nsfw_score = None

    if not reasons:
        return None

    return ScanResult(
        path=str(path),
        reasons=reasons,
        size_bytes=size_bytes,
        mime_type=mime,
        nsfw_score=nsfw_score,
    )


def write_reports(results: List[ScanResult], cfg: ScannerConfig) -> None:
    if cfg.report_json:
        try:
            out = [dataclasses.asdict(r) for r in results]
            with open(cfg.report_json, "w", encoding="utf-8") as f:
                json.dump(out, f, ensure_ascii=False, indent=2)
        except Exception:
            pass
    if cfg.report_csv:
        try:
            import csv

            with open(cfg.report_csv, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["path", "reasons", "size_bytes", "mime_type", "nsfw_score"])
                for r in results:
                    writer.writerow([
                        r.path,
                        ";".join(r.reasons),
                        r.size_bytes,
                        r.mime_type or "",
                        f"{r.nsfw_score:.4f}" if r.nsfw_score is not None else "",
                    ])
        except Exception:
            pass


def parse_args(argv: Optional[List[str]] = None) -> ScannerConfig:
    parser = argparse.ArgumentParser(
        prog="porn_finder",
        description="Scan directories for adult content using filename/content heuristics, with progress bar and optional NSFW image classification.",
    )
    parser.add_argument("roots", nargs="+", help="Directories or files to scan")
    parser.add_argument("--no-hidden", action="store_true", help="Exclude hidden files and directories")
    parser.add_argument("--follow-symlinks", action="store_true", help="Follow symlinks during scanning")
    parser.add_argument("--exclude", action="append", default=[], help="Glob to exclude (can be passed multiple times)")
    parser.add_argument(
        "--ext",
        action="append",
        default=[],
        help="Additional file extension to include (e.g., --ext .pdf). Can be repeated.",
    )
    parser.add_argument("--no-ripgrep", action="store_true", help="Disable ripgrep acceleration if installed")
    parser.add_argument("--max-text-bytes", type=int, default=2_000_000, help="Max bytes to read from text files")
    parser.add_argument("--workers", type=int, default=max(4, (os.cpu_count() or 4)), help="Number of worker threads")
    parser.add_argument("--deep-image", action="store_true", help="Enable deep NSFW image classification (requires nsfw-detector)")
    parser.add_argument("--nsfw-model-path", type=str, default=None, help="Path to NSFW detector model (h5)")
    parser.add_argument("--nsfw-threshold", type=float, default=0.85, help="Threshold to flag NSFW image [0-1]")
    parser.add_argument("--quarantine", type=str, default=None, help="Directory to move flagged files into")
    parser.add_argument("--delete", action="store_true", help="Delete flagged files (irreversible)")
    parser.add_argument("--apply", action="store_true", help="Apply actions (move/delete). Without this, dry-run only.")
    parser.add_argument("--report-json", type=str, default=None, help="Write JSON report to this path")
    parser.add_argument("--report-csv", type=str, default=None, help="Write CSV report to this path")

    args = parser.parse_args(argv)

    include_hidden = not args.no_hidden

    include_exts = set(DEFAULT_IMAGE_EXTENSIONS | DEFAULT_VIDEO_EXTENSIONS | DEFAULT_ARCHIVE_EXTENSIONS)
    for e in args.ext:
        if not e.startswith("."):
            e = "." + e
        include_exts.add(e.lower())

    cfg = ScannerConfig(
        roots=[str(Path(r)) for r in args.roots],
        include_hidden=include_hidden,
        follow_symlinks=args.follow_symlinks,
        exclude_globs=args.exclude,
        include_exts=include_exts,
        max_text_bytes=args.max_text_bytes,
        num_workers=args.workers,
        ripgrep=not args.no_ripgrep,
        deep_image_classify=args.deep_image,
        nsfw_model_path=args.nsfw_model_path,
        nsfw_threshold=args.nsfw_threshold,
        quarantine_dir=args.quarantine,
        delete=args.delete,
        apply=args.apply,
        dry_run=not args.apply,
        report_json=args.report_json,
        report_csv=args.report_csv,
    )

    if cfg.delete and cfg.quarantine_dir:
        parser.error("--delete and --quarantine are mutually exclusive")

    return cfg


def run_scan(cfg: ScannerConfig, on_progress: Optional[Callable[[int, int, int, Optional[str]], None]] = None) -> List[ScanResult]:
    # Compile keyword regex
    keyword_re = compile_keyword_regex(cfg.keywords)

    # Initialize optional NSFW model
    nsfw_model = None
    if cfg.deep_image_classify:
        if cfg.nsfw_model_path:
            try:
                nsfw_model = init_nsfw_model(cfg.nsfw_model_path)
            except Exception:
                nsfw_model = None
        else:
            nsfw_model = None

    # Optional ripgrep accelerated candidate paths (content matches)
    rg_candidates: Set[str] = set()
    if cfg.ripgrep:
        rg_candidates = gather_candidates_with_ripgrep(cfg.roots, cfg.keywords)

    # Enumerate files
    all_paths = list_files(cfg.roots, cfg.include_hidden, cfg.follow_symlinks, cfg.exclude_globs)

    # Merge ripgrep candidates into the list (ensure we include even if filtered by ext)
    if rg_candidates:
        extra = [Path(p) for p in rg_candidates if Path(p).exists()]
        # Avoid duplicates
        existing: Set[str] = {str(p) for p in all_paths}
        for p in extra:
            sp = str(p)
            if sp not in existing:
                all_paths.append(p)

    total_files = len(all_paths)

    results: List[ScanResult] = []
    flagged_count = 0

    def do_progress(current_processed: int, current_path: Optional[str] = None):
        if on_progress:
            try:
                on_progress(current_processed, total_files, flagged_count, current_path)
            except Exception:
                pass

    do_progress(0)

    # Thread pool scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=cfg.num_workers) as executor:
        future_to_path = {
            executor.submit(scan_one_file, p, cfg, keyword_re, nsfw_model): p for p in all_paths
        }
        processed = 0
        for fut in concurrent.futures.as_completed(future_to_path):
            p = future_to_path[fut]
            try:
                res = fut.result()
            except Exception:
                res = None
            if res is not None:
                results.append(res)
                flagged_count += 1
                if cfg.apply:
                    action_on_path(Path(res.path), cfg)
            processed += 1
            do_progress(processed, str(p))

    # Reports
    write_reports(results, cfg)

    return results


def main(argv: Optional[List[str]] = None) -> int:
    cfg = parse_args(argv)

    # Console progress bar wiring
    print("Indexing files...", file=sys.stderr)

    # If progress bar available, show it
    total_seen = 0
    flagged_seen = 0
    progress = None

    def on_progress(current_index: int, total: int, flagged_count: int, current_path: Optional[str]):
        nonlocal total_seen, flagged_seen, progress
        total_seen = total
        flagged_seen = flagged_count
        if tqdm:
            if progress is None:
                progress = tqdm(total=total, unit="file")
            else:
                # Sometimes total can be 0 initially, update when we know it
                if progress.total != total and total > 0:
                    progress.total = total
            # Ensure progress reflects current_index
            delta = current_index - progress.n
            if delta > 0:
                progress.update(delta)
            if progress.n:
                pct = (flagged_seen / max(1, progress.n)) * 100.0
            else:
                pct = 0.0
            progress.set_postfix({"flagged": flagged_seen, "%": f"{pct:.1f}"})

    results = run_scan(cfg, on_progress=on_progress)

    if progress:
        progress.close()

    total_files = sum(1 for _ in results) + (progress.n - flagged_seen if progress else 0)

    # Summary
    print()
    print(f"Flagged files: {len(results)}")
    # Reason breakdown
    reason_counts: Dict[str, int] = {}
    for r in results:
        for reason in r.reasons:
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
    if reason_counts:
        print("Breakdown by reason:")
        for reason, count in sorted(reason_counts.items(), key=lambda kv: (-kv[1], kv[0])):
            print(f"  - {reason}: {count}")

    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())