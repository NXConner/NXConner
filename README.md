# Porn Finder CLI

A fast, multi-threaded scanner with progress bar to locate adult content by filename, extension, content keywords, and optionally deep image classification. Can optionally leverage `ripgrep` for acceleration. Supports quarantine or deletion with `--apply`.

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# Optional for content search acceleration
# sudo apt-get install ripgrep
# Optional for deep image classification (heavy dependency):
# pip install nsfw-detector tensorflow
```

## Quick start

Dry-run scan with progress bar:

```bash
python porn_finder.py /path/to/scan --report-json report.json --report-csv report.csv
```

Exclude hidden files and common directories:

```bash
python porn_finder.py /home/user --no-hidden --exclude "*/.cache/*" --exclude "*/node_modules/*"
```

Add extra extensions to include:

```bash
python porn_finder.py /mnt/storage --ext .pdf --ext .docx
```

Use ripgrep acceleration (default on if `rg` is installed):

```bash
python porn_finder.py /data
```

Quarantine flagged files (dry-run by default):

```bash
python porn_finder.py /data --quarantine /tmp/quarantine
```

Apply actions (move/delete). Dangerous, use with care:

```bash
# Move flagged files into quarantine
python porn_finder.py /data --quarantine /secure/quarantine --apply

# OR delete flagged files (irreversible)
python porn_finder.py /data --delete --apply
```

Deep image NSFW classification (optional):

```bash
python porn_finder.py /data --deep-image --nsfw-model-path /path/to/model.h5 --nsfw-threshold 0.85
```

## Output

- Prints a summary with total scanned and flagged files, with a reason breakdown.
- Optional reports:
  - `--report-json report.json`
  - `--report-csv report.csv`

## Notes

- Progress bar requires `tqdm` (already in requirements). If missing, the script falls back gracefully.
- File type detection prefers `python-magic` and falls back to `mimetypes`.
- Ripgrep (`rg`) is optional but speeds up text content candidate discovery.
- Deep image classification is optional and requires `nsfw-detector` (and its ML backend). It is disabled by default.