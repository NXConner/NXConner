#!/usr/bin/env python3

import os
import sys
import threading
import time
import subprocess
from pathlib import Path
from typing import List, Optional

try:
    import PySimpleGUI as sg
except Exception as e:  # pragma: no cover
    print("PySimpleGUI is required. Install with: pip install PySimpleGUI", file=sys.stderr)
    sys.exit(1)

try:
    from porn_finder import ScannerConfig, run_scan
except Exception as e:  # pragma: no cover
    print(f"Failed to import scanner core: {e}", file=sys.stderr)
    sys.exit(1)


APP_TITLE = "Adult Content Scanner - One Click"


def resolve_roots_from_input(input_value: str, dropped_paths: List[str]) -> List[str]:
    roots: List[str] = []
    if input_value.strip():
        # Split by semicolon or newline to support multiple paths
        for token in input_value.replace("\n", ";").split(";"):
            token = token.strip().strip('"')
            if token:
                roots.append(token)
    for p in dropped_paths:
        p = p.strip().strip('"')
        if p:
            roots.append(p)
    # Normalize and dedupe
    normalized: List[str] = []
    seen = set()
    for r in roots:
        abspath = str(Path(r).expanduser().resolve())
        if abspath not in seen:
            seen.add(abspath)
            normalized.append(abspath)
    return normalized


def open_folder(path: Path) -> None:
    try:
        if sys.platform.startswith("linux"):
            subprocess.Popen(["xdg-open", str(path)])
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        elif os.name == "nt":
            os.startfile(str(path))  # type: ignore[attr-defined]
    except Exception:
        pass


def main() -> int:
    sg.theme("SystemDefault")

    drop_help = "Drag & drop files or folders here, or use Browse"

    layout = [
        [sg.Text("Select path(s) to scan:")],
        [
            sg.Input(key="-PATHS-", enable_events=True, expand_x=True, tooltip=drop_help),
            sg.FolderBrowse(target="-PATHS-", tooltip="Choose a folder"),
            sg.FilesBrowse(target="-PATHS-", tooltip="Choose files", file_types=(('All files', '*.*'),)),
        ],
        [sg.Text(drop_help, key="-DROP-LABEL-")],
        [sg.Checkbox("Include hidden", key="-HIDDEN-", default=True),
         sg.Checkbox("Follow symlinks", key="-SYMLINKS-", default=False),
         sg.Checkbox("Use ripgrep accel", key="-RG-", default=True)],
        [sg.Checkbox("Deep image classification (slower)", key="-DEEP-", default=False),
         sg.Text("Model:"), sg.Input(key="-MODEL-", size=(30,1)), sg.FileBrowse(target="-MODEL-")],
        [sg.Text("Destination folder:"), sg.Input(key="-DEST-", expand_x=True, default_text=str(Path.cwd()/"foundcontent")), sg.FolderBrowse(target="-DEST-")],
        [sg.Button("Start", key="-START-", bind_return_key=True, size=(18,2)), sg.Button("Open Found Folder", key="-OPEN-"), sg.Button("Exit")],
        [sg.ProgressBar(max_value=1000, orientation='h', size=(50, 20), key='-PROG-')],
        [sg.Text("Status: idle", key="-STATUS-", size=(80,2))],
        [sg.Multiline(key='-LOG-', size=(100, 16), autoscroll=True, disabled=True)],
    ]

    window = sg.Window(APP_TITLE, layout, finalize=True, return_keyboard_events=True, enable_drop=True)
    dropped: List[str] = []

    total_files: int = 0
    processed: int = 0
    flagged: int = 0

    def on_progress(current_index: int, total: int, flagged_count: int, current_path: Optional[str]) -> None:
        nonlocal processed, total_files, flagged
        processed = current_index
        total_files = total
        flagged = flagged_count
        pct = 0.0 if total == 0 else min(100.0, (processed / total) * 100.0)
        window['-PROG-'].update_bar(int(pct * 10))
        window['-STATUS-'].update(f"Status: scanning... {processed}/{total} | flagged {flagged} ({(flagged/max(1,total))*100:.1f}%)")
        if current_path:
            try:
                window['-LOG-'].update(f"{current_path}\n", append=True)
            except Exception:
                pass

    scanning_thread: Optional[threading.Thread] = None

    def start_scan_thread(roots: List[str], dest: Path, include_hidden: bool, follow_symlinks: bool, ripgrep: bool, deep: bool, model_path: Optional[str]):
        nonlocal processed, total_files, flagged
        processed = 0
        total_files = 0
        flagged = 0
        window['-LOG-'].update("")
        window['-STATUS-'].update("Status: indexing...")
        window['-PROG-'].update_bar(0)
        dest.mkdir(parents=True, exist_ok=True)
        cfg = ScannerConfig(
            roots=roots,
            include_hidden=include_hidden,
            follow_symlinks=follow_symlinks,
            ripgrep=ripgrep,
            deep_image_classify=deep,
            nsfw_model_path=model_path,
            quarantine_dir=str(dest),
            delete=False,
            apply=True,
            report_json=str(dest/"report.json"),
            report_csv=str(dest/"report.csv"),
        )
        try:
            results = run_scan(cfg, on_progress=on_progress)
            window['-STATUS-'].update(f"Done. Scanned {total_files}, flagged {len(results)}. Stored in {dest}")
            window['-LOG-'].update("\n" + "\n".join(f"FLAG: {r.path} -> {dest}" for r in results), append=True)
        except Exception as e:
            window['-STATUS-'].update(f"Error: {e}")

    while True:
        event, values = window.read(timeout=100)
        if event in (sg.WINDOW_CLOSED, "Exit"):
            break
        if event == "-OPEN-":
            try:
                open_folder(Path(values['-DEST-']))
            except Exception:
                pass
        # Handle OS-level drops into the window
        if isinstance(event, str) and event not in ("-START-", "-OPEN-", "Exit"):
            # Some backends send the dropped path via the Input's key event
            if event == "-PATHS-" and values.get("-PATHS-"):
                # Value already contains the dropped paths
                pass
            else:
                # Fallback: try to treat event as path
                if os.path.exists(event):
                    dropped.append(event)
                    window['-STATUS-'].update(f"Dropped: {event}")
        if event == "-START-":
            roots = resolve_roots_from_input(values.get("-PATHS-", ""), dropped)
            if not roots:
                sg.popup_error("Please choose a folder/files or drag & drop them into the window.")
                continue
            dest = Path(values.get("-DEST-", str(Path.cwd()/"foundcontent"))).expanduser().resolve()
            include_hidden = bool(values.get("-HIDDEN-", True))
            follow_symlinks = bool(values.get("-SYMLINKS-", False))
            ripgrep = bool(values.get("-RG-", True))
            deep = bool(values.get("-DEEP-", False))
            model_path = values.get("-MODEL-") or None
            if deep and not model_path:
                if not sg.popup_yes_no("Deep image mode selected but no model provided. Continue without deep image?", title=APP_TITLE) == 'Yes':
                    continue
                deep = False
            if scanning_thread and scanning_thread.is_alive():
                sg.popup_error("Scan already in progress")
                continue
            scanning_thread = threading.Thread(target=start_scan_thread, args=(roots, dest, include_hidden, follow_symlinks, ripgrep, deep, model_path), daemon=True)
            scanning_thread.start()

    window.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())