#!/usr/bin/env python3
"""
bundle_code.py - Copy a project's directory structure and all its code into ONE file.

Usage:
    python bundle_code.py                      # bundle current folder -> project_bundle.txt
    python bundle_code.py path/to/project      # bundle a specific folder
    python bundle_code.py . -o my_code.txt     # custom output name
    python bundle_code.py . -e .py .js .html   # only include these extensions
    python bundle_code.py . -i tests docs      # extra folders/files to ignore
    python bundle_code.py . --max-kb 200       # skip files larger than 200 KB
"""

import argparse
import os
import sys

# Folders that are almost never useful to share
DEFAULT_IGNORE_DIRS = {
    ".git", ".svn", ".hg", ".idea", ".vscode", "__pycache__", "node_modules",
    "venv", ".venv", "env", ".env", "dist", "build", ".next", ".nuxt",
    ".cache", ".pytest_cache", ".mypy_cache", ".tox", "target", "out",
    "coverage", ".gradle", "Pods", ".dart_tool", "vendor", ".terraform",
}

# Files that are noisy or sensitive
DEFAULT_IGNORE_FILES = {
    ".DS_Store", "Thumbs.db", "package-lock.json", "yarn.lock",
    "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock", "composer.lock",
    ".env", ".env.local", ".env.production",   # may contain secrets!
}

# Extensions that are binary / not useful as text
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z", ".exe", ".dll", ".so",
    ".dylib", ".class", ".jar", ".pyc", ".pyo", ".o", ".a", ".bin",
    ".mp3", ".mp4", ".mov", ".avi", ".wav", ".ttf", ".otf", ".woff",
    ".woff2", ".eot", ".sqlite", ".db", ".pkl", ".npy", ".h5", ".pt",
    ".onnx", ".log", ".min.js", ".map",
}


def is_binary(path):
    """Detect binary files by looking for null bytes in the first chunk."""
    try:
        with open(path, "rb") as f:
            return b"\0" in f.read(2048)
    except OSError:
        return True


def should_skip_file(name, path, args, ignore_names, allowed_ext):
    if name in DEFAULT_IGNORE_FILES or name in ignore_names:
        return True
    lower = name.lower()
    ext = os.path.splitext(lower)[1]
    if ext in BINARY_EXTENSIONS or lower.endswith(".min.js"):
        return True
    if allowed_ext and ext not in allowed_ext:
        return True
    try:
        if os.path.getsize(path) > args.max_kb * 1024:
            return True
    except OSError:
        return True
    return is_binary(path)


def build_tree(root, ignore_dirs, ignore_names, included_files):
    """Create a text tree of the folders and the files that will be included."""
    lines = [os.path.basename(os.path.abspath(root)) + "/"]

    def walk(current, prefix):
        try:
            entries = sorted(os.listdir(current), key=lambda n: (not os.path.isdir(os.path.join(current, n)), n.lower()))
        except OSError:
            return
        entries = [
            e for e in entries
            if not (os.path.isdir(os.path.join(current, e)) and e in ignore_dirs)
            and (os.path.isdir(os.path.join(current, e)) or os.path.join(current, e) in included_files)
        ]
        for i, entry in enumerate(entries):
            full = os.path.join(current, entry)
            last = i == len(entries) - 1
            connector = "└── " if last else "├── "
            if os.path.isdir(full):
                lines.append(f"{prefix}{connector}{entry}/")
                walk(full, prefix + ("    " if last else "│   "))
            else:
                lines.append(f"{prefix}{connector}{entry}")

    walk(root, "")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Bundle a project's code into a single file.")
    parser.add_argument("root", nargs="?", default=".", help="Project folder (default: current folder)")
    parser.add_argument("-o", "--output", default="project_bundle.txt", help="Output file name")
    parser.add_argument("-e", "--ext", nargs="*", default=None,
                        help="Only include these extensions, e.g. -e .py .js")
    parser.add_argument("-i", "--ignore", nargs="*", default=[],
                        help="Extra folder or file names to ignore")
    parser.add_argument("--max-kb", type=int, default=500, help="Skip files larger than this (default 500 KB)")
    args = parser.parse_args()

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        sys.exit(f"Error: '{args.root}' is not a folder.")

    output_path = os.path.abspath(args.output)
    ignore_dirs = DEFAULT_IGNORE_DIRS | set(args.ignore)
    ignore_names = set(args.ignore)
    allowed_ext = {e.lower() if e.startswith(".") else "." + e.lower() for e in args.ext} if args.ext else None

    # Collect files
    included = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in ignore_dirs)
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            if os.path.abspath(path) == output_path:
                continue  # don't include the output file itself
            if should_skip_file(name, path, args, ignore_names, allowed_ext):
                continue
            included.append(path)

    included_set = set(included)
    sep = "=" * 80

    with open(output_path, "w", encoding="utf-8") as out:
        out.write("PROJECT STRUCTURE\n" + sep + "\n")
        out.write(build_tree(root, ignore_dirs, ignore_names, included_set) + "\n\n")
        out.write("FILE CONTENTS\n" + sep + "\n\n")

        for path in included:
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except OSError as e:
                content = f"[Could not read file: {e}]"
            out.write(f"{sep}\nFILE: {rel}\n{sep}\n")
            out.write(content)
            if not content.endswith("\n"):
                out.write("\n")
            out.write("\n")

    print(f"Done! Bundled {len(included)} files into: {output_path}")


if __name__ == "__main__":
    main()
