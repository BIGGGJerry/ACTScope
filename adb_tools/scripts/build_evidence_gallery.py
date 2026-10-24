#!/usr/bin/env python3
"""Build an offline evidence table from evidence/catalog.json (Python stdlib only)."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
from pathlib import Path, PurePosixPath
import re
import sys
from urllib.parse import quote


MEDIA_EXTENSIONS = {
    "video": {".mp4", ".webm", ".mov", ".m4v"},
    "image": {".png", ".jpg", ".jpeg", ".webp", ".gif"},
}


def escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def inspect_media(root: Path, relative: str, kind: str) -> dict:
    if not isinstance(relative, str) or not relative.strip():
        raise ValueError("Media file must be a nonempty path")
    path = PurePosixPath(relative)
    if (path.is_absolute() or ".." in path.parts or "\\" in relative
            or len(path.parts) < 2 or path.parts[0] not in {"videos", "images"}):
        raise ValueError("Media file must stay within evidence/videos or evidence/images")
    if path.suffix.lower() not in MEDIA_EXTENSIONS[kind]:
        raise ValueError(f"Unsupported media extension for {kind}")
    local = (root / Path(*path.parts)).resolve()
    if not local.is_relative_to(root.resolve()):
        raise ValueError("Media symlink escapes the evidence directory")
    result = dict(status="missing", sha256=None, size_bytes=None, href=None)
    if not local.exists():
        return result
    if not local.is_file():
        raise ValueError("Media path is not a regular file")
    if local.stat().st_size == 0:
        result["status"] = "empty"
        return result
    digest = hashlib.sha256()
    with local.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    result.update(status="provided", sha256=digest.hexdigest(),
                  size_bytes=local.stat().st_size,
                  href="/".join(quote(part, safe="") for part in path.parts))
    return result


def read_catalog(root: Path) -> tuple[str, list[dict]]:
    catalog = json.loads((root / "catalog.json").read_text(encoding="utf-8"))
    if not isinstance(catalog, dict):
        raise ValueError("catalog must be a JSON object")
    if catalog.get("schema_version") != 1:
        raise ValueError("catalog.schema_version must be 1")
    if not isinstance(catalog.get("title"), str) or not catalog["title"].strip():
        raise ValueError("catalog.title must be a nonempty string")
    entries = catalog.get("items")
    if not isinstance(entries, list) or not entries:
        raise ValueError("catalog.items must be a nonempty list")
    result, seen = [], set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Every catalog item must be an object")
        item = dict(entry)
        for field in ("id", "platform", "finding", "kind", "title", "caption"):
            if not isinstance(item.get(field), str) or not item[field].strip():
                raise ValueError(f"Each item needs a nonempty {field}")
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", item["id"]):
            raise ValueError(f"Invalid item id: {item['id']!r}")
        if item["id"] in seen:
            raise ValueError(f"Duplicate item id: {item['id']}")
        seen.add(item["id"])
        if item["kind"] not in MEDIA_EXTENSIONS:
            raise ValueError(f"{item['id']}: kind must be video or image")
        for field in ("notes", "capture_date"):
            if item.get(field) is not None and not isinstance(item[field], str):
                raise ValueError(f"{item['id']}: {field} must be a string or null")
        item.update(status="pending", sha256=None, size_bytes=None, href=None)
        relative = item.get("file")
        if relative is not None:
            item.update(inspect_media(root, relative, item["kind"]))
        item["playback"] = None
        if item.get("playback_file") is not None:
            if item["kind"] != "video" or item["status"] != "provided":
                raise ValueError(f"{item['id']}: playback_file requires a provided original video")
            playback = inspect_media(root, item["playback_file"], "video")
            if playback["status"] != "provided":
                raise ValueError(f"{item['id']}: playback_file must exist and be nonempty")
            item["playback"] = {"file": item["playback_file"], **playback}
        github_video_url = item.get("github_video_url")
        if github_video_url is not None:
            if (item["kind"] != "video" or item["status"] != "provided"
                    or not isinstance(github_video_url, str)
                    or not re.fullmatch(
                        r"https://github\.com/user-attachments/assets/"
                        r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}",
                        github_video_url)):
                raise ValueError(f"{item['id']}: github_video_url must be a GitHub video attachment URL")
        anonymous_video_url = item.get("anonymous_video_url")
        if anonymous_video_url is not None:
            if (item["kind"] != "video" or item["status"] != "provided"
                    or not isinstance(anonymous_video_url, str)
                    or not re.fullmatch(
                        r"https://anonymous\.4open\.science/api/repo/[A-Za-z0-9_-]+/file/"
                        r"evidence/videos/[A-Za-z0-9_.-]+\.mp4", anonymous_video_url)):
                raise ValueError(f"{item['id']}: anonymous_video_url must be an anonymous repository MP4 URL")
        result.append(item)
    return catalog["title"], result


def status_label(item: dict) -> str:
    return {"provided": "File provided", "pending": "Awaiting author-provided media",
            "missing": "Referenced file is missing", "empty": "Referenced file is empty"}[item["status"]]


def media_html(item: dict, *, prefix: str = "") -> str:
    if item["status"] != "provided":
        detail = "No video or image has been included for this entry."
        if item["status"] in {"missing", "empty"}:
            detail = f"Check the catalog path: {item['file']}"
        return (f'<div class="placeholder"><span class="placeholder-type">{escape(item["kind"])} pending</span>'
                f'<strong>{escape(status_label(item))}</strong><p>{escape(detail)}</p></div>')
    href = escape(prefix + item["href"])
    if item["kind"] == "video":
        source = escape(prefix + (item.get("playback") or item)["href"])
        return (f'<video controls preload="metadata" playsinline aria-label="{escape(item["title"])}">'
                f'<source src="{source}">Your browser cannot play this file. '
                f'<a href="{href}">Open the original video</a>.</video>')
    return f'<a href="{href}"><img src="{href}" alt="{escape(item["title"])}" loading="lazy"></a>'


def detail_html(item: dict, *, prefix: str = "", for_readme: bool = False) -> str:
    parts = [f'<p>{escape(item["caption"])}</p>']
    if item.get("capture_date"):
        parts.append(f'<p><strong>Captured:</strong> {escape(item["capture_date"])}</p>')
    if item.get("notes"):
        parts.append(f'<p class="note">{escape(item["notes"])}</p>')
    if item["status"] == "provided":
        links = []
        if item.get("playback") and not (for_readme and item.get("github_video_url")):
            playback = item["playback"]
            playback_url = (item.get("anonymous_video_url") if for_readme else None) or prefix + playback["href"]
            links.append(f'<a href="{escape(playback_url)}">Play video</a>')
        label = "View full image" if item["kind"] == "image" else "Original video"
        links.append(f'<a href="{escape(prefix + item["href"])}">{label}</a>')
        parts.append('<p>' + ' · '.join(links) + '</p>')
    return "".join(parts)


def table_html(items: list[dict], *, prefix: str = "") -> str:
    headers = "".join(f'<th scope="col" id="{escape(i["id"])}"><span class="platform">{escape(i["platform"])}</span>'
                      f'<h2>{escape(i["title"])}</h2></th>' for i in items)
    media = "".join(f'<td><figure>{media_html(i, prefix=prefix)}</figure></td>' for i in items)
    details = "".join(f'<td class="description">{detail_html(i, prefix=prefix)}</td>' for i in items)
    return (f'<table style="min-width:{len(items) * 360}px">'
            '<caption>Scroll horizontally to view all items.</caption>'
            f'<thead><tr>{headers}</tr></thead><tbody><tr>{media}</tr><tr>{details}</tr></tbody></table>')


def readme_table_html(items: list[dict]) -> str:
    """Inline styles and explicit media sizes work without the gallery stylesheet."""
    headers, cells = [], []
    for item in items:
        headers.append('<th scope="col" width="340" style="min-width:340px;text-align:left;vertical-align:top;padding:12px">'
                       f'{escape(item["title"])}<br><small>{escape(item["platform"])}</small></th>')
        if item["status"] == "provided":
            href = escape("evidence/" + item["href"])
            if item["kind"] == "video" and item.get("github_video_url"):
                # GitHub strips repository-file video tags. A standalone attachment
                # URL is expanded into its native player, including inside a cell.
                media = "\n\n" + item["github_video_url"] + "\n\n"
            elif item["kind"] == "video":
                # Use the raw endpoint on Anonymous GitHub: its /r/ file-viewer
                # route can return HTML to media requests instead of MP4 bytes.
                source = escape(item.get("anonymous_video_url") or
                                "evidence/" + (item.get("playback") or item)["href"])
                media = (f'<video width="320" controls preload="metadata" playsinline '
                         f'style="width:320px;max-height:240px" aria-label="{escape(item["title"])}">'
                         f'<source src="{source}"><a href="{href}">Open the original video</a>.</video>')
            else:
                media = (f'<a href="{href}"><img width="320" src="{href}" '
                         f'style="width:320px;height:auto;max-height:320px;object-fit:contain" '
                         f'alt="{escape(item["title"])}"></a>')
        else:
            media = ('<div style="width:320px;min-height:120px;padding:16px;box-sizing:border-box;'
                     'border:1px dashed #aab7bd;background:#f5f7f7">'
                     f'<strong>{escape(status_label(item))}</strong><p>No media is displayed for this entry.</p></div>')
        cells.append('<td width="340" style="min-width:340px;vertical-align:top;padding:12px">'
                     f'{media}'
                     f'{detail_html(item, prefix="evidence/", for_readme=True)}</td>')
    return ('<div style="overflow-x:auto;max-width:100%" tabindex="0" role="region" '
            'aria-label="Supporting evidence table">\n'
            f'<table style="min-width:{len(items) * 340}px;table-layout:fixed;border-collapse:collapse" border="1">\n'
            '<caption>Scroll horizontally to view all items.</caption>\n'
            '<thead><tr>' + "".join(headers) + '</tr></thead>\n'
            '<tbody><tr>' + "".join(cells) + '</tr></tbody>\n</table>\n</div>\n')


def update_root_readme(evidence_root: Path, fragment: str) -> None:
    """Replace only the marked generated section, preserving all surrounding text."""
    readme = evidence_root.parent / "README.md"
    if not readme.exists():
        return
    content = readme.read_text(encoding="utf-8")
    start_marker, end_marker = "<!-- EVIDENCE:START -->", "<!-- EVIDENCE:END -->"
    if start_marker not in content and end_marker not in content:
        return
    if content.count(start_marker) != 1 or content.count(end_marker) != 1:
        raise ValueError("Root README must contain exactly one EVIDENCE:START / EVIDENCE:END marker pair")
    start = content.index(start_marker) + len(start_marker)
    end = content.index(end_marker)
    if end < start:
        raise ValueError("Root README evidence markers are out of order")
    updated = content[:start] + "\n\n" + fragment.rstrip() + "\n\n" + content[end:]
    readme.write_text(updated, encoding="utf-8")


STYLE = """
:root{color-scheme:light;--ink:#192b35;--muted:#536570;--line:#d4dee2;--accent:#126778}
*{box-sizing:border-box}body{margin:0;background:#f3f5f5;color:var(--ink);font:16px/1.55 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
main{max-width:1600px;margin:auto;padding:48px 32px 32px}.eyebrow{font-size:12px;letter-spacing:.15em;text-transform:uppercase;color:var(--accent);font-weight:700}
h1{font-size:clamp(28px,4vw,44px);line-height:1.2;margin:10px 0 18px;letter-spacing:-.035em}h1 span{font-size:.57em;font-weight:500;color:var(--muted);display:block;margin-top:10px;letter-spacing:0}
.intro{max-width:880px;color:var(--muted);margin:0 0 24px}.summary{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:24px}.summary span{border:1px solid var(--line);border-radius:6px;background:#fff;padding:7px 12px;font-size:14px}
.toolbar{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-bottom:10px}.scroll-hint{font-size:14px;color:var(--muted);margin:0}.buttons{display:flex;gap:6px}button{padding:6px 14px;border:1px solid #b3c2c9;border-radius:5px;color:var(--ink);background:white;cursor:pointer;font:inherit}button:hover{background:#e5eff0}
.table-scroll{overflow-x:scroll;overscroll-behavior-x:contain;scrollbar-gutter:stable;border:1px solid #b3c2c9;border-radius:8px;background:white;scrollbar-color:#708c98 #e4ebee;scrollbar-width:auto}
.table-scroll:focus{outline:3px solid #257f90;outline-offset:3px}.table-scroll::-webkit-scrollbar{height:14px}.table-scroll::-webkit-scrollbar-track{background:#e4ebee}.table-scroll::-webkit-scrollbar-thumb{background:#708c98;border:3px solid #e4ebee;border-radius:10px}
table{width:100%;table-layout:fixed;border-spacing:0;text-align:left}caption{text-align:left;caption-side:bottom;padding:14px 20px;color:var(--muted);font-size:13px;background:#f6f8f8;border-top:1px solid var(--line)}th,td{width:360px;padding:20px;vertical-align:top;border-right:1px solid var(--line)}th:last-child,td:last-child{border-right:0}th{background:#eaf0f1;border-bottom:1px solid var(--line)}th h2{font-size:20px;line-height:1.3;margin:8px 0}th p{font-size:13px;font-weight:400;margin:0;color:var(--muted)}.platform{font-size:12px;font-weight:750;letter-spacing:.1em;text-transform:uppercase;color:var(--accent)}
figure{margin:14px 0 0;height:220px}figure>a{display:block;width:100%;height:100%}video,img{display:block;width:100%;height:100%;object-fit:contain;background:#101d24;border-radius:5px}video{max-height:220px}.placeholder{height:100%;border:1px dashed #b8c6cc;border-radius:5px;display:flex;justify-content:center;align-items:flex-start;flex-direction:column;padding:24px;background:#f7f9f9}.placeholder-type{font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin-bottom:12px}.placeholder strong{font-size:16px;line-height:1.4}.placeholder p{font-size:13px;color:var(--muted);margin-bottom:0}.status{display:inline-block;font-size:12px;line-height:1.4;padding:4px 8px;border-radius:4px;background:#f3eddf;color:#745816}.status.provided{background:#e1efe8;color:#206346}.status.missing,.status.empty{background:#f7e4e0;color:#93422d}
.description{padding-top:0;font-size:14px}.description p{margin:0 0 14px}.note{color:var(--muted)}a{color:var(--accent);text-underline-offset:3px}details{margin-bottom:8px}summary{cursor:pointer;font-weight:600}code{overflow-wrap:anywhere;font-size:12px}footer{margin-top:22px;display:flex;justify-content:space-between;gap:20px;color:var(--muted);font-size:13px}footer p{margin:0}footer nav{display:flex;gap:18px;flex-wrap:wrap}
@media(max-width:640px){main{padding:24px 16px}.toolbar{align-items:flex-start}.scroll-hint{max-width:240px;font-size:13px}footer{flex-direction:column}th,td{padding:16px}.description{padding-top:0}}
@media(prefers-reduced-motion:no-preference){.table-scroll{scroll-behavior:smooth}}
"""


def build(root: Path) -> dict:
    title, items = read_catalog(root)
    provided = sum(i["status"] == "provided" for i in items)
    pending = sum(i["status"] == "pending" for i in items)
    problems = len(items) - provided - pending
    page = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)}</title><style>{STYLE}</style></head><body><main>
<div class="eyebrow">ACTScope · Paper artifact</div>
<h1>Supporting Evidence</h1>
<p class="intro">Installation hijacking, installation-path discovery, and network-proxy interference across cloud testing platforms.</p>
<div class="toolbar"><p id="scroll-hint" class="scroll-hint">Scroll horizontally to review each item. Focus the table and use the ← / → keys, or use the buttons.</p><div class="buttons"><button type="button" id="previous" aria-label="Scroll table left">←</button><button type="button" id="next" aria-label="Scroll table right">→</button></div></div>
<div id="evidence-table" class="table-scroll" tabindex="0" role="region" aria-label="Supporting evidence table" aria-describedby="scroll-hint">{table_html(items)}</div>
<footer><nav><a href="../README.md">Artifact README</a><a href="../README.md#adb-tools">ADB tools</a><a href="../README.md#android-app">Android app</a></nav></footer>
</main><script>
const scroller = document.getElementById('evidence-table');
document.getElementById('previous').addEventListener('click', () => scroller.scrollBy({{left:-360}}));
document.getElementById('next').addEventListener('click', () => scroller.scrollBy({{left:360}}));
scroller.addEventListener('keydown', event => {{
  if (event.target !== scroller) return;
  if (event.key === 'ArrowRight' || event.key === 'ArrowLeft') {{
    event.preventDefault(); scroller.scrollBy({{left:event.key === 'ArrowRight' ? 360 : -360}});
  }}
}});
</script></body></html>
'''
    (root / "index.html").write_text(page, encoding="utf-8")
    manifest = {"schema_version": 1, "hash_algorithm": "SHA-256",
                "note": "File hashes establish identity only. Experimental claims require review of the supplied evidence.",
                "items": [{key: i.get(key) for key in ("id", "platform", "finding", "kind", "title", "file", "status", "size_bytes", "sha256", "capture_date", "playback")} for i in items]}
    (root / "files-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    # Fragment paths are relative to the artifact root so the parent README may embed it unchanged.
    fragment = ("<!-- Generated by adb_tools/scripts/build_evidence_gallery.py; links are relative to the artifact root. -->\n\n"
                "## Supporting Evidence\n\n"
                + readme_table_html(items))
    update_root_readme(root, fragment)
    return {"provided": provided, "pending": pending, "missing_or_empty": problems}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path,
                        default=Path(__file__).resolve().parents[2] / "evidence")
    args = parser.parse_args()
    try:
        counts = build(args.evidence_dir.resolve())
    except (OSError, ValueError, TypeError) as exc:
        print(f"Evidence gallery build failed: {exc}", file=sys.stderr)
        return 1
    print(f"Evidence gallery built: {counts['provided']} supplied, {counts['pending']} pending, "
          f"{counts['missing_or_empty']} missing/empty.")
    return 2 if counts["missing_or_empty"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
