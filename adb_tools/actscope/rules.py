"""Parse legacy FOLDER.x/FILE.y rules without losing dots, case or spaces."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


@dataclass(frozen=True)
class FileRule:
    app: str
    path: str
    kind: str
    source: str
    line: int


def parse_rules(path: Path, root: str = "/sdcard") -> list[FileRule]:
    rules = []
    for number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        components, kind = [], "directory"
        for index, part in enumerate(line.split("/")):
            if part.startswith("FOLDER."):
                component = part[7:]
            elif part.startswith("FILE.") and index == len(line.split("/")) - 1:
                component, kind = part[5:], "file"
            else:
                raise ValueError(f"{path}:{number}: expected FOLDER.<name> or terminal FILE.<name>")
            if component in {"", ".", ".."} or "\x00" in component:
                raise ValueError(f"{path}:{number}: invalid component")
            components.append(component)
        rules.append(FileRule(path.stem, str(PurePosixPath(root, *components)), kind, str(path), number))
    return rules
