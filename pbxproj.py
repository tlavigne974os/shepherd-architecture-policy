"""Minimal reader for the committed Xcode project (`project.pbxproj`, an OpenStep-style property list).

The committed project file, not `project.yml`, is what `xcodebuild` builds (no build step regenerates it), so the
architecture check reads the build facts from it: which package products each app target links, which local
packages the project references, and which run-script phases a target executes. Candidate text is DATA: this module
parses it into plain dicts/lists/strings and never evaluates anything. Anything it cannot parse raises
`PbxprojError` and the caller fails closed.
"""
from __future__ import annotations

import hashlib
import re


class PbxprojError(Exception):
    pass


_UNQUOTED = re.compile(r"[A-Za-z0-9_./$+\-:@]+")


class _Reader:
    def __init__(self, text: str):
        self.text = text
        self.i = 0

    def _skip(self) -> None:
        text, n = self.text, len(self.text)
        while self.i < n:
            c = text[self.i]
            if c.isspace():
                self.i += 1
            elif text.startswith("/*", self.i):
                end = text.find("*/", self.i + 2)
                if end < 0:
                    raise PbxprojError("unterminated comment")
                self.i = end + 2
            elif text.startswith("//", self.i):
                end = text.find("\n", self.i)
                self.i = n if end < 0 else end + 1
            else:
                return

    def value(self):
        self._skip()
        if self.i >= len(self.text):
            raise PbxprojError("unexpected end of file")
        c = self.text[self.i]
        if c == "{":
            return self._dict()
        if c == "(":
            return self._array()
        if c == '"':
            return self._quoted()
        m = _UNQUOTED.match(self.text, self.i)
        if not m:
            raise PbxprojError(f"unexpected character {c!r} at {self.i}")
        self.i = m.end()
        return m.group(0)

    def _quoted(self) -> str:
        text = self.text
        self.i += 1
        out = []
        while self.i < len(text):
            c = text[self.i]
            if c == '"':
                self.i += 1
                return "".join(out)
            if c == "\\" and self.i + 1 < len(text):
                nxt = text[self.i + 1]
                out.append({"n": "\n", "t": "\t", "r": "\r"}.get(nxt, nxt))
                self.i += 2
                continue
            out.append(c)
            self.i += 1
        raise PbxprojError("unterminated string")

    def _dict(self) -> dict:
        self.i += 1
        result = {}
        while True:
            self._skip()
            if self.i >= len(self.text):
                raise PbxprojError("unterminated dictionary")
            if self.text[self.i] == "}":
                self.i += 1
                return result
            key = self.value()
            if not isinstance(key, str):
                raise PbxprojError("dictionary key is not a string")
            self._skip()
            if self.text[self.i:self.i + 1] != "=":
                raise PbxprojError(f"expected '=' after key {key!r}")
            self.i += 1
            result[key] = self.value()
            self._skip()
            if self.text[self.i:self.i + 1] != ";":
                raise PbxprojError(f"expected ';' after value of {key!r}")
            self.i += 1

    def _array(self) -> list:
        self.i += 1
        result = []
        while True:
            self._skip()
            if self.i >= len(self.text):
                raise PbxprojError("unterminated array")
            if self.text[self.i] == ")":
                self.i += 1
                return result
            result.append(self.value())
            self._skip()
            if self.text[self.i:self.i + 1] == ",":
                self.i += 1


def parse(text: str) -> dict:
    reader = _Reader(text)
    root = reader.value()
    if not isinstance(root, dict) or "objects" not in root or not isinstance(root["objects"], dict):
        raise PbxprojError("not a project file (no objects table)")
    return root


def sha256_of(script: str) -> str:
    return hashlib.sha256(script.encode()).hexdigest()


def native_targets(project: dict) -> dict[str, dict]:
    """Target name -> its object, for every PBXNativeTarget."""
    objects = project["objects"]
    return {o["name"]: o for o in objects.values()
            if isinstance(o, dict) and o.get("isa") == "PBXNativeTarget" and isinstance(o.get("name"), str)}


def linked_products(project: dict, target_name: str) -> set[str]:
    """Package product names the target links (its packageProductDependencies)."""
    objects = project["objects"]
    target = native_targets(project).get(target_name)
    if target is None:
        return set()
    products = set()
    for ref in target.get("packageProductDependencies", []) or []:
        dep = objects.get(ref)
        if isinstance(dep, dict) and isinstance(dep.get("productName"), str):
            products.add(dep["productName"])
    return products


def run_scripts(project: dict, target_name: str) -> list[str]:
    """The shellScript text of every run-script build phase of the target."""
    objects = project["objects"]
    target = native_targets(project).get(target_name)
    if target is None:
        return []
    scripts = []
    for ref in target.get("buildPhases", []) or []:
        phase = objects.get(ref)
        if isinstance(phase, dict) and phase.get("isa") == "PBXShellScriptBuildPhase":
            scripts.append(str(phase.get("shellScript", "")))
    return scripts


def local_package_paths(project: dict) -> list[str]:
    """Relative paths of every local Swift package the project references."""
    return sorted(o["relativePath"] for o in project["objects"].values()
                  if isinstance(o, dict) and o.get("isa") == "XCLocalSwiftPackageReference"
                  and isinstance(o.get("relativePath"), str))


def compiled_sources(project: dict, target_name: str) -> list[str]:
    """Repo-relative path of every file in the target's Sources phase, resolved through the group hierarchy
    (a file's `path` is relative to its parent groups unless its sourceTree says otherwise). A source whose location
    cannot be resolved to a project-relative path is returned as `?<sourceTree>:<path>` so the caller can refuse it."""
    objects = project["objects"]
    target = native_targets(project).get(target_name)
    if target is None:
        return []
    parent: dict[str, str] = {}
    for gid, obj in objects.items():
        if isinstance(obj, dict) and obj.get("isa") in ("PBXGroup", "PBXVariantGroup", "XCVersionGroup"):
            for child in obj.get("children", []) or []:
                parent[child] = gid

    def resolve(ref_id: str, seen: frozenset = frozenset()) -> str:
        obj = objects.get(ref_id)
        if not isinstance(obj, dict) or ref_id in seen:
            return "?unresolved:" + ref_id
        path = obj.get("path")
        tree = obj.get("sourceTree", "<group>")
        if tree == "SOURCE_ROOT":
            return path or ""
        if tree == "<group>":
            above = parent.get(ref_id)
            base = resolve(above, seen | {ref_id}) if above else ""
            if base.startswith("?"):
                return base
            return "/".join(part for part in (base, path) if part)
        return f"?{tree}:{path}"

    result = []
    for phase_id in target.get("buildPhases", []) or []:
        phase = objects.get(phase_id)
        if not (isinstance(phase, dict) and phase.get("isa") == "PBXSourcesBuildPhase"):
            continue
        for build_file_id in phase.get("files", []) or []:
            build_file = objects.get(build_file_id)
            ref = build_file.get("fileRef") if isinstance(build_file, dict) else None
            if ref:
                result.append(resolve(ref))
    return result
