#!/usr/bin/env python3
"""Architecture check for the Baxter iPad app (opd-6289 slice1).

Rejects direct hardware, networking, persistence and application-owned logging sinks, and the escape
routes around them, in application source and in the packages the app links, unless the code lives in the
designated kernel. Ordinary rendering and computation pass. Candidate source is DATA: this program reads
files and never imports, builds, runs or expands anything it finds.

  python3 arch_check.py --repo-root DIR --policy policy/ipad-app.policy.json [--trusted-policy FILE]
                        [--changed-files FILE] [--json]

Exit 0: clean. Exit 1: violations. Exit 2: usage/policy error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pbxproj  # noqa: E402
from swift_lex import Token, tokens  # noqa: E402


class PolicyError(Exception):
    pass


def load_policy(path: Path) -> dict:
    try:
        policy = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise PolicyError(f"cannot read policy {path}: {exc}") from exc
    for key in ("app_zones", "kernel_zones", "rules", "dependencies"):
        if key not in policy:
            raise PolicyError(f"policy {path} is missing '{key}'")
    return policy


def _glob_to_regex(pattern: str) -> re.Pattern:
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
        elif pattern.startswith("**", i):
            out += ".*"
            i += 2
        elif pattern[i] == "*":
            out += "[^/]*"
            i += 1
        elif pattern[i] == "?":
            out += "[^/]"
            i += 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.compile("^" + out + "$")


def _matches(path: str, patterns: list[str]) -> bool:
    return any(_glob_to_regex(p).match(path) for p in patterns)


# Every suffix Xcode/SwiftPM compiles as native source (lower-cased; assembly included). `.metal` shaders cannot reach
# hardware, network or storage and are not scanned.
SOURCE_SUFFIXES = {".swift", ".m", ".mm", ".h", ".hh", ".hpp", ".hxx", ".c", ".cc", ".cpp", ".cxx", ".c++", ".s"}
# Prebuilt code the scanner cannot read: refused in a shipped zone unless the policy names it.
ARTIFACT_SUFFIXES = {".a", ".o", ".dylib", ".so"}
ARTIFACT_DIR_SUFFIXES = (".framework", ".xcframework")


def _source_files(root: Path, patterns: list[str]) -> list[str]:
    found = []
    for p in sorted(root.rglob("*")):
        if p.suffix.lower() not in SOURCE_SUFFIXES or not p.is_file():
            continue
        rel = p.relative_to(root).as_posix()
        if _matches(rel, patterns):
            found.append(rel)
    return found


def _compile_rules(policy: dict) -> list[dict]:
    rules = []
    for rule in policy["rules"]:
        compiled = dict(rule)
        compiled["_symbols"] = set(rule.get("symbols", []))
        compiled["_calls"] = set(rule.get("call_symbols", []))
        compiled["_sequences"] = [s.split() for s in rule.get("sequences", [])]
        rules.append(compiled)
    return rules


def scan_source(text: str, rules: list[dict]) -> list[tuple[int, dict, str]]:
    """Returns (line, rule, matched) for every forbidden construct in `text`."""
    toks: list[Token] = list(tokens(text))
    hits: list[tuple[int, dict, str]] = []
    for idx, tok in enumerate(toks):
        previous = toks[idx - 1].text if idx else ""
        following = toks[idx + 1].text if idx + 1 < len(toks) else ""
        for rule in rules:
            if tok.text in rule["_symbols"]:
                hits.append((tok.line, rule, tok.text))
            # Free C-style calls only: `gate.open(...)`, `case .system` and `func write(` are not syscalls.
            if tok.text in rule["_calls"] and following == "(" and previous not in (".", "func", "case", "var", "let"):
                hits.append((tok.line, rule, tok.text + "("))
            for seq in rule["_sequences"]:
                if tok.text == seq[0] and all(
                    idx + k < len(toks) and toks[idx + k].text == seq[k] for k in range(len(seq))
                ):
                    hits.append((tok.line, rule, " ".join(seq)))
    return hits


def _site_allowed(policy: dict, rel: str, rule_id: str, matched: str) -> bool:
    for allowance in policy.get("allowed_sites", []):
        if allowance["file"] == rel and allowance["rule"] == rule_id and allowance["match"] == matched:
            return True
    return False


def check_source(root: Path, policy: dict) -> list[dict]:
    rules = _compile_rules(policy)
    kernel = policy["kernel_zones"]
    violations = []
    zones = list(policy["app_zones"]) + list(policy.get("linked_package_zones", []))
    for rel in _source_files(root, zones):
        if _matches(rel, kernel) or _matches(rel, policy.get("excluded", [])):
            continue
        try:
            text = (root / rel).read_text(errors="replace")
        except OSError as exc:
            violations.append({"file": rel, "line": 0, "rule": "unreadable", "match": str(exc),
                               "message": "source file could not be read"})
            continue
        for line, rule, matched in scan_source(text, rules):
            if _site_allowed(policy, rel, rule["id"], matched):
                continue
            violations.append({"file": rel, "line": line, "rule": rule["id"], "match": matched,
                               "message": f"{rule['category']}: '{matched}' outside the kernel. {rule['route']}"})
    return violations


# --- dependencies ------------------------------------------------------------------------------

def _yml_app_target_packages(project_yml: str, app_targets: list[str]) -> dict[str, set[str]]:
    """Product names each named target links, read from project.yml by indentation (no YAML library)."""
    result: dict[str, set[str]] = {}
    current = None
    in_deps = False
    lines = project_yml.splitlines()
    in_targets = False
    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        stripped = raw.strip()
        if indent == 0:
            in_targets = stripped == "targets:"
            current, in_deps = None, False
            continue
        if not in_targets:
            continue
        if indent == 2 and stripped.endswith(":"):
            current = stripped[:-1]
            in_deps = False
            result.setdefault(current, set())
            continue
        if current is None or current not in app_targets:
            continue
        if indent == 4 and stripped == "dependencies:":
            in_deps = True
            continue
        if indent == 4 and stripped.endswith(":"):
            in_deps = False
            continue
        if in_deps:
            m = re.match(r"-\s*product:\s*(\S+)", stripped) or re.match(r"product:\s*(\S+)", stripped)
            if m:
                result[current].add(m.group(1))
    return result


def check_dependencies(root: Path, policy: dict) -> list[dict]:
    deps = policy["dependencies"]
    violations = []
    project = root / "project.yml"
    if not project.exists():
        return [{"file": "project.yml", "line": 0, "rule": "dependency", "match": "project.yml",
                 "message": "project.yml not found; app dependencies cannot be verified"}]
    linked = _yml_app_target_packages(project.read_text(), deps["app_targets"])
    allowed = set(deps["allowed_app_products"])
    io_bearing = set(deps["kernel_only_products"])
    for target in deps["app_targets"]:
        for product in sorted(linked.get(target, set())):
            if product in io_bearing:
                violations.append({"file": "project.yml", "line": 0, "rule": "dependency-io-bearing",
                                   "match": f"{target}:{product}",
                                   "message": f"target {target} links I/O-bearing product '{product}'; only the "
                                              f"kernel package may depend on it. {deps['route']}"})
            elif product not in allowed:
                violations.append({"file": "project.yml", "line": 0, "rule": "dependency-unlisted",
                                   "match": f"{target}:{product}",
                                   "message": f"target {target} links '{product}', which is not an approved app "
                                              f"dependency. {deps['route']}"})
    return violations


def _shipped_zones(policy: dict) -> list[str]:
    return list(policy["app_zones"]) + list(policy.get("linked_package_zones", []))


def check_native_artifacts(root: Path, policy: dict) -> list[dict]:
    """Prebuilt native code (.a/.o/.dylib/.so, .framework/.xcframework) in a shipped zone is unscannable: refused
    unless the policy names that exact path."""
    zones = _shipped_zones(policy)
    skip = list(policy.get("excluded", [])) + list(policy["kernel_zones"])
    allowed = list(policy.get("allowed_binary_artifacts", []))
    violations, reported = [], set()
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        parts = rel.split("/")
        artifact = None
        for k, part in enumerate(parts):
            if part.endswith(ARTIFACT_DIR_SUFFIXES):
                artifact = "/".join(parts[:k + 1])
                break
        if artifact is None and p.is_file() and p.suffix.lower() in ARTIFACT_SUFFIXES:
            artifact = rel
        if artifact is None or artifact in reported:
            continue
        probe = artifact + "/x"
        if not (_matches(probe, zones) or _matches(artifact, zones)) or _matches(probe, skip):
            continue
        reported.add(artifact)
        if _matches(artifact, allowed):
            continue
        violations.append({"file": artifact, "line": 0, "rule": "native-artifact", "match": artifact,
                           "message": "prebuilt native code cannot be scanned for hardware, network, storage or logging "
                                      "use; name it in the policy's allowed_binary_artifacts through the owner-approved "
                                      "policy release or build it from source in a zone"})
    return violations


_LOCAL_PACKAGE_DEP = re.compile(r"""\.package\s*\(\s*(?:name\s*:\s*"[^"]*"\s*,\s*)?path\s*:\s*"([^"]+)\"""")


def _zoned(path: str, policy: dict) -> bool:
    probe = path.rstrip("/") + "/x"
    return _matches(probe, policy["kernel_zones"]) or _matches(probe, policy.get("linked_package_zones", []))


def _project_file(root: Path, policy: dict) -> tuple[Path, str]:
    rel = policy.get("project_file", "BaxterToo.xcodeproj/project.pbxproj")
    return root / rel, rel


def check_package_zoning(root: Path, policy: dict) -> list[dict]:
    """Every local Swift package the COMMITTED project references (the file xcodebuild builds), and every local
    package those packages depend on by path, must lie inside a scanned zone: an allowed package whose source is
    unzoned is a bypass."""
    path, rel = _project_file(root, policy)
    try:
        project = pbxproj.parse(path.read_text())
    except (OSError, pbxproj.PbxprojError) as exc:
        return [{"file": rel, "line": 0, "rule": "project-unreadable", "match": rel,
                 "message": f"the project file could not be read ({exc}); package coverage cannot be verified"}]
    violations = []
    queue = list(pbxproj.local_package_paths(project))
    seen = set()
    while queue:
        package = queue.pop(0).rstrip("/")
        if package in seen:
            continue
        seen.add(package)
        if not _zoned(package, policy):
            violations.append({"file": package, "line": 0, "rule": "package-unzoned", "match": package,
                               "message": "a local package the project links is outside every scanned zone; add its "
                                          "whole root to linked_package_zones through the owner-approved policy "
                                          "release or remove the link"})
            continue
        if _matches(package + "/x", policy["kernel_zones"]):
            continue  # the kernel's own dependencies are the kernel's business and its path is protected
        manifest = root / package / "Package.swift"
        if not manifest.is_file():
            violations.append({"file": package + "/Package.swift", "line": 0, "rule": "package-unzoned",
                               "match": package, "message": "the package has no readable Package.swift to verify"})
            continue
        for dep in _LOCAL_PACKAGE_DEP.findall(manifest.read_text(errors="replace")):
            resolved = Path(package, dep)
            parts = []
            for part in resolved.parts:
                if part == "..":
                    if parts:
                        parts.pop()
                elif part != ".":
                    parts.append(part)
            queue.append("/".join(parts))
    return violations


def check_compiled_sources(root: Path, policy: dict) -> list[dict]:
    """Every file the committed project compiles into an app target must lie inside a scanned zone. project.yml says
    nothing about what the committed project file compiles, and a source the project lists from outside the zones
    would never be scanned."""
    path, rel = _project_file(root, policy)
    try:
        project = pbxproj.parse(path.read_text())
    except (OSError, pbxproj.PbxprojError) as exc:
        return [{"file": rel, "line": 0, "rule": "project-unreadable", "match": rel,
                 "message": f"the project file could not be read ({exc}); compiled sources cannot be verified"}]
    zones = _shipped_zones(policy) + list(policy["kernel_zones"])
    violations, seen = [], set()
    targets = pbxproj.native_targets(project)
    for target in policy["dependencies"]["app_targets"]:
        if target not in targets:
            continue  # reported by check_project_build_input
        for source in pbxproj.compiled_sources(project, target):
            if source in seen:
                continue
            seen.add(source)
            parts = source.split("/")
            if source.startswith("?") or ".." in parts or source.startswith("/") or not _matches(source, zones):
                violations.append({"file": source if not source.startswith("?") else rel, "line": 0,
                                   "rule": "source-unzoned", "match": f"{target}:{source}",
                                   "message": f"target {target} compiles '{source}', which is outside every scanned "
                                              "zone (or cannot be resolved to a project path); move it under a zone "
                                              "or extend the zones through the owner-approved policy release"})
    return violations


def check_project_build_input(root: Path, policy: dict) -> list[dict]:
    """The committed project file is the build input (nothing regenerates it), so the app targets' linked package
    products and run-script phases are read from IT, in addition to project.yml: a pbxproj-only change cannot link
    an I/O product or add a build script unseen."""
    path, rel = _project_file(root, policy)
    try:
        project = pbxproj.parse(path.read_text())
    except (OSError, pbxproj.PbxprojError) as exc:
        return [{"file": rel, "line": 0, "rule": "project-unreadable", "match": rel,
                 "message": f"the project file could not be read ({exc}); app dependencies cannot be verified"}]
    deps = policy["dependencies"]
    allowed = set(deps["allowed_app_products"])
    io_bearing = set(deps["kernel_only_products"])
    scripts_ok = {entry["sha256"] for entry in policy.get("allowed_build_scripts", [])}
    targets = pbxproj.native_targets(project)
    violations = []
    for target in deps["app_targets"]:
        if target not in targets:
            violations.append({"file": rel, "line": 0, "rule": "dependency", "match": target,
                               "message": f"app target {target} is not in the project file; its build cannot be verified"})
            continue
        for product in sorted(pbxproj.linked_products(project, target)):
            if product in io_bearing:
                violations.append({"file": rel, "line": 0, "rule": "dependency-io-bearing",
                                   "match": f"{target}:{product}",
                                   "message": f"target {target} links I/O-bearing product '{product}' in the committed "
                                              f"project file; only the kernel package may depend on it. {deps['route']}"})
            elif product not in allowed:
                violations.append({"file": rel, "line": 0, "rule": "dependency-unlisted",
                                   "match": f"{target}:{product}",
                                   "message": f"target {target} links '{product}' in the committed project file, which "
                                              f"is not an approved app dependency. {deps['route']}"})
        for script in pbxproj.run_scripts(project, target):
            digest = pbxproj.sha256_of(script)
            if digest not in scripts_ok:
                violations.append({"file": rel, "line": 0, "rule": "build-phase-script",
                                   "match": f"{target}:{digest[:12]}",
                                   "message": f"target {target} runs a build-phase script that is not on the policy's "
                                              f"allowed_build_scripts (sha256 {digest}); a build script is a build "
                                              "input that ships bytes into the app"})
    return violations


def check_protected_changes(changed: list[str], policy: dict) -> list[dict]:
    """Policy, checker, pin and workflow edits are owner-controlled: a candidate that changes them fails
    this check and must be approved and published by the owner, never by the same change."""
    protected = policy.get("protected_paths", [])
    return [
        {"file": rel, "line": 0, "rule": "protected-path", "match": rel,
         "message": "this path defines the architecture boundary; it can only change through the owner-approved "
                    "policy release, not in a feature change"}
        for rel in changed if _matches(rel, protected)
    ]


def run(repo_root: Path, policy_path: Path, changed_files: list[str] | None = None,
        trusted_policy_path: Path | None = None) -> list[dict]:
    policy = load_policy(policy_path)
    if trusted_policy_path is not None:
        trusted = load_policy(trusted_policy_path)
        if json.dumps(trusted, sort_keys=True) != json.dumps(policy, sort_keys=True):
            raise PolicyError("candidate policy differs from the trusted policy; refusing to evaluate "
                              "against a policy the candidate controls")
        policy = trusted
    violations = (check_source(repo_root, policy) + check_native_artifacts(repo_root, policy)
                  + check_dependencies(repo_root, policy) + check_project_build_input(repo_root, policy)
                  + check_compiled_sources(repo_root, policy) + check_package_zoning(repo_root, policy))
    if changed_files is not None:
        violations += check_protected_changes(changed_files, policy)
    return violations


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo-root", required=True, type=Path)
    ap.add_argument("--policy", required=True, type=Path)
    ap.add_argument("--trusted-policy", type=Path)
    ap.add_argument("--changed-files", type=Path, help="file with one changed repo-relative path per line")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    try:
        changed = None
        if args.changed_files:
            changed = [line.strip() for line in args.changed_files.read_text().splitlines() if line.strip()]
        violations = run(args.repo_root, args.policy, changed, args.trusted_policy)
    except PolicyError as exc:
        print(f"architecture-check: policy error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({"ok": not violations, "violations": violations}, indent=2))
    else:
        for v in violations:
            print(f"{v['file']}:{v['line']}: [{v['rule']}] {v['message']}")
        print(f"architecture-check: {'OK' if not violations else str(len(violations)) + ' violation(s)'}")
    return 0 if not violations else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
