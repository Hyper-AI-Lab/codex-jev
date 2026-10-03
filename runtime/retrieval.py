"""Conservative native-read classification, not a shell parser or security gate."""

from __future__ import annotations

import fnmatch
import os
import re
import shlex
import stat
import subprocess
import time
from pathlib import Path

from common import no_symlinks, read_json, sha
from recovery import excluded

SHELL_TOOLS = {"Bash", "exec_command", "functions.exec_command"}
MAX_COMMAND = 16384
LARGE_READ = 48 * 1024
MAX_FILE = 8 * 1024 * 1024
MAX_LINES = 240


def ignored(root, relative):
    # check-ignore does not support the literal pathspec magic used by git().
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0", LC_ALL="C")
    check = subprocess.run(["git", "-C", str(root), "check-ignore", "--no-index", "-q", "--", relative],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, env=env, timeout=2)
    return check.returncode != 1


def result(state, reason, tool=None):
    return {"state": state, "reason": reason, **({"tool": tool} if tool else {})}


def exact_identifier(query):
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.:]{2,100}", query)
                and ("_" in query or "." in query or ":" in query
                     or re.search(r"[a-z][A-Z]", query) or query.isupper()))


def search_arguments(args, program):
    patterns, paths = [], []
    summary, files_only = False, False
    flags = {"-n", "--line-number", "-i", "--ignore-case", "-S", "--smart-case",
             "-s", "--case-sensitive", "-F", "--fixed-strings", "-w", "--word-regexp"}
    if program == "grep":
        flags |= {"-r", "-R", "-E"}
    index, end = 0, False
    while index < len(args):
        arg = args[index]
        index += 1
        if not end and arg == "--":
            end = True
        elif not end and arg in {"--files", "-l", "--files-with-matches", "-c", "--count", "-q", "--quiet"}:
            summary = True
            files_only = files_only or arg == "--files"
        elif not end and arg in flags:
            continue
        elif not end and re.fullmatch(r"-[niSFwsrRE]{2,8}", arg):
            if any("-" + flag not in flags for flag in arg[1:]):
                return None
        elif not end and arg in {"-e", "--regexp", "-g", "--glob", "-t", "--type", "-A", "-B", "-C"}:
            if index == len(args):
                return None
            value = args[index]
            index += 1
            if arg in {"-e", "--regexp"}:
                patterns.append(value)
            elif arg in {"-A", "-B", "-C"} and not re.fullmatch(r"[0-9]{1,3}", value):
                return None
            elif arg in {"-g", "--glob", "-t", "--type"} and program != "rg":
                return None
        elif not end and arg.startswith("-"):
            return None
        elif not patterns and not files_only:
            patterns.append(arg)
        else:
            paths.append(arg)
    if not patterns and not summary:
        return None
    return patterns, paths or ["."], summary


def private_path(name):
    return excluded(name) or any(
        part.lower() in {".config", ".npmrc", ".pypirc", ".netrc", "auth.json",
                         "application_default_credentials.json", "id_rsa", "id_ed25519"}
        or re.search(r"(^|[._-])(secret|credential|token|password)s?([._-]|$)", part, re.I)
        for part in Path(name).parts)


def inspect_paths(root, cwd, paths, config):
    """Metadata only. EvidenceService rechecks exclusions, authorization and reads."""
    if len(paths) > 16:
        return None
    checked = []
    exclusions = config.get("additional_exclusions", [])
    if not isinstance(exclusions, list) or not all(isinstance(p, str) for p in exclusions):
        return None
    for name in paths:
        if not name or any(c in name for c in "*?[]{}~"):
            return None
        candidate = Path(name) if Path(name).is_absolute() else cwd / name
        try:
            # Do not normalize away a traversed symlink or '..' segment.
            if ".." in candidate.parts:
                return None
            path = no_symlinks(candidate)
            rel = path.relative_to(root).as_posix()
            if private_path(rel) or any(fnmatch.fnmatchcase(rel, p) or rel.startswith(p.rstrip("/") + "/") for p in exclusions):
                return None
            if ignored(root, rel):
                return None
            info = path.stat()
            if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                return None
            if stat.S_ISREG(info.st_mode) and (info.st_nlink != 1 or info.st_size > MAX_FILE):
                return None
            checked.append(info)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            return None
    return checked


def classify(payload, root, config):
    if payload.get("tool_name") not in SHELL_TOOLS:
        return result("not_covered", "unsupported_tool")
    raw = payload.get("tool_input")
    if not isinstance(raw, dict):
        return result("unclassified", "unsupported_arguments")
    command = raw.get("cmd", raw.get("command"))
    if (not isinstance(command, str) or not command or len(command) > MAX_COMMAND
            or any(c in command for c in "\n\r\x00$`")):
        return result("unclassified", "unsupported_shell")
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split, lexer.commenters = True, ""
        args = list(lexer)
    except ValueError:
        return result("unclassified", "unsupported_shell")
    if (not args or len(args) > 128
            or any(token and all(c in ";&|<>()" for c in token) for token in args)
            or any(token.startswith("#") for token in args)):
        return result("unclassified", "unsupported_shell")
    program = args.pop(0)
    if program not in {"rg", "grep", "cat", "head", "tail", "sed"}:
        return result("unclassified", "unsupported_command")
    try:
        cwd = no_symlinks(Path(raw.get("workdir", payload.get("cwd", root))))
        root = no_symlinks(Path(root))
        if not cwd.is_absolute() or not cwd.is_relative_to(root) or not cwd.is_dir():
            return result("native_exception", "outside_workspace")
    except (OSError, TypeError, ValueError):
        return result("native_exception", "outside_workspace")
    if program in {"rg", "grep"}:
        parsed = search_arguments(args, program)
        if not parsed:
            return result("unclassified", "unsupported_search")
        patterns, paths, summary = parsed
        if inspect_paths(root, cwd, paths, config) is None:
            return result("native_exception", "ineligible_paths")
        if summary or all(exact_identifier(p) for p in patterns):
            return result("native", "metadata_or_exact_identifier")
        tool = "search_workspace_evidence"
    else:
        if program == "cat":
            if args[:1] == ["--"]:
                args = args[1:]
            if not args or any(p.startswith("-") for p in args):
                return result("unclassified", "unsupported_read")
            paths, lines = args, None
        else:
            if program == "sed":
                if len(args) != 3 or args[0] != "-n":
                    return result("unclassified", "unsupported_read")
                match = re.fullmatch(r"([1-9][0-9]{0,8})(?:,([1-9][0-9]{0,8}))?p", args[1])
                if not match:
                    return result("unclassified", "unsupported_read")
                start, end = int(match[1]), int(match[2] or match[1])
                lines = end - start + 1
                if lines <= 0:
                    return result("unclassified", "unsupported_read")
            elif len(args) == 3 and args[0] == "-n" and re.fullmatch(r"[1-9][0-9]{0,8}", args[1]):
                lines = int(args[1])
            elif len(args) == 2 and re.fullmatch(r"-n[1-9][0-9]{0,8}", args[0]):
                lines = int(args[0][2:])
            elif len(args) == 1 and not args[0].startswith("-"):
                lines = 10
            else:
                return result("unclassified", "unsupported_read")
            paths = [args[-1]]
        checked = inspect_paths(root, cwd, paths, config)
        if checked is None or not all(stat.S_ISREG(p.st_mode) for p in checked):
            return result("native_exception", "ineligible_paths")
        if (lines is not None and lines <= MAX_LINES) or sum(p.st_size for p in checked) <= LARGE_READ:
            return result("native", "bounded_read")
        tool = "read_large_text_evidence"
    if config.get("enabled") is not True or config.get("retrieval_default", True) is not True:
        return result("native_exception", "retrieval_disabled")
    return result("redirect", "broad_retrieval", tool)


def routing_decision(home, payload, root):
    config = read_json(home.path / "config.json")
    policy = read_json(home.path / "retrieval-policy.json")
    if not isinstance(policy, dict) or type(policy.get("enabled", True)) is not bool:
        raise ValueError("Invalid retrieval routing policy")
    decision = classify(payload, root, {**config, "retrieval_default": policy.get("enabled", True)})
    if decision["state"] != "redirect":
        return decision
    if str(root) not in [*config.get("allowed_roots", []), *home.registry()["roots"]]:
        return result("native_exception", "workspace_not_registered")
    exceptions = policy.get("native_exceptions", [])
    if not isinstance(exceptions, list) or len(exceptions) > 100:
        raise ValueError("Invalid native retrieval exceptions")
    raw = payload["tool_input"]
    cwd = str(no_symlinks(Path(raw.get("workdir", payload.get("cwd", root)))))
    command = raw.get("cmd", raw.get("command"))
    digest = sha((cwd + "\n" + command).encode())
    for exception in exceptions:
        if (not isinstance(exception, dict) or not re.fullmatch(r"[0-9a-f]{64}", str(exception.get("digest", "")))
                or type(exception.get("expires_at")) not in (int, float)
                or exception.get("reason") != "owner_requested"):
            raise ValueError("Invalid native retrieval exception")
        if exception["digest"] == digest and time.time() < exception["expires_at"] <= time.time() + 7 * 86400:
            return result("native_exception", "owner_requested")
    return decision
