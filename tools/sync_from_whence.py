#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Advanced Micro Devices, Inc. All rights reserved.
"""Populate firmware and archive trees from a WHENCE manifest.

This tool drives WHENCE-based syncs behind a single entry point with per-source
subcommands that share the WHENCE parsing, pinned-vs-latest selection, the
download helper, and commit-file recording:

  * "firmware" parses the "Driver: amdxdna" section of a drm-firmware WHENCE
    manifest, downloads each versioned file once, and reconstructs the
    npu.dev.sbin / cert.dev.sbin symlinks (and device-variant directory links)
    so the installed file name still reveals the firmware version.

The subcommand replaces the hand-maintained firmwares[] list that used to live
in tools/info.json.

Firmware layout in the drm-firmware WHENCE file:

    File: amdnpu/17f1_10/1.8_npu.sbin.2.5.0.172
    Link: amdnpu/17f1_10/npu.dev.sbin -> 1.8_npu.sbin.2.5.0.172

The driver always requests the stable name ("npu.dev.sbin" / "cert.dev.sbin"),
while the versioned real file lets us tell which firmware version is installed.
Device variants that share the same binary are captured upstream as directory
or file level symlinks and are reconstructed here as well.

Two modes are selected by the presence of a committed pin.

  * RELEASE: a pin is present, so downloads come from that immutable commit for
    reproducible release builds.
  * MAIN: no pin is present, so the latest commit is resolved once via
    "git ls-remote" and the resolved hash is recorded for the build to cache.
    WHENCE is never rewritten here.
"""

import argparse
import os
import posixpath
import shutil
import subprocess
import urllib.request

FW_REPO = "kernel-firmware/drm-firmware"
FW_RAW_URL = "https://gitlab.com/{repo}/-/raw/{ref}/{path}"
FW_CLONE_URL = "https://gitlab.com/{repo}.git"
AMDNPU_PREFIX = "amdnpu/"


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #
def ls_remote(url, ref):
    """Resolve a ref on a remote via "git ls-remote"; return "" if not found."""
    try:
        out = subprocess.check_output(
            ["git", "ls-remote", url, ref], text=True,
            stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, OSError):
        return ""
    for line in out.splitlines():
        sha, _, name = line.partition("\t")
        if name.strip() in ("refs/heads/" + ref, "refs/tags/" + ref, ref):
            return sha.strip()
    if out.strip():
        return out.split()[0].strip()
    return ""


def read_pin(text, key):
    """Return the "<key> <value>" pin from WHENCE text, or "" when absent."""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(key):
            return line.split(":", 1)[1].strip()
    return ""


def fetch_to(url, dest, timeout=60):
    """Download url to dest atomically via a ".part" temp file.

    The response is streamed in chunks so a large firmware blob is never held
    in memory in full, and a socket timeout keeps a stalled connection from
    hanging the build indefinitely.
    """
    tmp = dest + ".part"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp, \
                open(tmp, "wb") as out:
            shutil.copyfileobj(resp, out)
        os.replace(tmp, dest)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def write_commit_file(path, first, second, makedirs=False):
    """Write "<first>\\n<second>\\n" so the build can cache the resolved hash."""
    if makedirs:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w") as handle:
        handle.write(first + "\n")
        handle.write(second + "\n")


# --------------------------------------------------------------------------- #
# Firmware (Driver: amdxdna)
# --------------------------------------------------------------------------- #
def resolve_commit(ref):
    """Resolve a branch/tag name to a concrete commit hash on the remote."""
    url = FW_CLONE_URL.format(repo=FW_REPO)
    sha = ls_remote(url, ref)
    if sha:
        return sha
    raise SystemExit("error: could not resolve ref '%s' on %s" % (ref, url))


def read_firmware_whence(args):
    """Return (whence_text, download_ref, commit_hash).

    A local snapshot pins the download to the commit recorded in its header so
    that release branches are fully reproducible. Live mode resolves the branch
    tip once and downloads from that immutable commit.
    """
    if args.whence:
        with open(args.whence, "r") as handle:
            text = handle.read()
        commit = read_pin(text, "# whence-commit:")
        # A pinned commit gives reproducible downloads; fall back to the ref.
        return text, (commit or args.ref), commit
    commit = resolve_commit(args.ref)
    url = FW_RAW_URL.format(repo=FW_REPO, ref=commit, path="WHENCE")
    # A socket timeout keeps a stalled connection from hanging packaging
    # indefinitely, matching the timeout fetch_to() uses for the blobs.
    with urllib.request.urlopen(url, timeout=60) as resp:
        text = resp.read().decode("utf-8", "replace")
    return text, commit, commit


def extract_amdxdna_section(text):
    """Return the File:/Link: lines from the 'Driver: amdxdna' block."""
    section = []
    in_section = False
    for line in text.splitlines():
        if line.startswith("-----"):
            if in_section:
                break
            continue
        if line.startswith("Driver:"):
            in_section = line.startswith("Driver: amdxdna")
            continue
        if in_section:
            section.append(line)
    return section


def parse_section(section):
    """Return (files, links) where links maps link path -> target path."""
    files = set()
    links = {}
    for raw in section:
        line = raw.strip()
        if line.startswith("File:"):
            files.add(line[len("File:"):].strip())
        elif line.startswith("Link:"):
            body = line[len("Link:"):].strip()
            if "->" not in body:
                continue
            link_path, target = (part.strip() for part in body.split("->", 1))
            # A target without a slash is relative to the link's directory.
            if "/" not in target:
                target = posixpath.join(posixpath.dirname(link_path), target)
            else:
                target = posixpath.normpath(
                    posixpath.join(posixpath.dirname(link_path), target))
            links[link_path] = target
    return files, links


def resolve_link(link_path, links, files, seen=None):
    """Follow a (possibly chained) link to the underlying real File: path."""
    seen = seen or set()
    if link_path in seen:
        raise SystemExit("error: link cycle detected at %s" % link_path)
    seen.add(link_path)
    target = links[link_path]
    if target in links:
        return resolve_link(target, links, files, seen)
    return target


def strip_prefix(path):
    """Strip the "amdnpu/" prefix, rejecting anything that would escape it.

    WHENCE is external input (fetched live upstream or read from a snapshot),
    so a malformed manifest must never be able to steer a download or a symlink
    outside the requested --out tree. Only paths firmly rooted under "amdnpu/"
    are accepted: absolute paths and ".." components that climb out of the
    prefix are rejected outright.
    """
    if posixpath.isabs(path) or not path.startswith(AMDNPU_PREFIX):
        raise SystemExit(
            "error: WHENCE path %r is not rooted under %s" % (
                path, AMDNPU_PREFIX))
    rel = path[len(AMDNPU_PREFIX):]
    normalized = posixpath.normpath(rel)
    if posixpath.isabs(normalized) or normalized == ".." \
            or normalized.startswith("../"):
        raise SystemExit(
            "error: WHENCE path %r escapes %s" % (path, AMDNPU_PREFIX))
    return rel


def read_cached_commit(commit_file):
    """Return the drm-firmware commit a prior sync recorded, or "" if unknown.

    build.sh points --commit-file at ".whence_commit", into which
    write_commit_file() records "<ref>\\n<commit>". Reading the commit back lets
    a reused amdxdna_bins cache tell which drm-firmware commit its versioned
    firmware blobs were fetched from.
    """
    if not commit_file or not os.path.exists(commit_file):
        return ""
    try:
        with open(commit_file, "r") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return ""
    return lines[1].strip() if len(lines) > 1 else ""


def download_firmware(ref, remote_path, dest, refresh=False):
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    # Every blob is fetched from an immutable drm-firmware commit, so a cached
    # file is byte-identical to the source only while it was fetched from the
    # same commit. "refresh" is set when that is not guaranteed (the cache was
    # built from a different commit, e.g. a blob re-signed under the same
    # version/filename), in which case the stale file must be re-downloaded
    # rather than skipped on filename existence. fetch_to() writes to a ".part"
    # temp and atomically os.replace()s it, so a refresh overwrites cleanly.
    if os.path.exists(dest) and not refresh:
        return
    url = FW_RAW_URL.format(repo=FW_REPO, ref=ref, path=remote_path)
    print("  download %s" % remote_path)
    fetch_to(url, dest)


def make_symlink(link_dest, target_name):
    # A prior run (or the pre-WHENCE sync method) may have left a real file, a
    # dangling/real symlink, or a real directory at this path. Clear whatever is
    # there before recreating the link; os.remove() alone raises
    # IsADirectoryError on a real directory.
    if os.path.islink(link_dest) or os.path.isfile(link_dest):
        os.remove(link_dest)
    elif os.path.isdir(link_dest):
        shutil.rmtree(link_dest)
    os.symlink(target_name, link_dest)


def prune_device_dir(out_dir, rel_dir):
    """Remove superseded versioned firmware files from one device directory.

    download_firmware() skips a versioned file that already exists and never
    deletes the versioned file it supersedes, so a cached amdxdna_bins tree that
    is reused across CI runs (and never "-distclean"ed) slowly accumulates old
    ".sbin" blobs in each amdnpu/<dir>/. The packaging glob (pkg.cmake,
    PATTERN "*sbin*") would then ship every stale version into the plugin .deb.

    KEEP set for the directory = { the stable ".dev.sbin" alias symlink names
    present (npu.dev.sbin, cert.dev.sbin) } union { the basenames of the
    versioned files those aliases currently resolve to }. Every other plain
    regular file is a stale/superseded versioned ".sbin" left over from an
    earlier sync and is removed. Symlinks (the stable aliases and any device-
    variant directory links) are never followed or deleted, so the current
    target, its alias, variant directory links, and the firmware-root commit
    cache files (.whence_commit / .vtd_commit, which live outside these device
    directories) are all preserved.

    @param out_dir absolute firmware output root; pruning stays within it.
    @param rel_dir device directory relative to out_dir that this run
        materialized (e.g. "17f1_10"); the firmware root itself is never pruned.
    """
    # Guard: only ever operate on a real subdirectory of out_dir, never the
    # firmware root (which holds the commit cache files) and never a symlink.
    if not rel_dir:
        return
    dir_path = os.path.join(out_dir, rel_dir)
    if os.path.islink(dir_path) or not os.path.isdir(dir_path):
        return

    keep = set()
    for name in os.listdir(dir_path):
        full = os.path.join(dir_path, name)
        # Stable aliases are symlinks named "*.dev.sbin" (npu.dev.sbin,
        # cert.dev.sbin). Keep the alias itself and the versioned file it
        # currently resolves to (readlink, so we never follow the link).
        if os.path.islink(full) and name.endswith(".dev.sbin"):
            keep.add(name)
            target = os.readlink(full)
            # Only protect the versioned blob when it lives in this same
            # directory. A variant dir whose alias points elsewhere (e.g.
            # "../17f1_10/1.8_npu.sbin...") keeps its real blob in the
            # canonical dir, so any local file of that name here is a stale
            # copy from an older sync and must be pruned for cross-revision
            # dedup.
            if "/" not in target:
                keep.add(posixpath.basename(target))

    for name in os.listdir(dir_path):
        full = os.path.join(dir_path, name)
        # Delete only plain regular files; leave symlinks and subdirectories.
        if os.path.islink(full) or not os.path.isfile(full):
            continue
        if name in keep:
            continue
        print("  prune %s" % posixpath.join(rel_dir, name))
        os.remove(full)


def sync_firmware(args):
    text, download_ref, commit = read_firmware_whence(args)
    files, links = parse_section(extract_amdxdna_section(text))
    if not links:
        raise SystemExit(
            "error: no amdnpu Link: entries found in WHENCE; nothing to sync")

    out_dir = os.path.abspath(args.out)
    os.makedirs(out_dir, exist_ok=True)

    # The upstream WHENCE carries no per-file checksum, so commit identity is
    # the content check: a blob comes from an immutable drm-firmware commit, so
    # a cached tree still matches the source only while it was built from the
    # commit now being synced. When the recorded commit differs (or is unknown),
    # a reused cache may hold stale bytes under an unchanged version/filename, so
    # force a re-download for that file instead of skipping on existence alone.
    cached_commit = read_cached_commit(args.commit_file)
    refresh = (not commit) or (cached_commit != commit)
    # A single blob can back several aliases; refresh each real file only once so
    # a forced refresh does not re-download the same blob per alias in one run.
    refreshed = set()

    file_links = {}
    dir_links = {}
    for link_path, target in links.items():
        # Stable firmware aliases end in .sbin (npu.dev.sbin, cert.dev.sbin).
        # Everything else is a device-variant directory link, which may chain
        # to another directory link before reaching the canonical directory
        # (e.g. 17f2_15 -> 17f1_15 -> 17f1_13). Both symlinks are recreated so
        # the chain resolves on disk.
        if posixpath.basename(link_path).endswith(".sbin"):
            file_links[link_path] = target
        else:
            dir_links[link_path] = target

    # Real files behind the stable .sbin aliases.
    materialized = set()
    # Directories where a stable alias/file link was created. A dir that became
    # a variant (its .dev.sbin now points into another canonical dir) is not in
    # "materialized" but may still hold stale *.sbin blobs, so track it here too.
    aliased_dirs = set()
    for link_path in sorted(file_links):
        real = resolve_link(link_path, links, files)
        if real not in files:
            raise SystemExit(
                "error: %s resolves to %s which is not a File: entry"
                % (link_path, real))
        # Download the real file once, into its own canonical directory, so
        # variant directories only ever hold alias symlinks (no duplicate blob).
        real_dest = os.path.join(out_dir, strip_prefix(real))
        download_firmware(download_ref, real, real_dest,
                          refresh and real_dest not in refreshed)
        refreshed.add(real_dest)
        materialized.add(strip_prefix(posixpath.dirname(real)))
        # Create the stable alias in the link's own directory, pointing at the
        # canonical file (same-dir -> bare name, cross-dir -> ../canon/file).
        link_dest = os.path.join(out_dir, strip_prefix(link_path))
        os.makedirs(os.path.dirname(link_dest), exist_ok=True)
        aliased_dirs.add(strip_prefix(posixpath.dirname(link_path)))
        make_symlink(link_dest,
                     os.path.relpath(real_dest, os.path.dirname(link_dest)))

    # Device-variant directories that mirror another directory wholesale.
    for link_path in sorted(dir_links):
        # Follow the (possibly chained) link to the canonical directory and
        # skip variants whose target holds no .dev firmware, so we never
        # package a dangling symlink.
        final = link_path
        seen = set()
        while final in dir_links and final not in seen:
            seen.add(final)
            final = dir_links[final]
        if strip_prefix(final) not in materialized:
            print("  skip %s -> %s (no .dev firmware at target)"
                  % (strip_prefix(link_path), strip_prefix(dir_links[link_path])))
            continue
        link_dest = os.path.join(out_dir, strip_prefix(link_path))
        target_rel = os.path.relpath(
            os.path.join(out_dir, strip_prefix(dir_links[link_path])),
            os.path.dirname(link_dest))
        os.makedirs(os.path.dirname(link_dest), exist_ok=True)
        make_symlink(link_dest, target_rel)

    # After every download and symlink is in place, prune each materialized
    # device directory so a cached amdxdna_bins tree that is never "-distclean"ed
    # cannot accumulate superseded versioned firmware across CI runs. Only the
    # real directories that received a download this run are pruned; variant
    # directory-symlinks own no files and the firmware-root commit cache files
    # are left untouched. A dir that became a variant this run (its alias now
    # points into another canonical dir) is covered via aliased_dirs so stale
    # blobs in a reused cache are removed there too; prune_device_dir is safe on
    # variant dirs (it keeps aliases and their targets, deletes plain files).
    for rel_dir in sorted(materialized | aliased_dirs):
        prune_device_dir(out_dir, rel_dir)

    if args.commit_file and commit:
        write_commit_file(args.commit_file, args.ref, commit)
    print("firmware tree ready in %s (commit %s)" % (out_dir, commit or "live"))


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main():
    parser = argparse.ArgumentParser(
        description="Sync firmware or VTD archives from a WHENCE manifest.")
    sub = parser.add_subparsers(dest="command")
    sub.required = True

    fw = sub.add_parser(
        "firmware",
        help="sync the NPU firmware tree from the 'Driver: amdxdna' WHENCE "
             "section")
    fw.add_argument("--out", required=True,
                    help="firmware output directory (packaged as amdnpu/)")
    fw.add_argument("--whence",
                    help="local WHENCE snapshot; omit to fetch live")
    fw.add_argument("--ref", default="amd-ipu-staging",
                    help="drm-firmware branch to fetch when --whence unset")
    fw.add_argument("--commit-file",
                    help="write '<ref>\\n<commit>' for the build to cache")
    fw.set_defaults(func=sync_firmware)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
