#!/usr/bin/env python3
"""Update GitHub Release after successful dae build.
- Deletes old binary asset, uploads new one
- Auto-generates changelog from git log and updates release body

Usage: python3 update-release.py <release_id> <binary_path>
"""

import os
import re
import sys
import json
import subprocess
import urllib.request
import urllib.error
import ssl

TOKEN = os.environ.get("GITHUB_TOKEN", "")
REPO = os.environ.get("GITHUB_REPO", "itoywh/dae")

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

CHANGELOG_MARKER = "---\n\n"
MAX_CHANGELOG_ENTRIES = 30


def api(method, url, data=None):
    headers = {
        "Authorization": f"token {TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if data is not None:
        headers["Content-Type"] = "application/json"
        data = data.encode() if isinstance(data, str) else data
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        resp = urllib.request.urlopen(req, context=ctx, timeout=30)
        if resp.status == 204:
            return {"ok": True}
        return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"  HTTP {e.code}: {body}", file=sys.stderr)
        sys.exit(1)


def git_log(old_sha, new_sha="HEAD", limit=0):
    """Run git log between two revisions, returning list of (sha, subject) tuples."""
    args = ["git", "log", "--format=%H||%s", "--reverse"]
    if old_sha:
        args.append(f"{old_sha}..{new_sha}")
    elif limit:
        args.append(f"-{limit}")
    else:
        args.append("-10")
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  Warning: git log failed: {result.stderr}", file=sys.stderr)
        return []
    entries = []
    for line in result.stdout.strip().split("\n"):
        if not line:
            continue
        parts = line.split("||", 1)
        if len(parts) == 2:
            entries.append((parts[0][:7], parts[1]))
    return entries


def extract_last_changelog_sha(body):
    """Find the most recent commit SHA already in the changelog section."""
    # Look for lines like: * `abc1234` desc ...
    matches = re.findall(r'\* `([a-f0-9]+)` ', body)
    if matches:
        return matches[0]  # first match = newest entry
    return None


def build_changelog_body(commits):
    """Build a formatted changelog block from commit tuples."""
    if not commits:
        return ""
    lines = ["## Changelog", "", f"*Auto-generated changelog (last {len(commits)} commits)*", ""]
    for sha, subject in reversed(commits):  # newest first
        lines.append(f"* `{sha}` {subject}")
    lines.append("")
    return "\n".join(lines)


def update_body_with_changelog(old_body, new_sha):
    """
    Smart body update:
    - Keep existing content before the changelog marker
    - Generate fresh changelog from git log
    - Ensure version line reflects new_sha
    """
    # Split body at changelog marker
    if CHANGELOG_MARKER in old_body:
        header_part = old_body.split(CHANGELOG_MARKER, 1)[0].rstrip()
    else:
        # No marker found: find ## Changelog section boundary
        idx = old_body.find("## Changelog")
        if idx != -1:
            header_part = old_body[:idx].rstrip()
        else:
            header_part = old_body.rstrip()

    # Extract the last SHA already in the changelog (from original body)
    last_sha = extract_last_changelog_sha(old_body)

    # Determine what new commits to include
    if last_sha:
        # There is an existing changelog — get only new commits since last entry
        new_commits = git_log(last_sha, "HEAD")
        if not new_commits:
            print("  Already up-to-date (no new commits since last changelog entry).")
            # Still rebuild all commits for consistent display
            all_commits = git_log(None, "HEAD", MAX_CHANGELOG_ENTRIES)
        else:
            print(f"  Found {len(new_commits)} new commit(s) since {last_sha}.")
            # Rebuild full changelog: get all recent entries
            all_commits = git_log(None, "HEAD", MAX_CHANGELOG_ENTRIES)
    else:
        # No existing changelog — grab recent history
        all_commits = git_log(None, "HEAD", MAX_CHANGELOG_ENTRIES)
        print(f"  No existing changelog; building from last {len(all_commits)} commits.")

    # Build the changelog section
    changelog_block = build_changelog_body(all_commits)

    # Update version line
    version_line = f"**dae version**: `unstable-{new_sha}`"

    # Reconstruct body: header + version + blank + changelog
    # Extract pure header (remove any existing version line)
    header_clean = []
    for line in header_part.split("\n"):
        if "dae version" in line.lower():
            continue
        header_clean.append(line)
    # Remove trailing empty lines
    while header_clean and header_clean[-1] == "":
        header_clean.pop()

    new_body_parts = [
        "\n".join(header_clean),
        "",
        version_line,
        "",
        CHANGELOG_MARKER.strip(),
        changelog_block,
    ]
    new_body = "\n".join(new_body_parts)
    return new_body


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 update-release.py <release_id> <binary_path>")
        sys.exit(1)

    release_id = sys.argv[1]
    binary_path = sys.argv[2]
    full_sha = os.environ.get("GITHUB_SHA", "")
    short_sha = full_sha[:7] if full_sha else ""

    if not TOKEN:
        print("GITHUB_TOKEN not set!", file=sys.stderr)
        sys.exit(1)

    print(f"Updating release {release_id} in {REPO} (SHA: {short_sha})...")

    # 1. Get release, find old asset
    release = api("GET", f"https://api.github.com/repos/{REPO}/releases/{release_id}")
    print(f"  Release: {release['name']}")
    print(f"  Tag: {release['tag_name']}")

    for asset in release.get("assets", []):
        if asset["name"] == "dae-linux-x86_64":
            print(f"  Deleting old asset {asset['id']} ({asset['name']})...")
            api("DELETE", f"https://api.github.com/repos/{REPO}/releases/assets/{asset['id']}")
            break
    else:
        print("  No existing asset found (first upload).")

    # 2. Upload new binary
    print(f"  Uploading {binary_path}...")
    with open(binary_path, "rb") as f:
        binary_data = f.read()

    upload_url = f"https://uploads.github.com/repos/{REPO}/releases/{release_id}/assets?name=dae-linux-x86_64"
    headers = {
        "Authorization": f"token {TOKEN}",
        "Content-Type": "application/octet-stream",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Length": str(len(binary_data)),
    }
    req = urllib.request.Request(upload_url, data=binary_data, method="POST", headers=headers)
    resp = urllib.request.urlopen(req, context=ctx, timeout=120)
    result = json.loads(resp.read())
    print(f"  Uploaded: {result['name']} ({result['size']} bytes)")

    # 3. Update release body with changelog
    old_body = release.get("body", "") or ""
    new_body = update_body_with_changelog(old_body, short_sha)

    if new_body != old_body:
        api("PATCH", f"https://api.github.com/repos/{REPO}/releases/{release_id}",
            json.dumps({"body": new_body}))
        print("  Release body updated with fresh changelog.")
    else:
        print("  Release body unchanged (already up-to-date).")

    print("Done!")


if __name__ == "__main__":
    main()
