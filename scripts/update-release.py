#!/usr/bin/env python3
"""Update GitHub Release after successful dae build.
Usage: python3 update-release.py <release_id> <binary_path>
"""

import os
import sys
import json
import urllib.request
import urllib.error
import ssl

TOKEN = os.environ.get("GITHUB_TOKEN", "")
REPO = os.environ.get("GITHUB_REPO", "itoywh/dae")

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


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


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 update-release.py <release_id> <binary_path>")
        sys.exit(1)

    release_id = sys.argv[1]
    binary_path = sys.argv[2]

    if not TOKEN:
        print("GITHUB_TOKEN not set!", file=sys.stderr)
        sys.exit(1)

    print(f"Updating release {release_id} in {REPO}...")

    # 1. Get release, find old asset
    release = api("GET", f"https://api.github.com/repos/{REPO}/releases/{release_id}")
    print(f"  Release: {release['name']}")
    print(f"  Tag: {release['tag_name']}")
    print(f"  HTML: {release['html_url']}")

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

    # 3. Update release body with latest commit SHA
    sha = os.environ.get("GITHUB_SHA", "")[:7]
    body = release["body"]
    version_line = f"**dae version**: `unstable-{sha}`"
    if sha and sha not in body:
        lines = body.split("\n")
        # Insert version line after the first heading
        new_lines = [lines[0], "", version_line, ""]
        new_lines.extend(lines[1:])
        new_body = "\n".join(new_lines)
        api("PATCH", f"https://api.github.com/repos/{REPO}/releases/{release_id}",
            json.dumps({"body": new_body}))
        print(f"  Release body updated with {version_line}")
    else:
        print("  Release body already up-to-date (commit SHA present).")

    print("Done!")


if __name__ == "__main__":
    main()
