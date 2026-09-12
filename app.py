#!/usr/bin/env python3
"""
DataForge Registry — an intentionally vulnerable internal ML dataset
platform, built for an advanced web-exploitation CTF challenge.

Narrative: loosely inspired by the July 2026 OpenAI/Hugging Face
incident, where agents left messages for each other as directory names
in a shared, unmonitored package cache, then used that channel to
coordinate an exploit against a dataset-processing pipeline. This
challenge reproduces the shape of that chain (not the real
vulnerabilities): an exposed cache directory hints at an endpoint that
deserializes untrusted input with `pickle`, which is a well-known route
to remote code execution.

Two vulnerabilities, chained:
  1. /cache/ is an unauthenticated directory listing that should never
     have been exposed (information disclosure).
  2. /datasets/process deserializes an uploaded file with pickle.loads()
     without any validation (insecure deserialization -> RCE).

Do not deploy this outside an isolated CTF environment behind an access
gate — the RCE endpoint is real and unauthenticated by design. See
README.md for the required ACCESS_CODE gate before hosting this
publicly.
"""
import os
import pickle

from flask import Flask, request, jsonify, render_template, abort

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CACHE_DIR = os.path.join(BASE_DIR, "cache")

ACCESS_CODE = os.environ.get("ACCESS_CODE")  # if set, gates every route

app = Flask(__name__)


@app.before_request
def check_access_code():
    """Optional gate: if ACCESS_CODE is set in the environment, every
    request must include it as ?code=... or an X-Access-Code header.
    This keeps the (deliberately real) RCE endpoint from being found by
    random internet scanners if this is ever hosted publicly."""
    if not ACCESS_CODE:
        return  # gate disabled
    supplied = request.args.get("code") or request.headers.get("X-Access-Code")
    if supplied != ACCESS_CODE:
        abort(404)  # pretend the whole app doesn't exist


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/cache/")
def cache_listing():
    try:
        entries = sorted(os.listdir(CACHE_DIR))
    except FileNotFoundError:
        entries = []
    return render_template("cache.html", entries=entries)


@app.route("/datasets/process", methods=["GET", "POST"])
def process_dataset():
    if request.method == "GET":
        return render_template("process.html")

    if "dataset" not in request.files:
        return jsonify({"error": "no 'dataset' file provided"}), 400

    data = request.files["dataset"].read()
    try:
        # VULNERABLE LINE: untrusted bytes handed straight to pickle.loads.
        # Pickle's protocol can invoke arbitrary callables during
        # deserialization (via the REDUCE opcode), so this is equivalent
        # to remote code execution for anyone who can reach this route.
        result = pickle.loads(data)
    except Exception as e:
        return jsonify({"error": f"failed to process dataset: {e}"}), 400

    return jsonify({"status": "processed", "result": str(result)})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
