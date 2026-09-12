# DataForge Registry

**Category:** Web Exploitation
**Difficulty:** Advanced
**Points suggestion:** 400–500

## Description

DataForge Registry is an internal ML dataset platform. Someone left the
build cache exposed to the internet, and it looks like they weren't the
only ones who noticed.

Find the flag.

## Running it

**Docker (recommended):**

```
docker compose up --build
```

**Plain Python:**

```
pip install -r requirements.txt
python3 app.py
```

Then visit http://localhost:5000

## Hints (release progressively if needed)

1. *"That build cache didn't get exposed by accident. Someone's been
   using it — read what's there."*
2. *"The cache points at an endpoint. What does 'processing' a dataset
   actually mean on the server side?"*
3. *"Python's `pickle` format can rebuild arbitrary objects when you
   load it — including by calling arbitrary functions. If a server
   deserializes a file you control, that's not deserialization anymore."*
4. *"You don't need a shell — the response echoes back whatever your
   payload's `__reduce__` returns. Point that at reading the file the
   cache told you about."*

## Rules

- This app is intentionally vulnerable — that's the whole point. **Do
  not** deploy this publicly without setting the `ACCESS_CODE`
  environment variable (see "Hosting this publicly" below); an
  unauthenticated deserialization RCE endpoint left open on the real
  internet will get found and abused by scanners within hours, not by
  your players.
- Flag format: `FLAG{...}`

## Hosting this publicly

If you want to run this as a live, internet-facing challenge rather
than handing out the files, set the `ACCESS_CODE` environment variable
to a long random string before starting the app. Every route then
requires that value as either `?code=...` in the URL or an
`X-Access-Code` header, and requests without it get a plain 404 (the
app pretends not to exist). Share the code only with your players —
e.g. via a challenge portal that appends it to the link automatically,
or just tell them to add `?code=...` to every URL. This keeps
opportunistic internet scanners from ever reaching the real RCE
endpoint, while still letting your players use it exactly as designed.

Without `ACCESS_CODE` set, the app has no authentication at all — fine
for a private network, a local Docker run, or a VPN-gated CTF
instance, but not for the open internet.
