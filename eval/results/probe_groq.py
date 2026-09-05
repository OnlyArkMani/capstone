#!/usr/bin/env python3
"""
Probe — why is Groq returning 403?

`check_backends` reports 403 for the chat endpoint and a bare /v1/models listing
returns 403 too, so this is not a decommissioned model. Two candidates remain and
they need opposite fixes:

  A. The request is being refused before it reaches Groq. Groq is behind
     Cloudflare, and urllib identifies itself as "Python-urllib/3.11", which
     Cloudflare blocks with a 403 and an HTML body. pipeline/generation.py sets
     only Content-Type and Authorization -- no User-Agent -- so a completely
     valid key would still fail this way. Fix: send a User-Agent.

  B. The key is genuinely rejected. Then the body is JSON from Groq naming the
     reason (revoked, terms not accepted, region). Fix: a new key, and no code
     change would ever have helped.

The body distinguishes them: HTML means Cloudflare, JSON means Groq. Every
attempt prints its status and the first part of the body. The key is never
printed -- only its length and last four characters, enough to confirm the
container sees the same key you pasted into .env without putting it in a log.

Run:
  docker compose -f docker-compose.yml -f docker-compose.dev.yml \
      run --rm shell python3 eval/results/probe_groq.py
"""

import json
import os
import urllib.error
import urllib.request

URL = "https://api.groq.com/openai/v1/models"
BROWSER_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/125.0 Safari/537.36")


def attempt(label: str, headers: dict[str, str]) -> bool:
    print(f"\n--- {label} ---")
    print(f"  headers sent: {sorted(k for k in headers if k != 'Authorization')} + Authorization")
    req = urllib.request.Request(URL, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        ids = sorted(d["id"] for d in data.get("data", []))
        print(f"  HTTP 200 — {len(ids)} models available")
        for i in ids:
            print(f"    {i}")
        return True
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", "replace")
        except Exception:
            pass
        kind = ("HTML — refused BEFORE Groq (Cloudflare/proxy)" if "<html" in body[:400].lower()
                else "JSON — refused BY Groq" if body.strip().startswith("{")
                else "unrecognised")
        print(f"  HTTP {exc.code} {exc.reason}")
        print(f"  server: {exc.headers.get('server', '?')}   cf-ray: {exc.headers.get('cf-ray', '-')}")
        print(f"  body looks like: {kind}")
        print(f"  body[:400]: {body[:400]!r}")
        return False
    except Exception as exc:
        print(f"  {type(exc).__name__}: {exc}")
        return False


def main() -> None:
    key = os.environ.get("GROQ_API_KEY", "")
    if not key:
        print("GROQ_API_KEY is not visible inside this container. "
              "Check .env sits beside docker-compose.yml.")
        return
    print(f"key visible in container: {len(key)} chars, ends ...{key[-4:]}")

    base = {"Authorization": f"Bearer {key}"}
    ok_plain = attempt("A. as the code sends it today (no User-Agent)", dict(base))
    ok_ua = attempt("B. same request with a browser User-Agent",
                    {**base, "User-Agent": BROWSER_UA})
    attempt("C. no key at all — what does an UNAUTHENTICATED request return?",
            {"User-Agent": BROWSER_UA})

    print("\n" + "=" * 68)
    print("READING THIS")
    print("=" * 68)
    if ok_ua and not ok_plain:
        print("The User-Agent was the whole problem. The key is fine. Fix is one line in")
        print("pipeline/generation.py: send a User-Agent on every request.")
    elif ok_plain or ok_ua:
        print("Groq is reachable and the key works. The earlier 403 was the model name;")
        print("pick one from the list above and set RAG_GROQ_MODEL to it.")
    else:
        print("Both attempts refused. If attempt C ALSO returned 403 with an HTML body,")
        print("something between this container and Groq is blocking it and the key is")
        print("not implicated. If C returned 401 with JSON while A and B returned 403,")
        print("Groq is reaching us fine and is rejecting this specific key -- generate a")
        print("new one at console.groq.com. Either way, Ollama remains the offline route")
        print("and needs no key at all.")


if __name__ == "__main__":
    main()
