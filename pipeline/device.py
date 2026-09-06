"""
One place that decides which torch device the models run on.

Why this exists
---------------

Every model in this system was running on CPU on a machine with a GPU, and
nothing anywhere said so. `sentence-transformers` picks a device silently, the
injection backend never named one at all, and the only visible symptom was that
a query took eight seconds. Latency is a bad channel for a configuration error:
it looks like the system being slow rather than the system being misconfigured.

The specific failure was not a missing `.to('cuda')`. It was `torch 2.8.0+cpu` —
the CPU-only wheel, on a machine with an RTX 3050. `torch.version.cuda` is
`None` in that build, so no device argument anywhere in this codebase could have
helped. `describe()` separates the two cases explicitly, because "this machine
has no GPU" and "this build of torch cannot address the GPU it has" need
different fixes and look identical from the outside.

Contract
--------

`resolve(preference)` returns a device string, never raises, and falls back to
CPU whenever CUDA is unavailable for any reason. Every caller passes the result
to its model constructor explicitly rather than relying on a library default, so
placement is a recorded decision instead of an accident. `RAG_DEVICE=cpu` forces
CPU on a GPU machine, which is how a like-for-like comparison is run.

Nothing here changes what any model computes. Device placement moves the same
arithmetic to different silicon; the detectors' outputs are the responsibility
of the detectors.
"""

from __future__ import annotations

import os
from typing import Any

VALID = ("auto", "cuda", "cpu")


def resolve(preference: str = "auto") -> str:
    """Return the torch device string to construct models with.

    "auto" means CUDA when torch can actually reach a device, CPU otherwise.
    An explicit "cuda" that cannot be honoured degrades to CPU with a warning
    rather than raising: a slow run beats a dead one, and the warning says which
    happened.
    """
    pref = (preference or "auto").strip().lower()
    if pref not in VALID:
        raise ValueError(f"unknown device preference {preference!r}; expected one of {VALID}")
    if pref == "cpu":
        return "cpu"

    try:
        import torch  # noqa: PLC0415
    except Exception:
        if pref == "cuda":
            print("[pipeline] WARNING: device 'cuda' requested but torch is not importable; "
                  "running on CPU.", flush=True)
        return "cpu"

    if torch.cuda.is_available():
        return "cuda"

    if pref == "cuda":
        reason = ("this build of torch has no CUDA support (torch.version.cuda is None); "
                  "reinstall a CUDA build"
                  if getattr(torch.version, "cuda", None) is None else
                  "torch is a CUDA build but no device is visible (driver, or no GPU present)")
        print(f"[pipeline] WARNING: device 'cuda' requested but unavailable — {reason}. "
              f"Running on CPU.", flush=True)
    return "cpu"


def describe(preference: str = "auto") -> dict[str, Any]:
    """Everything needed to explain a placement decision in a log or a report."""
    info: dict[str, Any] = {"preference": preference, "resolved": None,
                            "torch": None, "cuda_build": None, "cuda_available": False,
                            "gpu_name": None, "note": ""}
    try:
        import torch  # noqa: PLC0415

        info["torch"] = torch.__version__
        info["cuda_build"] = getattr(torch.version, "cuda", None)
        info["cuda_available"] = bool(torch.cuda.is_available())
        if info["cuda_available"]:
            info["gpu_name"] = torch.cuda.get_device_properties(0).name
        elif info["cuda_build"] is None:
            info["note"] = ("CPU-only torch wheel: no device argument can reach a GPU from "
                            "this build. Install a CUDA build to use one.")
        else:
            info["note"] = "CUDA build of torch, but no visible device."
    except Exception as exc:
        info["note"] = f"torch unavailable ({type(exc).__name__})"
    info["resolved"] = resolve(preference)
    return info


def is_cuda_oom(exc: BaseException) -> bool:
    """Is this the out-of-memory error, as opposed to any other runtime error?

    Checked by message as well as by type because the OOM raised through
    different torch paths is not always `torch.cuda.OutOfMemoryError`. A 4 GB
    card running a 512-token batch is close enough to the limit that this is a
    live case rather than a defensive one.
    """
    if type(exc).__name__ in ("OutOfMemoryError", "CudaOutOfMemoryError"):
        return True
    return "out of memory" in str(exc).lower()


def empty_cache() -> None:
    """Release cached CUDA blocks after an OOM, so the retry has room to work in."""
    try:
        import torch  # noqa: PLC0415

        if torch.cuda.is_available():
            torch.cuda.empty_cache()
    except Exception:
        pass


def env_default() -> str:
    return os.environ.get("RAG_DEVICE", "auto")
