from __future__ import annotations
import argparse, json, os, sys

from .crypto import KeyPair
from .token import decode


def _write_private(path: str, data: dict) -> None:
    """Private keys are 0600 or they are a liability."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="adp", description="Agent Delegation Protocol CLI")
    sub = p.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen", help="generate an Ed25519 keypair")
    k.add_argument("--out", default="adp-key.json")
    d = sub.add_parser("decode", help="decode a token without verifying it")
    d.add_argument("token")
    args = p.parse_args(argv)

    if args.cmd == "keygen":
        kp = KeyPair.generate()
        _write_private(args.out, {"private_key": kp.private_key_b64, "public_key": kp.public_key_b64})
        print(f"{args.out} (public_key={kp.public_key_b64})")
    elif args.cmd == "decode":
        try:
            header, payload, _ = decode(args.token)
        except Exception as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        print(json.dumps({"header": header, "payload": payload}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
