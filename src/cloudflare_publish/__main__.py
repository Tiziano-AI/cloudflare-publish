"""Module entrypoint for `python -m cloudflare_publish`."""

from cloudflare_publish.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
