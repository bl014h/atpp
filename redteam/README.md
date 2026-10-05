# Red team: can an ATPP badge be faked?

A README badge is an image fetched from somebody's server. A public proof of concept showed that the image
can be **swapped after it is embedded** and that an SVG can **mimic anything**, even ordinary README text, and
be wrapped in a link. This page reproduces both against ATPP and shows what still holds. The scorecard of
every attack is regenerated daily by the [`redteam` workflow](https://github.com/bl014h/atpp/actions/workflows/redteam.yml); the
service is watched hourly by the [`canary` workflow](https://github.com/bl014h/atpp/actions/workflows/canary.yml).

**The point:** no image here can be trusted, including ours. What counts is `python3 atpp.py verify`, which
reads the signed `.atpp/` files, never README images or links.

## 1. A pinned badge (served from this repository)

[![ATPP scan](genuine/.atpp/badge.svg)](https://trust.redthreadsec.com/v/mcp/io.github.github/github-mcp-server)

This is a real, current claim for `io.github.github/github-mcp-server`, copied here. GitHub serves the image from this repository,
so nothing outside the repo can change it — demo 1 of the PoC does not apply. But because it was copied,
`python3 atpp.py verify redteam/genuine` **fails**: the claim belongs to a server whose registry listing points
at a different repository.

## 2. A live badge (served by trust.redthreadsec.com, through GitHub's image proxy)

[![ATPP live](https://trust.redthreadsec.com/badge/mcp/io.github.github/github-mcp-server.svg)](https://trust.redthreadsec.com/v/mcp/io.github.github/github-mcp-server)

This one *can* be swapped by whoever controls trust.redthreadsec.com, which is why it is optional. Its claim still
has to verify against a key the server does not hold.

## 3. A forged lookalike (served from this repository)

[![ATPP scan](forged-badge.svg)](https://example.com/)

Pixel-identical to a genuine pinned badge and claiming a perfect score. There is no claim behind it that
verifies. An image proves nothing.

## 4. README-text mimicry, wrapped in a link

[![](mimicry.svg)](https://example.com/)

The two lines above look like README text, but they are one image linking anywhere its author likes. GitHub
strips scripts from SVGs but not this. ATPP never emits an SVG containing links, styles, scripts or
animation; the canary checks every live badge for it hourly.

## Reproduce

```bash
pip install cryptography
python3 redteam.py                    # every attack against production, read-only
python3 canary.py --sample 12 --camo  # the hourly health check
```
