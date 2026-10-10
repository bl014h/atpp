# Listing swap — method

A **listing swap** is an MCP server in the official registry whose current version points at a different
remote-endpoint domain, or a different package owner, than the first version published under the same name.

Clients and users trust a server by its name. The registry verifies who owns a name, but not what the name
points at from one version to the next, and nothing in a client asks again when that changes. Most swaps are
probably legitimate (a rebrand, moved hosting, a package handed to a new maintainer). A takeover looks the same.

`count.py` reproduces the numbers in Redthread's write-up from public registry data and prints aggregates only.

| Rule | Detail |
|---|---|
| Versions compared | the first version ever published under the name vs the current one; deleted entries ignored |
| Remote domain | registrable domain of each remote URL (`api.example.com` and `mcp.example.com` are the same) |
| Package owner | npm scope or name, OCI repository namespace, PyPI/other identifier without version |
| Swap | remote domains share nothing, or package owners share nothing, or the server switched between local package and remote endpoint |

Not a swap: a new version, path or subdomain on the same domain, or a new package under the same npm scope.

The daily ATPP scan (rules `atf-4`) carries the same test as the `target-stable` check, so every server's badge
and signed claim now says whether its listing has swapped since it was first published.
