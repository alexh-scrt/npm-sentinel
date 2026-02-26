"""npm_sentinel - A CLI security tool for auditing npm package.json and node_modules.

This package provides tools to detect supply chain attack vectors including:
- Typosquatting via fuzzy string matching against popular npm packages
- Suspicious post-install hooks (curl/wget pipes, base64 payloads, eval patterns)
- Rogue MCP server injections in package metadata and install scripts

Public API:
    __version__: Current package version string
    __all__: Exported public symbols

Example usage::

    from npm_sentinel import __version__
    print(f"npm_sentinel v{__version__}")
"""

__version__ = "0.1.0"
__author__ = "npm-sentinel contributors"
__license__ = "MIT"

__all__ = ["__version__", "__author__", "__license__"]
