# npm-sentinel
npm_sentinel is a command-line security tool that audits package.json and node_modules directories for supply chain attack vectors including typosquatting, suspicious post-install hooks, and rogue MCP server injections. It uses fuzzy string matching against a curated database of legitimate popular packages to flag potential typosquats, inspects npm
