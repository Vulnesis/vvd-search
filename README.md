# Vulnetix VDB TUI

Interactive terminal interface for exploring the Vulnetix Vulnerability Database.

The VDB TUI implements the [Vulnetix Unified Command Line Utility](https://github.com/Vulnetix/cli)
so users can interact with the VDB in a more intuitive way for vulnerability data.
It is a subset of the full CLI intended to explore the VDB — power users would
benefit more from the CLI directly.

## Features
- Search CVEs by prefix with debounced input
- View vulnerability details (CVSS, EPSS, KEV, affected products, references)
- Exploit intelligence (Nuclei, Metasploit, ExploitDB, CrowdSec, etc.)
- Fix intelligence (patches, workarounds, mitigations, CWE remediations)
- CLI activity logging panel
- Auto-vendors latest CLI release at startup

## Installation

### Homebrew (macOS / Linux)
```bash
brew tap vulnetix/tap
brew install vvd-search
```

### Binary download
Download from [Releases](https://github.com/Vulnetix/vvd-search/releases/latest):
```bash
# Linux (AMD64)
curl -fsSL https://github.com/Vulnetix/vvd-search/releases/latest/download/vvd-search-linux-amd64 -o vvd-search
chmod +x vvd-search
sudo mv vvd-search /usr/local/bin/

# macOS (Apple Silicon)
curl -fsSL https://github.com/Vulnetix/vvd-search/releases/latest/download/vvd-search-darwin-arm64 -o vvd-search
chmod +x vvd-search
sudo mv vvd-search /usr/local/bin/
```

### Go install
```bash
go install github.com/vulnetix/vvd-search@latest
```

### From source
```bash
git clone https://github.com/Vulnetix/vvd-search.git
cd vvd-search
go build -o vvd-search .
```

## Prerequisites

The TUI requires the [Vulnetix CLI](https://github.com/Vulnetix/cli). At startup it
automatically downloads the latest release if not already present. You can also
install the CLI manually:
```bash
brew install vulnetix/tap/vulnetix
```

## Authentication

Configure credentials using any method supported by the Vulnetix CLI:
- `VULNETIX_API_KEY` + `VULNETIX_ORG_ID` environment variables
- `VVD_ORG` + `VVD_SECRET` environment variables
- `~/.vulnetix/credentials.json` (via `vulnetix auth login`)

## Usage
```bash
vvd-search
```

## Keybindings
| Key | Action |
|-----|--------|
| Tab | Switch focus (input ↔ list) |
| ↑/↓ | Navigate results / search history |
| Enter | Search / select vulnerability |
| m/PgDn | Show more detail lines |
| l/PgUp | Show fewer detail lines |
| Esc | Back / deselect |
| Ctrl+E | Toggle eager search (auto-debounce) |
| Ctrl+O | Save OpenAPI spec |
| q | Quit |
