# squadFix

A lightweight C++ utility to locally serve the Squad server list using **[WinDivert](https://www.reqrypt.org/windivert.html)**.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Features

-   **Local Server List:** Intercepts requests for `serverlist.cfg` and serves a local version.
-   **Auto-Updating:** On startup, automatically downloads the latest `serverlist.cfg` from a GitHub repository if the local copy is outdated.
-   **Zero Interference:** All other network traffic (HTTP/HTTPS) is completely unaffected.
-   **Native & Lightweight:** No external frameworks required. Built with native Windows APIs.

## How It Works

1.  **Update Check:** Connects to GitHub to compare local and remote `serverlist.cfg` hashes, updating if necessary.
2.  **Intercept:** Uses a WinDivert filter to listen for outgoing traffic on port 80.
3.  **Identify & Respond:** Finds the specific request for Squad's server list, blocks it, and sends back the local file with emulated Amazon S3 headers.
4.  **Ignore:** All other packets are passed through instantly.

## Requirements

-   Windows 10 or later (x64)
-   **Administrator Privileges** (to run the application)
-   [CMake](https://cmake.org/download/) (3.10+)
-   C++ Compiler (e.g., Visual Studio Build Tools)

## Quick Start Guide

#### 1. Build the Project

```sh
# Clone the repository
git clone https://github.com/YourGitHubUsername/SquadFix.git
cd SquadFix

# Configure and build
cmake -S . -B build
cmake --build build --config Release
```

#### 2. Run the Application

The final executable is located in `build/Release/`.

1.  Navigate to the directory: `cd build/Release`
2.  **Run `SquadFix.exe` as an Administrator.**

The app will check for updates and start listening. Press `Ctrl+C` to stop.

## Auto-Update Configuration

To use the auto-update feature with your own fork:

1.  **Edit `src/main.cpp`:** Change `GITHUB_USER`, `GITHUB_REPO`, and `GITHUB_BRANCH` constants to point to your repository.

2.  **Maintain `serverlist.cfg.sha`:** This file in your repository must contain the SHA-256 hash of `serverlist.cfg`. To generate it, use PowerShell:
    ```powershell
    Get-FileHash .\serverlist.cfg -Algorithm SHA256 | Select-Object -ExpandProperty Hash
    ```
    Commit both files whenever `serverlist.cfg` is updated.

## Disclaimer

This tool intercepts and modifies network packets. Use at your own risk. Not affiliated with or endorsed by Offworld Industries.