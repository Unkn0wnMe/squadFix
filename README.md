# squadFix

A lightweight C++ utility to locally serve the Squad server list using **[WinDivert](https://www.reqrypt.org/windivert.html)**.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Features

-   **Local Server List:** Intercepts requests for `serverlist.cfg` and serves a local version.
-   **Auto-Updating:** On startup, automatically downloads the latest `serverlist.cfg` from a GitHub repository if the local copy is outdated.
-   **Zero Interference:** All other network traffic (HTTP/HTTPS) is completely unaffected.
-   **Native & Lightweight:** No external frameworks required. Built with native Windows APIs.

## Requirements

-   Windows 10 or later (x64)
-   **Administrator Privileges** (to run the application)
-   [CMake](https://cmake.org/download/) (3.10+)
-   C++ Compiler (e.g., Visual Studio Build Tools)

## Quick Start Guide

#### 1. Build the Project

```sh
# Clone the repository
git clone https://github.com/Unkn0wnMe/squadFix.git
cd squadFix

# Configure and build
cmake -S . -B build
cmake --build build --config Release
```

#### 2. Run the Application

The final executable is located in `build/Release/`.

1.  Navigate to the directory: `cd build/Release`
2.  **Run `SquadFix.exe` as an Administrator.**

The app will check for updates and start listening. Press `Ctrl+C` to stop.

## Disclaimer
Use at your own risk. Not affiliated with or endorsed by Offworld Industries.
