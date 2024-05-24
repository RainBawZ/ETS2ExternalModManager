# WORK IN PROGRESS

Client - Clientside environment
- `Update.ps1`: Mod manager
- `GetActive`: Generates load priority and activation data file (`_active.txt`) in SII plaintext format (Deprecated, use load order export in `Update.ps1`)

Server - Serverside (repo) environment
- `Add-FileHashes.ps1`: Generates versions.json based on .scs files present (Deprecated)
- `Update.ps1`: Mod manager - Master for updating (Deprecated)
- `versions.json`: Version data
- `_active.txt`: Load prioritiy and activation data in SII plaintext format (Deprecated)

psm - PowerShell module for mod management
- WIP
