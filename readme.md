# WORK IN PROGRESS

Client - Clientside environment
- `Update.ps1`: Mod manager
- `GetActive`: Generates load priority and activation data file (_active.txt) in SII plaintext format

Server - Serverside (repo) environment
- `Add-FileHashes.ps1`: Generates versions.json based on .scs files present
- `Update.ps1`: Mod manager - Master for updating
- `versions.json`: Version data
- `_active.txt`: Load prioritiy and activation data in SII plaintext format
