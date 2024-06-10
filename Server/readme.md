# `information.json` contains repository config. Its repo location MUST be `/information.json`

- `Script`: Relative path of the client script. Must end in `.ps1` (`/<Script>`)
- `ModRoot`: Relative path of the mod directory. Must end with a `/` (`/<ModRoot>`)
- `OrderRoot`: Relative path of the load order directory. Must end with a `/` (`/<OrderRoot>`)
- `DefaultOrder`: Default load order name (`<loadOrder>.cfg` must exist within `/<OrderRoot>`)
- `Orders`: Relative path of the JSON file containing available orders. Must end in `.json` (`/<OrderRoot>/<Orders>`)
- `VersionData`: Relative path of the JSON file containing mod version data. Must end in `.json` (`/<VersionData>`)
- `DecFile`: Relative path of the SII decryptor executable. Must end in `.exe` (`/<DecFile>`)
- `DecHash`: Relative path of the .txt file containing the SII decryptor exe hash. Must be `text/plain` (`/<DecHash>`)
- `TSSE`: Relative path of the TS SE Tool ZIP archive. Must end in `.zip` (`/<TSSE>`)
