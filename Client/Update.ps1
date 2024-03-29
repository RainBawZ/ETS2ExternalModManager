#STR_version=3.4.1;
#STR_profile=***GAME_PROFILE_PLACEHOLDER***;
#NUM_start=0;
#NUM_validate=0;
#NUM_purge=0;
#NUM_noconfig=0;

#***GAME_PROFILE_PLACEHOLDER***

<#

    COPYRIGHT © 2024 RainBawZ

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software
    and associated documentation files (the "Software"), to deal in the Software without restriction,
    including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
    subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS," WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
    THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
    WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
    OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#>

Param ([String]$Updated)

Function Sync-Ets2ModRepo {
    [CmdletBinding()]

    Param ([String]$Updated)

    Function Limit-Range {
        [CmdletBinding()]

        Param (
            [Parameter(Mandatory, Position = 0)][Double]$Value,
            [Parameter(Mandatory, Position = 1)][Double]$Min,
            [Parameter(Mandatory, Position = 2)][Double]$Max
        )

        If ($Min -gt $Max -Or $Max -lt $Min) {Throw 'Invalid range'}

        If ($G__ClampAvailable) {Return [Math]::Clamp($Value, $Min, $Max)}
        Else                    {Return $(If ($Value -lt $Min) {$Min} ElseIf ($Value -gt $Max) {$Max} Else {$Value})}
    }

    Function Write-HostX {
        [CmdletBinding()]

        Param (
            [Parameter(Mandatory, Position = 0)][ValidateScript({$_ -ge 0 -And $_ -le $Host.UI.RawUI.BufferSize.Width})][UInt16]$X,
            [Parameter(Mandatory, Position = 1, ValueFromRemainingArguments)][String]$InputString,
            [ConsoleColor]$Color, [Switch]$Newline
        )

        [UInt16]$BufferWidth = $Host.UI.RawUI.BufferSize.Width
        [UInt16]$InputLimit  = $BufferWidth - $X

        # Prevent screen buffer overflows (line wrapping breaks the layout)
        If ($InputString.Length -ge $InputLimit) {$InputString = ($InputString.Substring(0, $InputLimit - 5) + '[...]')}

        [UInt16]$InputLength = $InputString.Length
        [Int]$RawPadLength   = $InputLimit - $InputLength
        [UInt16]$PadLength   = Limit-Range $RawPadLength 0 $BufferWidth

        [Hashtable]$WHSplat = @{
            Object    = ($InputString + (' ' * $PadLength))
            NoNewline = !$Newline.IsPresent
        }
        If ($Color) {$WHSplat['ForegroundColor'] = $Color}

        If ($G__HostCompatible) {[Console]::SetCursorPosition($X, $Host.UI.RawUI.CursorPosition.Y)}

        Write-Host @WHSplat
    }

    Function Read-HostX {
        [CmdletBinding()]

        Param ([Parameter(Position = 0)][String]$Prompt)

        [String]$UserInput = If ($Prompt) {Read-Host $Prompt} Else {Read-Host}
        If ($G__HostCompatible) {[Console]::CursorVisible = $False}
        Return $UserInput
    }

    Function Protect-Variables      {If ($GLOBAL:PROTECTED) {Throw 'The object is already initialized'} Else {[String[]]$GLOBAL:PROTECTED = (Get-Variable).Name + 'PROTECTED'}}
    Function Update-ProtectedVars   {If ($GLOBAL:PROTECTED) {Add-ProtectedVars (Get-UnprotectedVars)}}
    Function Get-UnprotectedVars    {If ($GLOBAL:PROTECTED) {Return [String[]](Get-Variable -Exclude $GLOBAL:PROTECTED).Name}}
    Function Remove-UnprotectedVars {If ($GLOBAL:PROTECTED) {Switch (Get-UnprotectedVars) {$Null {Return} Default {Remove-Variable $_ -ErrorAction SilentlyContinue}}}}
    Function Unprotect-Variables    {If ($GLOBAL:PROTECTED) {Remove-Variable PROTECTED -Scope GLOBAL}}
    Function Add-ProtectedVars      {
        [CmdletBinding()]

        Param ([Parameter(ValueFromPipeline)][String[]]$InputObject)

        If ($InputObject -And $GLOBAL:PROTECTED) {$GLOBAL:PROTECTED += $InputObject}
        $GLOBAL:PROTECTED = Select-Object -InputObject $GLOBAL:PROTECTED -Unique
    }

    Function Format-AndExportErrorData {
        [CmdletBinding()]

        Param ([Parameter(Mandatory)][Management.Automation.ErrorRecord]$Exception)

        [Hashtable]$ErrorLogIO = @{FilePath = 'Error.log.txt'; Encoding = 'UTF8'}

        [String]$Message   = $Exception.Exception.Message
        [String]$Details   = $Exception.ErrorDetails.Message
        [String]$Timestamp = Get-Date -Format 'yyyy.MM.dd AT HH:mm:ss'

        [String]$ErrorLogEntryHeader = "FATAL ERROR ON $Timestamp RUNNING VERSION $G__ScriptVersion :"
        [String]$ErrorLogEntryFooter = (('-' * 100), '', (Get-Content Error.log.txt -Encoding UTF8 -Raw -ErrorAction SilentlyContinue)) -Join "`n"

        $ErrorLogEntryHeader                 | Out-File @ErrorLogIO -Force
        $Exception.PSObject.Properties.Value | Out-File @ErrorLogIO -Append
        $ErrorLogEntryFooter                 | Out-File @ErrorLogIO -Append

        Return ($Details, $Message)[$Message.Length -gt $Details.Length]
    }

    Function Measure-TransferRate {
        [CmdletBinding()]

        Param (
            [Parameter(Mandatory, Position = 0)][Double]$Duration,
            [Parameter(Mandatory, Position = 1)][UInt32]$Bytes,
            [ValidateSet('B/s', 'kB/s', 'MB/s', 'GB/s')][String]$Unit
        )

        [Double]$BytesPerSecond = $Bytes / $Duration

        If ($Unit) {
            [String]$UnitSymbol    = $Unit.ToLower().Replace('b', 'B').Replace('m', 'M').Replace('g', 'G')
            [Double]$ConvertedRate = Switch ($UnitSymbol) {
                {$_ -eq 'B/s'}  {$BytesPerSecond}
                {$_ -eq 'kB/s'} {$BytesPerSecond / 1kB}
                {$_ -eq 'MB/s'} {$BytesPerSecond / 1MB}
                {$_ -eq 'GB/s'} {$BytesPerSecond / 1GB}
            }
        }
        Else {[Double]$ConvertedRate, [String]$UnitSymbol = ((($BytesPerSecond / 1MB), 'MB/s'), (($BytesPerSecond / 1kB), 'kB/s'))[$BytesPerSecond -lt 1MB]}

        Return [String](([Math]::Round($ConvertedRate, 2), [Math]::Round($ConvertedRate))[$UnitSymbol -eq 'B/s']) + " $UnitSymbol"
    }

    Function Get-ModRepoFile {
        [CmdletBinding(DefaultParameterSetName = 'NoIWR')]

        Param (
            [Parameter(Mandatory, Position = 0)][String]$File,
            [Parameter(ParameterSetName = 'NoIWR', Position = 1)][Byte]$X,
            [Parameter(ParameterSetName = 'NoIWR', Position = 2)][String]$State,
            [Parameter(Mandatory, ParameterSetName = 'IWR')][Switch]$UseIWR,
            [Parameter(ParameterSetName = 'IWR')][Switch]$Save
        )

        [Uri]$Uri = "$G__RepositoryURL/$File"

        If ($PSCmdlet.ParameterSetName -eq 'IWR') {
            [Hashtable]$IWRSplat = @{Uri = $Uri}
            If ($PSVersionTable.PSVersion.Major -lt 6) {$IWRSplat['UseBasicParsing'] = $True}
            If ($Save.IsPresent)                       {$IWRSplat['OutFile']         = $File}
            Return Invoke-WebRequest @IWRSplat
        }

        [Net.HttpWebRequest]$HeaderRequest   = [Net.WebRequest]::CreateHttp($Uri)
        $HeaderRequest.Method                = 'HEAD'
        $HeaderRequest.KeepAlive             = $False
        $HeaderRequest.Timeout               = 15000

        [Net.HttpWebRequest]$DownloadRequest = [Net.WebRequest]::CreateHttp($Uri)
        $DownloadRequest.Timeout             = 15000
        $DownloadRequest.Proxy               = [Net.GlobalProxySelection]::GetEmptyWebProxy()

        [Net.HttpWebResponse]$Header = $HeaderRequest.GetResponse()
        [UInt64]$DownloadSize        = $Header.ContentLength; $Header.Dispose()
        [UInt32]$BufferSize          = [Math]::Pow(2, [Math]::Floor([Math]::Log([Math]::Min($DownloadSize, [GC]::GetTotalMemory($False) / 10), 2)))
        [Byte[]]$Buffer              = New-Object Byte[] $BufferSize
        
        [DateTime]$IntervalStart       = (Get-Date).AddSeconds(-1)
        [Net.HttpWebResponse]$Download = $DownloadRequest.GetResponse()
        [IO.Stream]$DownloadStream     = $Download.GetResponseStream()
        [IO.FileStream]$FileStream     = New-Object IO.FileStream $File, Create
        
        [UInt32]$BytesRead       = $DownloadStream.Read($Buffer, 0, $Buffer.Length)
        [UInt64]$BytesDownloaded = $BytesRead

        [UInt32]$Unit, [String]$Symbol, [Byte]$Decimals = Switch ($DownloadSize) {
            {$_ -lt 1000kB} {1kB, 'kB', 0; Break}
            {$_ -lt 1000MB} {1MB, 'MB', 0; Break}
            {$_ -ge 1000MB} {1GB, 'GB', 2; Break}
        }
        [String]$ConvertedDownload = "$([Math]::Round($DownloadSize / $Unit, $Decimals)) $Symbol"

        [UInt32]$IntervalBytes, [Double]$ConvertedBytes, [Double]$IntervalLength, [String]$TransferRate = 0, 0, 0, '0 kB/s'

        While ($BytesRead -gt 0) {
            $FileStream.Write($Buffer, 0, $BytesRead)
            $BytesRead        = $DownloadStream.Read($Buffer, 0, $Buffer.Length)
            $BytesDownloaded += $BytesRead
            $ConvertedBytes   = [Math]::Round($BytesDownloaded / $Unit, $Decimals)
            $IntervalLength   = (New-TimeSpan $IntervalStart (Get-Date)).TotalSeconds

            If ($IntervalLength -ge 1) {
                $TransferRate  = Measure-TransferRate $IntervalLength ($BytesDownloaded - $IntervalBytes)
                $IntervalBytes = $BytesDownloaded
                $IntervalStart = Get-Date
            }

            Write-HostX $X -Color Green ("$State " + ("$ConvertedBytes".PadLeft(5)) + "/$ConvertedDownload ($TransferRate)")
        }

        $Download.Dispose()
        $FileStream.Flush()
        $FileStream.Close()
        $FileStream.Dispose()
        $DownloadStream.Dispose()

        Return "$ConvertedDownload", $BytesDownloaded
    }

    Function Test-PSHostCompatibility {Return $Host.UI.SupportsVirtualTerminal}

    Function Test-ModActive {
        [CmdletBinding()]

        Param ([Parameter(Mandatory)][String]$Mod)

        If (![IO.File]::Exists($G__GameLogPath) -Or $G__GameProcess -NotIn (Get-Process).Name) {Return $False}

        [Regex]$MountedPattern   = ' \: \[mod_package_manager\] Mod ".+" has been mounted\. \(package_name\: ' + $Mod + ','
        [Regex]$UnmountedPattern = " \: \[(zip|hash)fs\] $Mod\.(scs|zip)\: Unmounted\.?"

        ForEach ($Line in Get-Content $G__GameLogPath -Encoding UTF8) {
            If ($Line -Match $MountedPattern)   {[Bool]$IsLoaded = $True}
            If ($Line -Match $UnmountedPattern) {[Bool]$IsLoaded = $False}
        }

        Return $IsLoaded
    }

    Function Test-FileHash {
        [CmdletBinding()]

        Param (
            [Parameter(Position = 0)][AllowNull()][String]$File,
            [Parameter(Mandatory, Position = 1)][String]$Hash
        )

        If (![IO.File]::Exists($File)) {Return $False}
        Return (Get-FileHash $File -Algorithm SHA1).Hash -eq $Hash
    }

    Function Test-ArrayNullOrEmpty {
        [CmdletBinding()]

        Param ([AllowEmptyCollection()][Object[]]$Array)

        If ($Null -eq $Array) {Return $True}

        Return ([Math]::Max($Array.IndexOf(''), $Array.IndexOf($Null)) -ne -1)
    }
    
    Function Wait-WriteAndExit {
        [CmdletBinding()]

        Param ([String]$InputObject, [Switch]$Restart)

        Write-Host -ForegroundColor Red $InputObject
        Unprotect-Variables
        Wait-KeyPress
        If ($Restart.IsPresent) {
            $GLOBAL:G__ScriptRestart = $True
            [Void]$GLOBAL:G__ScriptRestart
            Return 'Restart'
        }
        Exit
    }

    Function Wait-KeyPress {
        [CmdletBinding(DefaultParameterSetName = 'NoPrompt')]

        Param (
            [Parameter(ParameterSetName = 'Prompt', Mandatory, Position = 0)][String]$Prompt,
            [Parameter(ParameterSetName = 'Prompt')][ConsoleColor]$ForegroundColor,
            [Parameter(ParameterSetName = 'Prompt')][ConsoleColor]$BackgroundColor,
            [Parameter(ParameterSetName = 'Prompt')][Switch]$NoNewline,
            [Parameter(ParameterSetName = 'Prompt')][Switch]$Clear
        )

        If ($PSCmdlet.ParameterSetName -eq 'Prompt') {
            [Hashtable]$PromptSplat = @{
                Object    = $Prompt
                NoNewline = ($NoNewline.IsPresent, $True)[$Clear.IsPresent]
            }
            If ($ForegroundColor) {$PromptSplat['ForegroundColor'] = $ForegroundColor}
            If ($BackgroundColor) {$PromptSplat['BackgroundColor'] = $BackgroundColor}
            Write-Host @PromptSplat
        }
        If ($G__HostCompatible) {
            [Void]$Host.UI.RawUI.ReadKey('NoEcho, IncludeKeyDown')
            If ($Clear.IsPresent) {
                [Console]::SetCursorPosition(0, $Host.UI.RawUI.CursorPosition.Y)
                Write-Host -NoNewline (' ' * $Prompt.Length)
                [Console]::SetCursorPosition(0, $Host.UI.RawUI.CursorPosition.Y)
            }
        }
        Else {[Void](Read-HostX)}
    }

    Function Read-KeyPress {
        [CmdletBinding()]

        Param (
            [Parameter(Position = 0)][String]$Prompt,
            [ConsoleColor]$ForegroundColor,
            [ConsoleColor]$BackgroundColor,
            [Switch]$NoNewline, [Switch]$Clear
        )

        If ($Prompt) {
            [Hashtable]$PromptSplat = @{
                Object    = $Prompt
                NoNewline = ($NoNewline.IsPresent, $True)[$Clear.IsPresent]
            }
            If ($ForegroundColor) {$PromptSplat['ForegroundColor'] = $ForegroundColor}
            If ($BackgroundColor) {$PromptSplat['BackgroundColor'] = $BackgroundColor}
            Write-Host @PromptSplat
        }
        If ($G__HostCompatible) {
            [String]$KeyPress = $Host.UI.RawUI.ReadKey('NoEcho, IncludeKeyDown').VirtualKeyCode
            If ($Clear) {
                [Console]::SetCursorPosition(0, $Host.UI.RawUI.CursorPosition.Y)
                Write-Host -NoNewline (' ' * $Prompt.Length)
                [Console]::SetCursorPosition(0, $Host.UI.RawUI.CursorPosition.Y)
            }
        }
        Else {[String]$KeyPress = Read-HostX}
        Return $KeyPress
    }

    Function Set-ForegroundWindow {
        [CmdletBinding(DefaultParameterSetName = 'Self')]

        Param (
            [Parameter(Mandatory, ParameterSetName = 'Self')][Switch]$Self,
            [Parameter(Mandatory, ParameterSetName = 'Name')][String]$Name,
            [Parameter(Mandatory, ParameterSetName = 'PID')][UInt32]$ID
        )

        [__ComObject]$WShell = New-Object -COM WScript.Shell
        [UInt32]$TargetPID   = Switch ($PSCmdlet.ParameterSetName) {
            'Self'  {$PID}
            'Name'  {(Get-Process $Name)[0].Id}
            'PID'   {$ID}
        }
        [Void]$WShell.AppActivate($TargetPID)
    }

    Function Convert-ModSourceName {
        [CmdletBinding(DefaultParameterSetName = 'Default')]

        Param (
            [String]$Name,
            [Parameter(Mandatory, ParameterSetName = 'AsPath')][Switch]$AsPath,
            [Parameter(Mandatory, ParameterSetName = 'ModType')][Switch]$ModType
        )

        [String]$Type, [String]$Hex = $Name -Split '\.', 2

        If ($ModType.IsPresent)                 {Return $Type}
        If ([String]::IsNullOrWhiteSpace($Hex)) {Return ($Name, "$G__GameModDirectory\$Name.scs")[$AsPath.IsPresent]}

        Return (($Name, [String][UInt32]"0x$Hex")[$Type -eq 'mod_workshop_package'], ("$G__GameModDirectory\$Name.scs", ("$G__WorkshopDirectory\" + [String][UInt32]"0x$Hex"))[$Type -eq 'mod_workshop_package'])[$AsPath.IsPresent]
    }

    Function Convert-ProfileFolderName {
        [CmdletBinding()]

        Param ([String]$Directory = $G__ActiveProfile)

        [Char[]]$Converted = For ([UInt16]$Index = 0; $Index -lt $Directory.Length; $Index += 2) {[Char][Byte]"0x$($Directory.Substring($Index, 2))"}

        Return $Converted -Join ''
    }

    Function ConvertTo-PlainTextProfileUnit {
        [CmdletBinding()]

        Param ([String]$File = $G__ProfileUnit)

        [String]$UnitDecoder   = Get-GameUnitDecoder
        [Object]$DecoderResult = Invoke-Expression "& '$UnitDecoder' --on_file -i '$G__ProfileUnit'"

        Switch ($LASTEXITCODE) {
            0       {Break}
            1       {Break}
            Default {Throw $DecoderResult}
        }
    }

    Function Test-WorkshopModInstalled {
        [CmdletBinding()]

        Param ([Parameter(Mandatory)][String]$ModFolder)

        Return [IO.Directory]::Exists((Convert-ModSourceName -Name $ModFolder -AsPath))
    }

    Function Get-GameDirectory {
        [CmdletBinding()]

        Param ([Parameter(Mandatory)][ValidateSet('Root', 'Workshop')][String]$Directory)

        [Regex]$PathSearchPattern  = '(?i)(?<="path"\s+")[a-z]\:(?:\\\\.+)+(?=")'
        [Regex]$AppIDSearchPattern = '(?<=")' + $G__GameAppID + '(?="\s+"\d+")'
        [Regex]$InstallDirPattern  = '(?<="installdir"\s+")[^"]+(?=")'

        [String]$RegKey        = 'HKLM:\SOFTWARE' + ('\', '\WOW6432Node\')[[Environment]::Is64BitOperatingSystem] + 'Valve\Steam'
        [String]$SteamRoot     = Get-ItemPropertyValue $RegKey InstallPath
        [String[]]$LibraryData = Get-Content "$SteamRoot\SteamApps\libraryfolders.vdf" -Encoding UTF8

        [String]$SteamApps = ForEach ($Line in $LibraryData) {
            If ($Line -Match $PathSearchPattern)  {[String]$Path = $Matches[0] -Replace '\\\\', '\'; Continue}
            If ($Line -Match $AppIDSearchPattern) {"$Path\SteamApps"; Break}
        }

        # If $Directory is 'Workshop', return the workshop directory
        If ($Directory -eq 'Workshop') {Return "$SteamApps\workshop\content\$G__GameAppID"}

        # Otherwise since the only other valid value is "Root" we return the game's root/install directory
        [String[]]$AppCacheData = Get-Content "$SteamApps\appmanifest_$G__GameAppID.acf" -Encoding UTF8
        [String]$RootDir        = ForEach ($Line in $AppCacheData) {If ($Line -Match $InstallDirPattern) {[IO.Path]::Combine("$SteamApps\common", $Matches[0]); Break}}

        Return $RootDir
    }

    Function Get-ProfileUnitFormat {
        [CmdletBinding()]

        Param ([String]$Target = $G__ProfileUnit)

        [Byte[]]$UnitData = [IO.File]::ReadAllBytes($Target)

        Return ('Text', 'Binary')[0 -In $UnitData]
    }

    Function Get-GameUnitDecoder {
        [CmdletBinding()]

        [String]$Path     = "$Env:TEMP\sii_decrypt.exe"
        [String]$Checksum = (Get-ModRepoFile sii_decrypt.txt -UseIWR).Content

        If (![IO.File]::Exists($Path))        {[IO.File]::WriteAllBytes($Path, [Byte[]](Get-ModRepoFile sii_decrypt.exe -UseIWR).Content)}
        If (!(Test-FileHash $Path $Checksum)) {Throw 'Unable to verify sii_decrypt.exe - Checksum mismatch'}

        Return $Path
    }

    Function Get-ModData {
        [CmdletBinding()]

        Param ([String[]]$RawData)

        If (!$RawData) {Return @{}}

        [Hashtable]$ParsedData = @{}
        [String[]]$Data        = ($RawData, ($RawData[0] -Split "`n"))[$RawData.Count -eq 1 -And [Char[]]$RawData[0] -Contains "`n"]

        ForEach ($Entry in $Data) {
            If ($Entry -Match '^ active_mods: \d+$') {Continue}

            [String]$Priority               = Switch (($Entry -Split '\[|\]', 3)[1]) {{$_ -As [UInt16] -eq $_} {$_} Default {Continue}}
            [String]$Source, [String]$Name  = Switch ((($Entry -Split '\[\d+\]: ', 2)[-1] -Split '\|', 2).Trim('"')) {{$_ -As [String[]] -eq $_} {$_}}

            $ParsedData["active_$Priority"] = [Hashtable]@{
                Name       = $Name
                Type       = Convert-ModSourceName -Name $Source -ModType
                Source     = $Source
                SourcePath = Convert-ModSourceName -Name $Source -AsPath
                SourceName = Convert-ModSourceName -Name $Source
            }
        }

        Return $ParsedData
    }

    Function Read-PlainTextProfileUnit {
        [CmdletBinding()]

        Param ([ValidateSet('Mods', 'Data', 'All')][String]$Return = 'All', [Switch]$Raw)

        [Bool]$Parse        = $False
        [String[]]$UnitMods = @()
        [String[]]$UnitData = @()
    
        ForEach ($Line in Get-Content $G__ProfileUnit -Encoding UTF8) {
            If ($Parse -And $Line -Match '^ customization: \d+$') {
                $Parse     = $False
                $UnitData += '<MODLIST_INSERTION_POINT>'
            }
            ElseIf ($Line -Match '^ active_mods: \d+$') {$Parse = $True}

            If ($Parse) {$UnitMods += $Line}
            Else        {$UnitData += $Line}
        }
        If ($Raw.IsPresent) {
            [String]$UnitMods = $UnitMods -Join "`n"
            [String]$UnitData = $UnitData -Join "`n"
        }

        Return (($UnitMods, $UnitData), $UnitMods, $UnitData)[('All', 'Mods', 'Data').IndexOf($Return)]        
    }

    Function Enable-OnlineModList {
        [CmdletBinding()]

        Param ([String]$ProfileUnit = $G__ProfileUnit)

        If ($G__GameProcess -In (Get-Process).Name) {
            Write-Host -ForegroundColor Yellow "$G__GameName must be closed in order to apply profile configuration."
            Return
        }

        Write-Host -NoNewline (''.PadRight(4) + 'Downloading configuration...'.PadRight(35))
        [String]$ActiveMods      = (Get-ModRepoFile _active.txt -UseIWR).Content
        [UInt16]$ActiveModsCount = (($ActiveMods -Split "`n", 2)[0] -Split ':', 2)[-1].Trim()
        Write-Host -ForegroundColor Green "OK - $ActiveModsCount active mods"

        Write-Host -NoNewline (''.PadRight(4) + 'Creating profile backup...'.PadRight(35))
        [String]$Backup = Backup-ProfileUnit
        Write-Host -ForegroundColor Green ('OK - ' + ([IO.Path]::GetFileName($Backup)))

        If ((Get-ProfileUnitFormat) -ne 'Text') {
            Write-Host -NoNewline (''.PadRight(4) + 'Decoding profile...'.PadRight(35))
            ConvertTo-PlainTextProfileUnit
            Write-Host -ForegroundColor Green 'OK'
        }
        
        Write-Host -NoNewline (''.PadRight(4) + 'Applying configuration...'.PadRight(35))

        [String[]]$ProfileMods, [String[]]$ProfileData = Read-PlainTextProfileUnit All

        [String]$RawProfileMods   = $ProfileMods -Join "`n"
        [UInt16]$ProfileModsCount = ($ProfileMods[0] -Split ':', 2)[-1].Trim()
        [Hashtable]$NewConfig     = Get-ModData $ActiveMods

        If ($RawProfileMods -cne $ActiveMods) {
            $ProfileData -Join "`n" -Replace '<MODLIST_INSERTION_POINT>', $ActiveMods | Set-Content $ProfileUnit @G__SCGlobal
            Write-Host -ForegroundColor Green "OK - $ProfileModsCount > $ActiveModsCount"
        }
        Else {Write-Host -ForegroundColor Green 'Already applied'}

        [String[]]$MissingWorkshopMods = Foreach ($Key in $NewConfig.Keys | Where-Object {$NewConfig[$_].Type -eq 'mod_workshop_package'}) {
            [Hashtable]$Current = $NewConfig[$Key]
            If (!(Test-WorkshopModInstalled $Current.Source)) {
                Write-Host -ForegroundColor Yellow (''.PadRight(4) + "MISSING WORKSHOP SUBSCRIPTION: " + $Current.Name)
                $Current.SourceName
            }
        }

        If ($MissingWorkshopMods) {
            Do {[Int]$UserInput = Read-KeyPress 'Open workshop item page in Steam? [Y/N]' -Clear} Until ($UserInput -Match '^(89|78)$')
            Switch ($UserInput) {
                89 {ForEach ($Mod in $MissingWorkshopMods) {Start-SteamWorkshopPage $Mod; Wait-KeyPress 'Press any key to continue...' -Clear}}
                78 {Break}
            }
        }
    }

    Function Backup-ProfileUnit {
        [CmdletBinding()]

        [String]$Name       = ('profile_' + (Get-Date -Format yy-MM-dd_HHmmss))
        [String]$BackupFile = "$G__ProfilePath\$Name.bak"

        Copy-Item $G__ProfileUnit $BackupFile

        Return $BackupFile
    }

    Function Select-Profile {
        [CmdletBinding()]

        Param ([Switch]$AllowEsc)

        [String[]]$AllProfiles = (Get-ChildItem "$G__GameRootDirectory\profiles" -Directory).Name | Sort-Object Length

        Clear-Host
        Write-Host ' SELECT PROFILE'
        Write-Host ('-' * $Host.UI.RawUI.BufferSize.Width)

        If (!$AllProfiles) {Throw "No profiles detected! Disable 'Use Steam Cloud' for the profile(s) you want to use."}

        If ($AllProfiles.Count -eq 1) {
            Set-ActiveProfile $AllProfiles[0]

            Write-Host -ForegroundColor Green ("$G__GameNameShort Profile '" + (Convert-ProfileFolderName $AllProfiles[0]) + "' was automatically selected as the active profile.")
            Start-Sleep 2

            Return $AllProfiles[0]
        }

        [UInt16]$LongestDir                               = $AllProfiles[-1].Length + 3
        [Byte]$Selected                                   = (0, $AllProfiles.IndexOf($G__ActiveProfile))[$G__ActiveProfile -In $AllProfiles]
        [String]$PreviousProfile                          = $G__ActiveProfile
        [Management.Automation.Host.Coordinates]$StartPos = $Host.UI.RawUI.CursorPosition

        Do {
            If ($G__HostCompatible) {[Console]::SetCursorPosition($StartPos.X, $StartPos.Y)}

            [Byte]$Iteration = 0

            ForEach ($Directory in $AllProfiles) {

                [String]$Name      = Convert-ProfileFolderName $Directory
                [Bool]$IsSelected  = $Iteration -eq $Selected

                Write-Host -NoNewline ' '
                Write-HostX 0 -Color ("DarkGray", "Green")[$IsSelected] (' ' + ('   ', '>> ')[$IsSelected] + $Directory.PadRight($LongestDir) + "$Name ") -Newline
                $Iteration++
            }
            Write-Host -NoNewline "`n * Use the "
            Write-Host -NoNewline -ForegroundColor Cyan "[UP]"
            Write-Host -NoNewline ' and '
            Write-Host -NoNewline -ForegroundColor Cyan '[DOWN]'
            Write-Host -NoNewline " keys to select an $G__GameNameShort profile.`n   Press "
            Write-Host -NoNewline -ForegroundColor Cyan '[ENTER]'
            Write-Host -NoNewline ' to confirm your selection'
            If ($AllowEsc.IsPresent) {
                Write-Host -NoNewline ', or '
                Write-Host -NoNewline -ForegroundColor Cyan '[ESC]'
                Write-Host ' to cancel.'
            }
            Else {Write-Host '.'}

            Do {
                [Bool]$UpdateSelection = $False
                Switch (Read-KeyPress -Clear) {
                    13 { # [ENTER]
                        Clear-Host
                        If ($AllProfiles[$Selected] -ne $PreviousProfile) {
                            Set-ActiveProfile $AllProfiles[$Selected]
                            Return $AllProfiles[$Selected]
                        }
                        Return
                    }
                    27 { # [ESC]
                        If (!$AllowEsc.IsPresent) {Continue}
                        Clear-Host
                        Return
                    }
                    38 { # [UP]
                        If ($Selected -gt 0) {$Selected--} Else {[Console]::Beep(1000, 150)}
                        $UpdateSelection = $True
                        Break
                    }
                    40 { # [DOWN]
                        If ($Selected -lt $AllProfiles.Count - 1) {$Selected++} Else {[Console]::Beep(1000, 150)}
                        $UpdateSelection = $True
                        Break
                    }
                    Default {Continue}
                }
            } Until ($UpdateSelection)
        } While ($True)
    }

    Function Get-ActiveProfile {
        [CmdletBinding()]

        [String]$StoredProfile = Read-EmbeddedValue $G__DataIndices.ActiveProfile

        If ($StoredProfile -eq '***GAME_PROFILE_PLACEHOLDER***' -Or [String]::IsNullOrWhiteSpace($StoredProfile) -Or ![IO.Directory]::Exists("$G__GameRootDirectory\profiles\$StoredProfile")) {$StoredProfile = Select-Profile}
        
        Return $StoredProfile
    }

    Function Set-ActiveProfile {
        [CmdletBinding()]

        Param ([Parameter(Mandatory)][String]$Directory)

        If ($Directory -ne $G__ActiveProfile) {
            
            Write-EmbeddedValue $G__DataIndices.ActiveProfile $Directory

            $GLOBAL:G__ScriptRestart = $True
            [Void]$GLOBAL:G__ScriptRestart
        }
    }

    Function Start-DefaultWebBrowser { # This function is deprecated and will be removed in a future version
        [CmdletBinding()]

        Param ([Parameter(Mandatory)][String]$Uri)

        [String]$BrowserName = (Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice).ProgId

        If ($BrowserName -eq 'AppXq0fevzme2pys62n3e0fbqa7peapykr8v') {Start-Process Microsoft-Edge:$Uri}
        Else {
            [Void](New-PSDrive HKCR Registry HKEY_CLASSES_ROOT -Scope GLOBAL -ErrorAction SilentlyContinue)
            [String]$BrowserPath = [Regex]::Match((Get-ItemProperty HKCR:\$BrowserName\shell\open\command).'(default)', '\".+?\"')
            Start-Process $BrowserPath $Uri
        }
    }

    Function Start-SteamWorkshopPage {
        [CmdletBinding()]

        Param ([Parameter(Mandatory)][String]$FileID)

        Start-Process "steam://url/CommunityFilePage/$FileID"
    }

    Function Show-LandingScreen {
        [CmdletBinding()]

        Param ([String]$Action)

        Write-Host ('-' * $Host.UI.RawUI.BufferSize.Width)
        Write-Host "`n    $($G__ScriptDetails['Title'])`n"
        Write-Host "    $($G__ScriptDetails['Version']), Updated $($G__ScriptDetails['VersionDate'])"
        Write-Host "    $($G__ScriptDetails['Copyright']) - $($G__ScriptDetails['Author'])`n"
        Write-Host "`n    $Action"
        Start-Sleep 2
    }

    Function Show-Menu {
        [CmdletBinding()]

        Param ([Switch]$Saved)

        Write-Host "`n    $($G__ScriptDetails['Title'])`n"
        Write-Host ('-' * $Host.UI.RawUI.BufferSize.Width)
        Write-Host -NoNewline "`n      Active profile: "
        Write-Host -ForegroundColor Green $G__ActiveProfileName
        Write-Host "`n"
        Write-HostFancy '      [0]      Change profile'
        Write-HostFancy "      [1]      Launch $G__GameName upon completion"
        Write-HostFancy '      [2]      Delete inactive mods (Frees up space)'
        Write-HostFancy '      [3]      Verify game file integrity (Force Workshop mod updates)'
        Write-HostFancy '      [4]      Skip profile configuration'
        Write-HostFancy ''
        Write-HostFancy "      [5]      Save current choices $(('', '[SAVED]')[$Saved.IsPresent])" -ForegroundColor ([Console]::ForegroundColor, 'Green')[$Saved.IsPresent]
        Write-HostFancy ''
        Write-HostFancy '      [ESC]    Exit'
        Write-HostFancy ''
        Write-HostFancy '      [SPACE]  Profile configuration ONLY'
        Write-HostFancy "      [ENTER]  Run updater$(('', ' + verify integrity')[$G__ValidateInstall])$(('', ' + delete inactive mods')[$G__DeleteDisabled])$(('', ' + skip profile config')[$G__NoProfileConfig])$(('', " + launch $G__GameNameShort")[$G__StartGame])"
        Write-HostFancy "      $(('', 'WARNING: Deleted mods must be reaquired if reactivated in the future.')[$G__DeleteDisabled])" -ForegroundColor Yellow

        While ($True) {
            [Int]$Choice = Read-KeyPress -Clear
            # 0 - Execute
            # 1 - Exit
            # 2 - Update profile
            # 3 - Execution option (G__DeleteDisabled)
            # 4 - Restart menu
            # 5 - Execution option (Steam validation)
            # 6 - Save options
            Switch ($Choice) {
                13 {Return 'Break'} # [ENTER]
                27 {Return 'Exit'} # [ESC]
                32 {Return '$G__NoUpdate = $True; Update-ProtectedVars; Break'} # [SPACE]
                48 {If (!(Select-Profile -AllowEsc)) {Return 'Continue'} Else {Return 'Unprotect-Variables; $GLOBAL:G__ScriptRestart = $True; Return "Menu"'}} # [0]
                49 {Return '$G__StartGame = !$G__StartGame; Update-ProtectedVars; $Save = $False; Continue'}                # [1]
                50 {Return '$G__DeleteDisabled = !$G__DeleteDisabled; Update-ProtectedVars; $Save = $False; Continue'}      # [2]
                51 {Return '$G__ValidateInstall = !$G__ValidateInstall; Update-ProtectedVars; $Save = $False; Continue'}    # [3]
                52 {Return '$G__NoProfileConfig = !$G__NoProfileConfig; Update-ProtectedVars; $Save = $False; Continue'}    # [4]
                53 {Return 'Write-AllEmbeddedValues; $Save = $True; Continue'}                                              # [5]
                Default {Break} # Invalid choice
            }
            [Console]::Beep(1000, 150)
        }
    }

    Function Confirm-Choice { # This function is currently unused and is subject to removal in a future version
        [CmdletBinding()]

        Param (
            [Parameter(Mandatory, Position = 0)][String]$Prompt,
            [Parameter(Position = 1)][ConsoleColor]$ForegroundColor = [Console]::ForegroundColor
        )

        Write-Host -ForegroundColor $ForegroundColor $Prompt
        While ($True) {
            Switch (Read-KeyPress -Clear) {
                78      {Return $False} # 78 = N
                89      {Return $True}  # 89 = Y
                Default {Break}         # Invalid
            }
            [Console]::Beep(1000, 150)
        }
    }

    Function Write-HostFancy { # This function will be deprecated in a future version
        [CmdletBinding()]

        Param (
            [Parameter(Position = 0)][String[]]$String = @(''),
            [Parameter(Position = 1)][UInt16]$Speed    = 0,
            [ConsoleColor]$ForegroundColor             = [Console]::ForegroundColor,
            [ConsoleColor]$BackgroundColor             = [Console]::BackgroundColor
        )

        [String[]]$Text   = $String -Join "`n" -Split "`n"
        [Hashtable]$Splat = @{
            ForegroundColor = $ForegroundColor
            BackgroundColor = $BackgroundColor
        }
        
        ForEach ($Line in $Text) {
            Write-Host @Splat ($Line + ' ' * ($Host.UI.RawUI.BufferSize.Width - $Line.Length))
            Start-Sleep -Milliseconds ($Speed, 0)[[String]::IsNullOrWhiteSpace($Line)]
        }
    }

    Function Clear-HostFancy {
        Param (
            [Parameter(Position = 0)][UInt16]$Lines = 10,
            [Parameter(Position = 1)][UInt16]$From  = 0,
            [Parameter(Position = 2)][UInt16]$Speed = 50,
            [Switch]$NoReturn
        )

        [Hashtable]$Splat = @{
            Object          = ' ' * $Host.UI.RawUI.BufferSize.Width
            ForegroundColor = [Console]::ForegroundColor
            BackgroundColor = [Console]::BackgroundColor
        }

        [Console]::SetCursorPosition(0, $From)

        For ([UInt16]$Y = 0; $Y -lt $Lines - 1; $Y++) {
            Write-Host @Splat
            Start-Sleep -Milliseconds $Speed
        }

        If (!$NoReturn.IsPresent) {[Console]::SetCursorPosition(0, $From)}
    }

    Function Read-EmbeddedValue {
        [CmdletBinding()]
        
        Param (
            [Parameter(Mandatory)][UInt32]$Index,
            [String[]]$CustomData
        )

        [String[]]$ScriptData = If ($CustomData) {$CustomData} Else {Get-Content $G__ScriptPath -Encoding UTF8}

        [String]$Info,   [String]$RawValue = $ScriptData[$Index].Substring(0, $ScriptData[$Index].IndexOf(';')).Substring(1) -Split '=', 2
        [String]$Format, [String]$Name     = $Info -Split '_', 2

        Switch ($Format) {
            'NUM'   {[Int64]$Value  = $RawValue}
            'DEC'   {[Double]$Value = $RawValue}
            Default {[String]$Value = $RawValue}
        }

        Return $Value
    }

    Function New-EmbeddedValue {
        [CmdletBinding()]
        
        Param (
            [Parameter(Mandatory, Position = 0)][String]$SourceData,
            [Parameter(Mandatory, Position = 1)][String]$Value
        )

        $Value = Switch ($Value) {
            'True'  {'1'}
            'False' {'0'}
            Default {$_}
        }

        Return $SourceData.Substring(0, $SourceData.IndexOf('=')) + "=$Value;"
    }

    Function Write-EmbeddedValue {
        [CmdletBinding()]
        
        Param (
            [Parameter(Mandatory)][UInt32]$Index,
            [Parameter(Mandatory)][String]$Value
        )

        [String[]]$ScriptData = Get-Content $G__ScriptPath -Encoding UTF8
        $ScriptData[$Index]   = New-EmbeddedValue $ScriptData[$Index] $Value

        $ScriptData -Join "`n" | Set-Content $G__ScriptPath @G__SCGlobal
    }

    Function Write-AllEmbeddedValues {
        [CmdletBinding()]

        [String[]]$ScriptData = Get-Content $G__ScriptPath -Encoding UTF8

        ForEach ($Key in $G__DataIndices.Keys) {

            [String]$Value = Get-Variable "G__$Key" -ValueOnly
            [UInt32]$Index = $G__DataIndices.$Key

            $ScriptData[$Index] = New-EmbeddedValue $ScriptData[$Index] $Value
        }

        $ScriptData -Join "`n" | Set-Content $G__ScriptPath @G__SCGlobal
    }

    $ErrorActionPreference = [Management.Automation.ActionPreference]::Stop
    $ProgressPreference    = [Management.Automation.ActionPreference]::SilentlyContinue

    Trap {Wait-WriteAndExit ("`n`nFATAL ERROR`n" + (Format-AndExportErrorData $_))}

    Protect-Variables

    [Hashtable]$G__DataIndices = @{
        ActiveProfile   = 1
        StartGame       = 2
        ValidateInstall = 3
        DeleteDisabled  = 4
        NoProfileConfig = 5
    }
    [String]$G__RepositoryURL  = 'http://your.domain/repo'
    [String]$G__ScriptPath     = $PSCommandPath
    [UInt16]$G__WndWidth       = 120
    [UInt16]$G__WndHeight      = 50
    [Bool]$G__NoUpdate         = $False
    [Bool]$G__HostCompatible   = Test-PSHostCompatibility
    [Bool]$G__ClampAvailable   = 'Clamp' -In [String[]][Math].GetMethods().Name
    [Hashtable]$G__SCGlobal    = @{Encoding = 'UTF8'; Force = $True}

    [UInt32]$G__GameAppID         = 227300
    [String]$G__GameName          = 'Euro Truck Simulator 2'
    [String]$G__GameNameShort     = 'ETS2'
    [String]$G__GameProcess       = 'eurotrucks2'
    [String]$G__GameRootDirectory = [IO.Path]::Combine([Environment]::GetFolderPath('MyDocuments'), $G__GameName)
    [String]$G__GameLogPath       = "$G__GameRootDirectory\game.log.txt"
    [String]$G__GameModDirectory  = "$G__GameRootDirectory\mod"

    Set-Location $G__GameModDirectory
    [IO.Directory]::SetCurrentDirectory($G__GameModDirectory)

    [Version]$G__ScriptVersion = Read-EmbeddedValue 0
    [Bool]$G__DeleteDisabled   = Read-EmbeddedValue $G__DataIndices.DeleteDisabled
    [Bool]$G__ValidateInstall  = Read-EmbeddedValue $G__DataIndices.ValidateInstall
    [Bool]$G__NoProfileConfig  = Read-EmbeddedValue $G__DataIndices.NoProfileConfig
    [Bool]$G__StartGame        = Read-EmbeddedValue $G__DataIndices.StartGame

    If ($G__HostCompatible) {
        [Console]::CursorVisible = $False
        [Console]::Title         = "$G__GameNameShort External Mod Manager v$G__ScriptVersion"
        [Console]::SetWindowSize($G__WndWidth, $G__WndHeight)
    }
    Else {Wait-WriteAndExit ("Startup aborted - Incompatible console host.`nCurrent host '" + $Host.Name + "' does not support required functionality.")}

    [String]$G__SaveEditorDirectory = "$G__GameRootDirectory\TruckSaveEditor"
    [String]$G__WorkshopDirectory   = Get-GameDirectory Workshop

    [Bool]$GLOBAL:G__ScriptRestart  = ($GLOBAL:G__ScriptRestart, $False)[$Null -eq $GLOBAL:G__ScriptRestart]
    [ScriptBlock]$G__EXEC_RESTART   = {If ($GLOBAL:G__ScriptRestart -eq $True) {Unprotect-Variables; Remove-Variable G__ScriptRestart -Scope GLOBAL -ErrorAction SilentlyContinue; Return ''}}
    
    If (![IO.Directory]::Exists($G__GameModDirectory)) {Wait-WriteAndExit "Startup aborted - Cannot locate the $G__GameNameShort mod directory '$G__GameModDirectory'.`nVerify that $G__GameName is correctly installed and try again."}
    If ($PSScriptRoot -ne $G__GameModDirectory)        {Wait-WriteAndExit "Startup aborted - Invalid script location.`n'$G__ScriptPath' must be placed in '$G__GameModDirectory' to run."}

    [String]$G__ActiveProfile     = Get-ActiveProfile
    [String]$G__ProfilePath       = "$G__GameRootDirectory\profiles\$G__ActiveProfile"
    [String]$G__ProfileUnit       = "$G__ProfilePath\profile.sii"
    [String]$G__ActiveProfileName = Convert-ProfileFolderName

    [Hashtable]$G__ScriptDetails = @{
        Author      = 'RainBawZ'
        Copyright   = [Char]0x00A9 + (Get-Date -Format yyyy)
        Title       = "$G__GameName External Mod Manager"
        Version     = "Version $G__ScriptVersion"
        VersionDate = '2024.2.20'
        GitHub      = 'https://github.com/RainBawZ/ETS2ExternalModManager/'
        Contact     = 'Discord - @realtam'
    }

    [String[]]$G__UpdateNotes = @(
        '3.4.1:',
        '- Improved visual feedback when saving settings',
        ' ',
        '3.4.0:',
        '- Added ability to save and auto-apply updater settings in future runs',
        '- Fixed issues with overlapping text in the menu interface',
        '- Fixed issue with locating Steam Workshop directory on 32-bit systems',
        '- Improved mod usage detection',
        '- Improved menu interface appearance'
    )
    [String[]]$G__KnownIssues = @()

    Update-ProtectedVars

    . $G__EXEC_RESTART

    If (!$Updated) {

        [Byte]$Padding = 15

        Clear-Host
        Write-Host " Checking Mod Manager version...`n"
        Write-Host (' ' + 'Installed'.PadRight($Padding) + 'Current'.PadRight($Padding) + 'Status')
        Write-Host ('-' * $Host.UI.RawUI.BufferSize.Width)
        Write-Host -NoNewline (' ' + "$G__ScriptVersion".PadRight($Padding))

        Try {
            [Byte[]]$UpdateBytes     = (Get-ModRepoFile Update.ps1 -UseIWR).Content
            [String[]]$UpdateContent = [Text.Encoding]::UTF8.GetString($UpdateBytes) -Split "`n"

            ForEach ($Key in $G__DataIndices.Keys) {
                [String]$Value = Get-Variable "G__$Key" -ValueOnly
                [UInt32]$Index = $G__DataIndices.$Key

                $UpdateContent[$Index] = New-EmbeddedValue $UpdateContent[$Index] $Value
            }

            [String]$UpdateVersion = Switch (Read-EmbeddedValue 0 -CustomData $UpdateContent) {Default {('0.0', $_)[[Bool]($_ -As [Version])]}}

            If ([Version]$UpdateVersion -gt $G__ScriptVersion) {
                [ConsoleColor]$VersionColor, [String]$VersionText, [String]$ReturnValue = (("Green", $UpdateVersion, 'Updated'), ("Red", 'Parsing error', 'Repaired'))[$UpdateVersion -eq '0.0']

                Write-Host -NoNewline -ForegroundColor $VersionColor $VersionText.PadRight($Padding)

                $UpdateContent -Join "`n" | Set-Content $G__ScriptPath @G__SCGlobal

                Unprotect-Variables

                Return $ReturnValue
            }
            Else {
                Write-Host -NoNewline $UpdateVersion.PadRight($Padding)
                Write-Host -ForegroundColor Green 'Up to date'
            }

            Write-Host "`n"
        }
        Catch {Write-Host -ForegroundColor Red (Format-AndExportErrorData $_)}
    }
    Else {
        Write-Host -ForegroundColor Green $Updated
        Write-Host ("`n What's new:`n   " + ($G__UpdateNotes -Join "`n   ") + "`n")
        If ($G__KnownIssues) {Write-Host ("`n Known issues:`n   " + ($G__KnownIssues -Join "`n   ") + "`n")}
        Wait-KeyPress ' Press any key to continue.' -Clear
        Clear-Host
    }

    Remove-UnprotectedVars

    Show-LandingScreen
    [Bool]$Save = $False
    While ($True) {
        Clear-HostFancy 19 0 0
        If ((Invoke-Expression (Show-Menu -Saved:$Save)) -eq 'Menu') {Return ''}
    }

    Clear-Host
    Write-Host "`n    $($G__ScriptDetails['Title'])`n"
    Write-Host ('-' * $Host.UI.RawUI.BufferSize.Width)

    If ($G__NoUpdate) {
        Write-Host "`n Configuring profile..."

        Enable-OnlineModList

        Write-Host "`n Done`n"

        Wait-KeyPress
        Unprotect-Variables
        Return
    }
    If ($G__ValidateInstall) {
        Start-Process "steam://validate/$G__GameAppID"
        Write-Host 'Started game file validation.'
        Start-Sleep 1
        Set-ForegroundWindow -Self
    }

    [Byte]$Failures             = 0
    [Byte]$Invalids             = 0
    [Byte]$Successes            = 0
    [Byte]$LongestName          = 3
    [Byte]$L_LongestVersion     = 9
    [Byte]$E_LongestVersion     = 7
    [Int64]$DownloadedData      = 0
    [UInt64]$TotalBytes         = 0
    [String[]]$NewVersions      = @()
    [String[]]$PreviousProgress = @()
    [Hashtable]$LocalMods       = @{}

    Update-ProtectedVars

    Add-Type -Assembly System.IO.Compression.FileSystem

    If ([IO.File]::Exists('versions.txt')) {
        [UInt64]$Line = 0

        ForEach ($RawData in Get-Content versions.txt -Encoding UTF8) {
            $Line++

            [String]$Name, [Version]$Ver = ($RawData -Split '=', 3)[0..1]
            If (Test-ArrayNullOrEmpty ($Name, $Ver)) {
                Try     {Throw "versions.txt[$Line]: Invalid data"}
                Catch   {[Void](Format-AndExportErrorData $_)}
                Continue
            }

            $LocalMods[$Name] = [Hashtable]@{
                FileName   = "$Name.scs"
                Version    = $Ver
                VersionStr = [String]$Ver
            }

            If ($Name.Length -gt $LongestName)       {$LongestName      = $Name.Length}
            If ("$Ver".Length -gt $L_LongestVersion) {$L_LongestVersion = "$Ver".Length}
        }
    }

    Try   {[PSCustomObject]$OnlineData = (Get-ModRepoFile versions.json -UseIWR).Content | ConvertFrom-JSON}
    Catch {Wait-WriteAndExit ("Unable to fetch version data from repository. Try again later.`nReason: " + (Format-AndExportErrorData $_))}

    ForEach ($Mod in $OnlineData.PSObject.Properties.Value) {
        If ($Mod.Name.Length -gt $LongestName)         {$LongestName      = $Mod.Name.Length}
        If ($Mod.Version.Length -gt $E_LongestVersion) {$E_LongestVersion = $Mod.Version.Length}
    }

    If ([IO.File]::Exists('progress.tmp')) {
        $PreviousProgress = Get-Content progress.tmp -Encoding UTF8
        Remove-Item progress.tmp -Force
    }

    $L_LongestVersion += 3
    $E_LongestVersion += 3
    $LongestName      += 3

    Write-Host ("Active profile: $G__ActiveProfileName".PadLeft($Host.UI.RawUI.BufferSize.Width - 1) + "`n" + $G__ActiveProfile.PadLeft($Host.UI.RawUI.BufferSize.Width - 1))
    Write-Host (' ' + 'Mod'.PadRight($LongestName) + 'Installed'.PadRight($L_LongestVersion) + 'Current'.PadRight($E_LongestVersion) + 'Status')
    Write-Host ('-' * $Host.UI.RawUI.BufferSize.Width)

    ForEach ($CurrentMod in $OnlineData.PSObject.Properties.Value) {
        
        $CurrentMod.Version  = [Version]$CurrentMod.Version
        [String]$OldFile     = ('old_' + $CurrentMod.FileName)
        [Hashtable]$LocalMod = $LocalMods.($CurrentMod.Name)
        [Byte]$Repair        = 0 # 0: No repair   1: Entry   2: File

        Write-Host -NoNewline (' ' + $CurrentMod.Title.PadRight($LongestName))

        [Byte]$StatusEval = ([Bool]$LocalMod.Version, [IO.File]::Exists($CurrentMod.FileName) | Group-Object | Where-Object {$_.Name -eq 'True'}).Count
        [String]$Status   = Switch ($StatusEval) {
            0 {'Installing...'; Write-Host -NoNewline '---'.PadRight($L_LongestVersion)}
            1 {'Repairing...';  $Repair = (2, 1)[[Bool]$LocalMod.Version]; Write-Host -NoNewline -ForegroundColor Red ('???', $LocalMod.VersionStr)[[Bool]$LocalMod.Version].PadRight($L_LongestVersion)}
            2 {'Updating...';   Write-Host -NoNewline $LocalMod.VersionStr.PadRight($L_LongestVersion)}
        }

        [ConsoleColor]$VersionColor = ("Green", "White")[($LocalMod.Version -ge $CurrentMod.Version)]

        Write-Host -NoNewline -ForegroundColor $VersionColor $CurrentMod.VersionStr.PadRight($E_LongestVersion)
        If ($CurrentMod.Name -In $PreviousProgress) {
            Write-Host -NoNewline -ForegroundColor Green 'Up to date'
            $NewVersions += ($CurrentMod.Name, $CurrentMod.VersionStr) -Join '='
            Continue
        }

        [UInt16]$XPos = $Host.UI.RawUI.CursorPosition.X

        If ($LocalMod.Version -ge $CurrentMod.Version -Or $Repair -eq 2) {
            Write-Host -NoNewline ('Validating...', $Status)[[Bool]$Repair]

            If (!(Test-FileHash $CurrentMod.FileName $CurrentMod.Hash)) {
                If ($Repair -eq 0) {
                    Write-HostX $XPos -Color Red 'Validation failed.'
                    [String]$Status = 'Reinstalling...'
                    Start-Sleep 1
                }

                Try   {$LocalMod['Version'] = [Version]'0.0'}
                Catch {[Hashtable]$LocalMod = @{Version = [Version]'0.0'}}
            }
            Else {
                Write-HostX $XPos -Color Green ('Up to date', 'Repaired')[[Bool]$Repair] -Newline
                $NewVersions += ($CurrentMod.Name, $CurrentMod.VersionStr) -Join '='
                If ([Bool]$Repair) {$Successes++}
                Continue
            }
        }
        If ($LocalMod.Version -lt $CurrentMod.Version -Or [Bool]$Repair) {
            If ([IO.File]::Exists($CurrentMod.FileName)) {
                [UInt64]$OriginalSize = Get-ItemPropertyValue $CurrentMod.FileName Length
                Rename-Item $CurrentMod.FileName $OldFile -Force -ErrorAction SilentlyContinue
            }
            Else {[UInt64]$OriginalSize = 0}

            Try {
                If ($Status -eq 'Updating...' -And (Test-ModActive $CurrentMod.Name)) {Throw "Close $G__GameName to update this mod."}

                [String]$Result, [UInt64]$NewSize = Get-ModRepoFile $CurrentMod.FileName $XPos $Status

                If ([IO.File]::Exists($OldFile))                            {Remove-Item $OldFile -Force}
                If ($Repair -eq 0 )                                         {Write-HostX $XPos 'Validating...'}
                If (!(Test-FileHash $CurrentMod.FileName $CurrentMod.Hash)) {Throw 'Validation unsuccessful.'}

                Switch ($Status) {
                    'Updating...'     {Write-HostX $XPos -Color Green "Updated        ($Result)" -Newline}
                    'Installing...'   {Write-HostX $XPos -Color Green "Installed      ($Result)" -Newline}
                    'Reinstalling...' {Write-HostX $XPos -Color Green "Reinstalled    ($Result)" -Newline}
                    'Repairing...'    {Write-HostX $XPos -Color Green "Repaired       ($Result)" -Newline}
                }

                $CurrentMod.Name | Out-File progress.tmp -Encoding UTF8 -Append
                $NewVersions    += ($CurrentMod.Name, $CurrentMod.VersionStr) -Join '='
                $DownloadedData += $NewSize - $OriginalSize
                $Successes++
            }
            Catch {
                If ([IO.File]::Exists($CurrentMod.FileName)) {Remove-Item $CurrentMod.FileName -Force -ErrorAction SilentlyContinue}
                If ([IO.File]::Exists($OldFile))             {Rename-Item $OldFile $CurrentMod.FileName -Force -ErrorAction SilentlyContinue}
                $NewVersions += ($CurrentMod.Name, $LocalMod.VersionStr) -Join '='
                $Failures++

                Write-HostX $XPos -Color Red ('Failed: ' + (Format-AndExportErrorData $_)) -Newline
            }
        }
    }

    If (![IO.Directory]::Exists($G__SaveEditorDirectory)) {

        Write-Host -NoNewline (' ' + 'Save Editor'.PadRight($LongestName) + '---'.PadRight($L_LongestVersion))
        Write-Host -NoNewline -ForegroundColor Green '---'.PadRight($E_LongestVersion)

        [UInt16]$XPos = $Host.UI.RawUI.CursorPosition.X

        Write-Host -NoNewline -ForegroundColor Green 'Installing...'

        If ($G__HostCompatible) {[Console]::SetCursorPosition($XPos, $Host.UI.RawUI.CursorPosition.Y)}

        Try {
            [Void](Get-ModRepoFile TruckSaveEditor.zip -UseIWR -Save)

            [Void][IO.Directory]::CreateDirectory($G__SaveEditorDirectory)
            [System.IO.Compression.ZipFile]::ExtractToDirectory('TruckSaveEditor.zip', $G__SaveEditorDirectory)

            If ([IO.File]::Exists('TruckSaveEditor.zip')) {Remove-Item TruckSaveEditor.zip -Force}

            Write-Host -ForegroundColor Green 'Installed          '
        }
        Catch {
            If ([IO.File]::Exists('TruckSaveEditor.zip'))        {Remove-Item TruckSaveEditor.zip -Force}
            If ([IO.Directory]::Exists($G__SaveEditorDirectory)) {Remove-Item $G__SaveEditorDirectory -Recurse -Force}
            $Failures++

            Write-Host -ForegroundColor Red 'Failed              '
        }
    }

    $NewVersions -Join "`n" | Set-Content versions.txt @G__SCGlobal
    Remove-Item progress.tmp -Force -ErrorAction SilentlyContinue

    Write-Host ('-' * $Host.UI.RawUI.BufferSize.Width)

    If ($G__DeleteDisabled) {
        [UInt64]$PreDeletionSize  = 0
        [UInt64]$PostDeletionSize = 0
        [String[]]$InstalledFiles = (Get-ChildItem *.scs -File).Name
        [String[]]$EnabledFiles   = $OnlineData.PSObject.Properties.Value.FileName
        [String[]]$Targets        = ForEach ($File in $InstalledFiles) {If ($File -NotIn $EnabledFiles) {$File}}
        [Byte]$LongestTarget      = ($Targets | Sort-Object Length | Select-Object -Last 1).Length + 9

        ForEach ($Filesize in Get-ItemPropertyValue *.scs Length) {$PreDeletionSize += $Filesize}

        Write-Host "`nDeleting $($Targets.Count) inactive mod$(('', 's')[$Targets.Count -ne 1]):"
        ForEach ($Target in $Targets) {
            Write-Host -NoNewline "    $Target...".PadRight($LongestTarget)
            Try {
                Remove-Item $Target -Force -ErrorAction Stop
                Write-Host -ForegroundColor Green 'Deleted'
            }
            Catch {Write-Host -ForegroundColor Red 'Failed to delete'}
        }

        ForEach ($Filesize in Get-ItemPropertyValue *.scs Length) {$PostDeletionSize += $Filesize}
        
        [String]$DeletionTotal = Switch ($PreDeletionSize - $PostDeletionSize) {
            {[Math]::Abs($_) -lt 1024}   {"$_ B"; Break}
            {[Math]::Abs($_) -lt 1024kB} {"$([Math]::Round($_ / 1kB, 1)) kB"; Break}
            {[Math]::Abs($_) -lt 1024MB} {"$([Math]::Round($_ / 1MB, 1)) MB"; Break}
            {[Math]::Abs($_) -ge 1024MB} {"$([Math]::Round($_ / 1GB, 2)) GB"; Break}
        }

        Write-Host -ForegroundColor Green "Freed up $DeletionTotal of inactive mods."
    }

    If (!$G__NoProfileConfig) {
        Write-Host "`n Configuring profile..."

        Enable-OnlineModList
    }

    [String]$S_PluralMod  = 'mod' + ('s', '')[($Successes -eq 1)]
    [String]$F_PluralMod  = 'mod' + ('s', '')[($Failures -eq 1)]
    [String]$I_PluralMod  = 'mod' + ('s', '')[($Invalids -eq 1)] 

    [ConsoleColor]$ColorA = Switch ($Null) {{$Failures -eq 0} {"Green"} {$Failures -gt 0 -And $Successes -eq 0} {"Red"} {$Failures -gt 0 -And $Successes -gt 0} {"Yellow"}}
    [ConsoleColor]$ColorB = ("White", "Yellow", "Red")[[Math]::Min(2, [Math]::Ceiling($Invalids / 2))]

    [Hashtable]$TextColor = @{ForegroundColor = $ColorA}

    [String]$DownloadedStr = Switch ($DownloadedData) {
        {[Math]::Abs($_) -lt 1024}   {"$_ B"; Break}
        {[Math]::Abs($_) -lt 1024kB} {"$([Math]::Round($_ / 1kB, 1)) kB"; Break}
        {[Math]::Abs($_) -lt 1024MB} {"$([Math]::Round($_ / 1MB, 1)) MB"; Break}
        {[Math]::Abs($_) -ge 1024MB} {"$([Math]::Round($_ / 1GB, 2)) GB"; Break}
    }
    If ($DownloadedData -gt 0) {$DownloadedStr = "+$DownloadedStr"}

    ForEach ($Filesize in Get-ItemPropertyValue *.scs Length) {$TotalBytes += $Filesize}

    [String]$TotalStr = Switch ($TotalBytes) {
        {$_ -lt 1024}   {"$_ B"; Break}
        {$_ -lt 1024kB} {"$([Math]::Round($_ / 1kB, 1)) kB"; Break}
        {$_ -lt 1024MB} {"$([Math]::Round($_ / 1MB, 1)) MB"; Break}
        {$_ -ge 1024MB} {"$([Math]::Round($_ / 1GB, 2)) GB"; Break}
    }
    
    Write-Host @TextColor "`n Done`n"
    If ($Successes + $Failures -eq 0) {Write-Host @TextColor " All mods up to date - $TotalStr"}
    If ($Successes -gt 0)             {Write-Host @TextColor "   $Successes $S_PluralMod processed successfully - $TotalStr ($DownloadedStr)"}
    If ($Failures -gt 0)              {Write-Host @TextColor "   $Failures $F_PluralMod failed to process"}
    If ($Invalids -gt 0)              {Write-Host -ForegroundColor $ColorB "   $Invalids $I_PluralMod failed to validate"}
    If ($Failures + $Invalids -gt 0)  {Write-Host @TextColor "`n Exit and restart the updater to try again"}

    Wait-KeyPress "Press any key to$(('', ' launch game and')[$G__StartGame]) exit"
    If ($Successes + $Failures -eq 0 -And $G__StartGame) {Start-Process "steam://launch/$G__GameAppID/dialog"}
    Unprotect-Variables
    Return
}
If (!$Updated) {
    Switch (Sync-Ets2ModRepo) {
        {$_ -eq ''}    {& $PSCommandPath; Break}
        {$Null -ne $_} {& $PSCommandPath "$_"; Break}
    }
}
Else {[Void](Sync-Ets2ModRepo -Updated $Updated)}
