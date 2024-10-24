#STR_version=3.6.1;
#STR_profile=***GAME_PROFILE_PLACEHOLDER***;
#NUM_start=0;
#NUM_validate=0;
#NUM_purge=0;
#NUM_noconfig=0;
#STR_loadorder=Default;
#NUM_editor=0;
#STR_server=http://your.domain/repo;
#STR_offlinedata={};

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

# TODO: Add cross-platform (Windows/Linux) compatibility
# TODO: Add core mod management (dll/injector mods)
# TODO: Fix self-restart

Param ([String]$InputParam)

If (!$InputParam) {

    [DateTime]$_LoadTime  = Get-Date
    [String]$G__SessionID = (Get-FileHash -InputStream ([IO.MemoryStream]::New([Byte[]][Char[]]$_LoadTime.ToString())) -Algorithm MD5).Hash.Substring(0, 8)
    [String]$_Tab         = ' ' * 4
    [String]$Message      = '. . .  L O A D I N G  . . .'
    $Message              = ' ' * [Math]::Max(0, [Math]::Floor(($Host.UI.RawUI.WindowSize.Width - $Message.Length) / 2)) + $Message 

    Try {[Console]::CursorVisible = $False} Catch {}

    Write-Host ''
    Write-Host -NoNewline -BackgroundColor DarkBlue -ForegroundColor White ($Message + (' ' * ($Host.UI.RawUI.BufferSize.Width - $Message.Length)))

    Write-Host -NoNewline "`n`n$($_Tab * 3)Loading functions... "

    [DateTime]$_Step = Get-Date
    Remove-Variable Message
}

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

        If ($Max - $Min -lt 0)  {Throw 'Invalid range'}
        If ($G__ClampAvailable) {Return [Math]::Clamp($Value, $Min, $Max)} Else {Return ($Value, $Min, $Max)[$Value -lt $Min + ($Value -gt $Max * 2)]}
    }

    Function Write-HostX {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory, Position = 0)][ValidateScript({$_ -ge 0 -And $_ -le [Console]::BufferWidth})][UInt16]$X,
            [Parameter(Mandatory, Position = 1, ValueFromRemainingArguments)][String]$InputString,
            [ConsoleColor]$Color, [Switch]$Newline
        )

        [UInt16]$BufferWidth = [Console]::BufferWidth
        [UInt16]$InputLimit  = $BufferWidth - $X

        # Prevent screen buffer overflows (line wrapping breaks the layout)
        If ($InputString.Length -ge $InputLimit) {$InputString = ($InputString.Substring(0, $InputLimit - 5) + '[...]')}

        [UInt16]$InputLength = $InputString.Length
        [Int]$RawPadLength   = $InputLimit - $InputLength
        [UInt16]$PadLength   = Limit-Range $RawPadLength 0 $BufferWidth

        [Hashtable]$WHSplat = @{
            Object    = $InputString + ' ' * $PadLength
            NoNewline = !$Newline.IsPresent
        }
        If ($Color) {$WHSplat['ForegroundColor'] = $Color}
        [Console]::SetCursorPosition($X, [Console]::CursorTop)
        Write-Host @WHSplat
    }

    Function Read-HostX {
        [CmdletBinding()]
        Param ([Parameter(Position = 0)][String]$Prompt)

        [String]$UserInput       = If ($Prompt) {Read-Host $Prompt} Else {Read-Host}
        [Console]::CursorVisible = $False

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

    Function Get-UTF8Content {
        [CmdletBinding(DefaultParameterSetName = 'Path')]
        Param (
            [Parameter(Mandatory, ParameterSetName = 'Bytes')][Collections.Generic.List[Byte]]$FromBytes,
            [Parameter(Mandatory, Position = 0, ParameterSetName = 'Path')][IO.FileInfo]$Path,
            [Parameter(ParameterSetName = 'Path')][UInt64]$Offset = 0,
            [Parameter(ParameterSetName = 'Path')][UInt64]$Count = 0,
            [Parameter(ParameterSetName = 'Path')][Switch]$UseGC,
            [ValidateSet('CRLF', 'LF', 'CR', 'Any')][String]$EOL = 'LF',
            [Switch]$Raw, [Switch]$AsByteArray, [Switch]$NoLog
        )

        [Hashtable]$EOLMap = @{CRLF = "`r`n"; LF = "`n"; CR = "`r"}
        If ($Raw.IsPresent -And $AsByteArray.IsPresent -And !$NoLog.IsPresent) {Write-Log WARN 'Both -Raw and -AsByteArray switches are present. -Raw will be ignored.'}
        [Collections.Generic.List[Byte]]$Bytes = Switch ($PSCmdlet.ParameterSetName) {
            'Path' {
                If (!$Path.Exists) {If (!$NoLog.IsPresent) {Write-Log WARN "File '$($Path.FullName)' not found. Returning null."} Return}
                Try {
                    If ($UseGC.IsPresent) {
                        If (!$NoLog.IsPresent) {Write-Log INFO '-UseGC: Forcing file reader fallback to Get-Content.'}
                        [String]$Source = "GC Raw ByteStream '$($Path.FullName)'"
                        Throw 'UseGC'
                    }
                    
                    [String]$Source = "FileStream OpenRead '$($Path.FullName)'"
                    $Offset, $Count = [Math]::Min($Offset, $Path.Length - 1), ($Count, $Path.Length)[$Count -eq 0]
                    If ($Offset -le 3) {
                        If (!$NoLog.IsPresent -And $Offset -ne 0) {Write-Log INFO "Offset is within in the BOM range. Overriding Offset and Count values. (Offset: $Offset > 0; Count: $Count > $($Count + $Offset))"}
                        $Length += $Offset; $Offset = 0
                    }
                
                    [Byte[]]$Buffer = [Byte[]]::New($Count)
                    [IO.FileStream]$Stream = [IO.File]::OpenRead($Path.FullName)
                    [Void]$Stream.Read($Buffer, $Offset, $Count)
                    $Stream.Dispose()
                    If (!$NoLog.IsPresent) {Write-Log INFO "Successfully read '$($Path.FullName)' FileStream bytes"}
                }
                Catch {
                    If ($_.Exception.Message -ne 'UseGC') {
                        If (!$NoLog.IsPresent) {
                            Write-Log ERROR "Failed to read '$($Path.FullName)' FileStream bytes: $($_.Exception.Message)"
                            Write-Log INFO 'File reader fallback to Raw Get-Content ByteStream.'
                        }
                        [String]$Source = "GC Raw ByteStream '$($Path.FullName)' (Fallback)"
                    }
                    Try {
                        [Byte[]]$Buffer = Get-Content $Path.FullName -AsByteStream -Raw
                        If (!$NoLog.IsPresent) {Write-Log INFO "Successfully read '$($Path.FullName)' Raw ByteStream."}
                        Break
                    }
                    Catch {Throw $_}
                }
                Finally {
                    If ($Null -ne $Stream) {$Stream.Dispose()}
                    $Buffer
                }
                Break
            }
            'Bytes' {
                If ($FromBytes.Count -lt 1) {If (!$NoLog.IsPresent) {Write-Log WARN 'No byte array provided. Returning null.'} Return}
                [String]$Source = 'Param -FromBytes <Byte[]>'
                $FromBytes
                Break
            }
        }

        [String]$FileHeader = ('', (($Bytes.GetRange(0, [Math]::Min(3, $Bytes.Count)) | ForEach-Object {$_.ToString('X2')}) -Join ''))[$Bytes.Count -ge 3]
        [Byte]$BOMOffset    = (0, 3)[$FileHeader -eq 'EFBBBF']
        [Collections.Generic.List[Byte]]$Bytes = $Bytes.GetRange($BOMOffset, $Bytes.Count - $BOMOffset)

        [Text.Encoding]$UTF8 = [Text.UTF8Encoding]::New($False)
        [String]$Content     = $UTF8.GetString($Bytes)

        If ($EOL -ne 'Any') {
            $Content = [Regex]::Replace($Content, '\r\n|\r|\n', $EOLMap[$EOL])
            If (!$NoLog.IsPresent) {Write-Log INFO "Converted line endings to $EOL."}
        }

        If (!$NoLog.IsPresent) {
            If ($BOMOffset -eq 3) {Write-Log INFO "Omitted UTF-8 BOM reading $Source."}
            Write-Log INFO "$($Bytes.Count) bytes read from $Source."
        }
        If ($AsByteArray.IsPresent) {Return [Byte[]]$UTF8.GetBytes($Content)}
        If ($Raw.IsPresent)         {Return [String]$Content}
        Else                        {Return [String[]]($Content -Split "`n")}
    }

    Function Set-UTF8Content {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory, Position = 0)][IO.FileInfo]$Path,
            [Parameter(Position = 1)][Collections.Generic.List[String]]$String,
            [Switch]$Append, [Switch]$NoNewline, [Switch]$NoLog
        )

        [String]$JoinedString = $String -Join "`n"
        If (!$NoNewline.IsPresent) {$JoinedString += "`n"}
        
        [Collections.Generic.List[Byte]]$Bytes    = ([Text.UTF8Encoding]::New($False)).GetBytes($JoinedString)
        [Collections.Generic.List[Byte]]$Existing = If ($Path.Exists) {[IO.File]::ReadAllBytes($Path.FullName)} Else {[Byte[]]@()}
        [Collections.Generic.List[Byte]]$Content  = ($Bytes, ($Existing + $Bytes))[$Append.IsPresent]
        
        [IO.File]::WriteAllBytes($Path.FullName, $Content)

        If (!$NoLog.IsPresent) {Write-Log INFO "$($Content.Count) bytes written to '$($Path.FullName)'."}
    }

    Function Format-AndExportErrorData {
        [CmdletBinding()]
        Param ([Parameter(Mandatory)][Management.Automation.ErrorRecord]$Exception)

        [String]$Timestamp = Get-Date -Format 'yyyy.MM.dd AT HH:mm:ss'
        [String]$Message   = $Exception.Exception.Message
        [String]$Details   = $Exception.ErrorDetails.Message

        [String[]]$LogData = @(
            "FATAL ERROR ON $Timestamp RUNNING VERSION $G__ScriptVersion :",
            "$($Exception.PSObject.Properties.Value -Join "`n")",
            "$('-' * 100)`n`n",
            "$(Get-UTF8Content "$G__SessionID.log.txt" -Raw -NoLog)"
        )
        Set-UTF8Content "$G__SessionID.log.txt" $LogData -NoNewline -NoLog

        Return ($Details, $Message)[$Message.Length -gt $Details.Length]
    }

    Function Write-Log {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory, Position = 0)][String]$Type,
            [Parameter(Position = 1)][String]$Message = ''
        )

        [String]$Timestamp = Get-Date -Format 'yyyy.MM.dd HH:mm:ss'
        [String[]]$LogData = @(
            "[$Timestamp] $Type : $((Get-PSCallStack)[1].FunctionName) : $Message",
            "$(Get-UTF8Content "$G__SessionID.log.txt" -Raw -NoLog)"
        )
        Set-UTF8Content "$G__SessionID.log.txt" $LogData -NoNewline -NoLog
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
                'B/s'  {$BytesPerSecond}
                'kB/s' {$BytesPerSecond / 1kB}
                'MB/s' {$BytesPerSecond / 1MB}
                'GB/s' {$BytesPerSecond / 1GB}
            }
        }
        Else {[Double]$ConvertedRate, [String]$UnitSymbol = ((($BytesPerSecond / 1MB), 'MB/s'), (($BytesPerSecond / 1kB), 'kB/s'))[$BytesPerSecond -lt 1MB]}

        Return "$(([Math]::Round($ConvertedRate, 2), [Math]::Round($ConvertedRate))[$UnitSymbol -eq 'B/s']) $UnitSymbol"
    }

    Function Get-ModRepoFile {
        [CmdletBinding(DefaultParameterSetName = 'NoIWR')]
        Param (
            [Parameter(Mandatory, Position = 0)][String]$File,
            [Parameter(ParameterSetName = 'NoIWR', Position = 1)][Byte]$X,
            [Parameter(ParameterSetName = 'NoIWR', Position = 2)][String]$State,
            [Parameter(ParameterSetName = 'NoIWR', Position = 3)][String]$Hash,
            [Parameter(Mandatory, ParameterSetName = 'IWR')][Switch]$UseIWR,
            [Parameter(ParameterSetName = 'IWR')][Switch]$Save,
            [String]$Repository = $G__RepositoryURL,
            [UInt16]$Timeout    = 15000
        )

        Trap {
            Write-Log ERROR "$($_.Exception.Message)"

            Try {$CryptoProvider.Dispose()} Catch {}
            Try {$FileStream.Dispose()}     Catch {}
            Try {$DownloadStream.Dispose()} Catch {}
            Try {$HttpClient.Dispose()}     Catch {}

            Throw $_
        }

        If ($G__OfflineMode) {Throw 'Offline mode is enabled. Unable to download files.'}

        [Uri]$Uri = "$Repository/$File"

        If ($PSCmdlet.ParameterSetName -eq 'IWR') {
            [Hashtable]$IWRSplat = @{Uri = $Uri; TimeoutSec = $Timeout}

            If ($PSVersionTable.PSVersion.Major -lt 6) {$IWRSplat['UseBasicParsing'] = $True}
            If ($Save.IsPresent)                       {$IWRSplat['OutFile']         = $File}

            Return Invoke-WebRequest @IWRSplat
        }

        [Net.Http.HttpClient]$HttpClient = [Net.Http.HttpClient]::New()
        $HttpClient.Timeout              = [TimeSpan]::FromMilliseconds($Timeout)
        $HttpClient.DefaultRequestHeaders.Add('User-Agent', 'ETS2ExtModMan')

        [Net.Http.HttpResponseMessage]$RepoResponse = $HttpClient.GetAsync($Uri, [Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result

        If (!$RepoResponse.IsSuccessStatusCode) {Throw "Failed to download file: $($RepoResponse.StatusCode)"}

        [UInt64]$DownloadSize = $RepoResponse.Content.Headers.ContentLength

        [UInt32]$BufferSize = [Math]::Pow(2, [Math]::Floor([Math]::Log([Math]::Min($DownloadSize, [GC]::GetTotalMemory($False) / 10), 2)))
        [Byte[]]$Buffer     = [Byte[]]::New($BufferSize)

        [Security.Cryptography.SHA1CryptoServiceProvider]$CryptoProvider = [Security.Cryptography.SHA1CryptoServiceProvider]::New()
        
        [DateTime]$IntervalStart   = (Get-Date).AddSeconds(-1)
        [IO.Stream]$DownloadStream = $RepoResponse.Content.ReadAsStreamAsync().Result
        [IO.FileStream]$FileStream = [IO.FileStream]::New($File, [IO.FileMode]::Create)

        [UInt64]$BytesRead       = $DownloadStream.Read($Buffer, 0, $Buffer.Length)
        [UInt64]$BytesDownloaded = $BytesRead

        [UInt32]$Unit, [String]$Symbol, [Byte]$Decimals = Switch ($DownloadSize) {
            {$_ -lt 1000kB} {1kB, 'kB', 0; Break}
            {$_ -lt 1000MB} {1MB, 'MB', 0; Break}
            {$_ -ge 1000MB} {1GB, 'GB', 2; Break}
        }
        [String]$ConvertedDownload = "$([Math]::Round($DownloadSize / $Unit, $Decimals)) $Symbol"
        [UInt64]$IntervalBytes, [Double]$ConvertedBytes, [Double]$IntervalLength, [String]$TransferRate = 0, 0, 0, '0 kB/s'

        While ($BytesRead -gt 0) {

            $FileStream.Write($Buffer, 0, $BytesRead)

            [Void]$CryptoProvider.TransformBlock($Buffer, 0, $BytesRead, $Null, $Null)
            
            $BytesRead        = $DownloadStream.Read($Buffer, 0, $Buffer.Length)
            $BytesDownloaded += $BytesRead
            $ConvertedBytes   = [Math]::Round($BytesDownloaded / $Unit, $Decimals)
            $IntervalLength   = (New-TimeSpan $IntervalStart (Get-Date)).TotalSeconds

            If ($IntervalLength -ge 1) {
                $TransferRate  = Measure-TransferRate $IntervalLength ($BytesDownloaded - $IntervalBytes)
                $IntervalBytes = $BytesDownloaded
                $IntervalStart = Get-Date
            }

            Write-HostX $X -Color Green ("$State " + "$ConvertedBytes".PadLeft(5) + "/$ConvertedDownload ($TransferRate)")
        }

        If ($BytesDownloaded -eq 0) {Throw "Download failed: BD=$BytesDownloaded,BR=$BytesRead,DS=$DownloadSize,BS=$BufferSize"}

        [Void]$CryptoProvider.TransformFinalBlock($Buffer, 0, 0)
        [String]$FileHash = [BitConverter]::ToString($CryptoProvider.Hash) -Replace '-', ''

        If ('Hash' -In $PSBoundParameters.Keys -And $FileHash -ne $Hash) {Throw "Download failed: Hash mismatch"}

        $CryptoProvider.Dispose()
        $FileStream.Dispose()
        $DownloadStream.Dispose()
        $HttpClient.Dispose()
        
        Return $ConvertedDownload, $BytesDownloaded, $FileHash
    }

    Function Test-PSHostCompatibility {Return $Host.UI.SupportsVirtualTerminal}

    Function Test-ModActive {
        [CmdletBinding()]
        Param ([Parameter(Mandatory)][String]$Mod)

        If (!$G__GameLogPath.Exists -Or $G__GameProcess -NotIn (Get-Process).Name) {Return $False}

        [Regex]$MountedPattern   = ' \: \[mod_package_manager\] Mod ".+" has been mounted\. \(package_name\: ' + $Mod + ','
        [Regex]$UnmountedPattern = " \: \[(zip|hash)fs\] $Mod\.(scs|zip)\: Unmounted\.?"
        
        ForEach ($Line in Get-UTF8Content $G__GameLogPath -UseGC) {
            If ($Line -Match $MountedPattern)   {[Bool]$IsLoaded = $True}
            If ($Line -Match $UnmountedPattern) {[Bool]$IsLoaded = $False}
        }
        Return $IsLoaded
    }

    Function Test-FileHash {
        [CmdletBinding()]
        Param (
            [Parameter(Position = 0)][IO.FileInfo]$File,
            [Parameter(Mandatory, Position = 1)][String]$Hash,
            [Parameter(Position = 2)][UInt64]$Size
        )

        If (!$File.Exists -Or ($Size -And $File.Length -ne $Size)) {Return $False}

        [UInt64]$Buffer        = [Math]::Pow(2, [Math]::Floor([Math]::Log([Math]::Min($File.Length, [GC]::GetTotalMemory($False) / 4), 2)))
        [IO.FileStream]$Stream = [IO.FileStream]::New($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read, $Buffer)

        Try     {Return [BitConverter]::ToString($G__CryptoProvider.ComputeHash($Stream)) -Replace '-', '' -eq $Hash}
        Catch   {Return $False}
        Finally {$Stream.Dispose()}
    }

    Function Test-ArrayNullOrEmpty {
        [CmdletBinding()]
        Param ([AllowEmptyCollection()][Object[]]$Array)

        If ($Null -eq $Array) {Return $True}

        Return ([Math]::Max($Array.IndexOf(''), $Array.IndexOf($Null)) -ne -1)
    }

    Function Test-GameConfiguration {
        # TODO: Not yet implemented
        [CmdletBinding()]
        Param ([IO.FileInfo]$ConfigPath = $G__GameConfigPath)

        [Hashtable]$ConfigData = @{}

        ForEach ($Line in Get-UTF8Content $ConfigPath) {
            If ($Line -NotMatch '^uset ') {Continue}
            $Line = $Line -Replace '(?<=^)uset (?=.*$)', ''
            [String]$Name, [String]$Value = $Line -Replace '"', '' -Split ' ', 2
            $ConfigData[$Name]            = $Value
        }
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
        [Void]$Host.UI.RawUI.ReadKey('NoEcho, IncludeKeyDown')
        If ($Clear.IsPresent) {
            [Console]::SetCursorPosition(0, [Console]::CursorTop)
            Write-Host -NoNewline (' ' * $Prompt.Length)
            [Console]::SetCursorPosition(0, [Console]::CursorTop)
        }
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

        [String]$KeyPress = $Host.UI.RawUI.ReadKey('NoEcho, IncludeKeyDown').VirtualKeyCode

        If ($Clear.IsPresent) {
            [Console]::SetCursorPosition(0, [Console]::CursorTop)
            Write-Host -NoNewline (' ' * $Prompt.Length)
            [Console]::SetCursorPosition(0, [Console]::CursorTop)
        }
        Return $KeyPress
    }

    Function Set-ForegroundWindow {
        [CmdletBinding(DefaultParameterSetName = 'Self')]
        Param (
            [Parameter(Mandatory, ParameterSetName = 'Self')][Switch]$Self,
            [Parameter(Mandatory, ParameterSetName = 'Name')][String]$Name,
            [Parameter(Mandatory, ParameterSetName = 'PID')][UInt32]$ID
        )

        [__ComObject]$WShell                = New-Object -COM WScript.Shell
        [UInt32]$TargetPID, [IntPtr]$Handle = Switch ($PSCmdlet.ParameterSetName) {
            'Self' {$PID, (Get-Process -Id $PID)[0].MainWindowHandle; Break}
            'Name' {(Get-Process $Name)[0] | ForEach-Object {$_.Id, $_.MainWindowHandle}; Break}
            'PID'  {$ID, (Get-Process -Id $ID)[0].MainWindowHandle; Break}
        }
        [Void]$WShell.AppActivate($TargetPID)
        [Void][WndHelper]::SetForegroundWindow($Handle)
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
        If ([String]::IsNullOrWhiteSpace($Hex)) {Return ($Name, "$($G__GameModDirectory.FullName)\$Name.scs")[$AsPath.IsPresent]}

        Return (($Name, [String][UInt32]"0x$Hex")[$Type -eq 'mod_workshop_package'], ("$($G__GameModDirectory.FullName)\$Name.scs", ("$($G__WorkshopDirectory.FullName)\" + [String][UInt32]"0x$Hex"))[$Type -eq 'mod_workshop_package'])[$AsPath.IsPresent]
    }

    Function Convert-ProfileFolderName {
        [CmdletBinding()]
        Param ([String]$Directory = $G__ActiveProfile)

        [Char[]]$Converted = For ([UInt16]$Index = 0; $Index -lt $Directory.Length; $Index += 2) {[Char][Byte]"0x$($Directory.Substring($Index, 2))"}
        Return $Converted -Join ''
    }

    Function ConvertTo-PlainTextProfileUnit {
        [CmdletBinding()]
        Param ([IO.FileInfo]$File = $G__ProfileUnit, [IO.FileInfo]$OutFile = $G__TempProfileUnit, [Switch]$OnFile)

        [IO.FileInfo]$UnitDecoder = Get-GameUnitDecoder
        [String]$DecodeCommand    = "& '$($UnitDecoder.FullName)'" + (" '$($File.FullName)' '$($OutFile.FullName)'", " --on_file -i '$($File.FullName)'")[$OnFile.IsPresent]
        [Object]$DecoderResult    = Invoke-Expression $DecodeCommand

        Write-Log INFO "Profile unit decoder finished with exit code $LASTEXITCODE ($DecoderResult).`n    Command: $DecodeCommand"

        Switch ($LASTEXITCODE) {
            0       {Break}
            1       {Break}
            Default {Throw $DecoderResult}
        }
        If ((Get-ProfileUnitFormat $OutFile) -eq 'Binary') {Throw 'Profile unit decoder failed to convert to plaintext profile text format.'}
    }

    Function Test-WorkshopModInstalled {
        [CmdletBinding()]
        Param ([Parameter(Mandatory)][IO.DirectoryInfo]$ModFolder)

        Return [IO.Directory]::Exists((Convert-ModSourceName -Name $ModFolder -AsPath))
    }

    Function Get-GameDirectory {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory, ParameterSetName = 'GameRoot')][Switch]$Root,
            [Parameter(Mandatory, ParameterSetName = 'Workshop')][Switch]$Workshop
        )

        [Regex]$PathSearchPattern  = '(?i)(?<="path"\s+")[a-z]\:(?:\\\\.+)+(?=")'
        [Regex]$AppIDSearchPattern = '(?<=")' + $G__GameAppID + '(?="\s+"\d+")'
        [Regex]$InstallDirPattern  = '(?<="installdir"\s+")[^"]+(?=")'

        [String]$RegKey        = 'HKLM:\SOFTWARE' + ('\', '\WOW6432Node\')[[Environment]::Is64BitOperatingSystem] + 'Valve\Steam'
        [String]$SteamRoot     = Get-ItemPropertyValue $RegKey InstallPath
        [String[]]$LibraryData = Get-UTF8Content "$SteamRoot\SteamApps\libraryfolders.vdf"
        [String]$SteamApps     = ForEach ($Line in $LibraryData) {
            If ($Line -Match $PathSearchPattern)  {[String]$Path = $Matches[0] -Replace '\\\\', '\'; Continue}
            If ($Line -Match $AppIDSearchPattern) {"$Path\SteamApps"; Break}
        }
        # If $Directory is 'Workshop', return the workshop directory
        If ($Workshop.IsPresent) {Return [IO.DirectoryInfo]"$SteamApps\workshop\content\$G__GameAppID"}

        # Otherwise since the only other valid value is "Root" we return the game's root/install directory
        [String[]]$AppCacheData    = Get-UTF8Content "$SteamApps\appmanifest_$G__GameAppID.acf"
        [IO.DirectoryInfo]$RootDir = ForEach ($Line in $AppCacheData) {If ($Line -Match $InstallDirPattern) {[IO.Path]::Combine("$SteamApps\common", $Matches[0]); Break}}

        Return $RootDir
    }

    Function Get-ProfileUnitFormat {
        [CmdletBinding()]
        Param ([IO.FileInfo]$Target = $G__TempProfileUnit)

        [Collections.Generic.List[Byte]]$UnitData = [IO.File]::ReadAllBytes($Target.FullName)
        [String]$UnitFormat                       = ('Text', 'Binary')[0 -In $UnitData]

        Switch ($UnitFormat) {
            'Binary' {Write-Log INFO "Null-byte detected in '$($Target.FullName)'. Assuming binary format."; Break}
            'Text'   {Write-Log INFO "No null-bytes detected in '$($Target.FullName)'. Assuming text format."; Break}
            Default  {Throw "Unable to determine format of '$($Target.FullName)' - Unexpected format '$UnitFormat'"}
        }
        Return $UnitFormat
    }

    Function Get-GameUnitDecoder {
        [CmdletBinding()]
        Param ([String]$DecFile = $G__RepositoryInfo.DecFile)

        [IO.FileInfo]$Path = "$Env:TEMP\$DecFile"
        [String]$Checksum  = (Get-ModRepoFile $G__RepositoryInfo.DecHash -UseIWR).Content

        If (!$Path.Exists) {
            If ($G__OfflineMode) {Throw 'Offline mode is enabled. Unable to download files.'}

            [IO.File]::WriteAllBytes($Path.FullName, [Byte[]](Get-ModRepoFile $DecFile -UseIWR).Content)
            
            Write-Log INFO "Game unit decoder downloaded to '$($Path.FullName)'"
        }

        If (!(Test-FileHash $Path.FullName $Checksum)) {
            Write-Log ERROR "Unable to verify '$DecFile' - Checksum mismatch. The file will be deleted."

            $Path.Delete()

            Throw "Unable to verify '$DecFile' - Checksum mismatch"
        }
        Write-Log INFO 'Game unit decoder successfully verified.'
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
        Write-Log INFO "Parsed $($ParsedData.Keys.Count) mod data entries."
        Return $ParsedData
    }

    Function Install-CoreMod {
        # TODO: Not yet implemented
        [CmdletBinding()]
        Param ()
    }

    Function Read-PlainTextProfileUnit {
        [CmdletBinding()]
        Param ([ValidateSet('Mods', 'Data', 'All')][String]$Return = 'All', [Switch]$Raw, [Switch]$Direct)

        [Bool]$Parse        = $False
        [String[]]$UnitMods = @()
        [String[]]$UnitData = @()
        [IO.FileInfo]$File  = ($G__TempProfileUnit, $G__ProfileUnit)[$Direct.IsPresent]
        Write-Log INFO "$(('Using TempProfileUnit', "'-Direct' specified - Using ProfileUnit")[$Direct.IsPresent]) as source profile.`n    ('$($File.FullName)') "

        ForEach ($Line in Get-UTF8Content $File) {
            If ($Parse -And $Line -Match '^ customization: \d+$') {
                $Parse     = $False
                $UnitData += '<MODLIST_INSERTION_POINT>'
            }
            ElseIf ($Line -Match '^ active_mods: \d+$') {$Parse = $True}

            If ($Parse) {$UnitMods += $Line} Else {$UnitData += $Line}
        }
        Write-Log INFO "Parsed $($UnitMods.Count) active mod entries. Returning $Return."
        If ($Raw.IsPresent) {
            [String]$UnitMods = $UnitMods -Join "`n"
            [String]$UnitData = $UnitData -Join "`n"
        }
        Return (($UnitMods, $UnitData), $UnitMods, $UnitData)[('All', 'Mods', 'Data').IndexOf($Return)]        
    }

    Function Edit-ProfileLoadOrder {
        [CmdletBinding()]
        Param ([IO.FileInfo]$ProfileUnit = $G__ProfileUnit)

        Write-Host "`n Configuring load order..."

        If ($G__GameProcess -In (Get-Process).Name) {
            Write-Log WARN 'Game is running. Aborted load order configuration.'
            Write-Host -ForegroundColor Yellow " $G__GameName must be closed in order to apply load order."
            Return
        }

        Write-Host -ForegroundColor Green (''.PadRight(4) + "$G__LoadOrder - $G__ActiveModsCount active mods")

        [String]$ProfileFormat = Get-ProfileUnitFormat $ProfileUnit

        If ($ProfileFormat -ne 'Text') {
            Write-Host -NoNewline (''.PadRight(4) + 'Decoding profile...'.PadRight(35))
            ConvertTo-PlainTextProfileUnit
            Write-Host -ForegroundColor Green 'OK'
        }

        [String[]]$ProfileMods, [String[]]$ProfileData = Read-PlainTextProfileUnit All -Direct:($ProfileFormat -eq 'Text')
        [String]$RawProfileMods                        = $ProfileMods -Join "`n"
        [UInt16]$ProfileModsCount                      = ($ProfileMods[0] -Split ':', 2)[-1].Trim()

        If ($RawProfileMods -cne $G__LoadOrderText) {
            Write-Host -NoNewline (''.PadRight(4) + 'Creating profile backup...'.PadRight(35))
            
            [IO.FileInfo]$Backup = Backup-ProfileUnit

            Write-Host -ForegroundColor Green "OK - $($Backup.Name)"
            Write-Host -NoNewline (''.PadRight(4) + 'Applying load order...'.PadRight(35))

            If ($ProfileFormat -ne 'Text') {ConvertTo-PlainTextProfileUnit -OnFile}
            [String]$ProfileRaw = $ProfileData -Join "`n" -Replace '<MODLIST_INSERTION_POINT>', $G__LoadOrderText
            Set-UTF8Content $ProfileUnit $ProfileRaw -NoNewline

            Write-Log INFO "Load order applied. $ProfileModsCount > $G__ActiveModsCount"
            Write-Host -ForegroundColor Green "OK - $ProfileModsCount > $G__ActiveModsCount"
        }
        Else {
            Write-Log INFO 'Load order already applied.'
            Write-Host -ForegroundColor Green '    Already applied'
        }
        [String[]]$MissingWorkshopMods = ForEach ($Key in $G__LoadOrderData.Keys | Where-Object {$G__LoadOrderData[$_].Type -eq 'mod_workshop_package'}) {
            [Hashtable]$Current = $G__LoadOrderData[$Key]
            If (!(Test-WorkshopModInstalled $Current.Source)) {

                Write-Log WARN "Missing workshop subscription: $($Current.Name)"
                Write-Host -ForegroundColor Yellow (''.PadRight(4) + 'MISSING WORKSHOP SUBSCRIPTION: ' + $Current.Name)

                $Current.SourceName
            }
        }
        If ($MissingWorkshopMods) {
            Do {[Int]$UserInput = Read-KeyPress ' Open Workshop item page in Steam? [Y/N]' -Clear} Until ($UserInput -Match '^(89|78)$')
            
            Switch ($UserInput) {
                89 {ForEach ($Mod in $MissingWorkshopMods) {Start-SteamWorkshopPage $Mod; Wait-KeyPress 'Press any key to continue...' -Clear}}
                78 {Break}
            }
        }
    }

    Function Backup-ProfileUnit {
        [CmdletBinding()]
        Param ([IO.FileInfo]$ProfileUnit = $G__ProfileUnit)

        [String]$Name            = 'profile_' + (Get-Date -Format yy-MM-dd_HHmmss)
        [IO.FileInfo]$BackupFile = $G__ProfileUnit.CopyTo("$($G__ProfilePath.FullName)\$Name.bak")

        Write-Log INFO "Profile backup created: $($BackupFile.Name)"

        Return $BackupFile
    }

    Function Export-LoadOrder {
        [CmdletBinding()]
        Param ([IO.FileInfo]$ProfileUnit = $G__ProfileUnit)

        [IO.FileInfo]$SaveTarget = Get-FilePathByDialog -Save 'Save load order as...' 'Load order file (*.order)|*.order|All files (*.*)|*.*' 'MyLoadOrder.order'

        #TODO: Implement checks for successful export
        If (![String]::IsNullOrWhiteSpace($SaveTarget)) {
            Try {
                [String]$ProfileFormat = Get-ProfileUnitFormat $ProfileUnit

                If ($ProfileFormat -ne 'Text') {ConvertTo-PlainTextProfileUnit}

                [String]$ProfileMods = Read-PlainTextProfileUnit Mods -Raw -Direct:($ProfileFormat -eq 'Text')
                Set-UTF8Content $SaveTarget $ProfileMods -NoNewline

                [String]$SavedData           = Get-UTF8Content $SaveTarget -Raw
                [String[]]$FormatTestResults = Test-LoadOrderFormat $SavedData -ContinueOnError -ReturnInfo

                If ($FormatTestResults)          {Throw "$($FormatTestResults -Join "`n")"}
                If ($SavedData -ne $ProfileMods) {Throw 'Failed to export load order'}

                Write-Log INFO "Load order for active profile '$G__ActiveProfileName' successfully exported to '$($SaveTarget.FullName)'"
                [Void][Windows.MessageBox]::Show("Success!`n`nExported load order from active profile `"$G__ActiveProfileName`"`nto:`n$($SaveTarget.FullName)", 'Export successful', 0, 64)
            }
            Catch {
                Write-Log ERROR "An error occurred while exporting the load order of profile '$G__ActiveProfileName': $($_.Exception.Message)"
                Format-AndExportErrorData $_
                [Void][Windows.MessageBox]::Show("An error occurred while exporting the load order from profile`n`"$G__ActiveProfileName`"`n$($_.Exception.Message)", 'Export failed', 0, 16)
            }
        }
    }

    Function Move-SelfToModDirectory {
        [CmdletBinding()]
        Param ()

        [IO.DirectoryInfo]$SelfPath = $MyInvocation.MyCommand.Path
        [String]$SelfName           = [IO.Path]::GetFileName($SelfPath)
        [IO.FileInfo]$ModPath       = "$($G__GameModDirectory.FullName)\$SelfName"

        Try {
            If (!$ModPath.Exists) {
                $SelfPath.MoveTo($ModPath.FullName)
                Write-Log INFO "Successfully moved self ('$($SelfPath.FullName)\$SelfName') to mod directory '$($ModPath.FullName)'"
            }
        
            [Console]::SetCursorPosition(1, 10)
            Write-HostX 1 -Color Yellow (' ' * ([Console]::BufferWidth - 1))

            [Console]::SetCursorPosition(1, 10)
            Write-Host -ForegroundColor Black -BackgroundColor Yellow (' ' * ([Console]::BufferWidth - 1))

            Write-Log INFO "Executing script from new directory."
            Start-Process (Get-Process -ID $PID).MainModule.ModuleName -ArgumentList "-ExecutionPolicy Bypass -File `"$($ModPath.FullName)`""

            Write-Log INFO 'Exiting session.'
            Return $True
        }
        Catch {
            Write-Log ERROR "Failed to move self to mod directory: $($_.Exception.Message)"
            Return $False
        }
    }

    Function Import-LoadOrder {
        [CmdletBinding()]
        Param ()

        [IO.FileInfo]$InFile = Get-FilePathByDialog -Open 'Import load order' 'Load order file (*.order)|*.order|All files (*.*)|*.*'
        Clear-Host

        If ($InFile) {Return $InFile} Else {Return $G__LoadOrder}
    }

    Function Select-Profile {
        [CmdletBinding()]
        Param ([Switch]$AllowEsc)

        [String[]]$AllProfiles = (Get-ChildItem "$($G__GameRootDirectory.FullName)\profiles" -Directory).Name | Sort-Object Length

        Write-Log INFO 'Displaying profile selection menu.'

        Clear-Host
        Write-Host ' SELECT PROFILE'
        Write-Host ($G__UILine * [Console]::BufferWidth)

        If (!$AllProfiles) {
            Write-Log WARN 'No profiles detected. Aborting profile selection.'
            Throw 'No profiles detected! Disable ''Use Steam Cloud'' for the profile(s) you want to use.'
        }
        If ($AllProfiles.Count -eq 1) {
            Set-ActiveProfile $AllProfiles[0]
            [String]$ProfileName = Convert-ProfileFolderName $AllProfiles[0]

            Write-Log INFO "Singular profile detected. Profile '$($AllProfiles[0])' ($ProfileName) automatically applied as active profile."
            Write-Host -ForegroundColor Green "$G__GameNameShort Profile '$ProfileName' was automatically selected as the active profile."
            Start-Sleep 2

            Return $AllProfiles[0]
        }

        [UInt16]$LongestDir                               = $AllProfiles[-1].Length + 3
        [Byte]$Selected                                   = (0, $AllProfiles.IndexOf($G__ActiveProfile))[$G__ActiveProfile -In $AllProfiles]
        [String]$PreviousProfile                          = $G__ActiveProfile
        [Management.Automation.Host.Coordinates]$StartPos = $Host.UI.RawUI.CursorPosition

        Do {
            $Host.UI.RawUI.CursorPosition = $StartPos
            [Byte]$Iteration              = 0

            ForEach ($Directory in $AllProfiles) {
                [String]$Name     = Convert-ProfileFolderName $Directory
                [Bool]$IsSelected = $Iteration -eq $Selected

                Write-Host -NoNewline ' '
                Write-HostX 0 -Color ("DarkGray", "Green")[$IsSelected] (' ' + ('   ', '>> ')[$IsSelected] + $Directory.PadRight($LongestDir) + "$Name ") -Newline
                $Iteration++
            }
            Write-Host -NoNewline "`n * Use the "
            Write-Host -NoNewline -ForegroundColor Cyan '[UP]'
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

            [String]$SelectedProfile = $AllProfiles[$Selected]

            Do {
                [Bool]$UpdateSelection = $False
                Switch (Read-KeyPress -Clear) {
                    13 { # [ENTER]
                        Clear-Host
                        If ($SelectedProfile -ne $PreviousProfile) {
                            Set-ActiveProfile $SelectedProfile
                            Return $SelectedProfile
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
        Param ()

        [String]$StoredProfile = Read-EmbeddedValue $G__DataIndices.ActiveProfile

        If ($StoredProfile -eq '***GAME_PROFILE_PLACEHOLDER***' -Or [String]::IsNullOrWhiteSpace($StoredProfile) -Or ![IO.Directory]::Exists("$($G__GameRootDirectory.FullName)\profiles\$StoredProfile")) {$StoredProfile = Select-Profile}
        
        Return $StoredProfile
    }

    Function Set-ActiveProfile {
        [CmdletBinding()]
        Param ([Parameter(Mandatory)][String]$Directory)

        If ($Directory -ne $G__ActiveProfile) {
            Write-EmbeddedValue $G__DataIndices.ActiveProfile $Directory
            Write-Log INFO "Active profile changed from '$G__ActiveProfile' to '$Directory'. Executing script restart."

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

        Write-Host ($G__UILine * [Console]::BufferWidth)
        Write-Host "`n    $($G__ScriptDetails['Title'])`n"
        Write-Host "    $($G__ScriptDetails['Version']), Updated $($G__ScriptDetails['VersionDate'])"
        Write-Host "    $($G__ScriptDetails['Copyright']) - $($G__ScriptDetails['Author'])`n"
        Write-Host "`n    $Action"

        Start-Sleep 2
    }

    Function Invoke-Menu {
        [CmdletBinding()]
        Param ([Switch]$Saved)

        [Byte]$UILineWidth      = 100
        [String]$SetAndContinue = '; Update-ProtectedVars; $Save = $False; Continue'
        [String]$OrderRunText   = 'Update active mods'
        [String]$AllRunText     = 'Update all mods'
        If ($G__ValidateInstall) {
            $OrderRunText += ' + verify integrity'
            $AllRunText   += ' + verify integrity'
        }
        If ($G__DeleteDisabled)  {$OrderRunText += " + delete$(('', ' managed', ' ALL')[$G__DDSel]) inactive mods"}
        If ($G__NoProfileConfig) {
            $OrderRunText += ' + skip load order config'
            $AllRunText   += ' + skip load order config'
        }
        If ($G__StartGame) {
            $OrderRunText += " + launch $G__GameNameShort"
            $AllRunText   += " + launch $G__GameNameShort"
            If ($G__StartSaveEditor) {
                $OrderRunText += " + launch $($G__TSSETool.Name)"
                $AllRunText   += " + launch $($G__TSSETool.Name)"
            }
        }

        [Byte]$ActiveDataPadding = ("Active $G__GameNameShort profile: ", 'Active load order: ' | Sort-Object Length)[-1].Length
        [Console]::SetCursorPosition(0, 0)

        Write-Host "`n    $($G__ScriptDetails['Title'])   $G__ScriptVersion`n"

        Write-Host ($G__UILine * [Console]::BufferWidth)

        Write-Host -NoNewline ("`n      " + "Active $G__GameNameShort profile: ".PadRight($ActiveDataPadding))
        Write-HostFancy -ForegroundColor Green $G__ActiveProfileName
        Write-Host -NoNewline ('      ' + 'Active load order: '.PadRight($ActiveDataPadding))
        Write-HostFancy -ForegroundColor Green $G__LoadOrder

        Write-HostFancy "`n    $($G__UILine * $UILineWidth)`n"

        Write-HostFancy "     [1]       Launch $G__GameName upon completion`n"
        Write-HostFancy "     [2]       Launch $($G__TSSETool.Name) with $G__GameName" -ForegroundColor ("DarkGray", [Console]::ForegroundColor)[$G__TSSETool.Installed]

        Write-HostFancy "`n    $($G__UILine * $UILineWidth)`n"

        Write-HostFancy "     [3]       Delete$((' managed', ' ALL', ' managed')[$G__DDSel]) mods not in the active load order ([TAB] will override this option)`n" -ForegroundColor ([Console]::ForegroundColor, "DarkGray")[$G__OfflineMode]
        Write-HostFancy "     [4]       Verify game file integrity (Forces Steam Workshop mod updates)`n"
        Write-HostFancy "     [5]       Skip profile load order configuration ([SPACE] will override this option)" -ForegroundColor ([Console]::ForegroundColor, "DarkGray")[$G__OfflineMode]

        Write-HostFancy "`n    $($G__UILine * $UILineWidth)`n"

        Write-HostFancy "     [6]       Save current options $(('', '[SAVED]')[$Saved.IsPresent])" -ForegroundColor ([Console]::ForegroundColor, 'Green')[$Saved.IsPresent]

        Write-HostFancy "`n    $($G__UILine * $UILineWidth)`n"

        Write-HostFancy "     [7]       Export load order from active profile`n"
        Write-HostFancy '     [8]       Import custom load order'

        Write-HostFancy "`n    $($G__UILine * $UILineWidth)`n"

        Write-HostFancy "     [9]       Change load order`n" -ForegroundColor ([Console]::ForegroundColor, "DarkGray")[$G__OfflineMode]
        Write-HostFancy "     [0]       Change profile"

        Write-HostFancy "`n    $($G__UILine * $UILineWidth)`n"

        Write-HostFancy "     [ESC]     Exit"

        Write-HostFancy "`n    $($G__UILine * $UILineWidth)`n"

        Write-HostFancy "     [SPACE]   Configure profile load order ONLY`n"
        Write-HostFancy "     [ENTER]   $OrderRunText" -ForegroundColor ([Console]::ForegroundColor, "DarkGray")[$G__OfflineMode]
        Write-HostFancy "     [TAB]     $AllRunText" -ForegroundColor ([Console]::ForegroundColor, "DarkGray")[$G__OfflineMode]

        Write-HostFancy "`n    $($G__UILine * $UILineWidth)`n"

        Write-HostFancy "       $(('', "WARNING: Deleted mods must be reaquired if reactivated in the future.`n")[$G__DeleteDisabled])" -ForegroundColor Yellow

        While ($True) {
            [Int]$Choice = Read-KeyPress -Clear
            # 9  - Execute (Update all mods)
            # 13 - Execute (Update based on load order only)
            # 27 - Exit
            # 32 - No update
            # 48 - Change profile
            # 49 - Start game
            # 50 - Start save editor
            # 51 - Delete inactive mods
            # 52 - Validate install
            # 53 - Skip load order config
            # 54 - Save options
            # 55 - Export load order
            # 56 - Import load order
            # 57 - Change load order
            Switch ($Choice) {
                9  {If ($G__OfflineMode) {Break} Return '$G__UpdateAll = $True; Update-ProtectedVars; Break'} # [TAB]
                13 {If ($G__OfflineMode) {Break} Return 'Break'} # [ENTER]
                27 {Return 'Exit'} # [ESC]
                32 {If ($G__OfflineMode) {Break} Return '$G__NoUpdate = $True; Update-ProtectedVars; Break'} # [SPACE]
                48 {If (!(Select-Profile -AllowEsc)) {Return 'Continue'} Else {Return 'Unprotect-Variables; $GLOBAL:G__ScriptRestart = $True; Return "Menu"'}} # [0]
                49 {Return '$G__StartGame = !$G__StartGame' + $SetAndContinue}                     # [1]
                50 {Return '$G__StartSaveEditor = $G__StartGame -And !$G__StartSaveEditor' + $SetAndContinue} # [2]
                51 {If ($G__OfflineMode) {Break} Return '$G__DDSel = ($G__DDSel + 1) % 3; $G__DeleteDisabled = $G__DDSel -ne 0;' + $SetAndContinue}           # [3]
                52 {Return '$G__ValidateInstall = !$G__ValidateInstall' + $SetAndContinue}         # [4]
                53 {If ($G__OfflineMode) {Break} Return '$G__NoProfileConfig = !$G__NoProfileConfig' + $SetAndContinue}         # [5]
                54 {Return 'Write-AllEmbeddedValues; $Save = $True; Continue'; Write-AllEmbeddedValues} # [6]
                55 {Return 'Export-LoadOrder; Continue'; Export-LoadOrder}   # [7]
                56 {Return '$G__LoadOrder = Set-ActiveLoadOrder (Import-LoadOrder)' + $SetAndContinue; Import-LoadOrder}   # [8]
                57 {If ($G__OfflineMode) {Break} Return '$G__LoadOrder = Set-ActiveLoadOrder (Select-LoadOrder)' + $SetAndContinue; Select-LoadOrder; Set-ActiveLoadOrder} # [9]
                Default {Break} # Invalid choice
            }
            [Console]::Beep(1000, 150)
        }
    }

    Function Confirm-Choice { #TODO: This function is currently unused and is subject to removal in a future version
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

    Function Write-HostFancy { #TODO: "This function will be deprecated in a future version"(TM)
        [CmdletBinding()]
        Param (
            [Parameter(Position = 0)][String[]]$String = @(''),
            [Parameter(Position = 1)][UInt16]$Speed    = 0,
            [ConsoleColor]$ForegroundColor = [Console]::ForegroundColor,
            [ConsoleColor]$BackgroundColor = [Console]::BackgroundColor
        )

        [String[]]$Text   = $String -Join "`n" -Split "`n"
        [Hashtable]$Splat = @{
            ForegroundColor = $ForegroundColor
            BackgroundColor = $BackgroundColor
        }
        ForEach ($Line in $Text) {
            Write-Host @Splat ($Line + ' ' * ([Console]::BufferWidth - $Line.Length - [Console]::CursorLeft))
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
            Object          = ' ' * [Console]::BufferWidth
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

    Function Read-EmbeddedValue { #TODO: Slow - Make not slow.
        [CmdletBinding()]
        Param ([Parameter(Mandatory)][UInt32]$Index, [Collections.Generic.List[String]]$CustomData)
        
        [Collections.Generic.List[String]]$ScriptData = If ($CustomData) {$CustomData} Else {Get-UTF8Content $G__ScriptPath -Count 500}
        [String]$Info,   [String]$RawValue = $ScriptData[$Index].Substring(0, $ScriptData[$Index].IndexOf(';')).Substring(1) -Split '=', 2
        [String]$Format, [String]$Name     = $Info -Split '_', 2

        Switch ($Format) {
            'NUM'   {[Int64]$Value  = $RawValue}
            'DEC'   {[Double]$Value = $RawValue}
            Default {[String]$Value = $RawValue}
        }
        Write-Log INFO "Read embedded value: '$Name' > '$Value'"
        Return $Value
    }

    Function Read-AllEmbeddedValues {
        [CmdletBinding()]
        Param ([Hashtable]$DataIndices = $G__DataIndices, [Collections.Generic.List[String]]$CustomData)

        $DataIndices['ScriptVersion'] = 0
        [Hashtable]$ReadData          = @{}
        [String[]]$Pairs              = @()
        [Collections.Generic.List[String]]$ScriptData = If ($CustomData) {$CustomData} Else {Get-UTF8Content $G__ScriptPath -Count 500}

        ForEach ($Key in $DataIndices.Keys) {
            [String]$ScriptLine              = $ScriptData[$DataIndices.$Key]
            [String]$Info, [String]$RawValue = $ScriptLine.Substring(0, $ScriptLine.IndexOf(';')).Substring(1) -Split '=', 2
            [String]$Format, [String]$Name   = $Info -Split '_', 2
            Switch ($Format) {
                'NUM'   {[Int64]$Value  = $RawValue}
                'DEC'   {[Double]$Value = $RawValue}
                Default {[String]$Value = $RawValue}
            }
            $Pairs += "$($Key.PadRight(16))> '$Value'"
            $ReadData[$Key] = $Value
        }
        Write-Log INFO "All embedded values read ($($ReadData.Keys.Count)):`n    $($Pairs -Join "`n    ")"
        Return $ReadData
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
        [String]$DataKey = $SourceData.Substring(0, $SourceData.IndexOf('='))
        Write-Log INFO "New embedded value: $("'$DataKey'".PadRight(19))> '$Value'"
        Return "$DataKey=$Value;"
    }

    Function Write-EmbeddedValue {  #TODO: Slow - Make not slow.
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory)][UInt32]$Index,
            [Parameter(Mandatory)][String]$Value
        )

        [Collections.Generic.List[String]]$ScriptData = Get-UTF8Content $G__ScriptPath
        $ScriptData[$Index] = New-EmbeddedValue $ScriptData[$Index] $Value

        Set-UTF8Content $G__ScriptPath $ScriptData -NoNewline
        Write-Log INFO "Embedded value written: '$Value'"
    }

    Function Write-AllEmbeddedValues {
        [CmdletBinding()]
        Param ()
        
        [Collections.Generic.List[String]]$ScriptData = Get-UTF8Content $G__ScriptPath
        [String[]]$Pairs = @()

        ForEach ($Key in $G__DataIndices.Keys) {
            [String]$Value = Get-Variable "G__$Key" -ValueOnly
            [UInt32]$Index = $G__DataIndices.$Key
            $Pairs        += "'$Key' > '$Value'"

            $ScriptData[$Index] = New-EmbeddedValue $ScriptData[$Index] $Value
        }
        Set-UTF8Content $G__ScriptPath $ScriptData -NoNewline
        Write-Log INFO "All embedded values written ($($Pairs.Count)):`n    $($Pairs -Join "`n    ")"
    }

    Function Switch-GrammaticalNumber {
        [CmdletBinding(DefaultParameterSetName = 'Auto')]
        Param (
            [Parameter(Mandatory, Position = 0, ValueFromPipeline)][String]$Word,
            [Parameter(ParameterSetName = 'Count', Position = 1)][Int64[]]$Count,
            [Parameter(ParameterSetName = 'Singular')][Alias('S')][Switch]$Singularize,
            [Parameter(ParameterSetName = 'Plural')][Alias('P')][Switch]$Pluralize
        )

        If (!$G__PlrSvc) {Throw 'Pluralization service is unavailable'}

        [String]$ParamSet = $PSCmdlet.ParameterSetName
        [String]$Plural   = $G__PlrSvc.Pluralize($Word)
        [String]$Singular = $G__PlrSvc.Singularize($Word)

        If ($ParamSet -eq 'Count' -And $Count.Count -gt 1) {[String[]]$Return = ForEach ($Instance in $Count) {($Plural, $Singular)[[Math]::Abs($Instance) -eq 1]}}
        Else {[String]$Return = Switch ($ParamSet) {
            'Auto'     {($Plural, $Singular)[$G__PlrSvc.IsSingular($Word)]; Break}
            'Count'    {($Plural, $Singular)[[Math]::Abs($Count[0]) -eq 1]; Break}
            'Singular' {$Singular; Break}
            'Plural'   {$Plural; Break}
            Default    {$Word; Break}
        }}
        Return $Return
    }

    Function Get-EnglishCulture {
        [CmdletBinding()]
        Param ()

        # Default: 1033, en-US (English, United States)
        [String]$CurrentCulture = [CultureInfo]::CurrentCulture.Name
        [String[]]$EngCultures  = ([CultureInfo]::GetCultures([Globalization.CultureTypes]::AllCultures) | Where-Object {$_.Name -Like 'en-*'}).Name | Select-Object -Unique

        Write-Log INFO "Current culture: $CurrentCulture"

        Return [CultureInfo]::GetCultureInfo(('en-US', $CurrentCulture)[$CurrentCulture -In $EngCultures])
    }

    Function Get-LoadOrderData {
        [CmdletBinding()]
        Param ([String]$Name = $G__LoadOrder, [Switch]$Data, [Switch]$Raw)

        [String]$Content = If     ([IO.Path]::GetExtension($Name) -eq '.order') {Get-UTF8Content $Name -Raw} 
                           ElseIf (!$G__OfflineMode)                            {Get-UTF8Content -FromBytes (Get-ModRepoFile "$Name.cfg" -UseIWR).Content -Raw}
                           Else                                                 {Throw [ApplicationException]::New('Unavailable. (Offline mode)')}

        If (!(Test-LoadOrderFormat $Content -ShowInfo -ContinueOnError)) {Throw 'Invalid load order data'}
        [Hashtable]$LoadOrderData = Get-ModData $Content

        If     ($Data.IsPresent -And $Raw.IsPresent)  {Return $LoadOrderData, $Content}
        ElseIf ($Data.IsPresent -And !$Raw.IsPresent) {Return $LoadOrderData}
        ElseIf (!$Data.IsPresent -And $Raw.IsPresent) {Return $Content}
        Else                                          {Return}
    }

    Function Remove-InactiveMods {
        [CmdletBinding()]
        Param ()

        [UInt16]$DeletedTargets, [UInt64]$OldSize = 0, 0
        [IO.FileInfo[]]$EnabledFiles = ForEach ($Key in $G__LoadOrderData.Keys | Where-Object {$G__LoadOrderData[$_].Type -ne 'mod_workshop_package'}) {[IO.Path]::GetFileName($G__LoadOrderData[$Key].SourcePath)}
        [IO.FileInfo[]]$Targets = ForEach ($File in Get-ChildItem *.scs -File) {$OldSize += $File.Length; If ($File -NotIn $EnabledFiles -And (($File.Name -In $G__OnlineData.PSObject.Properties.Name -And $G__DDSel -eq 1) -Or $G__DDSel -eq 2)) {$File}}

        If (!$Targets) {Write-Host "`n No mods to delete."; Return}

        [Byte]$TargetPadding = ($Targets.Name | Sort-Object Length)[-1].Length + 8

        Write-Host "`n Deleting $($Targets.Count) inactive $(Switch-GrammaticalNumber 'mod' $Targets.Count):"

        ForEach ($Target in $Targets) {
            Write-Host -NoNewline ('    ' + "'$($Target.Name)'...".PadRight($TargetPadding))
            
            Try {
                $Target.Delete()
                $DeletedTargets++

                Write-Log INFO "Deleted inactive mod '$($Target.FullName)'"
                Write-Host -ForegroundColor Green 'Deleted'
            }
            Catch {
                Write-Log WARN "Failed to delete mod '$($Target.FullName)': $($_.Exception.Message)"
                Write-Host -ForegroundColor Red 'Failed to delete'
            }
        }
        [String]$DeletionResult = Switch ($OldSize - (Get-ItemPropertyValue *.scs Length | Measure-Object -Sum).Sum) {
            {[Math]::Abs($_) -lt 1024}   {"$_ B"; Break}
            {[Math]::Abs($_) -lt 1024kB} {"$([Math]::Round($_ / 1kB, 1)) kB"; Break}
            {[Math]::Abs($_) -lt 1024MB} {"$([Math]::Round($_ / 1MB, 1)) MB"; Break}
            {[Math]::Abs($_) -ge 1024MB} {"$([Math]::Round($_ / 1GB, 2)) GB"; Break}
        }
        $DeletionResult = "Deleted $DeletedTargets inactive $(Switch-GrammaticalNumber 'mod' $DeletedTargets) ($DeletionResult)"
        Write-Log INFO $DeletionResult
        Write-Host -ForegroundColor Green " $DeletionResult"
    }

    Function Select-LoadOrder {
        [CmdletBinding()]
        Param ()

        If (!$G__AllLoadOrders -Or $G__AllLoadOrders.Count -le 1) {
            Write-Log WARN 'No load orders detected. Aborting selection and using the current load order.'
            Return $G__LoadOrder
        }

        Write-Log INFO 'Displaying load order selection prompt'

        Clear-Host
        Write-Host ' SELECT MOD LOAD ORDER'
        Write-Host ($G__UILine * [Console]::BufferWidth)

        [Byte]$Selected                                   = (0, $G__AllLoadOrders.IndexOf($G__LoadOrder))[$G__LoadOrder -In $G__AllLoadOrders]
        [String]$PreviousLoadOrder                        = $G__LoadOrder
        [Management.Automation.Host.Coordinates]$StartPos = $Host.UI.RawUI.CursorPosition

        Do {
            $Host.UI.RawUI.CursorPosition = $StartPos
            [Byte]$Iteration              = 0

            ForEach ($Order in $G__AllLoadOrders) {
                [Bool]$IsSelected = $Iteration -eq $Selected

                Write-Host -NoNewline ' '
                Write-HostX 0 -Color ("DarkGray", "Green")[$IsSelected] (' ' + ('   ', '>> ')[$IsSelected] + "$Order ") -Newline

                $Iteration++
            }

            Write-Host -NoNewline "`n * Use the "
            Write-Host -NoNewline -ForegroundColor Cyan '[UP]'
            Write-Host -NoNewline ' and '
            Write-Host -NoNewline -ForegroundColor Cyan '[DOWN]'
            Write-Host -NoNewline " keys to select a load order.`n * Press "
            Write-Host -NoNewline -ForegroundColor Cyan '[ENTER]'
            Write-Host -NoNewline ' to confirm your selection, or '
            Write-Host -NoNewline -ForegroundColor Cyan '[ESC]'
            Write-Host ' to cancel.'

            [String]$SelectedLoadOrder = $G__AllLoadOrders[$Selected]
            Write-Log INFO "Selection set: '$SelectedLoadOrder'"

            Do {
                [Bool]$UpdateSelection = $False
                Switch (Read-KeyPress -Clear) {
                    13 { # [ENTER]
                        [String]$ConfirmedSelection = ($PreviousLoadOrder, $SelectedLoadOrder)[$SelectedLoadOrder -ne $PreviousLoadOrder]
                        Write-Log INFO "Selection confirmed: '$ConfirmedSelection'"
                        Clear-Host
                        Return $ConfirmedSelection
                    }
                    27 { # [ESC]
                        Write-Log INFO "Selection cancelled. Reverting to previous value: '$PreviousLoadOrder'"
                        Clear-Host
                        Return $PreviousLoadOrder
                    }
                    38 { # [UP]
                        If ($Selected -gt 0) {$Selected--} Else {[Console]::Beep(1000, 150)}
                        $UpdateSelection = $True
                        Break
                    }
                    40 { # [DOWN]
                        If ($Selected -lt $G__AllLoadOrders.Count - 1) {$Selected++} Else {[Console]::Beep(1000, 150)}
                        $UpdateSelection = $True
                        Break
                    }
                    Default {Continue}
                }
            } Until ($UpdateSelection)
        } While ($True)
    }

    Function Set-ActiveLoadOrder {
        [CmdletBinding()]
        Param ([Parameter(Mandatory)][String]$LoadOrder)

        If ($LoadOrder -ne $G__LoadOrder) {
            Write-EmbeddedValue $G__DataIndices.LoadOrder $LoadOrder
            Write-Log INFO "Active load order changed from '$G__LoadOrder' to '$LoadOrder'"

            Return $LoadOrder
        }
        Return $G__LoadOrder
    }

    Function Get-LoadOrderList {
        [CmdletBinding()]
        Param ()

        If ($G__OfflineMode) {
            Write-Log WARN "Can't fetch load orders in offline mode"
            Return [String[]]@($G__LoadOrder)
        }
        [String[]]$LoadOrderList = (Get-ModRepoFile $G__RepositoryInfo.Orders -UseIWR).Content | ConvertFrom-JSON
        Write-Log INFO "Fetched available load orders ($($LoadOrderList.Count)) from master server"

        Return $LoadOrderList
    }

    Function Test-LoadOrderFormat {
        [CmdletBinding()]
        Param ([Parameter(Position = 0)][String]$Content, [Switch]$ShowInfo, [Switch]$ContinueOnError, [Switch]$ReturnInfo)

        [Regex]$HeaderValidationExpr = '(?-i)^ ?active_mods: ?\d+$(?i)'
        [Regex]$FormatValidationExpr = '(?-i)^ ?active_mods\[\d+\]: ?"(?:mod_workshop_package\.00000000[0-9A-F]{8}|[\w\- ]+)\|.+"$'
        [Regex]$TotalValueExpr       = '(?<=(?-i)^ ?active_mods(?i): ?)\d+(?=$)'
        [Regex]$IndexValueExpr       = '(?<=(?-i)^ ?active_mods(?i)\[)\d+(?=\]:)'

        [Hashtable]$WhXSplat = @{
            X       = 0
            Color   = [ConsoleColor]::Red
            Newline = $True
        }
        [Byte]$IndexModifier = 2
        [Bool]$IsValid       = $True
        [String[]]$Failures  = @()

        Try {
            [String]$Header, [String]$RawData = $Content -Split "`n", 2
            [String[]]$Data                   = $RawData -Split "`n"

            # Check header
            If ($Header -NotMatch $HeaderValidationExpr) {
                [String]$FailureMessage = "$Name : Invalid header format '$Header'"
                $Failures += $FailureMessage

                Write-Log ERROR $FailureMessage
                If ($ShowInfo.IsPresent)        {Write-HostX @WhXSplat $FailureMessage}
                If ($ContinueOnError.IsPresent) {$IsValid = $False} Else {Throw [ApplicationException]::New($FailureMessage)}
            }
            # Match expected entries with actual entries
            [UInt16]$ExpectedCount = Switch ([Regex]::Match($Header, $TotalValueExpr).Value) {
                {[UInt16]::TryParse($_, [Ref]$Null)} {[UInt16]::Parse($_); Break}
                Default {
                    [String]$FailureMessage = "$Name : Can't parse header mod count '$_' from '$Header'"
                    $Failures += $FailureMessage

                    Write-Log ERROR $FailureMessage
                    If ($ShowInfo.IsPresent)        {Write-HostX @WhXSplat $FailureMessage}
                    If ($ContinueOnError.IsPresent) {$IsValid = $False} Else {Throw [ApplicationException]::New($FailureMessage)}
                }
            }
            If ($Data.Count -ne $ExpectedCount) {
                [String]$FailureMessage = "$Name : Invalid mod count. Expected '$ExpectedCount', got '$($Data.Count)'"
                $Failures += $FailureMessage

                Write-Log ERROR $FailureMessage
                If ($ShowInfo.IsPresent)        {Write-HostX @WhXSplat $FailureMessage}
                If ($ContinueOnError.IsPresent) {$IsValid = $False} Else {Throw [ApplicationException]::New($FailureMessage)}
            }

            # Check formatting and indices
            For ([UInt16]$Index = 0; $Index -lt $Data.Count; $Index++) {

                [UInt16]$Line       = $Index + $IndexModifier
                [String]$Entry      = $Data[$Index]
                [UInt16]$EntryIndex = Switch ([Regex]::Match($Entry, $IndexValueExpr).Value) {
                    {[UInt16]::TryParse($_, [Ref]$Null)} {[UInt16]::Parse($_); Break}
                    Default {
                        [String]$FailureMessage = "$Name ($Line): Can't parse entry index '$_' from '$Entry'"
                        $Failures += $FailureMessage

                        Write-Log ERROR $FailureMessage
                        If ($ShowInfo.IsPresent)        {Write-HostX @WhXSplat $FailureMessage}
                        If ($ContinueOnError.IsPresent) {$IsValid = $False} Else {Throw [ApplicationException]::New($FailureMessage)}
                    }
                }

                If ($EntryIndex -ne $Index) {
                    [String]$FailureMessage = "$Name ($Line): Expected index $Index but received $EntryIndex"
                    $Failures += $FailureMessage

                    Write-Log ERROR $FailureMessage
                    If ($ShowInfo.IsPresent)        {Write-HostX @WhXSplat $FailureMessage}
                    If ($ContinueOnError.IsPresent) {$IsValid = $False} Else {Throw [ApplicationException]::New($FailureMessage)}
                }

                If ($Entry -NotMatch $FormatValidationExpr) {
                    [String]$FailureMessage = "$Name ($Line): Malformed entry '$Entry'"
                    $Failures += $FailureMessage

                    Write-Log ERROR $FailureMessage
                    If ($ShowInfo.IsPresent)        {Write-HostX @WhXSplat $FailureMessage}
                    If ($ContinueOnError.IsPresent) {$IsValid = $False} Else {Throw [ApplicationException]::New($FailureMessage)}
                }
            }
        }
        Catch {
            If ($_.Exception -IsNot [ApplicationException]) {
                [String]$FailureMessage = "$Name : " + $_.Exception.Message
                $Failures += $FailureMessage

                Write-Log ERROR $FailureMessage
                If ($ShowInfo.IsPresent) {Write-HostX @WhXSplat $FailureMessage}
            }
            Return ($False, $Failures)[$ReturnInfo.IsPresent]
        }
        If (!$IsValid) {Write-Log ERROR "$Name : INVALID - Failed to validate load order format"}
        Else           {Write-Log INFO "$Name : SUCCESS - Successfully validated load order format"}

        Return ($IsValid, $Failures)[$ReturnInfo.IsPresent]
    }

    Function Get-FilePathByDialog {
        [CmdletBinding(DefaultParameterSetName = 'Open')]
        Param (
            [Parameter(Mandatory, ParameterSetName = 'Open')][Switch]$Mode,
            [Parameter(Mandatory, ParameterSetName = 'Save')][Switch]$Save,
            [Parameter(Position = 0)][String]$Title     = 'Select file',
            [Parameter(Position = 1)][String]$Filter    = 'All files (*.*)|*.*',
            [Parameter(Position = 2)][String]$File      = '',
            [Parameter(Position = 3)][String]$Directory = $G__GameRootDirectory.Fullname,
            [Parameter(ParameterSetName = 'Open')][Switch]$MultiSelect,
            [Parameter(ParameterSetName = 'Save')][Switch]$NoOverwritePrompt,
            [Parameter(ParameterSetName = 'Save')][Switch]$CreatePrompt,
            [Parameter(ParameterSetName = 'Save')][Switch]$NoPathCheck
        )

        If ($PSCmdlet.ParameterSetName -eq 'Save') {
            [Windows.Forms.SaveFileDialog]$Browser = @{
                CheckPathExists  = !$NoPathCheck.IsPresent
                CreatePrompt     = $CreatePrompt.IsPresent
                OverwritePrompt  = !$NoOverwritePrompt.IsPresent
                FileName         = $File
                InitialDirectory = $Directory
                Filter           = $Filter
                Title            = $Title
            }
        }
        Else {
            [Windows.Forms.OpenFileDialog]$Browser = @{
                FileName         = $File
                InitialDirectory = $Directory
                Filter           = $Filter
                Multiselect      = $MultiSelect.IsPresent
                Title            = $Title
            }
        }

        Write-Log INFO "Displaying $($PSCmdlet.ParameterSetName)FileDialog '$Title'"

        [String]$DialogInteraction = $Browser.ShowDialog()

        Write-Log INFO "$($PSCmdlet.ParameterSetName)FileDialog interaction: '$DialogInteraction', FileName: '$($Browser.FileName)'"
        
        If ($DialogInteraction -eq 'OK') {
            [IO.FileInfo]$FileSelection = $Browser.FileName
            Return $FileSelection
        }
    }

    Function Assert-TSSENamingScheme {
        [CmdletBinding()]
        Param ()

        Write-Log INFO 'Searching for TS SE Tool directory.'
        [String]$RootName         = $G__TSSETool.RootDirectory.Name
        [String]$Executable       = $G__TSSETool.Executable.Name
        [IO.DirectoryInfo]$Target = (Get-ChildItem $G__GameRootDirectory.FullName -Include $Executable -File -Recurse -Depth 2 | Sort-Object LastWriteTime -Descending)[0].Directory

        If ([String]::IsNullOrWhiteSpace($Target)) {Write-Log WARN "    Unable to locate TS SE Tool directory. Using '$RootName'"; Return $RootName}
        If ($Target.Name -eq $RootName)            {Write-Log INFO "    Success: '$RootName'"; Return $RootName}
        Write-Log INFO "    Success: '$($Target.FullName)'"
        Try {
            Rename-Item $Target.FullName $RootName
            Write-Log INFO "Renamed '$($Target.FullName)' to '$RootName'"
            Return $RootName
        }
        Catch {
            Write-Log WARN "Failed to rename '$($Target.FullName)' to '$RootName': $($_.Exception.Message)"
            Return $Target.Name
        }
    }

    Function Get-RepositoryInfo {
        [CmdletBinding()]
        Param ([String]$RepoURL = $G__RepositoryURL)

        Try   {[PSObject]$RepoData = (Get-ModRepoFile information.json -Repository $RepoURL -UseIWR).Content | ConvertFrom-JSON}
        Catch {
            Write-Log WARN "Failed to retrieve repository information: $($_.Exception.Message)"
            Throw "Unable to communicate with master server '$RepoURL':`n    '$($_.Exception.Message)"
        }
        [UInt16]$Longest      = ($RepoData.PSObject.Properties.Name | Sort-Object Length)[-1].Length
        [String[]]$RepoLogMsg = ForEach ($Name in $RepoData.PSObject.Properties.Name) {$Name + (' ' * ($Longest - $Name.Length)) + ' = ' + $RepoData.$Name}

        Write-Log INFO "Retrieved repository information from '$RepoURL':`n    $($RepoLogMsg -Join "`n    ")"
        Return $RepoData
    }

    Function Remove-ExpiredLogs {
        [CmdletBinding()]
        Param ([SByte]$Days = $G__LogRetentionDays)

        [IO.FileInfo[]]$TextFiles = Get-ChildItem "$($G__GameModDirectory.FullName)\*.txt" -File
        [IO.FileInfo[]]$LogFiles  = ForEach ($File in $TextFiles) {
            If ([Regex]::IsMatch($File.Name, "^$G__SessionID\.log\.txt$")) {Continue}
            If ([Regex]::IsMatch($File.Name, '^[A-F0-9]{8}\.log\.txt$')) {
                [DateTime]$Threshold = (Get-Date).AddDays($Days * -1)
                If     ($Days -le 0)                        {Write-Log INFO "Detected expired log '$($File.Name)'"; $File}
                ElseIf ($File.LastWriteTime -lt $Threshold) {Write-Log INFO "Detected expired log '$($File.Name)'"; $File}
            }
        }

        If ($LogFiles.Count -eq 0) {Write-Log INFO 'No old logs to delete'; Return 0}

        [UInt16]$DeletionCount = 0

        ForEach ($Log in $LogFiles) {
            Try {
                [Double]$TimePastRetention = [Math]::Round(((Get-Date).AddDays(-$Days) - $Log.LastWriteTime).TotalDays, 3)
                Remove-Item $Log.FullName -Force
                $DeletionCount++
                Write-Log INFO "Deleted log '$($Log.Name)' ($TimePastRetention d days past retention)"
            }
            Catch {Write-Log WARN "Failed to delete log '$($Log.Name)' ($TimePastRetention d past retention): $($_.Exception.Message)"}
        }

        If ($DeletionCount -lt $LogFiles.Count) {Write-Log WARN "Failed to delete $($LogFiles.Count - $DeletionCount) log(s)"}

        Return $DeletionCount
    }

    Write-Host -ForegroundColor Green "OK - $([Int](New-TimeSpan -Start $_Step -End (Get-Date)).TotalMilliseconds)ms`n"

    Write-Log INFO "Session started. Session ID: $G__SessionID"

    Trap {Wait-WriteAndExit ("`n`n FATAL ERROR`n " + (Format-AndExportErrorData $_))}

    $ErrorActionPreference = [Management.Automation.ActionPreference]::Stop
    $ProgressPreference    = [Management.Automation.ActionPreference]::SilentlyContinue

    $_Step = Get-Date
    Write-Host "$($_Tab * 3)Importing assemblies"
    [String[]]$AssList = @(
        'System.Windows.Forms',
        'System.IO.Compression.FileSystem',
        'System.Data.Entity.Design',
        'System.Net.Http',
        'PresentationCore',
        'PresentationFramework'
    )
    [Byte]$LongestAss   = (($AssList | ForEach-Object {$_ -Replace '^System\.', ''}) | Sort-Object Length)[-1].Length + 4
    [DateTime]$_StepAss = Get-Date

    ForEach ($Ass in $AssList) {
        Write-Host -NoNewline "$($_Tab * 5)$("$($Ass -Replace '^System\.', '')...".PadRight($LongestAss))"

        Add-Type -Assembly $Ass

        Write-Host -ForegroundColor Green "OK - $([Int](New-TimeSpan -Start $_StepAss -End (Get-Date)).TotalMilliseconds)ms"
        $_StepAss = Get-Date
    }
    Write-Host -NoNewline "$($_Tab * 5)$('Type Definitions...'.PadRight($LongestAss))"
    Add-Type 'using System; using System.Runtime.InteropServices; public class WndHelper {[DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);}'
    Write-Host -ForegroundColor Green "OK - $([Int](New-TimeSpan -Start $_StepAss -End (Get-Date)).TotalMilliseconds)ms"
    Remove-Variable AssList, LongestAss, Ass, _StepAss -ErrorAction SilentlyContinue

    Write-Host -ForegroundColor Green "$($_Tab * 5)$([Int](New-TimeSpan -Start $_Step -End (Get-Date)).TotalMilliseconds)ms"
    $_Step = Get-Date
    Write-Host "`n$($_Tab * 3)Initializing"
    Write-Host -NoNewline "$($_Tab * 5)Scope constraints... "

    Protect-Variables
    Write-Host -ForegroundColor Green "OK - $([Int](New-TimeSpan -Start $_Step -End (Get-Date)).TotalMilliseconds)ms"
    $_Step = Get-Date

    Write-Host -NoNewline "$($_Tab * 5)Global values...     "

    [Hashtable]$G__DataIndices = @{
        # ScriptVersion = 0  <-- Script version is ALWAYS the first embedded value (hardcoded)
        ActiveProfile   = 1
        StartGame       = 2
        ValidateInstall = 3
        DDSel           = 4
        NoProfileConfig = 5
        LoadOrder       = 6
        StartSaveEditor = 7
        RepositoryURL   = 8
        OfflineData     = 9
    }
    [IO.FileInfo]$G__ScriptPath = $PSCommandPath
    [String]$G__UILine          = [Char]0x2500
    [UInt16]$G__MinWndWidth     = 120
    [UInt16]$G__MinWndHeight    = 55
    [SByte]$G__LogRetentionDays = 0
    [Bool]$G__DeleteExpiredLogs = $True
    [Bool]$G__OfflineMode       = $False
    [Bool]$G__ClampAvailable    = 'Clamp' -In [String[]][Math].GetMethods().Name
    [Hashtable]$G__RI_RENGlobal = @{Force = $True; ErrorAction = 'SilentlyContinue'}

    [Security.Cryptography.SHA1CryptoServiceProvider]$G__CryptoProvider       = [Security.Cryptography.SHA1CryptoServiceProvider]::New()
    [Data.Entity.Design.PluralizationServices.PluralizationService]$G__PlrSvc = [Data.Entity.Design.PluralizationServices.PluralizationService]::CreateService((Get-EnglishCulture))

    [UInt32]$G__GameAppID                      = 227300
    [String]$G__GameName                       = 'Euro Truck Simulator 2'
    [String]$G__GameNameShort                  = 'ETS2'
    [String]$G__GameProcess                    = 'eurotrucks2'
    [IO.DirectoryInfo]$G__GameRootDirectory    = [IO.Path]::Combine([Environment]::GetFolderPath('MyDocuments'), $G__GameName)
    [IO.FileInfo]$G__GameLogPath               = "$($G__GameRootDirectory.FullName)\game.log.txt"
    [IO.FileInfo]$G__GameConfigPath            = "$($G__GameRootDirectory.FullName)\config.cfg"
    [IO.DirectoryInfo]$G__GameModDirectory     = "$($G__GameRootDirectory.FullName)\mod"
    [IO.DirectoryInfo]$G__WorkshopDirectory    = Get-GameDirectory -Workshop
    [IO.DirectoryInfo]$G__GameInstallDirectory = Get-GameDirectory -Root; [Void]$G__GameInstallDirectory # TODO: Remove the voided reference when $G__GameInstallDirectory is referenced properly

    Set-Location $G__GameModDirectory.FullName
    [IO.Directory]::SetCurrentDirectory($G__GameModDirectory.FullName)

    [Bool]$G__NoUpdate  = $False
    [Bool]$G__UpdateAll = $False

    Write-Host -ForegroundColor Green "OK - $([Int](New-TimeSpan -Start $_Step -End (Get-Date)).TotalMilliseconds)ms"
    $_Step = Get-Date

    If ($G__DeleteExpiredLogs) {
        Write-Host -NoNewline "$($_Tab * 5)Purging logs...      "
        [UInt16]$_RemovedLogs = Remove-ExpiredLogs
        Write-Host -ForegroundColor Green "OK - $([Int](New-TimeSpan -Start $_Step -End (Get-Date)).TotalMilliseconds)ms - $_RemovedLogs"
        $_Step = Get-Date
    }

    Write-Host "$($_Tab * 5)Persistent data"
    [Hashtable]$PersistentData = Read-AllEmbeddedValues

    Write-Host -NoNewline "$($_Tab * 7)ScriptVersion...   "
    [Version]$G__ScriptVersion = $PersistentData.ScriptVersion
    Write-Host -ForegroundColor Green "$G__ScriptVersion"

    Write-Host -NoNewline "$($_Tab * 7)DDSel...           "
    [Byte]$G__DDSel            = $PersistentData.DDSel
    Write-Host -ForegroundColor Green "$G__DDSel"

    Write-Host -NoNewline "$($_Tab * 7)ValidateInstall... "
    [Bool]$G__ValidateInstall  = $PersistentData.ValidateInstall
    Write-Host -ForegroundColor Green "$G__ValidateInstall"

    Write-Host -NoNewline "$($_Tab * 7)NoProfileConfig... "
    [Bool]$G__NoProfileConfig  = $PersistentData.NoProfileConfig
    Write-Host -ForegroundColor Green "$G__NoProfileConfig"

    Write-Host -NoNewline "$($_Tab * 7)StartGame...       "
    [Bool]$G__StartGame        = $PersistentData.StartGame
    Write-Host -ForegroundColor Green "$G__StartGame"

    Write-Host -NoNewline "$($_Tab * 7)LoadOrder...       "
    [String]$G__LoadOrder      = $PersistentData.LoadOrder
    Write-Host -ForegroundColor Green "$G__LoadOrder"

    Write-Host -NoNewline "$($_Tab * 7)StartSaveEditor... "
    [Bool]$G__StartSaveEditor  = $PersistentData.StartSaveEditor
    Write-Host -ForegroundColor Green "$G__StartSaveEditor"

    Write-Host -NoNewline "$($_Tab * 7)RepositoryURL...   "
    [String]$G__RepositoryURL  = $PersistentData.RepositoryURL
    Write-Host -ForegroundColor Green "$G__RepositoryURL"

    Write-Host -NoNewline "$($_Tab * 7)OfflineData...     "
    [String]$G__OfflineData    = $PersistentData.OfflineData
    Write-Host -ForegroundColor Green 'OK'

    Write-Host -NoNewline "$($_Tab * 7)ActiveProfile...   "
    Write-Host -ForegroundColor Green "$($PersistentData.ActiveProfile)"

    Write-Host -ForegroundColor Green "$($_Tab * 7)$([Int](New-TimeSpan -Start $_Step -End (Get-Date)).TotalMilliseconds)ms"
    $_Step = Get-Date

    Write-Host -NoNewline "`n$($_Tab * 5)Console and Environment... "

    If (!(Test-PSHostCompatibility)) {Wait-WriteAndExit (" Startup aborted - Incompatible console host.`n Current host '" + $Host.Name + "' does not support required functionality.")}

    [Console]::CursorVisible     = $False
    [Console]::Title             = "$G__GameNameShort External Mod Manager v$G__ScriptVersion"
    [UInt16]$WndX, [UInt16]$WndY = [Console]::WindowWidth, [Console]::WindowHeight
    [UInt16]$G__WndWidth         = ($WndX, $G__MinWndWidth)[$WndX -lt $G__MinWndWidth]
    [UInt16]$G__WndHeight        = ($WndY, $G__MinWndHeight)[$WndY -lt $G__MinWndHeight]

    [Console]::SetWindowSize($G__WndWidth, $G__WndHeight)
    
    If (!$G__GameModDirectory.Exists)                    {Wait-WriteAndExit " Startup aborted - Cannot locate the $G__GameNameShort mod directory:`n     '$($G__GameModDirectory.FullName)' `n Verify that $G__GameName is correctly installed and try again."}
    If ($PSScriptRoot -ne $G__GameModDirectory.FullName) {
        If (!(Move-SelfToModDirectory)) {Wait-WriteAndExit "Startup aborted - Invalid script location.`n Unable to fix automatically.`n '$($G__ScriptPath.FullName)' must be manually placed in '$G__GameModDirectory' to run."}
        Else                            {Exit}
    }
    
    Write-Host -ForegroundColor Green "OK - $([Int](New-TimeSpan -Start $_Step -End (Get-Date)).TotalMilliseconds)ms"
    $_Step = Get-Date

    Write-Host -NoNewline "$($_Tab * 5)Repo and Game Data...      "
    If ([String]::IsNullOrEmpty($G__RepositoryURL) -Or $G__RepositoryURL -eq 'http://your.domain/repo') {
        Write-Log WARN 'No repository URL specified. Prompting for input.'
        Do {
            [Console]::SetCursorPosition(0, 10)
            [String]$URL = Read-Host ' Enter mod repository URL:'
            Try   {
                [PSObject]$G__RepositoryInfo = Get-RepositoryInfo -RepoURL $URL -ErrorAction Stop
                Break
            }
            Catch {Write-Host -ForegroundColor Red ' No valid repository data found. Please try again.'; Start-Sleep 2}
        } While ($True)

        $G__RepositoryURL = $URL

        Write-EmbeddedValue $G__DataIndices.RepositoryURL $G__RepositoryURL
        Write-Log INFO "Repository URL set to '$G__RepositoryURL'"
    }
    Else {
        Try {
            [PSObject]$G__RepositoryInfo = Get-RepositoryInfo
            Try {
                [String]$RepositoryInfoString = $G__RepositoryInfo | ConvertTo-JSON -Compress
                If ([String]::IsNullOrEmpty($RepositoryInfoString)) {
                    $RepositoryInfoString = '{}'
                    Throw 'No repository data.'
                }
                $G__OfflineData = $RepositoryInfoString
                Write-EmbeddedValue $G__DataIndices.OfflineData $RepositoryInfoString
                Write-Log INFO "Updated offline repository information:`n    $RepositoryInfoString"
            }
            Catch {
                Write-Log WARN "Failed to update offline repository information:`n    $($_.Exception.Message)"
                Throw
            }
        }
        Catch {
            $G__OfflineMode              = $True
            $G__NoUpdate                 = $True
            [PSObject]$G__RepositoryInfo = $G__OfflineData | ConvertFrom-JSON

            If ([String]::IsNullOrEmpty($G__RepositoryInfo)) {
                Write-Log ERROR 'No offline data available. Terminating session.'
                Wait-WriteAndExit ' Unable to retrieve repository information. No offline data available.'
            }
            Write-Host -ForegroundColor Yellow ' Unable to retrieve repository information. Using cached data. Some features may be limited or unavailable.'
            Wait-KeyPress ' ' -Clear
        }
    }

    [Bool]$GLOBAL:G__ScriptRestart = ($GLOBAL:G__ScriptRestart, $False)[$Null -eq $GLOBAL:G__ScriptRestart]
    [ScriptBlock]$G__EXEC_RESTART  = {If ($GLOBAL:G__ScriptRestart -eq $True) {Unprotect-Variables; Remove-Variable G__ScriptRestart -Scope GLOBAL -ErrorAction SilentlyContinue; Return ''}}

    [String]$G__ActiveProfile         = Get-ActiveProfile
    [IO.DirectoryInfo]$G__ProfilePath = "$($G__GameRootDirectory.FullName)\profiles\$G__ActiveProfile"
    [IO.FileInfo]$G__ProfileUnit      = "$($G__ProfilePath.FullName)\profile.sii"
    [IO.FileInfo]$G__TempProfileUnit  = "$Env:TEMP\profile.sii"
    [String]$G__ActiveProfileName     = Convert-ProfileFolderName
    [Bool]$G__DeleteDisabled          = $G__DDSel -ne 0
    [String[]]$G__AllLoadOrders       = Get-LoadOrderList

    If ([IO.Path]::GetExtension($G__LoadOrder) -ne '.order' -And $G__LoadOrder -NotIn $G__AllLoadOrders -And !$G__OfflineMode) {
        Write-Log WARN "The active load order '$G__LoadOrder' is not present in the repository. Applying fallback load order."
        $G__LoadOrder = Set-ActiveLoadOrder $G__RepositoryInfo.DefaultOrder
    }
    Write-Host -ForegroundColor Green "OK - $([Int](New-TimeSpan -Start $_Step -End (Get-Date)).TotalMilliseconds)ms"
    $_Step = Get-Date

    Write-Host -NoNewline "$($_Tab * 5)TS SE Tool Information...  "
    [Hashtable]$G__TSSETool = @{
        RootDirectory = [IO.DirectoryInfo]"$($G__GameRootDirectory.FullName)\TS SE Tool"
        Archive       = [IO.FileInfo]$G__RepositoryInfo.TSSE
        Executable    = [IO.FileInfo]"$($G__GameRootDirectory.FullName)\TS SE Tool\TS SE Tool.exe"
        Name          = 'TS SE Tool'
    }

    Switch (Assert-TSSENamingScheme) {
        Default {
            $G__TSSETool['RootDirectory'] = [IO.DirectoryInfo]"$($G__GameRootDirectory.FullName)\$_"
            $G__TSSETool['Executable']    = [IO.FileInfo]"$($G__GameRootDirectory.FullName)\$_\TS SE Tool.exe"
            $G__TSSETool['Installed']     = $G__TSSETool.Executable.Exists
        }
    }
    Write-Host -ForegroundColor Green "OK - $([Int](New-TimeSpan -Start $_Step -End (Get-Date)).TotalMilliseconds)ms"
    $_Step = Get-Date

    Write-Host -NoNewline "$($_Tab * 5)Script Information...      "
    [Hashtable]$G__ScriptDetails = @{
        Author      = 'RainBawZ'
        Copyright   = [Char]0x00A9 + (Get-Date -Format yyyy)
        Title       = "$G__GameName External Mod Manager"
        ShortTitle  = 'ETS2ExtModMan'
        Version     = "Version $G__ScriptVersion"
        VersionDate = '2024.10.24'
        GitHub      = 'https://github.com/RainBawZ/ETS2ExternalModManager/'
        Contact     = 'Discord - @realtam'
    }
    [String[]]$G__UpdateNotes = @(
        '3.6.1',
        '- Added detailed information to loading screen.',
        '- Fixed issue causing empty active load order exports.',
        '- Fixed issue causing script slowdowns if the log file gets too big. Logs now generate per session.',
        '- Improved loading times.',
        '- Improved event logging.',
        '- Stability improvements.'
    )
    [String[]]$G__KnownIssues = @()

    Write-Host -ForegroundColor Green "OK - $([Int](New-TimeSpan -Start $_Step -End (Get-Date)).TotalMilliseconds) ms"
    Write-Host -ForegroundColor Green "`n$($_Tab * 4)Loading complete. ($([Int](New-TimeSpan -Start $_LoadTime -End (Get-Date)).TotalSeconds) sec.)"

    Write-Log INFO "Loading complete. Time to load was $([Int](New-TimeSpan -Start $_LoadTime -End (Get-Date)).TotalMilliSeconds) seconds."
    Remove-Variable _Step, _LoadTime, _Tab, _RemovedLogs -Scope GLOBAL -ErrorAction SilentlyContinue

    Update-ProtectedVars

    Start-Sleep 1

    . $G__EXEC_RESTART

    If (!$Updated) {
        [Byte]$Padding = 15

        Clear-Host
        Write-Host " Checking $($G__ScriptDetails.ShortVersion) version...`n"
        Write-Host (' ' + 'Installed'.PadRight($Padding) + 'Current'.PadRight($Padding) + 'Status')
        Write-Host ($G__UILine * [Console]::BufferWidth)
        Write-Host -NoNewline (' ' + "$G__ScriptVersion".PadRight($Padding))

        Try {
            [Byte[]]$UpdateBytes     = (Get-ModRepoFile $G__RepositoryInfo.Script -UseIWR).Content
            [String[]]$UpdateContent = Get-UTF8Content -FromBytes $UpdateBytes

            ForEach ($Key in $G__DataIndices.Keys) {
                [String]$Value         = Get-Variable "G__$Key" -ValueOnly
                [UInt32]$Index         = $G__DataIndices.$Key
                $UpdateContent[$Index] = New-EmbeddedValue $UpdateContent[$Index] $Value
            }

            [String]$UpdateVersion = Switch (Read-EmbeddedValue 0 -CustomData $UpdateContent) {Default {('0.0.0.0', $_)[[Bool]($_ -As [Version])]}}

            If ([Version]$UpdateVersion -gt $G__ScriptVersion) {
                [ConsoleColor]$VersionColor, [String]$VersionText, [String]$ReturnValue = (("Green", $UpdateVersion, 'Updated'), ("Red", 'Parsing error', 'Repaired'))[$UpdateVersion -eq '0.0']

                Write-Host -NoNewline -ForegroundColor $VersionColor $VersionText.PadRight($Padding)
                
                Set-UTF8Content $G__ScriptPath $UpdateContent -NoNewline

                Unprotect-Variables

                Return $ReturnValue
            }
            Else {
                Write-Host -NoNewline $UpdateVersion.PadRight($Padding)
                Write-Host -ForegroundColor Green 'Up to date'
            }
            Write-Host "`n"
        }
        Catch {
            Write-Host -ForegroundColor Red (Format-AndExportErrorData $_)
            Write-Host "`n"
            Wait-KeyPress ' Press any key to continue.' -Clear
            Clear-Host
        }
    }
    ElseIf ($Updated -ne 'Restart') {
        Write-Host -ForegroundColor Green $Updated
        Write-Host ("`n What's new:`n   " + ($G__UpdateNotes -Join "`n   ") + "`n")
        If ($G__KnownIssues) {Write-Host ("`n Known issues:`n   " + ($G__KnownIssues -Join "`n   ") + "`n")}
        Wait-KeyPress ' Press any key to continue.' -Clear
        Clear-Host
    }

    Remove-UnprotectedVars

    If ($Updated -ne 'Restart') {
        Show-LandingScreen
        Clear-HostFancy 19 0 10
    }
    Else {Remove-Variable Updated -ErrorAction SilentlyContinue}
    [Bool]$Save = $False
    While ($True) {If ((Invoke-Expression (Invoke-Menu -Saved:$Save)) -eq 'Menu') {Return 'Restart'}}

    Remove-Variable Save -ErrorAction SilentlyContinue
    Try {
        [Hashtable]$G__LoadOrderData, [String]$G__LoadOrderText = Get-LoadOrderData -Raw -Data
        [UInt16]$G__ActiveModsCount  = (($G__LoadOrderText -Split "`n", 2)[0] -Split ':', 2)[-1].Trim()
        [String[]]$G__ActiveModFiles = $G__LoadOrderData.GetEnumerator() | ForEach-Object {[IO.Path]::GetFileName($_.Value.SourcePath) | Where-Object {[IO.Path]::GetExtension($_) -eq '.scs'}}
        Update-ProtectedVars
    }
    Catch [ApplicationException] {}

    Clear-Host
    Write-Host "`n    $($G__ScriptDetails['Title'])   v$G__ScriptVersion`n"
    Write-Host ($G__UILine * [Console]::BufferWidth)

    If ($G__NoUpdate) {
        Edit-ProfileLoadOrder

        Write-Host -ForegroundColor Green "`n Done`n"
        Write-Log INFO 'Session complete. Waiting for user input.'
        Wait-KeyPress
        Unprotect-Variables

        Write-Log INFO 'Exiting session.'

        Return
    }

    Write-Log INFO 'Update init : Preparing mod update routine.'

    [PSObject]$G__OnlineData    = [PSObject]::New()
    [Byte]$Failures             = 0
    [Byte]$Invalids             = 0
    [Byte]$Successes            = 0
    [Byte]$LongestName          = 3
    [Byte]$TotalMods            = 0
    [Byte]$ModCounter           = 0
    [Byte]$L_LongestVersion     = 9
    [Byte]$E_LongestVersion     = 7
    [Int64]$DownloadedData      = 0
    [String[]]$NewVersions      = @()
    [String[]]$PreviousProgress = @()
    [Hashtable]$LocalMods       = @{}

    Try {
        Write-Log INFO "Update init : Fetching version data ('$($G__RepositoryInfo.VersionData)') from repository."
        $G__OnlineData = (Get-ModRepoFile $G__RepositoryInfo.VersionData -UseIWR).Content | ConvertFrom-JSON
        Write-Log INFO 'Update init : Version data fetched successfully.'
    }
    Catch {Wait-WriteAndExit (" Unable to fetch version data from repository. Try again later.`n Reason: " + (Format-AndExportErrorData $_))}

    If ($G__ValidateInstall) {
        Start-Process "steam://validate/$G__GameAppID"
        Write-Log INFO 'Update init : Started game file integrity check (Steam).'
        Write-Host ' Started Steam game file validation.'
        Start-Sleep 1
        Set-ForegroundWindow -Self
    }

    Update-ProtectedVars

    [String[]]$Names    = @()
    [String[]]$Versions = @('Installed')

    If ([IO.File]::Exists('versions.txt')) {
        Write-Log INFO "Update init : Parsing local version data from 'versions.txt'"
        [UInt64]$Line = 0
        
        ForEach ($LocalVersionData in Get-UTF8Content versions.txt) {
            $Line++

            [String]$Name, [Version]$Ver = ($LocalVersionData -Split '=', 3)[0..1]
            If (Test-ArrayNullOrEmpty ($Name, $Ver)) {
                Try   {Throw "versions.txt[$Line]: Invalid data"}
                Catch {[Void](Format-AndExportErrorData $_)}
                Continue
            }
            [IO.FileInfo]$FileName = "$Name.scs"
            [String]$VerStr        = $Ver.ToString()
            
            $LocalMods[$Name] = [Hashtable]@{
                FileName   = $FileName.FullName
                Version    = $Ver
                VersionStr = $VerStr
            }
            $Names    += $Name
            $Versions += "$Ver"
        }
        Write-Log INFO "Update init : Local version data successfully parsed. Entries: $($LocalMods.Keys.Count)"
    }
    $TotalMods        = $G__OnlineData.PSObject.Properties.Value.Count
    $LongestName      = ($Names + $G__OnlineData.PSObject.Properties.Value.Name | Sort-Object Length)[-1].Length + 3
    $L_LongestVersion = ($Versions | Sort-Object Length)[-1].Length + 3
    $E_LongestVersion = (@('Current') + $G__OnlineData.PSObject.Properties.Value.VersionStr | Sort-Object Length)[-1].Length + 3

    If ([IO.File]::Exists('progress.tmp')) {
        $PreviousProgress = Get-UTF8Content progress.tmp
        Remove-Item progress.tmp -Force

        Write-Log INFO 'Update init : Previous session did not complete. Resuming previous session progress.'
    }

    Write-Log INFO 'Update init : Ready.'

    Write-Host ("Active profile: $G__ActiveProfileName, load order: $G__LoadOrder".PadLeft([Console]::BufferWidth - 1) + "`n" + $G__ActiveProfile.PadLeft([Console]::BufferWidth - 1))
    Write-Host (' ' + 'No.'.PadRight(8) + 'Mod'.PadRight($LongestName) + 'Installed'.PadRight($L_LongestVersion) + 'Current'.PadRight($E_LongestVersion) + 'Status')
    Write-Host ($G__UILine * [Console]::BufferWidth)

    Write-Log INFO 'Starting mod update routine.'
    ForEach ($CurrentMod in $G__OnlineData.PSObject.Properties.Value) {
        $ModCounter++
        
        $CurrentMod.Version   = [Version]$CurrentMod.Version
        [IO.FileInfo]$OldFile = 'old_' + $CurrentMod.FileName
        [Hashtable]$LocalMod  = $LocalMods.($CurrentMod.Name)
        [Byte]$Repair         = 0 # 0: No repair   1: Entry   2: File
        [String]$ModCountStr  = "$ModCounter".PadLeft(2) + "/$TotalMods"

        Write-Host -NoNewline (' ' + $ModCountStr.PadRight(8) + $CurrentMod.Title.PadRight($LongestName))

        [Byte]$StatusEval = ([Bool]$LocalMod.Version, [IO.File]::Exists($CurrentMod.FileName) | Group-Object | Where-Object {$_.Name -eq 'True'}).Count
        [String]$Status   = Switch ($StatusEval) {
            0 {'Installing...'; Write-Host -NoNewline '---'.PadRight($L_LongestVersion)}
            1 {'Repairing...';  $Repair = (2, 1)[[Bool]$LocalMod.Version]; Write-Host -NoNewline -ForegroundColor Red ('???', $LocalMod.VersionStr)[[Bool]$LocalMod.Version].PadRight($L_LongestVersion)}
            2 {'Updating...';   Write-Host -NoNewline $LocalMod.VersionStr.PadRight($L_LongestVersion)}
        }

        [ConsoleColor]$VersionColor = ("Green", "White")[($LocalMod.Version -ge $CurrentMod.Version)]
        Write-Host -NoNewline -ForegroundColor $VersionColor $CurrentMod.VersionStr.PadRight($E_LongestVersion)

        If ($CurrentMod.Name -In $PreviousProgress) {
            Write-Log INFO "'$($CurrentMod.Name)' : Skipped - Already processed."
            Write-Host -ForegroundColor Green 'Up to date'

            $NewVersions += ($CurrentMod.Name, $CurrentMod.VersionStr) -Join '='

            Continue
        }

        If ($CurrentMod.FileName -NotIn $G__ActiveModFiles -And !$G__UpdateAll) {
            Write-Log INFO "'$($CurrentMod.Name)' : Skipped - Not in load order."
            Write-Host -ForegroundColor DarkGray 'Skipped - Not in load order'

            If (!$G__DeleteDisabled) {$NewVersions += ($CurrentMod.Name, $CurrentMod.VersionStr) -Join '='}

            Continue
        }
        [UInt16]$XPos = [Console]::CursorLeft

        If ($LocalMod.Version -ge $CurrentMod.Version -Or $Repair -eq 2) {
            Write-Host -NoNewline ('Validating...', $Status)[[Bool]$Repair]

            If (!(Test-FileHash $CurrentMod.FileName $CurrentMod.Hash $CurrentMod.Size)) {
                If ($Repair -eq 0) {
                    Write-Log WARN "'$($CurrentMod.Name)' : Validation failed. Reinstalling."
                    Write-HostX $XPos -Color Red 'Validation failed.'
                    [String]$Status = 'Reinstalling...'

                    Start-Sleep 1
                }
                Try   {$LocalMod['Version'] = [Version]'0.0'}
                Catch {[Hashtable]$LocalMod = @{Version = [Version]'0.0'}}
            }
            Else {
                Write-Log INFO "'$($CurrentMod.Name)': $(('Up to date', 'Repaired')[[Bool]$Repair])"
                Write-HostX $XPos -Color Green ('Up to date', 'Repaired')[[Bool]$Repair] -Newline

                $NewVersions += ($CurrentMod.Name, $CurrentMod.VersionStr) -Join '='

                If ([Bool]$Repair) {$Successes++}

                Continue
            }
        }
        If ($LocalMod.Version -lt $CurrentMod.Version -Or [Bool]$Repair) {
            Try {
                Write-HostX $XPos 'Preparing...'
                If (!(Test-FileHash $CurrentMod.FileName $CurrentMod.Hash $CurrentMod.Size)) {
                    If (Test-ModActive $CurrentMod.Name) {Throw [IO.IOException]::New("Close $G__GameName to update this mod.")}

                    Write-Log INFO "'$($CurrentMod.Name)': Downloading."

                    If ([IO.File]::Exists($CurrentMod.FileName)) {
                        [UInt64]$OriginalSize = Get-ItemPropertyValue $CurrentMod.FileName Length
                        Rename-Item $CurrentMod.FileName $OldFile.Name @G__RI_RENGlobal
                    }
                    Else {[UInt64]$OriginalSize = 0}

                    [String]$Result, [UInt64]$NewSize, [String]$NewHash = Get-ModRepoFile $CurrentMod.FileName $XPos $Status $CurrentMod.Hash

                    $OldFile.Refresh()
                    If ($OldFile.Exists) {$OldFile.Delete()}

                    Switch ($Status) {
                        'Updating...'     {Write-HostX $XPos -Color Green "Updated        ($Result)" -Newline}
                        'Installing...'   {Write-HostX $XPos -Color Green "Installed      ($Result)" -Newline}
                        'Reinstalling...' {Write-HostX $XPos -Color Green "Reinstalled    ($Result)" -Newline}
                        'Repairing...'    {Write-HostX $XPos -Color Green "Repaired       ($Result)" -Newline}
                    }
                }
                Else {Write-HostX $XPos -Color Green 'Repaired       ' -Newline}

                Write-Log INFO "'$($CurrentMod.Name)': Processed successfully. $Result"
                
                Set-UTF8Content progress.tmp "$($CurrentMod.Name)" -Append

                $NewVersions    += ($CurrentMod.Name, $CurrentMod.VersionStr) -Join '='
                $DownloadedData += $NewSize - $OriginalSize
                $Successes++
            }
            Catch {
                If ($_.Exception -Is [IO.IOException]) {Write-Log WARN "'$($CurrentMod.Name)': Skipped - File in use by $G__GameName process."}
                Else                                   {Write-Log ERROR "'$($CurrentMod.Name)': Failed - $($_.Exception.Message)"}

                Write-HostX $XPos -Color Red ('Failed: ' + (Format-AndExportErrorData $_)) -Newline

                $OldFile.Refresh()
                If ([IO.File]::Exists($CurrentMod.FileName)) {Remove-Item $CurrentMod.FileName @G__RI_RENGlobal}
                If ($OldFile.Exists)                         {$OldFile.MoveTo($CurrentMod.FileName)}

                $NewVersions += ($CurrentMod.Name, $LocalMod.VersionStr) -Join '='
                $Failures++
            }
        }
    }
    If (!$G__TSSETool.RootDirectory.Exists) {
        Write-Log INFO "'$($G__TSSETool.Name)': $($G__TSSETool.Name) not detected in '$($G__TSSETool.RootDirectory.FullName)'. Installing."
        Write-Host -NoNewline (' ' + $G__TSSETool.Name.PadRight($LongestName) + '---'.PadRight($L_LongestVersion))
        Write-Host -NoNewline -ForegroundColor Green '---'.PadRight($E_LongestVersion)

        [UInt16]$XPos = [Console]::CursorLeft

        Write-Host -NoNewline -ForegroundColor Green 'Installing...'
        
        [Console]::SetCursorPosition($XPos, [Console]::CursorTop)

        Try {
            Write-Log INFO "'$($G__TSSETool.Name)': Downloading $($G__TSSETool.Name) archive '$($G__TSSETool.Archive.Name)'."
            [Void](Get-ModRepoFile $G__TSSETool.Archive.Name -UseIWR -Save)
            Write-Log INFO "'$($G__TSSETool.Name)': Downloaded archive to '$($G__TSSETool.Archive.FullName)'."

            $G__TSSETool.RootDirectory.Create()
            [System.IO.Compression.ZipFile]::ExtractToDirectory($G__TSSETool.Archive.FullName, $G__TSSETool.RootDirectory.FullName)
            Write-Log INFO "'$($G__TSSETool.Name)': Extracted archive '$($G__TSSETool.Archive.Name)' to directory '$($G__TSSETool.RootDirectory.FullName)'."

            If ($G__TSSETool.Archive.Exists) {$G__TSSETool.Archive.Delete()}
            $G__TSSETool['Installed'] = $True

            Write-Log INFO "'$($G__TSSETool.Name)': Installed successfully."
            Write-Host -ForegroundColor Green 'Installed          '
        }
        Catch {
            Write-Log ERROR "'$($G__TSSETool.Name)': Failed - $($_.Exception.Message)"
            Try {
                If ($G__TSSETool.Archive.Exists)       {$G__TSSETool.Archive.Delete()}
                If ($G__TSSETool.RootDirectory.Exists) {$G__TSSETool.RootDirectory.Delete()}
            }
            Catch {[Void](Format-AndExportErrorData $_)}
            $Failures++

            Write-Host -ForegroundColor Red 'Failed              '
        }
    }
    
    Set-UTF8Content versions.txt $NewVersions -NoNewline
    Write-Log INFO 'Updated versions.txt.'

    Remove-Item progress.tmp @G__RI_RENGlobal

    Write-Log INFO 'Cleared progress file.'
    Write-Host ($G__UILine * [Console]::BufferWidth)

    If ($G__DeleteDisabled)   {Remove-InactiveMods}
    If (!$G__NoProfileConfig) {Edit-ProfileLoadOrder}

    Write-Log INFO 'Finishing up.'

    [String]$DownloadedStr = Switch ($DownloadedData) {
        {[Math]::Abs($_) -lt 1024}   {"$_ B"; Break}
        {[Math]::Abs($_) -lt 1024kB} {"$([Math]::Round($_ / 1kB, 1)) kB"; Break}
        {[Math]::Abs($_) -lt 1024MB} {"$([Math]::Round($_ / 1MB, 1)) MB"; Break}
        {[Math]::Abs($_) -ge 1024MB} {"$([Math]::Round($_ / 1GB, 2)) GB"; Break}
    }
    If ($DownloadedData -gt 0) {$DownloadedStr = "+$DownloadedStr"}

    [String]$TotalStr = Switch ((Get-ItemPropertyValue *.scs Length | Measure-Object -Sum).Sum) {
        {$_ -lt 1024}   {"$_ B"; Break}
        {$_ -lt 1024kB} {"$([Math]::Round($_ / 1kB, 1)) kB"; Break}
        {$_ -lt 1024MB} {"$([Math]::Round($_ / 1MB, 1)) MB"; Break}
        {$_ -ge 1024MB} {"$([Math]::Round($_ / 1GB, 2)) GB"; Break}
    }

    [ConsoleColor]$ColorA = Switch ($Null) {{$Failures -eq 0} {"Green"} {$Failures -gt 0 -And $Successes -eq 0} {"Red"} {$Failures -gt 0 -And $Successes -gt 0} {"Yellow"}}
    [ConsoleColor]$ColorB = ("White", "Yellow", "Red")[[Math]::Min(2, [Math]::Ceiling($Invalids / 2))]
    [Hashtable]$TextColor = @{ForegroundColor = $ColorA}

    [String]$S_PluralMod, [String]$F_PluralMod, [String]$I_PluralMod = Switch-GrammaticalNumber 'mod' $Successes, $Failures, $Invalids
    
    Write-Host @TextColor "`n Done`n"

    If ($Successes + $Failures -eq 0) {Write-Host @TextColor " All mods up to date - $TotalStr"}
    If ($Successes -gt 0)             {Write-Host @TextColor "   $Successes $S_PluralMod processed successfully - $TotalStr ($DownloadedStr)"}
    If ($Failures -gt 0)              {Write-Host @TextColor "   $Failures $F_PluralMod failed to process"}
    If ($Invalids -gt 0)              {Write-Host -ForegroundColor $ColorB "   $Invalids $I_PluralMod failed to validate"}
    If ($Failures + $Invalids -gt 0)  {Write-Host @TextColor "`n Exit and restart the updater to try again"}
    
    Write-Host "`n"
    Write-Log INFO 'Session complete. Waiting for user input.'

    Wait-KeyPress " Press any key to$(('', " launch $G__GameNameShort $(('', "+ $($G__TSSETool.Name) ")[$G__StartSaveEditor])and")[$G__StartGame]) exit"
    If ($Successes + $Failures -eq 0 -And $G__StartGame) {
        If ($G__GameProcess -NotIn (Get-Process).Name) {
            Start-Process "steam://launch/$G__GameAppID"
            Write-Log INFO "Started $G__GameName."
        }
        If ($G__StartSaveEditor -And $G__TSSETool.Executable.Exists -And $G__TSSETool.Name -NotIn (Get-Process).Name) {
            Start-Process $G__TSSETool.Executable.FullName -WorkingDirectory $G__TSSETool.RootDirectory.FullName
            Write-Log INFO "Started $($G__TSSETool.Name)."
        }
    }
    Write-Log INFO 'Exiting session.'

    Unprotect-Variables
    Exit
}

#If (!$InputParam) {
    [String]$Out = $InputParam
    While ($True) {
        [String]$Out = Switch (Sync-Ets2ModRepo $Out) {
            {[String]::IsNullOrWhiteSpace($_)} {& $PSCommandPath; Break}
            {$Null -ne $_} {& $PSCommandPath "$_"; Break}
        }
    }
#}
<#Else {
    Switch (Sync-Ets2ModRepo -Updated $InputParam) {
        {[String]::IsNullOrWhiteSpace($_)}    {& $PSCommandPath; Break}
        {$Null -ne $_} {& $PSCommandPath "$_"; Break}
    }
}#>
