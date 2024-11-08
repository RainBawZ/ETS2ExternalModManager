#STR_version=3.7.0;
#STR_profile=015261696E4261775A;
#NUM_start=0;
#NUM_validate=0;
#NUM_purge=0;
#NUM_noconfig=0;
#STR_loadorder=Default;
#NUM_editor=0;
#STR_server=http://tams.pizza/ets2repo;
#STR_offlinedata={"Script":"ETS2ExtModMan.ps1","ETS2":{"DefaultOrder":"Default","Orders":"load_orders.json","VersionData":"versions.json"},"ATS":{"DefaultOrder":"ats/Default","Orders":"ats/load_orders.json","VersionData":"ats/versions.json"},"DefaultOrder":"Default","Orders":"load_orders.json","VersionData":"versions.json","DecFile":"sii_decrypt.exe","DecHash":"sii_decrypt.txt","TSSE":"TruckSaveEditor.zip"};
#NUM_logretention=0;
#NUM_experimental=33;
#STR_targetgame=ETS2;
#NUM_autobackup=1;
#PERSIST_END

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
# TODO: Add core mod management (dll/injector mods) - Install-CoreMod
# TODO: Implement Test-GameConfiguration
# TODO: Fix self-restart

Param (
    [Parameter(Position = 0)][String]$InputParam,
    [ValidateSet('ETS2', 'ATS')][String]$_Game
)

$G__OS = If ($Env:OS -Match 'Windows') {'Windows'} Else {'Linux'}

If (!$PSBoundParameters.ContainsKey('InputParam')) {
    [DateTime]$T__LoadTime = [DateTime]::Now
    [String]$G__SessionID  = (Get-FileHash -InputStream ([IO.MemoryStream]::New([Byte[]][Char[]]$T__LoadTime.ToString())) -Algorithm MD5).Hash.Substring(0, 8)
    $T__Message            = ' ' * [Math]::Max(0, [Math]::Floor(($Host.UI.RawUI.WindowSize.Width - $T__Message.Length) / 2) - $T__SessionStr.Length) + $T__Message
    [String]$T__Game       = $_Game

    If ($T__Game -NotIn 'ETS2', 'ATS') {
        [Collections.Generic.List[String]]$T__Data  = @()
        [Threading.CancellationTokenSource]$T__TSrc = [Threading.CancellationTokenSource]::New()
        [Collections.Generic.IAsyncEnumerable[String]]$T__Enm  = [IO.File]::ReadLinesAsync($PSCommandPath, $T__TSrc.Token)
        [Collections.Generic.IAsyncEnumerator[String]]$T__Feed = $T__Enm.GetAsyncEnumerator($T__TSrc.Token)
        Try {While ($T__Feed.MoveNextAsync().AsTask().Result -And !$T__TSrc.IsCancellationRequested) {
            If ($T__Feed.Current -eq '#PERSIST_END') {$T__TSrc.Cancel(); Break}
            Else                                     {$T__Data.Add($T__Feed.Current)} 
        }}
        Catch {[Collections.Generic.List[String]]$T__Data = @('#STR_targetgame=XXXX;')}
        Finally {
            If ($Null -ne $T__Feed) {[Void]$T__Feed.DisposeAsync()}
            If ($Null -ne $T__TSrc) {[Void]$T__TSrc.Dispose()}
            Remove-Variable T__TSrc, T__Enm, T__Feed -EA 0
        }
        Switch (($T__Data | Where-Object {$_ -Match '^#STR_targetgame=\w+;$'}) | ForEach-Object {[Regex]::Match($_, '(?<=^#STR_targetgame=)\w+(?=;$)').Value}) {
            {$_ -In 'ETS2', 'ATS'} {[String]$T__Game = $_; Break}
            Default {
                [String]$T__OSDependentPattern = ('(?<=\\Documents\\)[ \w]+(?=\\?)', '(?<=\/home\/)[ \w]+(?=\/?)')[$G__OS -eq 'Linux']
                [String]$T__Game = ([Regex]::Match($PSScriptRoot, $T__OSDependentPattern).Value -Split ' ' | ForEach-Object {$_[0]}) -Join ''
                If ($T__Game -NotIn 'ETS2', 'ATS') {
                    Try {[Console]::CursorVisible = $True} Catch {}
                    Write-Host -NoNewline -ForegroundColor Red 'Failed to auto-detect sim name. '
                    Write-Host -NoNewline 'Select manually [0: ETS2 | 1: ATS | ESC: Exit]'
                    $Host.UI.RawUI.FlushInputBuffer()
                    Do {
                        If ($Null -ne $T__In) {[Console]::Beep(700, 250)}
                        [Byte]$T__In = $Host.UI.RawUI.ReadKey('NoEcho, IncludeKeyDown').VirtualKeyCode
                        If ($T__In -eq 27) {Exit}
                    } Until ($T__In -In [Byte[]][Char[]]'01')
                    Clear-Host
                    [String]$T__Game = ('ETS2', 'ATS')[$T__In - 48]
                    Break
                }
            }
        }
    }
    [String]$T__Tab        = ' ' * 4
    [String]$T__Message    = '. . .  L O A D I N G  . . .'
    [String]$T__SessionStr = " Session ID: $G__SessionID"
    [String]$T__GameMode   = "Targeting: $T__Game "
    $T__Message            = ' ' * [Math]::Max(0, [Math]::Floor(($Host.UI.RawUI.WindowSize.Width - $T__Message.Length) / 2) - $T__SessionStr.Length) + $T__Message
    [Hashtable]$T__LoadSplat_Session = @{
        Object          = "`n$T__SessionStr"
        ForegroundColor = [ConsoleColor]::DarkGray
        BackgroundColor = [ConsoleColor]::DarkBlue
        NoNewline       = $True
    }
    [Hashtable]$T__LoadSplat_Message = @{
        Object          = "$T__Message$(' ' * ($Host.UI.RawUI.BufferSize.Width - $T__Message.Length - $T__SessionStr.Length - $T__GameMode.Length))"
        ForegroundColor = [ConsoleColor]::White
        BackgroundColor = [ConsoleColor]::DarkBlue
        NoNewline       = $True
    }
    [Hashtable]$T__LoadSplat_Target = @{
        Object          = $T__GameMode
        ForegroundColor = [ConsoleColor]::DarkGray
        BackgroundColor = [ConsoleColor]::DarkBlue
        NoNewline       = $True
    }

    Try {[Console]::CursorVisible = $False} Catch {}

    Write-Host @T__LoadSplat_Session
    Write-Host @T__LoadSplat_Message
    Write-Host @T__LoadSplat_Target

    Write-Host -NoNewline "`n`n$($T__Tab * 3)Loading functions... "

    [DateTime]$T__Step = [DateTime]::Now
    Remove-Variable T__Message, T__SessionStr, T__GameMode, T__Data, T__OSDependentPattern, T__In, T__LoadSplat_Session, T__LoadSplat_Message, T__LoadSplat_Target, _Game -EA 0
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

        # TODO: Swap upper and lower bounds if Min > Max?
        If ($Max - $Min -lt 0) {
            Write-Log ERROR "Invalid range: Maximum value ($Max) cannot be less than the Minimum value ($Min)."
            Throw 'Invalid range'
        }
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

        $Host.UI.RawUI.FlushInputBuffer()
        Write-Log INFO 'Flushed input buffer.'

        [Console]::CursorVisible = $True

        Write-Log INFO 'Awaiting user input...'
        [String]$UserInput = If ($Prompt) {Read-Host $Prompt} Else {Read-Host}

        Write-Log INFO "User input received: '$UserInput'"
        
        [Console]::CursorVisible = $False

        Return $UserInput
    }

    Function Protect-Variables      {If ($GLOBAL:PROTECTED) {Throw 'The object is already initialized'} Else {[String[]]$GLOBAL:PROTECTED = (Get-Variable).Name + 'PROTECTED'}}
    Function Update-ProtectedVars   {If ($GLOBAL:PROTECTED) {Add-ProtectedVars (Get-UnprotectedVars)}}
    Function Get-UnprotectedVars    {If ($GLOBAL:PROTECTED) {Return [String[]](Get-Variable -Exclude $GLOBAL:PROTECTED).Name}}
    Function Remove-UnprotectedVars {If ($GLOBAL:PROTECTED) {Switch (Get-UnprotectedVars) {$Null {Return} Default {Remove-Variable $_ -EA 0}}}}
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

        If (!$NoLog.IsPresent) {
            Switch ($PSCmdlet.ParameterSetName) {
                'Path'  {Write-Log INFO "Received UTF8 file content request for '$($Path.FullName)'."; Break}
                'Bytes' {Write-Log INFO 'Received UTF8 byte array content request.'; Break}
            }
        }

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
                
                    [Byte[]]$Buffer        = [Byte[]]::New($Count)
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
                Finally {If ($Null -ne $Stream) {$Stream.Dispose()} $Buffer}
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
            [String]$PreEOLConversion = $Content
            $Content = [Regex]::Replace($Content, '\r\n|\r|\n', $EOLMap[$EOL])
            If ($PreEOLConversion -cne $Content -And !$NoLog.IsPresent) {Write-Log INFO "Converted line endings to $EOL."}
        }

        If (!$NoLog.IsPresent) {
            If ($BOMOffset -eq 3) {Write-Log INFO "Omitted UTF-8 BOM reading '$Source'."}
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

        If (!$NoLog.IsPresent) {Write-Log INFO "Received data write request for '$($Path.FullName)'."}

        [Text.UTF8Encoding]$UTF8 = [Text.UTF8Encoding]::New($False)
        [String]$JoinedString    = $String -Join "`n"
        If (!$NoNewline.IsPresent) {$JoinedString += "`n"}
        
        [Collections.Generic.List[Byte]]$Bytes    = $UTF8.GetBytes($JoinedString)
        
        If ($Append.IsPresent) {[IO.File]::AppendAllText($Path.FullName, $UTF8.GetString($Bytes), $UTF8)}
        Else                   {[IO.File]::WriteAllBytes($Path.FullName, $Bytes)}
        
        If (!$NoLog.IsPresent) {Write-Log INFO "$($Bytes.Count) bytes written to '$($Path.FullName)'."}
    }

    Function Format-AndExportErrorData {
        [CmdletBinding()]
        Param ([Parameter(Mandatory)][Management.Automation.ErrorRecord]$Exception)

        [String]$Timestamp = [DateTime]::Now.ToString('yyyy.MM.dd AT HH:mm:ss.fff')
        [String]$Message   = $Exception.Exception.Message
        [String]$Details   = $Exception.ErrorDetails.Message

        [String[]]$LogData = @(
            "[$Timestamp] FATAL ERROR",
            "$($Exception.PSObject.Properties.Value -Join "`n")",
            "$('-' * 100)"
        )
        Set-UTF8Content $G__SessionLog $LogData -Append -NoLog

        Return ($Details, $Message)[$Message.Length -gt $Details.Length]
    }

    Function Write-Log {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory, Position = 0)][String]$Type,
            [Parameter(Position = 1)][String]$Message = ''
        )

        [String]$EntryPrefix = "[$([DateTime]::Now.ToString('yyyy.MM.dd HH:mm:ss.fff'))] " + $Type.PadRight(6) + ': '

        [Management.Automation.CallStackFrame[]]$CallStack = Get-PSCallStack
        [String]$Source = "$($CallStack[1].FunctionName) : "
        $EntryPrefix += '    ' * ($CallStack.Count - 4)

        [String[]]$LogData = ($EntryPrefix + $Source + $Message) -Split "`n" -Join "`n$(' ' * (4 + $EntryPrefix.Length))" -Split "`n"

        Set-UTF8Content $G__SessionLog $LogData -Append -NoLog
    }

    Function Measure-TransferRate {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory, Position = 0)][Double]$Duration,
            [Parameter(Mandatory, Position = 1)][UInt32]$Bytes,
            [ValidateSet('B/s', 'kB/s', 'MB/s', 'GB/s')][String]$Unit
        )

        [Double]$BytesPerSecond = $Bytes / $Duration

        If ($PSBoundParameters.ContainsKey('Unit')) {
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

        Write-Log INFO "Received download request of '$File' from '$Repository' ('$Repository/$File')."

        If ($G__OfflineMode) {
            Write-Log ERROR "$($G__ScriptDetails['ShortTitle']) is running in Offline Mode. Unable to download file '$File'."
            Throw 'Offline mode is enabled. Unable to download files.'
        }

        [Uri]$Uri = "$Repository/$File"

        If ($PSCmdlet.ParameterSetName -eq 'IWR') {
            Write-Log INFO "Invoke-WebRequest | Initializing WebRequest for download of '$Uri'."
            [Hashtable]$IWRSplat = @{Uri = $Uri; TimeoutSec = $Timeout}

            If ($PSVersionTable.PSVersion.Major -lt 6) {$IWRSplat['UseBasicParsing'] = $True}
            If ($Save.IsPresent)                       {$IWRSplat['OutFile']         = $File}

            Write-Log INFO "Invoke-WebRequest | Downloading '$Uri' $(('into memory.', "to '$File'.")[$Save.IsPresent])."
            
            Try     {Return Invoke-WebRequest @IWRSplat}
            Catch   {Write-Log ERROR "Invoke-WebRequest | Failed to download file: $($_.Exception.Message)"; Throw $_}
            Finally {Write-Log INFO "Invoke-WebRequest | Successfully downloaded '$Uri'."}
        }

        Write-Log INFO "HttpClient | Initializing HTTP client for download of '$File' from '$Repository'."
        [Net.Http.HttpClient]$HttpClient = [Net.Http.HttpClient]::New()
        $HttpClient.Timeout              = [TimeSpan]::FromMilliseconds($Timeout)
        $HttpClient.DefaultRequestHeaders.Add('User-Agent', $G__ScriptDetails['ShortTitle'])

        [Net.Http.HttpResponseMessage]$RepoResponse = $HttpClient.GetAsync($Uri, [Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result

        If (!$RepoResponse.IsSuccessStatusCode) {
            Write-Log ERROR "HttpClient | Failed to download file:`n$($RepoResponse.StatusCode)"
            Throw "Failed to download file: $($RepoResponse.StatusCode)"
        }

        [UInt64]$DownloadSize = $RepoResponse.Content.Headers.ContentLength

        [UInt32]$BufferSize = [Math]::Pow(2, [Math]::Floor([Math]::Log([Math]::Min($DownloadSize, [GC]::GetTotalMemory($False) / 10), 2)))
        [Byte[]]$Buffer     = [Byte[]]::New($BufferSize)
        Write-Log INFO "HttpClient | Ready to transfer $DownloadSize bytes to '$File'."
        
        [Security.Cryptography.SHA1CryptoServiceProvider]$CryptoProvider = [Security.Cryptography.SHA1CryptoServiceProvider]::New()
        Write-Log INFO 'CryptoProvider | Ready for blockwise SHA1 computation.'

        [DateTime]$IntervalStart   = [DateTime]::Now.AddSeconds(-1)
        [IO.FileStream]$FileStream = [IO.FileStream]::New($File, [IO.FileMode]::Create)
        [IO.Stream]$DownloadStream = $RepoResponse.Content.ReadAsStreamAsync().Result
        
        Write-Log INFO "Download started. Block size: $BufferSize"

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
            $IntervalLength   = (New-TimeSpan $IntervalStart ([DateTime]::Now)).TotalSeconds

            If ($IntervalLength -ge 1) {
                $TransferRate  = Measure-TransferRate $IntervalLength ($BytesDownloaded - $IntervalBytes)
                $IntervalBytes = $BytesDownloaded
                $IntervalStart = [DateTime]::Now
            }

            Write-HostX $X -Color Green ("$State " + "$ConvertedBytes".PadLeft(5) + "/$ConvertedDownload ($TransferRate)")
        }

        If ($BytesDownloaded -eq 0) {
            Write-Log ERROR "HttpClient | Download failed: No data received.`nBD=$BytesDownloaded,BR=$BytesRead,DS=$DownloadSize,BS=$BufferSize"
            Throw "Download failed: BD=$BytesDownloaded,BR=$BytesRead,DS=$DownloadSize,BS=$BufferSize"
        }

        [Void]$CryptoProvider.TransformFinalBlock($Buffer, 0, 0)
        [String]$FileHash = [BitConverter]::ToString($CryptoProvider.Hash) -Replace '-', ''
        Write-Log INFO "CryptoProvider | Block transformation complete. SHA1 Hash: $FileHash"

        If ('Hash' -In $PSBoundParameters.Keys -And $FileHash -ne $Hash) {
            Write-Log ERROR "HttpClient | Download failed: FileHash mismatch for '$File'`nExpected: $Hash`nActual:   $FileHash"
            Throw 'Download failed: Hash mismatch'
        }

        Write-Log INFO "HttpClient | Download completed. $BytesDownloaded bytes ($ConvertedDownload) transferred."

        $CryptoProvider.Dispose()
        $FileStream.Dispose()
        $DownloadStream.Dispose()
        $HttpClient.Dispose()
        
        Return $ConvertedDownload, $BytesDownloaded, $FileHash
    }

    Function Test-PSHostCompatibility {
        [Bool]$IsCompatible = $Host.UI.SupportsVirtualTerminal
        If (!$IsCompatible) {Write-Log ERROR "PSHost compatibility check: FAIL -- $($Host.Name) | Incompatible."}
        Else                {Write-Log INFO "PSHost compatibility check: PASS -- $($Host.Name) | Compatible."}

        Return $IsCompatible
    }

    Function Test-ModActive {
        [CmdletBinding()]
        Param ([Parameter(Mandatory)][String]$Mod)

        Write-Log INFO 'Received mod usage status request.'

        If (!$G__GameLogPath.Exists -Or $G__GameProcess -NotIn (Get-Process).Name) {Return $False}

        [Regex]$MountedPattern   = ' \: \[mod_package_manager\] Mod ".+" has been mounted\. \(package_name\: ' + $Mod + ','
        [Regex]$UnmountedPattern = ' \: \[(zip|hash)fs\] ' + $Mod + '\.(scs|zip)\: Unmounted\.?'
        
        ForEach ($Line in Get-UTF8Content $G__GameLogPath -UseGC) {
            If ($Line -Match $MountedPattern)   {[Bool]$IsLoaded = $True}
            If ($Line -Match $UnmountedPattern) {[Bool]$IsLoaded = $False}
        }
        Write-Log INFO "Mod '$Mod' is $(('not ', '')[$IsLoaded])loaded."
        Return $IsLoaded
    }

    Function Get-StringHash {
        [CmdletBinding(DefaultParameterSetName = 'String')]
        Param (
            [Parameter(Mandatory, ParameterSetName = 'String', Position = 0)]
            [String[]]$String,

            [Parameter(Mandatory, ParameterSetName = 'Bytes', Position = 0)]
            [Byte[]]$Bytes,

            [Parameter(Position = 1)]
            [ValidateSet('CRC32', 'SHA1', 'SHA256', 'SHA384', 'SHA512', 'MD5')]
            [String]$Algorithm = 'SHA256',

            [Parameter(ParameterSetName = 'String')]
            [Text.Encoding]$Encoding = [Text.UTF8Encoding]::New($False)
        )

        If ($PSBoundParameters.ContainsKey('String')) {[Byte[]]$Bytes = $Encoding.GetBytes($String -Join "`n")}

        If ($Algorithm -eq 'CRC32') {
            Return ([WindowsAPI]::RtlComputeCrc32(0, $Bytes, $Bytes.Count).ToString('X8'))
        }
        Else {
            [Hashtable]$GfHSplat = @{InputStream = [IO.MemoryStream]::New($Bytes); Algorithm = $Algorithm}
            Return (Get-FileHash @GfHSplat).Hash
        }
    }

    Function Test-FileHash {
        [CmdletBinding()]
        Param (
            [Parameter(Position = 0)][IO.FileInfo]$File,
            [Parameter(Mandatory, Position = 1)][String]$Hash,
            [Parameter(Position = 2)][UInt64]$Size
        )

        Write-Log INFO "Received FileHash test request for '$($File.FullName)' with Hash: $Hash$(('', " and Size: $Size")[$PSBoundParameters.ContainsKey('Size')])."
        If (!$File.Exists) {
            Write-Log INFO "Test FAILED : Cannot find File '$($File.Name)'."
            Return $False
        }
        If ($Size -And $File.Length -ne $Size) {
            Write-Log INFO "Test FAILED : FileSize Mismatch for File '$($File.Name)'`nExpected: $Size, Actual:   $($File.Length)."
            Return $False
        }

        Try {
            [UInt64]$Buffer        = [Math]::Pow(2, [Math]::Floor([Math]::Log([Math]::Min($File.Length, [GC]::GetTotalMemory($False) / 4), 2)))
            [IO.FileStream]$Stream = [IO.FileStream]::New($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read, $Buffer)

            [String]$ComputedHash = [BitConverter]::ToString($G__CryptoProvider.ComputeHash($Stream)) -Replace '-', ''
            If ($ComputedHash -ne $Hash) {
                Write-Log INFO "Test FAILED : Computed FileHash Mismatch for File '$($File.Name)'`nExpected: $Hash`nActual:   $ComputedHash"
                Return $False
            }
            Else {
                Write-Log INFO "Test PASSED : Computed FileHash Match for File '$($File.Name)'"
                Return $True
            }
        }
        Catch   {
            Write-Log ERROR "Test FAILED : Failed to compute FileHash for File '$($File.Name)':`n$($_.Exception.Message)"
            Return $False
        }
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

        Write-Log INFO 'Received wait and exit request.'

        Write-Host -ForegroundColor Red $InputObject
        
        Unprotect-Variables
        [Void](Read-KeyPress)

        If ($Restart.IsPresent) {
            Write-Log INFO 'Executing restart routine...'
            $GLOBAL:G__ScriptRestart = $True
            [Void]$GLOBAL:G__ScriptRestart
            Return 'Restart'
        }
        Exit
    }

    Function Read-KeyPress {
        [CmdletBinding(DefaultParameterSetName = 'Default')]
        Param (
            [Parameter(Position = 0)][String]$Prompt,
            [Alias('Fg')][ConsoleColor]$ForegroundColor = [Console]::ForegroundColor,
            [Alias('Bg')][ConsoleColor]$BackgroundColor = [Console]::BackgroundColor,
            [Switch]$NoNewline, [Switch]$Clear,

            [Parameter(ParameterSetName = 'Timeout', Mandatory)][UInt16]$Timeout,
            [Parameter(ParameterSetName = 'Timeout')][Byte]$DefaultKeyCode,
            [Parameter(ParameterSetName = 'Timeout')][Char]$DefaultKey,
            [Parameter(ParameterSetName = 'Timeout')][Double]$RefreshRateMs = 100
        )

        Write-Log INFO 'Received key press input request.'

        [TimeSpan]$TimerDuration = [TimeSpan]::Zero
        [DateTime]$TimerStart    = [DateTime]::Now
        [Int]$SecondsLeft        = $Timeout
        If ($PSBoundParameters.ContainsKey('DefaultKey')) {
            If ($PSBoundParameters.ContainsKey('DefaultKeyCode')) {Write-Log WARN 'Duplicate keypress defaults specified. Ignoring -DefaultKeyCode parameter in favor of -DefaultKey.'}
            [Byte]$DefaultKeyCode = [Byte]$DefaultKey
        }
        
        If ($Prompt) {
            [Hashtable]$PromptSplat = @{
                Object    = $Prompt -Replace '\$Timeout', "$Timeout"
                NoNewline = ($NoNewline.IsPresent, $True)[$Clear.IsPresent]
            }
            If ($ForegroundColor) {$PromptSplat['ForegroundColor'] = $ForegroundColor}
            If ($BackgroundColor) {$PromptSplat['BackgroundColor'] = $BackgroundColor}
            [Hashtable]$OriginalCursorPos = @{X = [Console]::CursorLeft; Y = [Console]::CursorTop}
            Write-Host @PromptSplat
        }

        $Host.UI.RawUI.FlushInputBuffer()
        Write-Log INFO 'Flushed input buffer.'

        If ($PSCmdlet.ParameterSetName -eq 'Timeout') {
            Write-Log INFO "Awaiting key press. $Timeout second timeout..."

            While ($TimerDuration.TotalSeconds -lt $Timeout) {
                $TimerDuration = [DateTime]::Now - $TimerStart
                If ($Prompt) {
                    Switch ([Math]::Abs([Math]::Ceiling($Timeout - $TimerDuration.TotalSeconds))) {
                        $SecondsLeft {Break}
                        Default {
                            [String]$_Prompt       = $Prompt -Replace '\$Timeout', "$_"
                            $PromptSplat['Object'] = $_Prompt
                            If ($ClearPrompt.Length - $NoNewline.IsPresent -ne $_Prompt.Length) {
                                [String[]]$ClearLines = @()
                                ForEach ($PromptLine in $_Prompt -Split "`n") {$ClearLines += ' ' * $PromptLine.Length}
                                [String]$ClearPrompt = $ClearLines -Join "`n"
                                If (!$NoNewline.IsPresent) {$ClearProimpt += "`n"}
                                [Console]::SetCursorPosition($OriginalCursorPos.X, $OriginalCursorPos.Y)
                                Write-Host -NoNewline $ClearPrompt
                            }
                            [Console]::SetCursorPosition($OriginalCursorPos.X, $OriginalCursorPos.Y)
                            Write-Host @PromptSplat
                            $SecondsLeft = $_
                            Break
                        }
                    }
                }
                If ($Host.UI.RawUI.KeyAvailable) {[Byte]$KeyCode = $Host.UI.RawUI.ReadKey('NoEcho, IncludeKeyDown').VirtualKeyCode; Break}
                Start-Sleep -Milliseconds $RefreshRateMs
            }
            [Byte]$KeyPress = If ($Null -eq $KeyCode) {Write-Log INFO "Timed out. Using default keypress: $DefaultKeyCode"; $DefaultKeyCode} Else {Write-Log INFO "Keypress received: $KeyCode"; $KeyCode}
        }
        Else {
            Write-Log INFO 'Awaiting key press...'
            [Byte]$KeyPress = $Host.UI.RawUI.ReadKey('NoEcho, IncludeKeyDown').VirtualKeyCode
            Write-Log INFO "Keypress received: $KeyPress"
        }

        If ($Clear.IsPresent -And $Prompt) {
            If ($ClearPrompt.Length - $NoNewline.IsPresent -ne $PromptSplat.Object.Length) {
                [String[]]$ClearLines = @()
                ForEach ($PromptLine in $PromptSplat.Object -Split "`n") {$ClearLines += ' ' * $PromptLine.Length}
                [String]$ClearPrompt = $ClearLines -Join "`n"
            }
            [Console]::SetCursorPosition($OriginalCursorPos.X, $OriginalCursorPos.Y)
            Write-Host -NoNewline $ClearPrompt
            [Console]::SetCursorPosition($OriginalCursorPos.X, $OriginalCursorPos.Y)
        }
        
        Return $KeyPress
    }

    Function Set-ForegroundWindow {
        [CmdletBinding(DefaultParameterSetName = 'PID')]
        Param (
            [Parameter(ParameterSetName = 'Self', Mandatory)]
            [Switch]$Self,

            [Parameter(ParameterSetName = 'Self')]
            [Parameter(ParameterSetName = 'PID')]
            [UInt32]$ID = $PID,

            [Parameter(ParameterSetName = 'Name', Mandatory)]
            [Parameter(ParameterSetName = 'Name_WHnd', Mandatory)]
            [Parameter(ParameterSetName = 'Name_Title', Mandatory)]
            [Parameter(ParameterSetName = 'Name_Both', Mandatory)]
            [String]$Name,
            
            [Parameter(ParameterSetName = 'Name_WHnd', Mandatory)]
            [Parameter(ParameterSetName = 'Name_Both', Mandatory)]
            [IntPtr]$Handle,
            
            [Parameter(ParameterSetName = 'Name_Title', Mandatory)]
            [Parameter(ParameterSetName = 'Name_Both', Mandatory)]
            [String]$Title
        )

        [Management.Automation.CommandMetaData]$ParamSets    = [Management.Automation.CommandMetaData]::New((Get-PSCallStack)[0].FunctionName).ParameterSets.Name
        [Management.Automation.WildcardPattern]$TitlePattern = [Management.Automation.WildcardPattern]::New($Title, 2 -BOr 4) # Options - 0=None, 1=Compiled, 2=IgnoreCase, 4=CultureInvariant
        [Void]$TitlePattern # Suppresses false unused variable warning. Used in Default case of Switch ($PSCmdlet.ParameterSetName) statement.
        If (!$Handle) {[IntPtr]$Handle = [IntPtr]::Zero}

        [String]$Msg        = 'Received set foreground window request for '
        [String[]]$NameEval = @('($_.MainWindowHandle -ne $Handle)', '')

        [String]$Filter, [String]$Info = Switch ($PSCmdlet.ParameterSetName) {
            'Self'  {@('', "$_ (PID $ID)."); Break}
            'PID'   {@('', "process ID $ID."); Break}
            'Name'  {@($NameEval[0], "$($NameEval[1]) process name '$Name'."); Break}
            Default {
                $NameEval = Switch ($_) {
                    'Name_WHnd'  {@("!$($NameEval[0])", " (WHnd: $Handle)."); Break}
                    'Name_Title' {@("$($NameEval[0]) -And `$TitlePattern.IsMatch(`$_.MainWindowTitle)", " (Title: $Title)."); Break}
                    'Name_Both'  {@("!$($NameEval[0]) -And `$TitlePattern.IsMatch(`$_.MainWindowTitle)", " (WHnd: $Handle, Title: $Title).")
                    Default      {Throw 'Invalid parameter set name.'}
                }}
                $NameEval[1] = "process name '$Name'." + $NameEval[1]
                $NameEval; Break
            }
        }
        Write-Log INFO ($Msg + $Info)
        Write-Log INFO "ParameterSets: $($ParamSets -Join ', '))"

        [ScriptBlock]$FilterScript = [ScriptBlock]::Create($Filter)
        Write-Log INFO "Set FilterScript: $Filter"

        [System.Diagnostics.Process]$Target = Switch ($PSCmdlet.ParameterSetName) {
            {$_ -Match '^(PID)|(Self)$'} {[System.Diagnostics.Process]::GetProcessesById($ID)[0]; Break}
            {$_ -Match '^Name'}          {([System.Diagnostics.Process]::GetProcessesByName($Name) | Where-Object $FilterScript)[0]; Break}
        }

        [UInt32]$TargetPID  = $Target.Id
        [IntPtr]$TargetWHnd = $Target.MainWindowHandle
        [String]$TargetName = $Target.Name
        Write-Log INFO "Fetched target process information: Name '$TargetName', PID: $TargetPID, WHnd: $TargetWHnd."

        [Void]$G__WScriptShell.AppActivate($TargetPID)
        [Void][WindowsAPI]::SetForegroundWindow($TargetWHnd)

        If ([WindowsAPI]::GetForegroundWindow() -eq $TargetWhnd) {Write-Log INFO "Activated PID $TargetPID and set foreground window to handle '$TargetWHnd'."}
        Else                                                     {Write-Log ERROR "Failed to set foreground window to handle '$TargetWHnd'."}
    }

    Function ConvertFrom-ActiveModEntry {
        [CmdletBinding()]
        Param ([Parameter(Position = 0)][String]$Locator, [Parameter(Position = 1)][String]$Name)

        Write-Log INFO "Received mod source conversion request for '$Locator'."

        [String]$Type, [String]$Hex = $Locator -Split '\.', 2
        $Type = ('Local', 'Workshop')[$Type -eq 'mod_workshop_package']

        [String]$Converted = Switch ($Type) {
            'Local'    {"$($G__GameModDirectory.FullName)\$Locator.scs"; Break}
            'Workshop' {"$($G__WorkshopDirectory.FullName)\" + [String][UInt32]"0x$Hex"; Break}
            Default    {Throw "Invalid mod source type '$_'."}
        }
        Write-Log INFO "Converted '$Locator' >> '$Converted'"
        
        Return [Hashtable]@{
            Name       = $Name
            Type       = $Type
            Source     = $Locator
            SourcePath = $Converted
            SourceName = [IO.Path]::GetFileName($Converted)
        }
    }

    Function Convert-ProfileFolderName {
        [CmdletBinding()]
        Param ([String]$Directory = $G__ActiveProfile)

        Write-Log INFO 'Received profile folder conversion request.'

        [Char[]]$Converted = For ([UInt16]$Index = 0; $Index -lt $Directory.Length; $Index += 2) {[Char][Byte]"0x$($Directory.Substring($Index, 2))"}
        Write-Log INFO "Converted profile folder name '$Directory' to '$($Converted -Join '')'."
        
        Return $Converted -Join ''
    }

    Function ConvertTo-PlainTextProfileUnit {
        [CmdletBinding()]
        Param ([IO.FileInfo]$File = $G__ProfileUnit, [IO.FileInfo]$OutFile = $G__TempProfileUnit, [Switch]$OnFile)

        Write-Log INFO 'Received profile format conversion request.'

        [IO.FileInfo]$UnitDecoder = Get-GameUnitDecoder
        [String]$DecodeCommand    = "& '$($UnitDecoder.FullName)'" + (" '$($File.FullName)' '$($OutFile.FullName)'", " --on_file -i '$($File.FullName)'")[$OnFile.IsPresent]
        [Object]$DecoderResult    = Invoke-Expression $DecodeCommand

        Write-Log INFO "Profile unit decoder finished with exit code $LASTEXITCODE`n($DecoderResult).`nCommand: $DecodeCommand"

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

        Write-Log INFO 'Received Workshop mod install status request.'

        [Bool]$Result = [IO.Directory]::Exists($ModFolder.FullName)
        Write-Log INFO "Test for Workshop mod '$ModFolder' returned $Result."
        Return $Result
    }

    Function Get-GameDirectory {
        [CmdletBinding(DefaultParameterSetName = 'Both')]
        Param (
            [Parameter(Mandatory, ParameterSetName = 'GameRoot')][Switch]$Root,
            [Parameter(Mandatory, ParameterSetName = 'Workshop')][Switch]$Workshop,
            [Parameter(ParameterSetName = 'Both')][Switch]$Both
        )

        Switch ($PSCmdlet.ParameterSetName) {
            'GameRoot' {Write-Log INFO "Received $G__GameNameShort ($G__GameAppID) Game Root Directory Lookup request."; Break}
            'Workshop' {Write-Log INFO "Received $G__GameNameShort ($G__GameAppID) Workshop Directory Lookup request."; Break}
            'Both'     {Write-Log INFO "Received $G__GameNameShort ($G__GameAppID) Game Root + Workshop Directory Lookup request."; Break}
            Default    {Throw 'Invalid parameter set name.'}
        }

        [Regex]$PathSearchPattern  = ('(?i)(?<="path"\s+")[a-z]\:(?:\\\\.+)+(?=")', '(?i)(?<="path"\s+")[a-z]\:(?:\/\/.+)+(?=")')[$G__OS -eq 'Linux']
        [Regex]$AppIDSearchPattern = '(?<=")' + $G__GameAppID + '(?="\s+"\d+")'
        [Regex]$InstallDirPattern  = '(?<="installdir"\s+")[^"]+(?=")'

        [String]$RegKey    = 'HKLM:\SOFTWARE' + ('\', '\WOW6432Node\')[[Environment]::Is64BitOperatingSystem] + 'Valve\Steam'
        [String]$SteamRoot = Get-ItemPropertyValue $RegKey InstallPath
        Write-Log INFO "Located Steam Root Directory at: '$SteamRoot'."
        
        Write-Log INFO "Performing $G__GameNameShort SteamApps Directory Lookup in Steam Library VDF ('$SteamRoot\SteamApps\libraryfolders.vdf')."
        [String[]]$LibraryData = Get-UTF8Content ([IO.Path]::Combine($SteamRoot, 'SteamApps', 'libraryfolders.vdf'))
        [String]$SteamApps     = ForEach ($Line in $LibraryData) {
            If ($Line -Match $PathSearchPattern)  {[String]$Path = $Matches[0] -Replace '\\\\', '\'; Continue}
            If ($Line -Match $AppIDSearchPattern) {[IO.Path]::Combine($Path, 'SteamApps'); Break}
        
        }
        Write-Log INFO "Located $G__GameNameShort SteamApps Directory at: '$SteamApps'."

        [IO.DirectoryInfo]$WorkshopDir = [IO.Path]::Combine($SteamApps, 'workshop', 'content', $G__GameAppID)
        Write-Log INFO "Successfully Located $G__GameNameShort Workshop Direcory at: '$($WorkshopDir.FullName)'."
        
        # If the user provided -Workshop, return the workshop directory
        If ($Workshop.IsPresent) {Return $WorkshopDir}

        # Otherwise the user must have provided -Root, so we locate and return the game's root/install directory
        [String]$AppManifestACF = [IO.Path]::Combine($SteamApps, "appmanifest_$G__GameAppID.acf")
        Write-Log INFO "Performing Game Root Directory Lookup in $G__GameNameShort App Manifest ACF ('$AppManifestACF')."

        [String[]]$AppCacheData = Get-UTF8Content $AppManifestACF
        ForEach ($Line in $AppCacheData) {If ($Line -Match $InstallDirPattern) {[String]$InstallDir = [IO.Path]::Combine($SteamApps, 'common', $($Matches[0])); Break}}
        
        [IO.DirectoryInfo]$RootDir = $InstallDir

        Write-Log INFO "Successfully Located $G__GameNameShort Game Root Directory at '$InstallDir'."

        If ($Root.IsPresent) {Return $RootDir}

        Return [IO.DirectoryInfo[]]@($RootDir, $WorkshopDir)
    }

    Function Get-ProfileUnitFormat {
        [CmdletBinding()]
        Param ([IO.FileInfo]$Target = $G__TempProfileUnit)

        Write-Log INFO "Received Format detection request for '$($Target.FullName)'."

        [Collections.Generic.List[Byte]]$UnitData = [IO.File]::ReadAllBytes($Target.FullName)
        [String]$UnitFormat                       = ('Text', 'Binary')[$UnitData.Contains([Byte]0)]

        Switch ($UnitFormat) {
            'Binary' {Write-Log INFO "Null-byte detected in '$($Target.Name)' contents. Assuming binary format."; Break}
            'Text'   {Write-Log INFO "No null-bytes detected in '$($Target.Name)' contents. Assuming text format."; Break}
            Default  {
                Write-Log ERROR "Unable to determine format of '$($Target.Name)' - Unexpected format '$UnitFormat'"
                Throw "Unable to determine format of '$($Target.Name)' - Unexpected format '$UnitFormat'"
            }
        }
        Return $UnitFormat
    }

    Function Get-GameUnitDecoder {
        [CmdletBinding()]
        Param ([String]$DecFile = $G__RepositoryInfo.DecFile)

        Write-Log INFO "Received Game Unit Decoder '$DecFile' request."

        [IO.FileInfo]$Path = "$Env:TEMP\$DecFile"
        [String]$Checksum  = (Get-ModRepoFile $G__RepositoryInfo.DecHash -UseIWR).Content
        Write-Log INFO "Expected FileHash for '$DecFile' is: '$Checksum'."

        If (!$Path.Exists) {
            Write-Log INFO "Decoder not found at '$($Path.FullName)'. Downloading from repository."
            If ($G__OfflineMode) {
                Write-Log ERROR "$($G__ScriptDetails['ShortTitle']) is running in Offline Mode. Unable to download file '$DecFile'."
                Throw 'Offline mode is enabled. Unable to download files.'
            }

            [IO.File]::WriteAllBytes($Path.FullName, [Byte[]](Get-ModRepoFile $DecFile -UseIWR).Content)
            Write-Log INFO "Game Unit Decoder downloaded and saved to '$($Path.FullName)'."
        }

        If (!(Test-FileHash $Path.FullName $Checksum)) {
            Write-Log ERROR "'$DecFile' failed to validate - FileHash mismatch. The file will be deleted."

            $Path.Delete()

            Throw "Failed to validate '$DecFile' - Checksum mismatch"
        }
        Write-Log INFO 'Game Unit Decoder is ready.'
        Return $Path
    }

    Function Get-ModData {
        [CmdletBinding()]
        Param ([String[]]$RawData)

        Write-Log INFO 'Received mod data parse request.'

        If (!$RawData) {
            Write-Log WARN 'Nothing to parse. Returning @{}.'
            Return @{}
        }

        [Hashtable]$ParsedData = @{}
        [String[]]$Data        = ($RawData, ($RawData[0] -Split "`n"))[$RawData.Count -eq 1 -And [Char[]]$RawData[0] -Contains "`n"]

        ForEach ($Entry in $Data) {
            If ($Entry -Match '^ active_mods: \d+$') {Continue}

            [String]$Priority               = Switch (($Entry -Split '\[|\]', 3)[1]) {{$_ -As [UInt16] -eq $_} {$_} Default {Continue}}
            [String]$Source, [String]$Name  = Switch ((($Entry -Split '\[\d+\]: ', 2)[-1] -Split '\|', 2).Trim('"')) {{$_ -As [String[]] -eq $_} {$_}}
            $ParsedData["active_$Priority"] = ConvertFrom-ActiveModEntry $Source $Name
        }
        Write-Log INFO "Parsed $($ParsedData.Keys.Count) mod data entries."

        Return $ParsedData
    }

    Function Install-CoreMod { # TODO: Not yet implemented
        [CmdletBinding()]
        Param ()
    }

    Function Read-PlainTextProfileUnit {
        [CmdletBinding()]
        Param ([ValidateSet('Mods', 'Data', 'All')][String]$Return = 'All', [Switch]$Raw, [Switch]$Direct)

        Write-Log INFO 'Received Profile Data request.'

        [Bool]$Parse        = $False
        [String[]]$UnitMods = @()
        [String[]]$UnitData = @()
        [IO.FileInfo]$File  = ($G__TempProfileUnit, $G__ProfileUnit)[$Direct.IsPresent]
        Write-Log INFO "$(('Using TempProfileUnit', "'-Direct' specified - Using ProfileUnit")[$Direct.IsPresent]) as source profile ('$($File.FullName)')."

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
        Write-Log INFO "Reveiced Load order configuration request for '$($ProfileUnit.Name)'."

        If ($G__GameProcess -In (Get-Process).Name) {
            Write-Log WARN 'Game is running. Aborted load order configuration.'
            Write-Host -ForegroundColor Yellow " $G__GameName must be closed in order to apply load order."
            Return
        }
        Else {Write-Log INFO 'Profile Unit is clear. Proceeding with load order configuration.'}

        Write-Host -ForegroundColor Green (''.PadRight(4) + "$G__LoadOrder - $G__ActiveModsCount active mods")

        Write-Log INFO 'Preparing Profile reconfiguration.'
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
            Write-Log INFO "Profile Unit mod list does not match active load order ($ProfileModsCount > $G__ActiveModsCount). Proceeding."

            If ($G__ProfileBackups) {
                Write-Host -NoNewline (''.PadRight(4) + 'Creating profile backup...'.PadRight(35))
                
                [IO.FileInfo]$Backup = Backup-ProfileUnit

                Write-Host -ForegroundColor Green "OK - $($Backup.Name)"
            }
            Else {Write-Log INFO 'Profile backups are disabled - Skipping profile backup.'}

            Write-Host -NoNewline (''.PadRight(4) + 'Applying load order...'.PadRight(35))
            Write-Log INFO "Applying active load order ($G__LoadOrder) to profile '$($ProfileUnit.Name)'."

            If ($ProfileFormat -ne 'Text') {ConvertTo-PlainTextProfileUnit -OnFile}
            [String]$ProfileRaw = $ProfileData -Join "`n" -Replace '<MODLIST_INSERTION_POINT>', $G__LoadOrderText
            Set-UTF8Content $ProfileUnit $ProfileRaw -NoNewline

            Write-Log INFO "Load order applied successfully. $ProfileModsCount > $G__ActiveModsCount"
            Write-Host -ForegroundColor Green "OK - $ProfileModsCount > $G__ActiveModsCount"
        }
        Else {
            Write-Log INFO 'Load order already applied.'
            Write-Host -ForegroundColor Green '    Already applied'
        }
        [String[]]$MissingWorkshopMods = ForEach ($Key in $G__LoadOrderData.Keys | Where-Object {$G__LoadOrderData[$_].Type -eq 'mod_workshop_package'}) {
            [Hashtable]$Current = $G__LoadOrderData[$Key]
            If (!(Test-WorkshopModInstalled $Current.SourcePath)) {

                Write-Log WARN "Missing workshop subscription: $($Current.Name)"
                Write-Host -ForegroundColor Yellow (''.PadRight(4) + 'MISSING WORKSHOP SUBSCRIPTION: ' + $Current.Name)

                $Current.SourceName
            }
        }
        If ($MissingWorkshopMods) {
            Do {[Byte]$UserInput = Read-KeyPress ' Open Workshop item page in Steam? [Y/N]' -Clear} Until ($UserInput -In [Byte[]][Char[]]'YN')
            
            Switch ($UserInput) {
                ([Byte][Char]'Y') {ForEach ($Mod in $MissingWorkshopMods) {Start-SteamWorkshopPage $Mod; [Void](Read-KeyPress ' Press any key to continue...' -Clear)}}
                ([Byte][Char]'N') {Break}
            }
        }
    }

    Function Backup-ProfileUnit {
        [CmdletBinding()]
        Param ([IO.FileInfo]$ProfileUnit = $G__ProfileUnit)

        Write-Log INFO 'Received profile backup request.'

        [String]$Name            = 'profile_' + [DateTime]::Now.ToString('yy-MM-dd_HHmmss')
        [IO.FileInfo]$BackupFile = $G__ProfileUnit.CopyTo("$($G__ProfilePath.FullName)\$Name.bak")

        Write-Log INFO "Profile backup created: $($BackupFile.Name)"

        Return $BackupFile
    }

    Function Export-LoadOrder {
        [CmdletBinding()]
        Param ([IO.FileInfo]$ProfileUnit = $G__ProfileUnit)

        Write-Log INFO 'Received active load order export request.'

        [IO.FileInfo]$SaveTarget = Get-FilePathByDialog -Save 'Save load order as...' 'Load order file (*.order)|*.order|All files (*.*)|*.*' 'MyLoadOrder.order'

        #TODO: Implement checks for successful export
        If (![String]::IsNullOrWhiteSpace($SaveTarget)) {
            Try {
                Write-Log INFO "Preparing active profile ('$G__ActiveProfileName') for load order export."
                [String]$ProfileFormat = Get-ProfileUnitFormat $ProfileUnit

                If ($ProfileFormat -ne 'Text') {ConvertTo-PlainTextProfileUnit}

                [String]$ProfileMods = Read-PlainTextProfileUnit Mods -Raw -Direct:($ProfileFormat -eq 'Text')
                Write-Log INFO "Writing load order of $(($ProfileMods -Split "`n").Count) mods to '$($SaveTarget.FullName)'."
                Set-UTF8Content $SaveTarget $ProfileMods -NoNewline

                Write-Log INFO 'Verifying export.'
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

        Write-Log INFO 'Received self-move request.'

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

            Write-Log INFO 'Executing script from new directory.'
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

        Write-Log INFO 'Received load order import request.'

        Write-Log INFO 'Displaying file selection dialog.'
        [IO.FileInfo]$InFile = Get-FilePathByDialog -Open 'Import load order' 'Load order file (*.order)|*.order|All files (*.*)|*.*'
        Clear-Host

        If ($InFile) {
            Write-Log INFO "File '$($InFile.FullName)' selected for import."
            Return $InFile
        }
        Else {
            Write-Log INFO 'No file selected for import. Selecting current load order for import.'
            Return $G__LoadOrder
        }
    }

    Function Select-Profile {
        [CmdletBinding()]
        Param ([Switch]$AllowEsc)

        Write-Log INFO 'Received profile selection request.'

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
                Write-HostX 0 -Color ('DarkGray', 'Green')[$IsSelected] (' ' + ('   ', '>> ')[$IsSelected] + $Directory.PadRight($LongestDir) + "$Name ") -Newline
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
                Switch (Read-KeyPress) {
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

        Write-Log INFO 'Received active profile request.'

        [String]$StoredProfile = Read-EmbeddedValue $G__DataIndices.ActiveProfile.Index

        If ($StoredProfile -eq '***GAME_PROFILE_PLACEHOLDER***' -Or [String]::IsNullOrWhiteSpace($StoredProfile) -Or ![IO.Directory]::Exists("$($G__GameRootDirectory.FullName)\profiles\$StoredProfile")) {$StoredProfile = Select-Profile}
        
        Return $StoredProfile
    }

    Function Set-ActiveProfile {
        [CmdletBinding()]
        Param ([Parameter(Mandatory)][String]$Directory)

        Write-Log INFO 'Received active profile change request.'

        If ($Directory -ne $G__ActiveProfile) {
            Write-EmbeddedValue $G__DataIndices.ActiveProfile.Index $Directory
            Write-Log INFO "Active profile changed from '$G__ActiveProfile' to '$Directory'. Executing script restart routine."

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
            [Void](New-PSDrive HKCR Registry HKEY_CLASSES_ROOT -Scope GLOBAL -EA 0)
            [String]$BrowserPath = [Regex]::Match((Get-ItemProperty HKCR:\$BrowserName\shell\open\command).'(default)', '\".+?\"')

            Start-Process $BrowserPath $Uri
        }
    }

    Function Start-SteamWorkshopPage {
        [CmdletBinding()]
        Param ([Parameter(Mandatory)][String]$FileID)

        Start-Process "steam://url/CommunityFilePage/$FileID"

        Write-Log INFO "Opened Steam Workshop page for '$FileID'."
    }

    Function Show-LandingScreen {
        Write-Host ($G__UILine * [Console]::BufferWidth)
        Write-Host "`n$G__UITab$($G__ScriptDetails.Title)`n"
        Write-Host "$G__UITab$($G__ScriptDetails.Version), Updated $($G__ScriptDetails.VersionDate)"
        Write-Host "$G__UITab$($G__ScriptDetails.Copyright) - $($G__ScriptDetails.Author)`n"

        [Void](Read-KeyPress " Continuing in `$Timeout seconds. Press any key to skip..." -Timeout 3 -DefaultKeyCode 13 -Clear)
    }

    Function Invoke-Menu {
        [CmdletBinding()]
        Param ([Switch]$Saved)

        Write-Log INFO 'Received menu display request.'
        
        [Byte]$UILineWidth      = 100
        [String]$SetAndContinue = '; Update-ProtectedVars; $Save = $False; Continue'
        [String]$OrderRunText   = 'Update active mods'
        [String]$AllRunText     = 'Update all mods'
        If ($G__ValidateInstall) {
            $OrderRunText += ' + verify integrity'
            $AllRunText   += ' + verify integrity'
        }
        If ($G__DeleteDisabled)  {$OrderRunText += " + delete $G__DDSel inactive mods"}
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
        Write-Log INFO 'Formatted menu entries and options.'

        Write-Log INFO 'Displaying main menu.'

        Write-Host "`n    $($G__ScriptDetails.Title)   $($G__ScriptDetails.Version)`n"

        Write-Host ($G__UILine * [Console]::BufferWidth)

        Write-Host -NoNewline ("`n      " + "Active $G__GameNameShort profile: ".PadRight($ActiveDataPadding))
        Write-HostFancy -ForegroundColor Green $G__ActiveProfileName
        Write-Host -NoNewline ('      ' + 'Active load order: '.PadRight($ActiveDataPadding))
        Write-HostFancy -ForegroundColor Green $G__LoadOrder

        Write-HostFancy "`n    $($G__UILine * $UILineWidth)`n"

        Write-HostFancy " $G__UITab[1]       Launch $G__GameName upon completion`n"
        Write-HostFancy " $G__UITab[2]       Launch $($G__TSSETool.Name) with $G__GameName" -ForegroundColor ('DarkGray', [Console]::ForegroundColor)[$G__TSSETool.Installed]

        Write-HostFancy "`n$G__UITab$($G__UILine * $UILineWidth)`n"

        Write-HostFancy " $G__UITab[3]       Delete$((' managed', ' ALL', ' managed')[$G__DDSel]) mods not in the active load order ([TAB] will override this option)`n" -ForegroundColor ([Console]::ForegroundColor, 'DarkGray')[$G__OfflineMode]
        Write-HostFancy " $G__UITab[4]       Verify game file integrity (Forces Steam Workshop mod updates)`n"
        Write-HostFancy " $G__UITab[5]       Skip profile load order configuration ([SPACE] will override this option)" -ForegroundColor ([Console]::ForegroundColor, 'DarkGray')[$G__OfflineMode]

        Write-HostFancy "`n$G__UITab$($G__UILine * $UILineWidth)`n"

        Write-HostFancy " $G__UITab[6]       Save current options $(('', '[SAVED]')[$Saved.IsPresent])" -ForegroundColor ([Console]::ForegroundColor, 'Green')[$Saved.IsPresent]

        Write-HostFancy "`n$G__UITab$($G__UILine * $UILineWidth)`n"

        Write-HostFancy " $G__UITab[7]       Export load order from active profile`n"
        Write-HostFancy " $G__UITab[8]       Import custom load order"

        Write-HostFancy "`n$G__UITab$($G__UILine * $UILineWidth)`n"

        Write-HostFancy " $G__UITab[9]       Change load order`n" -ForegroundColor ([Console]::ForegroundColor, 'DarkGray')[$G__OfflineMode]
        Write-HostFancy " $G__UITab[0]       Change profile"

        Write-HostFancy "`n$G__UITab$($G__UILine * $UILineWidth)`n"

        Write-HostFancy " $G__UITab[ESC]     Exit"

        Write-HostFancy "`n$G__UITab$($G__UILine * $UILineWidth)`n"

        Write-HostFancy " $G__UITab[SPACE]   Configure profile load order ONLY`n"
        Write-HostFancy " $G__UITab[ENTER]   $OrderRunText" -ForegroundColor ([Console]::ForegroundColor, 'DarkGray')[$G__OfflineMode]
        Write-HostFancy " $G__UITab[TAB]     $AllRunText" -ForegroundColor ([Console]::ForegroundColor, 'DarkGray')[$G__OfflineMode]

        Write-HostFancy "`n$G__UITab$($G__UILine * $UILineWidth)`n"

        Write-HostFancy "   $G__UITab$(('', "WARNING: Deleted mods must be reaquired if reactivated in the future.`n")[$G__DeleteDisabled])" -ForegroundColor Yellow

        While ($True) {
            [Byte]$Choice = Read-KeyPress
            #--------------------- NUM LOCK ON
            # KEY    CODE  DESCRIPTION
            # TAB   / 9  - Execute (Update all mods)
            # ENTER / 13 - Execute (Update based on load order only)
            # ESC   / 27 - Exit
            # SPACE / 32 - No update
            # 0     / 48 - Change profile
            # 1     / 49 - Start game
            # 2     / 50 - Start save editor
            # 3     / 51 - Delete inactive mods
            # 4     / 52 - Validate install
            # 5     / 53 - Skip load order config
            # 6     / 54 - Save options
            # 7     / 55 - Export load order
            # 8     / 56 - Import load order
            # 9     / 57 - Change load order
            # TODO: Implement NumLk toggle for additional options
            #--------------------- NUM LOCK OFF
            # NUM1  / 35 - Toggle/set log retention
            # NUM2  / 40 - Toggle auto backups
            # NUM3  / 34 - Switch target game
            # NUM4  / 37 - Set Repository URL
            Switch ($Choice) {
                9  {Write-Log INFO "$Choice : [TAB] ('Execute (Update all)') selected."          # [TAB]
                    If ($G__OfflineMode) {Write-Log WARN "Aborted: Choice invalid in offline mode."; Break}
                    Return '$G__UpdateAll = $True; Update-ProtectedVars; Break'}
                13 {Write-Log INFO "$Choice : [ENTER] ('Execute (Update active)') selected."     # [ENTER]
                    If ($G__OfflineMode) {Write-Log WARN "Aborted: Choice invalid in offline mode."; Break}
                    Return 'Break'}
                27 {Write-Log INFO "$Choice : [ESC] ('Exit') selected."                          # [ESC]
                    Return 'Exit'}
                32 {Write-Log INFO "$Choice : [SPACE] ('Configure load order only') selected."   # [SPACE]
                    If ($G__OfflineMode) {Write-Log WARN "Aborted: Choice invalid in offline mode."; Break}
                    Return '$G__NoUpdate = $True; Update-ProtectedVars; Break'}
                48 {Write-Log INFO "$Choice : [0] ('Change profile') selected."                  # [0]
                    If (!(Select-Profile -AllowEsc)) {Return 'Continue'}
                    Else {Return 'Unprotect-Variables; $GLOBAL:G__ScriptRestart = $True; Return "Menu"'}}
                49 {Write-Log INFO "$Choice : [1] ('Start game') selected."                      # [1]
                    Return '$G__StartGame = !$G__StartGame' + $SetAndContinue}
                50 {Write-Log INFO "$Choice : [2] ('Start save editor') selected."               # [2]
                    Return '$G__StartSaveEditor = $G__StartGame -And !$G__StartSaveEditor' + $SetAndContinue}
                51 {Write-Log INFO "$Choice : [3] ('Delete inactive mods') selected."            # [3]
                    If ($G__OfflineMode) {Write-Log WARN "Aborted: Choice invalid in offline mode."; Break}
                    Return '$G__DDSel = ($G__DDSel + 1) % 3; $G__DeleteDisabled = $G__DDSel -ne 0;' + $SetAndContinue}
                52 {Write-Log INFO "$Choice : [4] ('Validate install') selected."                # [4]
                    Return '$G__ValidateInstall = !$G__ValidateInstall' + $SetAndContinue}
                53 {Write-Log INFO "$Choice : [5] ('Skip load order config') selected."          # [5]
                    If ($G__OfflineMode) {Write-Log WARN "Aborted: Choice invalid in offline mode."; Break}
                    Return '$G__NoProfileConfig = !$G__NoProfileConfig' + $SetAndContinue}
                54 {Write-Log INFO "$Choice : [6] ('Save options') selected."                    # [6]
                    Return 'Write-AllEmbeddedValues; $Save = $True; Continue'
                    Write-AllEmbeddedValues}
                55 {Write-Log INFO "$Choice : [7] ('Export load order') selected."               # [7]
                    Return 'Export-LoadOrder; Continue'
                    Export-LoadOrder}
                56 {Write-Log INFO "$Choice : [8] ('Import load order') selected."               # [8]
                    Return '$G__LoadOrder = Set-ActiveLoadOrder (Import-LoadOrder)' + $SetAndContinue
                    Import-LoadOrder}
                57 {Write-Log INFO "$Choice : [9] ('Change load order') selected."               # [9]
                    If ($G__OfflineMode) {Write-Log WARN "Aborted: Choice invalid in offline mode."; Break}
                    Return '$G__LoadOrder = Set-ActiveLoadOrder (Select-LoadOrder)' + $SetAndContinue
                    Select-LoadOrder
                    Set-ActiveLoadOrder}
                Default {Write-Log INFO "Invalid menu choice: '$Choice'"; Break} # Invalid choice
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
            Switch (Read-KeyPress) {
                ([Byte][Char]'N') {Return $False} # 78
                ([Byte][Char]'Y') {Return $True}  # 89
                Default           {Break}         # Invalid
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

    Function Get-PersistentStorage {
        [CmdletBinding()]
        Param ([IO.FileInfo]$File = $G__ScriptPath, [String]$EOF = '#PERSIST_END', [String]$BOF)

        Write-Log INFO 'Received persistent storage request.'

        [Collections.Generic.List[String]]$Data = @()
        [Text.UTF8Encoding]$UTF8Encoding        = [Text.UTF8Encoding]::New($False)

        [Threading.CancellationTokenSource]$Cancellation    = [Threading.CancellationTokenSource]::New()
        [Collections.Generic.IAsyncEnumerable[String]]$Enum = [IO.File]::ReadLinesAsync($File.FullName, $UTF8Encoding, $Cancellation.Token)
        [Collections.Generic.IAsyncEnumerator[String]]$Feed = $Enum.GetAsyncEnumerator($Cancellation.Token)

        Write-Log INFO "Initialized cancellation token and asynchronous enumerator for '$($File.FullName)'."
        
        Try {
            [Bool]$InRange = !$PSBoundParameters.ContainsKey('BOF')
            If ($InRange) {Write-Log INFO "Performing asynchronous enumeration until EOF token '$EOF'."}
            Else          {Write-Log INFO "Performing asynchronous enumeration until EOF token '$EOF'. Ignoring data preceding BOF token '$BOF'."}
            While ($Feed.MoveNextAsync().AsTask().Result -And !$Cancellation.IsCancellationRequested) {
                [String]$Line = $Feed.Current
                If     ($Line -eq '')   {Continue}
                ElseIf (!$InRange)      {$InRange = $Line -eq $BOF}
                ElseIf ($Line -eq $EOF) {$Cancellation.Cancel()}
                Else                    {$Data.Add($Line)}
            }
            Write-Log INFO "Enumeration halted on $($Data.Count): IsCancellationRequested=$($Cancellation.IsCancellationRequested); Current='$Line'"
        }
        Catch   {Write-Log ERROR "Failed to read persistent storage: $($_.Exception.Message)"; Throw $_}
        Finally {
            If ($Null -ne $Feed)         {[Void]$Feed.DisposeAsync()}
            If ($Null -ne $Cancellation) {$Cancellation.Dispose()}
            Write-Log INFO 'Disposed feed and cancellation token.'
        }
        
        If ($Data.Count -eq 0) {
            Write-Log ERROR "Failed to read persistent storage: No data was read using EOF '$EOF'$(('', " + BOF '$BOF'")[$PSBoundParameters.ContainsKey('BOF')])."
            Throw 'Failed to read persistent storage: No data was read.'
        }

        Write-Log INFO "Retrieved $($Data.Count) entries:`n$($Data -Join "`n")"
        
        Return $Data
    }

    Function Set-PersistentStorage {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory, Position = 0)][Collections.Generic.List[String]]$Data,
            [Parameter(Position = 1)][IO.FileInfo]$File = $G__ScriptPath,
            [String]$EOF = '#PERSIST_END', [String]$BOF
        )

        Write-Log INFO 'Received persistent storage write request.'

        [Collections.Generic.List[String]]$FileContents = Get-UTF8Content $File
        Write-Log INFO "Loaded '$($File.FullName)'."

        [Int]$BOFIndex = If ($PSBoundParameters.ContainsKey('BOF')) {$FileContents.IndexOf($BOF)} Else {0}
        If ($BOFIndex -eq -1) {
            Write-Log WARN "BOF token '$BOF' not detected in '$($File.Name)'. Using start index 0. Inserting token at index 0 of provided data."
            $Data.Insert(0, $BOF)
            $BOFIndex = 0
        }

        [Int]$EOFIndex = $FileContents.IndexOf($EOF)
        If ($EOFIndex -eq -1) {
            $Data.Add($EOF)
            Write-Log WARN "Failed to retrieve existing storage: EOF token '$EOF' not detected in '$($File.Name)'. Appending token to provided storage data."
            Write-Log WARN 'Attempting to retrieve existing storage by line matching. EOF: ''<#'''
            [Int]$EOFIndex = $FileContents.IndexOf('<#')
            If ($EOFIndex -eq -1) {
                Write-Log ERROR "Failed to retrieve existing storage: EOF token '<#' not detected in '$($File.Name)'. Aborting operation."
                Throw "Failed to retrieve existing storage: EOF token '<#' not detected in '$($File.Name)'."
            }
            Else {
                [Collections.Generic.List[String]]$_Storage = $FileContents.GetRange(0, $EOFIndex)
                For ([UInt32]$Index = $_Storage.Count - 1; $Index -ge 0; $Index--) {If ($_Storage[$Index] -NotMatch '^#(NUM|DEC|STR)_[a-z]+=.+;$') {$_Storage.RemoveAt($Index)} Else {Break}}
                If ($_Storage.Count -eq 0) {
                    Write-Log ERROR 'Failed to retrieve existing storage: No valid data detected in storage range. Aborting operation.'
                    Throw 'Failed to retrieve existing storage: No valid data detected in storage range.'
                }
                Write-Log INFO 'Detected storage data by line matching.'
                [Collections.Generic.List[String]]$ExistingStorage = $_Storage
            }
        }
        Else {[Collections.Generic.List[String]]$ExistingStorage = $FileContents.GetRange($BOFIndex, $EOFIndex)}

        Write-Log INFO "Existing storage: $BOFIndex..$($ExistingStorage.Count)/$($FileContents.Count) entries."

        If ((Get-StringHash $ExistingStorage) -eq (Get-StringHash $Data)) {
            Write-Log INFO 'No changes detected in provided persistent storage. Aborting operation.'
            Return
        }

        $FileContents.RemoveRange($BOFIndex, $ExistingStorage.Count)
        $FileContents.InsertRange($BOFIndex, $Data)
        
        Write-Log INFO "Removed old storage range $BOFIndex..$($ExistingStorage.Count). Inserted new storage range: $BOFIndex..$($Data.Count)"

        Set-UTF8Content $File $FileContents -NoNewline

        Write-Log INFO 'Successfully updated persistent storage data.'
    }

    Function Read-EmbeddedValue {
        [CmdletBinding()]
        Param ([Parameter(Mandatory)][UInt32]$Index, [Collections.Generic.List[String]]$CustomData)
        
        Write-Log INFO 'Received embedded value read request.'

        If ($PSBoundParameters.ContainsKey('CustomData')) {
            [Collections.Generic.List[String]]$ScriptData = $CustomData
            Write-Log INFO 'Reading embedded value from provided custom data.'
        }
        Else {[Collections.Generic.List[String]]$ScriptData = $G__StoredData}

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
        
        Write-Log INFO 'Received read request of all embedded values.'
        If ($PSBoundParameters.ContainsKey('CustomData')) {
            [Collections.Generic.List[String]]$ScriptData = $CustomData
            Write-Log INFO 'Reading embedded values from provided custom data.'
        }
        Else {[Collections.Generic.List[String]]$ScriptData = $G__StoredData}
        
        $DataIndices['ScriptVersion'] = [Hashtable]@{Index = 0; Type = [String]}
        [Hashtable]$ReadData          = @{}
        [String[]]$Pairs              = @()

        ForEach ($Key in $DataIndices.Keys) {
            [String]$ScriptLine              = $ScriptData[$DataIndices.$Key.Index]
            [String]$Info, [String]$RawValue = $ScriptLine -Split '=', 2
            $Info = $Info.Substring(1)
            $RawValue = $RawValue.Substring(0, $RawValue.Length - 1)
            [String]$Format, [String]$Name   = $Info -Split '_', 2
            Switch ($Format) {
                'NUM'   {[Int64]$Value  = $RawValue}
                'DEC'   {[Double]$Value = $RawValue}
                Default {[String]$Value = $RawValue}
            }
            $Pairs += "$($Key.PadRight(16))> '$Value'"
            $ReadData[$Key] = $Value
        }
        Write-Log INFO "All embedded values read ($($ReadData.Keys.Count)):`n$($Pairs -Join "`n")"
        Return $ReadData
    }

    Function New-EmbeddedValue {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory, Position = 0)][String]$SourceData,
            [Parameter(Mandatory, Position = 1)][String]$Value
        )
        
        Write-Log INFO "Received new embedded value reqiest of '$Value'."

        $Value = Switch ($Value) {
            'True'  {'1'}
            'False' {'0'}
            Default {$_}
        }
        [String]$DataKey = $SourceData.Substring(0, $SourceData.IndexOf('='))
        Write-Log INFO "New embedded value: $("'$DataKey'".PadRight(19))> '$Value'"
        Return "$DataKey=$Value;"
    }

    Function Write-EmbeddedValue {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory)][UInt32]$Index,
            [Parameter(Mandatory)][String]$Value
        )

        Write-Log INFO "Received embedded value write request: '$Value' at index $Index."

        [Collections.Generic.List[String]]$ScriptData = Get-PersistentStorage
        $ScriptData[$Index] = New-EmbeddedValue $ScriptData[$Index] $Value

        Set-PersistentStorage $ScriptData
        Write-Log INFO "Embedded value written: '$Value'"
    }

    Function Write-AllEmbeddedValues {
        [CmdletBinding()]
        Param ()
        
        Write-Log INFO 'Received write request for all embedded values.'

        [Collections.Generic.List[String]]$ScriptData = Get-PersistentStorage
        [String[]]$Pairs = @()

        ForEach ($Key in $G__DataIndices.Keys) {
            [String]$Value = Get-Variable "G__$Key" -ValueOnly
            [UInt32]$Index = $G__DataIndices.$Key.Index
            $Pairs        += "'$Key' > '$Value'"

            $ScriptData[$Index] = New-EmbeddedValue $ScriptData[$Index] $Value
        }
        Set-PersistentStorage $ScriptData
        Write-Log INFO "All embedded values written ($($Pairs.Count)):`n$($Pairs -Join "`n")"
    }

    Function Switch-GrammaticalNumber {
        [CmdletBinding(DefaultParameterSetName = 'Auto')]
        Param (
            [Parameter(Mandatory, Position = 0, ValueFromPipeline)][String]$Word,
            [Parameter(ParameterSetName = 'Count', Position = 1)][Int64[]]$Count,
            [Parameter(ParameterSetName = 'Singular')][Alias('S')][Switch]$Singularize,
            [Parameter(ParameterSetName = 'Plural')][Alias('P')][Switch]$Pluralize
        )

        Write-Log INFO 'Received grammatical number switch request.'

        If (!$G__PluralizerService) {
            Write-Log ERROR 'Pluralization service is unavailable.'
            Throw 'Pluralization service is unavailable'
        }

        [String]$ParamSet = $PSCmdlet.ParameterSetName
        [String]$Plural   = $G__PluralizerService.Pluralize($Word)
        [String]$Singular = $G__PluralizerService.Singularize($Word)

        If ($ParamSet -eq 'Count' -And $Count.Count -gt 1) {[String[]]$Return = ForEach ($Instance in $Count) {($Plural, $Singular)[[Math]::Abs($Instance) -eq 1]}}
        Else {[String]$Return = Switch ($ParamSet) {
            'Auto'     {($Plural, $Singular)[$G__PluralizerService.IsSingular($Word)]; Break}
            'Count'    {($Plural, $Singular)[[Math]::Abs($Count[0]) -eq 1]; Break}
            'Singular' {$Singular; Break}
            'Plural'   {$Plural; Break}
            Default    {$Word; Break}
        }}
        Write-Log INFO "Grammatical number switched: '$Word' > '$Return'"
        Return $Return
    }

    Function Get-ContrastingColor {
        [CmdletBinding(DefaultParameterSetName = 'ForColor')]
        Param (
            [Parameter(ParameterSetName = 'ForColor', Mandatory, Position = 0)]
            [Parameter(ParameterSetName = 'ForBackground', Position = 0)]
            [Parameter(ParameterSetName = 'ForForeground', Position = 0)]
            [ConsoleColor]$Color,
            [Parameter(ParameterSetName = 'ForBackground', Mandatory)][Switch]$ForBackground,
            [Parameter(ParameterSetName = 'ForForeground', Mandatory)][Switch]$ForForeground
        )

        Write-Log INFO "Received contrasting color request for '$Color'."

        [ConsoleColor]$Contrast = Switch ($Color) {
            'Black'   {[ConsoleColor]::White}
            'DarkGray'{[ConsoleColor]::White}
            'White'   {'Black'}
            Default    {'DarkGray'}
        }
        Write-Log INFO "Contrasting color for '$Color': '$Contrast'"
        Return $Contrast
    }

    Function Get-EnglishCulture {
        [CmdletBinding()]
        Param ([Switch]$Set)

        Write-Log INFO 'Received optimal English culture request.'
        # Default: 1033, en-US (English, United States)

        [CultureInfo]$CurrentCulture = [CultureInfo]::CurrentCulture
        Write-Log INFO "Current culture: LCID $($CurrentCulture.LCID) - $($CurrentCulture.Name) ($($CurrentCulture.DisplayName))"

        [String[]]$EngCultures = ([CultureInfo]::GetCultures([Globalization.CultureTypes]::AllCultures) | Where-Object {$_.Name -Like 'en-*'}).Name | Select-Object -Unique
        Write-Log INFO "Collected $($EngCultures.Count) EN culture candidates."

        [CultureInfo]$OptimalCulture = [CultureInfo]::GetCultureInfo(('en-US', $CurrentCulture.Name)[$CurrentCulture.Name -In $EngCultures])
        Write-Log INFO "Optimal EN culture: LCID $($OptimalCulture.LCID) - $($OptimalCulture.Name) ($($OptimalCulture.DisplayName))"

        If ($Set.IsPresent -And $CurrentCulture -ne $OptimalCulture) {
            [CultureInfo]::CurrentCulture = $OptimalCulture
            $CurrentCulture = [CultureInfo]::CurrentCulture
            Write-Log INFO "Set Session culture: LCID $($OptimalCulture.LCID) - $($OptimalCulture.Name) ($($OptimalCulture.DisplayName))"
        }

        Return $OptimalCulture
    }

    Function Get-LoadOrderData {
        [CmdletBinding()]
        Param ([String]$Name = $G__LoadOrder, [Switch]$Data, [Switch]$Raw)

        Write-Log INFO "Received load order data request for '$Name'."

        [String]$Content = If     ([IO.Path]::GetExtension($Name) -eq '.order') {Write-Log INFO "Load order data source: $Name (LOCAL)"; Get-UTF8Content $Name -Raw} 
                           ElseIf (!$G__OfflineMode)                            {Write-Log INFO "Load order data source: $Name.cfg (REPO)"; Get-UTF8Content -FromBytes (Get-ModRepoFile "$Name.cfg" -UseIWR).Content -Raw}
                           Else                                                 {Write-Log ERROR "Load order data unavailable: Unable to reach data source for $Name.cfg (REPO)."; Throw [ApplicationException]::New('Unavailable. (Offline mode)')}

        If (!(Test-LoadOrderFormat $Content -ShowInfo -ContinueOnError)) {Throw 'Invalid load order data'}
        [Hashtable]$LoadOrderData = Get-ModData $Content

        Write-Log INFO "Successfully imported load order data from '$Name'"

        If     ($Data.IsPresent -And $Raw.IsPresent)  {Return $LoadOrderData, $Content}
        ElseIf ($Data.IsPresent -And !$Raw.IsPresent) {Return $LoadOrderData}
        ElseIf (!$Data.IsPresent -And $Raw.IsPresent) {Return $Content}
        Else                                          {Return}
    }

    Function Remove-InactiveMods {
        [CmdletBinding()]
        Param ()

        Write-Log INFO 'Received inactive mod removal request.'

        [UInt16]$DeletedTargets, [UInt64]$OldSize = 0, 0
        [IO.FileInfo[]]$EnabledFiles = ForEach ($Key in $G__LoadOrderData.Keys | Where-Object {$G__LoadOrderData[$_].Type -ne 'mod_workshop_package'}) {[IO.Path]::GetFileName($G__LoadOrderData[$Key].SourcePath)}
        [IO.FileInfo[]]$Targets = ForEach ($File in Get-ChildItem *.scs -File) {$OldSize += $File.Length; If ($File -NotIn $EnabledFiles -And (($File.Name -In $G__OnlineData.PSObject.Properties.Name -And $G__DDSel -eq 1) -Or $G__DDSel -eq 2)) {$File}}

        If (!$Targets) {
            Write-Log INFO 'No mods to delete.'
            Write-Host "`n No mods to delete."
            Return
        }
        Else {Write-Log INFO "Detected $($Targets.Count) inactive $(Switch-GrammaticalNumber 'mod' $Targets.Count) for deletion."}

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

        Write-Log INFO 'Received load order selection request.'

        If (!$G__AllLoadOrders -Or $G__AllLoadOrders.Count -le 1) {
            Write-Log WARN 'No load orders detected. Aborting selection and using the current load order.'
            Return $G__LoadOrder
        }

        Write-Log INFO 'Displaying load order selection prompt.'

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
                Write-HostX 0 -Color ('DarkGray', 'Green')[$IsSelected] (' ' + ('   ', '>> ')[$IsSelected] + "$Order ") -Newline

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
                Switch (Read-KeyPress) {
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
            Write-EmbeddedValue $G__DataIndices.LoadOrder.Index $LoadOrder
            Write-Log INFO "Active load order changed from '$G__LoadOrder' to '$LoadOrder'"

            Return $LoadOrder
        }
        Return $G__LoadOrder
    }

    Function Get-LoadOrderList {
        [CmdletBinding()]
        Param ()

        If ($G__OfflineMode) {
            Write-Log WARN 'Can''t fetch load orders in offline mode'
            Return [String[]]@($G__LoadOrder)
        }
        [String[]]$LoadOrderList = (Get-ModRepoFile $G__RepositoryInfo.$G__GameNameShort.Orders -UseIWR).Content | ConvertFrom-JSON
        Write-Log INFO "Fetched available load orders ($($LoadOrderList.Count)) from master server"

        Return $LoadOrderList
    }

    Function Test-LoadOrderFormat {
        [CmdletBinding()]
        Param ([Parameter(Position = 0)][String]$Content, [Switch]$ShowInfo, [Switch]$ContinueOnError, [Switch]$ReturnInfo)

        Write-Log INFO 'Received load order format validation request.'

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
            [Parameter(Mandatory, ParameterSetName = 'Open')][Switch]$Open,
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

        Write-Log INFO 'Received file dialog request.'

        If ($Save.IsPresent) {[Windows.Forms.SaveFileDialog]$Browser = @{
            CheckPathExists  = !$NoPathCheck.IsPresent
            CreatePrompt     = $CreatePrompt.IsPresent
            OverwritePrompt  = !$NoOverwritePrompt.IsPresent
            FileName         = $File
            InitialDirectory = $Directory
            Filter           = $Filter
            Title            = $Title
        }}
        Else {[Windows.Forms.OpenFileDialog]$Browser = @{
            FileName         = $File
            InitialDirectory = $Directory
            Filter           = $Filter
            Multiselect      = $MultiSelect.IsPresent
            Title            = $Title
        }}
        Write-Log INFO "Initialized $($PSCmdlet.ParameterSetName)FileDialog '$Title'"

        Write-Log INFO "Displaying $($PSCmdlet.ParameterSetName)FileDialog '$Title'"

        [String]$DialogInteraction = $Browser.ShowDialog()

        Write-Log INFO "$($PSCmdlet.ParameterSetName)FileDialog interaction: '$DialogInteraction', FileName: '$($Browser.FileName)'"
        
        If ($DialogInteraction -eq 'OK') {Return [IO.FileInfo]$Browser.FileName}
    }

    Function Assert-TSSENamingScheme {
        [CmdletBinding()]
        Param ()

        Write-Log INFO 'Searching for TS SE Tool directory.'
        [String]$RootName         = $G__TSSETool.RootDirectory.Name
        [String]$Executable       = $G__TSSETool.Executable.Name
        [IO.DirectoryInfo]$Target = (Get-ChildItem -Path $G__GameRootDirectory.FullName -Filter $Executable -File -Recurse -Depth 2 | Sort-Object LastWriteTime -Descending)[0].Directory

        If ([String]::IsNullOrWhiteSpace($Target)) {Write-Log WARN "    Unable to locate TS SE Tool directory. Using '$RootName'"; Return $RootName}
        If ($Target.Name -eq $RootName)            {Write-Log INFO "    Success: '$RootName'"; Return $RootName}
        Write-Log INFO "    Success: '$($Target.FullName)'"
        Try {
            Rename-Item $Target.FullName $RootName
            Write-Log INFO "Renamed '$($Target.FullName)' to '$RootName'"
            Return $RootName
        }
        Catch {
            Write-Log WARN "Failed to rename '$($Target.FullName)' to '$RootName':`n$($_.Exception.Message)"
            Return $Target.Name
        }
    }

    Function Get-RepositoryInfo {
        [CmdletBinding()]
        Param ([String]$RepoURL = $G__RepositoryURL, [String]$Game = $G__GameNameShort)

        Try   {[PSObject]$RepoData = (Get-ModRepoFile information.json -Repository $RepoURL -UseIWR).Content | ConvertFrom-JSON}
        Catch {
            Write-Log WARN "Failed to retrieve repository information:`n$($_.Exception.Message)"
            Throw "Unable to communicate with master server '$RepoURL':`n    '$($_.Exception.Message)"
        }
        [UInt16]$Longest      = ($RepoData.PSObject.Properties.Name | Sort-Object Length)[-1].Length
        [String[]]$RepoLogMsg = ForEach ($Name in $RepoData.PSObject.Properties.Name) {$Name + (' ' * ($Longest - $Name.Length)) + ' = ' + $RepoData.$Name}

        Write-Log INFO "Retrieved repository information from '$RepoURL':`n$($RepoLogMsg -Join "`n")"
        Return $RepoData
    }

    Function Remove-ExpiredLogs {
        [CmdletBinding()]
        Param ([SByte]$Days = $G__LogRetentionDays)

        Write-Log INFO 'Received log deletion request.'

        $Days = Limit-Range $Days -1 ([SByte]::MaxValue)
        If ($Days -eq -1) {Write-Log INFO 'Log deletion is disabled'; Return 0}

        [DateTime]$Threshold      = [DateTime]::Now.AddDays($Days * -1)
        [IO.FileInfo[]]$TextFiles = Get-ChildItem "$($G__GameModDirectory.FullName)\*.txt" -File
        [IO.FileInfo[]]$LogFiles  = ForEach ($File in $TextFiles) {
            If ([Regex]::IsMatch($File.Name, "^$G__SessionID\.log\.txt$")) {Continue}
            If ([Regex]::IsMatch($File.Name, '^[A-F0-9]{8}\.log\.txt$'))   {If ($Days -eq 0 -Or $File.LastWriteTime -lt $Threshold) {$File}}
        }

        If ($LogFiles.Count -eq 0) {Write-Log INFO 'No old logs to delete'; Return 0}
        Else                       {Write-Log INFO "Detected $($LogFiles.Count) expired $(Switch-GrammaticalNumber 'log' $LogFiles.Count) for deletion"}

        [UInt16]$DeletionCount = 0

        ForEach ($Log in $LogFiles) {
            Try {
                [Double]$DaysPastRetention = [Math]::Round(($Threshold - $Log.LastWriteTime).TotalDays, 3)
                $Log.Delete()
                $DeletionCount++
                Write-Log INFO "Deleted log '$($Log.Name)' ($DaysPastRetention d past retention)"
            }
            Catch {Write-Log WARN "Failed to delete log '$($Log.Name)' ($DaysPastRetention d past retention): $($_.Exception.Message)"}
        }

        If ($DeletionCount -lt $LogFiles.Count) {Write-Log WARN "Failed to delete $($LogFiles.Count - $DeletionCount) log(s)"}

        Return $DeletionCount
    }
    Function Import-DotNetTypes {
        [CmdletBinding()]
        Param ([String[]]$Assemblies, [String[]]$TypeDefinitions)

        Write-Log INFO 'Received .NET type import request.'

        [String[]]$AssemblyNames = @()
        [String[]]$TypeNames     = @()

        If ($PSBoundParameters.ContainsKey('Assemblies')) {$Assemblies | ForEach-Object {$AssemblyNames += "Assembly: $_"}}
        If ($PSBoundParameters.ContainsKey('TypeDefinitions')) {
            ForEach ($TypeDef in $TypeDefinitions) {
                [Regex]::Matches($TypeDef, '(?<= )(class|enum) (\w+)(?= \{)').Value | ForEach-Object {
                    [String]$DefType, [String]$DefName = $_ -Split ' ', 2
                    $TypeNames += [String]('TypeDef: ' + $G__CultureTextInfo.ToTitleCase($DefType) + " $DefName")
                }
            }
        }
        [UInt16]$LongestTypeName = ($AssemblyNames + $TypeNames | Sort-Object Length)[-1].Length + 4

        If ($PSBoundParameters.ContainsKey('Assemblies')) {
            ForEach ($Assembly in $Assemblies) {
                Write-Host -NoNewline (($T__Tab * 5) + "Assembly: $Assembly...".PadRight($LongestTypeName))
                Add-Type -Assembly $Assembly
                Write-Host -ForegroundColor Green 'OK'
            }
            Write-Log INFO "Imported $($AssemblyNames.Count) assemblies."
        }

        If ($PSBoundParameters.ContainsKey('TypeDefinitions')) {
            ForEach ($TypeName in $TypeNames) {
                Write-Host -NoNewline (($T__Tab * 5) + "$TypeName...".PadRight($LongestTypeName))
                Write-Host -ForegroundColor Green 'OK'
            }
            ForEach ($TypeDef in $TypeDefinitions) {Add-Type -Language CSharp -TypeDefinition $TypeDef}
            Write-Log INFO "Imported $($TypeNames.Count) type definitions."
        }
    }
    Write-Host -ForegroundColor Green "OK - $([UInt32](New-TimeSpan $T__Step ([DateTime]::Now)).TotalMilliseconds)ms`n"

    [String]$T__ModDir          = ('Euro Truck Simulator 2', 'American Truck Simulator')[$T__Game -eq 'ATS'] + '\mod'
    [IO.FileInfo]$G__SessionLog = [Environment]::GetFolderPath('MyDocuments') + "\$T__ModDir\$G__SessionID.log.txt"
    
    Write-Log INFO "Session started. Session ID: $G__SessionID"
    Write-Log INFO "Environment info:`n$(($PSVersionTable.GetEnumerator() | ForEach-Object {"$($_.Key): $($_.Value)"}) -Join "`n")"
    
    Trap {Wait-WriteAndExit ("`n`n FATAL ERROR`n " + (Format-AndExportErrorData $_))}

    $ErrorActionPreference = [Management.Automation.ActionPreference]::Stop
    $ProgressPreference    = [Management.Automation.ActionPreference]::SilentlyContinue

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::TLS12
    [CultureInfo]$G__CurrentCulture             = Get-EnglishCulture -Set
    [Globalization.TextInfo]$G__CultureTextInfo = $G__CurrentCulture.TextInfo

    $T__Step = [DateTime]::Now
    Write-Host "$($T__Tab * 3)Importing assemblies"
    [String[]]$T__AssemblyList = @(
        'System.Windows.Forms',
        'System.IO.Compression.FileSystem',
        'System.Data.Entity.Design',
        'System.Net.Http',
        'PresentationCore',
        'PresentationFramework'
    )
    [String]$T__TypeDef = @(
        'using System;',
        'using System.Runtime.InteropServices;',
        'public class WindowsAPI {',
        '    [DllImport("user32.dll")] public static extern short GetAsyncKeyState(int vKey);',
        '    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);',
        '    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();',
        '    [DllImport("ntdll.dll")] public static extern uint RtlComputeCrc32(uint dwInitial, byte[] pData, int iLen);',
        '}',
        'public enum DeleteDisabledOptions {Off = 0, ManagedOnly = 1, All = 2}',
        'public enum ModUpdateState {Installing = 0, Repairing = 1, Updating = 2, Validating = 3, Reinstalling = 4}',
        'public enum ModRepairAction {None = 0, Entry = 1, File = 2}'
    ) -Join "`n"

    Import-DotNetTypes -Assemblies $T__AssemblyList -TypeDefinitions $T__TypeDef

    Write-Host -ForegroundColor Green "$($T__Tab * 5)$([UInt32](New-TimeSpan $T__Step ([DateTime]::Now)).TotalMilliseconds)ms`n"
    $T__Step = [DateTime]::Now

    Write-Host "`n$($T__Tab * 3)Initializing"
    Write-Host -NoNewline "$($T__Tab * 5)Scope constraints... "

    Protect-Variables
    Write-Host -ForegroundColor Green "OK - $([UInt32](New-TimeSpan $T__Step ([DateTime]::Now)).TotalMilliseconds)ms"
    $T__Step = [DateTime]::Now

    Write-Host -NoNewline "$($T__Tab * 5)Global values...     "

    [IO.FileInfo]$G__ScriptPath = $PSCommandPath
    [String]$G__UILine          = [Char]0x2500
    [String]$G__UITab           = ' ' * 4
    [UInt16]$G__MinWndWidth     = 120
    [UInt16]$G__MinWndHeight    = 55
    [Bool]$G__OfflineMode       = $False
    [Bool]$G__ClampAvailable    = 'Clamp' -In [String[]][Math].GetMethods().Name
    [Hashtable]$G__RI_RENGlobal = @{Force = $True; EA = 0}
    
    [Collections.Generic.List[String]]$G__StoredData = Get-PersistentStorage

    [Hashtable]$G__DataIndices = @{
        # ScriptVersion  = 0  <-- Script version is ALWAYS the first embedded value (hardcoded)
        ActiveProfile    = [Hashtable]@{Index = 1; Type = [String]}
        StartGame        = [Hashtable]@{Index = 2; Type = [Bool]}
        ValidateInstall  = [Hashtable]@{Index = 3; Type = [Bool]}
        DDSel            = [Hashtable]@{Index = 4; Type = [DeleteDisabledOptions]}
        NoProfileConfig  = [Hashtable]@{Index = 5; Type = [Bool]}
        LoadOrder        = [Hashtable]@{Index = 6; Type = [String]}
        StartSaveEditor  = [Hashtable]@{Index = 7; Type = [String]}
        RepositoryURL    = [Hashtable]@{Index = 8; Type = [String]}
        OfflineData      = [Hashtable]@{Index = 9; Type = [String]}
        LogRetentionDays = [Hashtable]@{Index = 10; Type = [SByte]}
        IsExperimental   = [Hashtable]@{Index = 11; Type = [Int]}
        TargetGame       = [Hashtable]@{Index = 12; Type = [String]}
        ProfileBackups   = [Hashtable]@{Index = 13; Type = [Bool]}
    }
    [Hashtable]$G__AllGameInfo = @{
        ETS2 = [Hashtable]@{
            AppID    = 227300
            Name     = 'Euro Truck Simulator 2'
            Short    = 'ETS2'
            Process  = 'eurotrucks2'
        }
        ATS = [Hashtable]@{
            AppID    = 270880
            Name     = 'American Truck Simulator'
            Short    = 'ATS'
            Process  = 'amtrucks'
        }
    }

    [__ComObject]$G__WScriptShell                                       = New-Object -COM WScript.Shell
    [Security.Cryptography.SHA1CryptoServiceProvider]$G__CryptoProvider = New-Object Security.Cryptography.SHA1CryptoServiceProvider
    [Data.Entity.Design.PluralizationServices.PluralizationService]$G__PluralizerService = [Data.Entity.Design.PluralizationServices.PluralizationService]::CreateService($G__CurrentCulture)
    
    [Hashtable]$G__TitleSpecifics           = $G__AllGameInfo[$T__Game]
    [UInt32]$G__GameAppID                   = $G__TitleSpecifics.AppID
    [String]$G__GameName                    = $G__TitleSpecifics.Name
    [String]$G__GameNameShort               = $G__TitleSpecifics.Short
    [String]$G__GameProcess                 = $G__TitleSpecifics.Process
    [IO.DirectoryInfo]$G__GameRootDirectory = [IO.Path]::Combine([Environment]::GetFolderPath('MyDocuments'), $G__GameName)
    [IO.FileInfo]$G__GameLogPath            = "$($G__GameRootDirectory.FullName)\game.log.txt"
    [IO.FileInfo]$G__GameConfigPath         = "$($G__GameRootDirectory.FullName)\config.cfg"
    [IO.DirectoryInfo]$G__GameModDirectory  = "$($G__GameRootDirectory.FullName)\mod"
    
    [IO.DirectoryInfo]$G__GameInstallDirectory, [IO.DirectoryInfo]$G__WorkshopDirectory = Get-GameDirectory -Both
    [Void]$G__GameInstallDirectory # TODO: Remove the voided reference when $G__GameInstallDirectory is referenced properly
    [IO.Directory]::SetCurrentDirectory((Set-Location $G__GameModDirectory.FullName -PassThru))

    [Bool]$G__NoUpdate  = $False
    [Bool]$G__UpdateAll = $False

    Write-Host -ForegroundColor Green "OK - $([UInt32](New-TimeSpan $T__Step ([DateTime]::Now)).TotalMilliseconds)ms"
    $T__Step = [DateTime]::Now

    Write-Host "$($T__Tab * 5)Persistent data"
    [Hashtable]$T__PersistentData = Read-AllEmbeddedValues

    ForEach ($T__Key in $G__DataIndices.Keys) {
        Write-Host -NoNewline "$($T__Tab * 7)$($T__Key.PadRight(20)): "
        [String]$T__Var = "G__$T__Key"

        [PSVariable]$T__SetValue = Set-Variable $T__Var ($T__PersistentData.$T__Key -As $G__DataIndices.$T__Key.Type) -Force -PassThru
        
        Write-Host -ForegroundColor Green (([String]$T__SetValue.Value).Substring(0, [Math]::Min(20, ([String]$T__SetValue.Value).Length)) + '[...]')
    }

    Write-EmbeddedValue $G__DataIndices.TargetGame.Index $G__TargetGame

    If ($G__LogRetentionDays -ge 0) {
        Write-Host -NoNewline "$($T__Tab * 5)Purging logs...      "
        [UInt16]$T__RemovedLogs = Remove-ExpiredLogs
        Write-Host -ForegroundColor Green "OK - $([Int](New-TimeSpan $T__Step ([DateTime]::Now)).TotalMilliseconds)ms - $T__RemovedLogs"
        $T__Step = [DateTime]::Now
    }

    [UInt32]$G__Revision          = Limit-Range $G__IsExperimental 0 ([UInt32]::MaxValue)
    [Bool]$G__IsExperimental      = $G__IsExperimental -gt -1
    [Hashtable]$G__TitleSpecifics = $G__AllGameInfo.$G__TargetGame
    [UInt32]$G__GameAppID         = $G__TitleSpecifics.AppID
    [String]$G__GameName          = $G__TitleSpecifics.Name
    [String]$G__GameNameShort     = $G__TitleSpecifics.Short
    [String]$G__GameProcess       = $G__TitleSpecifics.Process

    Write-Host -ForegroundColor Green "$($T__Tab * 7)$([UInt32](New-TimeSpan $T__Step ([DateTime]::Now)).TotalMilliseconds)ms"
    $T__Step = [DateTime]::Now

    Write-Host -NoNewline "`n$($T__Tab * 5)Console and Environment... "

    If (!(Test-PSHostCompatibility)) {Wait-WriteAndExit (" Startup aborted - Incompatible console host.`n Current host '" + $Host.Name + "' does not support required functionality.")}

    [Console]::CursorVisible     = $False
    [Console]::Title             = "TruckSim External Mod Manager v$G__ScriptVersion"
    [UInt16]$WndX, [UInt16]$WndY = [Console]::WindowWidth, [Console]::WindowHeight
    [UInt16]$G__WndWidth         = ($WndX, $G__MinWndWidth)[$WndX -lt $G__MinWndWidth]
    [UInt16]$G__WndHeight        = ($WndY, $G__MinWndHeight)[$WndY -lt $G__MinWndHeight]

    [Console]::SetWindowSize($G__WndWidth, $G__WndHeight)
    
    If (!$G__GameModDirectory.Exists)                    {Wait-WriteAndExit " Startup aborted - Cannot locate the $G__GameNameShort mod directory:`n     '$($G__GameModDirectory.FullName)' `n Verify that $G__GameName is correctly installed and try again."}
    If ($PSScriptRoot -ne $G__GameModDirectory.FullName) {
        If (!(Move-SelfToModDirectory)) {Wait-WriteAndExit "Startup aborted - Invalid script location.`n Unable to fix automatically.`n '$($G__ScriptPath.FullName)' must be manually placed in '$G__GameModDirectory' to run."}
        Else                            {Exit}
    }
    
    Write-Host -ForegroundColor Green "OK - $([UInt32](New-TimeSpan $T__Step ([DateTime]::Now)).TotalMilliseconds)ms"
    $T__Step = [DateTime]::Now

    Write-Host -NoNewline "$($T__Tab * 5)Repo and Game Data...      "
    If ([String]::IsNullOrWhitespace($G__RepositoryURL) -Or $G__RepositoryURL -eq 'http://your.domain/repo') {
        Write-Log WARN 'No repository URL specified. Prompting for input.'
       
        [DateTime]$T__PromptStart = [DateTime]::Now
        [Hashtable]$T__OrigPos    = @{X = [Console]::CursorLeft; Y = [Console]::CursorTop}
        [HashTable]$T__PromptPos  = @{X = $T__OrigPos.X - 27; Y = $T__OrigPos.Y + 2}

        Do {
            [Console]::SetCursorPosition($T__PromptPos.X, $T__PromptPos.Y)
            
            $Host.UI.RawUI.FlushInputBuffer()
            Write-Log INFO 'Flushed input buffer.'
            [Console]::CursorVisible = $True

            Write-Host -NoNewline -BackgroundColor Yellow ' Enter mod repository URL: '
            [String]$T__URL          = Read-Host
            [Console]::CursorVisible = $False

            Try   {[PSObject]$G__RepositoryInfo = Get-RepositoryInfo -RepoURL $T__URL -EA 1; Break}
            Catch {Write-Host -ForegroundColor Red ' No valid repository data found. Please try again.'; Start-Sleep 2}
            [UInt16]$T__LineDiff = [Console]::CursorTop - $T__PromptPos.Y
            [Console]::SetCursorPosition($T__PromptPos.X, $T__PromptPos.Y)
            For ([UInt16]$T__Line = 0; $T__Line -lt $T__LineDiff; $T__Line++) {Write-Host (' ' * ([Console]::BufferWidth - $T__PromptPos.X))}
            Write-Host -NoNewline (' ' * ([Console]::BufferWidth - $T__PromptPos.X))
        } While ($True)
        
        [Console]::SetCursorPosition($T__OrigPos.X, $T__OrigPos.Y)
        [TimeSpan]$T__PromptDuration = New-TimeSpan $T__PromptStart ([DateTime]::Now)

        $G__RepositoryURL = $T__URL

        Write-EmbeddedValue $G__DataIndices.RepositoryURL.Index $G__RepositoryURL
        Write-Log INFO "Repository URL set to '$G__RepositoryURL'"
    }
    Else {
        [TimeSpan]$T__PromptDuration = [TimeSpan]::Zero
        Try {
            [PSObject]$G__RepositoryInfo = Get-RepositoryInfo
            Try {
                [String]$T__RepositoryInfoString = $G__RepositoryInfo | ConvertTo-JSON -Compress
                If ([String]::IsNullOrEmpty($T__RepositoryInfoString)) {
                    $T__RepositoryInfoString = '{}'
                    Throw 'No repository data.'
                }
                $G__OfflineData = $T__RepositoryInfoString
                Write-EmbeddedValue $G__DataIndices.OfflineData.Index $T__RepositoryInfoString
                Write-Log INFO "Updated offline repository information: $T__RepositoryInfoString"
            }
            Catch {
                Write-Log WARN "Failed to update offline repository information:`n$($_.Exception.Message)"
                Throw $_
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
            [Void](Read-KeyPress)
        }
    }

    [IO.FileInfo]$G__TempProfileUnit = "$Env:TEMP\profile.sii"
    [Bool]$G__DeleteDisabled         = $G__DDSel -ne 0
    [String[]]$G__AllLoadOrders      = Get-LoadOrderList
    
    If ([IO.Path]::GetExtension($G__LoadOrder) -ne '.order' -And $G__LoadOrder -NotIn $G__AllLoadOrders -And !$G__OfflineMode) {
        Write-Log WARN "The active load order '$G__LoadOrder' is not present in the repository. Applying fallback load order."
        $G__LoadOrder = Set-ActiveLoadOrder $G__RepositoryInfo.$G__GameNameShort.DefaultOrder
    }

    [Bool]$GLOBAL:G__ScriptRestart = ($GLOBAL:G__ScriptRestart, $False)[$Null -eq $GLOBAL:G__ScriptRestart]
    [ScriptBlock]$G__EXEC_RESTART  = {If ($GLOBAL:G__ScriptRestart -eq $True) {Unprotect-Variables; Remove-Variable G__ScriptRestart -Scope GLOBAL -EA 0; Return ''}}

    Write-Host -ForegroundColor Green "OK - $([UInt32](New-TimeSpan $T__Step ([DateTime]::Now)).TotalMilliseconds)ms"
    $T__Step = [DateTime]::Now

    Write-Host -NoNewline "$($T__Tab * 5)TS SE Tool Information...  "
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
    Write-Host -ForegroundColor Green "OK - $([UInt32](New-TimeSpan $T__Step ([DateTime]::Now)).TotalMilliseconds)ms"
    $T__Step = [DateTime]::Now

    Write-Host -NoNewline "$($T__Tab * 5)Script Information...      "
    [Hashtable]$G__ScriptDetails = @{
        Author      = 'RainBawZ'
        Copyright   = [Char]0x00A9 + [DateTime]::Now.ToString('yyyy')
        Title       = ($Null, '[Experimental] ')[$G__IsExperimental] + "TruckSim External Mod Manager"
        ShortTitle  = 'TSExtModMan'
        Version     = "Version $G__ScriptVersion" + ($Null, " (EXPERIMENTAL - Rev. $G__Revision)")[$G__IsExperimental]
        VersionDate = '2024.11.8'
        GitHub      = 'https://github.com/RainBawZ/ETS2ExternalModManager/'
        Contact     = 'Discord - @realtam'
    }
    $G__ScriptDetails['GitHubFile']  = $G__ScriptDetails.GitHub + 'blob/main/Client/' + ($Null, 'Experimental/')[$G__IsExperimental] + "$($G__ScriptDetails.ShortTitle).ps1"
    [String[]]$G__UpdateNotes = @(
        '',
        "3.7.0$(($Null, ' (EXPERIMENTAL)')[$G__IsExperimental])",
        '',
        '- Added experimental support for American Truck Simulator (ATS).',
        '- Added secondary menu for additional options accessible by pressing Num Lock [NUMLK].',
        '  * Added menu option for toggling deletion of expired logs or setting log retention time.',
        '  * Added menu option for toggling automatic profile backups.',
        '  * Added menu option for manually setting repository URL.',
        '  * Added menu option for switching target sim.',
        '- Added internal support for experimental versions.',
        '- Added live countdown timer for keypress prompts.',
        '',
        '- Fixed crash upon selecting "Import load order" from the main menu.',
        '- Fixed uncommanded menu and prompt interactions when input was provided without an active prompt.',
        '- Fixed first-time profile selection menu starting before the script had finished loading.',
        '- Fixed text collisions between Repository URL prompt and loading screen information.',
        '- Fixed keypress prompts with timeouts not timing out.',
        '- Fixed repository downloader not supporting HTTPS in UseIWR mode.',
        '- Fixed TLS 1.2 not being enforced for repository communication.',
        '',
        '- Improved overall script performance.',
        '- Improved file I/O performance.',
        '- Improved keypress prompt interactivity.',
        '- Improved loading screen layout and information.',
        '- Improved Repository URL prompt appearance.',
        '- Improved log timestamp accuracy.',
        '- Improved log formatting and readability.',
        '- Improved type definition and assembly importing.',
        '',
        '- Changed script name to "TruckSim External Mod Manager" (TSExtModMan) to reflect addition of ATS support.',
        '- Changed log entry chronology. (Reversed from bottom-to-top).'
    )
    [String[]]$G__KnownIssues = @(
        '- Automatic moving of the script if misplaced does not work.',
        '- Significant slowdown when loading TS SE Tool information under PowerShell 5.1.',
        '- Significant slowdown when starting the mod updating procedure under PowerShell 5.1.',
        '- Slight slowdown when processing load order after mod updating under PowerShell 5.1.'
    )

    Write-Host -ForegroundColor Green "OK - $([UInt32](New-TimeSpan $T__Step ([DateTime]::Now)).TotalMilliseconds) ms"

    [UInt16]$T__TotalLoadTime = ((New-TimeSpan $T__LoadTime ([DateTime]::Now)) - $T__PromptDuration).TotalSeconds

    Write-Host -ForegroundColor Green "`n$($T__Tab * 4)Loading complete. ($T__TotalLoadTime sec.)"
    Write-Log INFO "Loading complete. Load time: $T__TotalLoadTime sec."

    [Void](Read-KeyPress "`n$($T__Tab * 4)Continuing in `$Timeout seconds. Press any key to skip..." -Timeout 2 -DefaultKeyCode 13 -Clear)

    (Get-Variable "T__*" -EA 0).Name | Remove-Variable -EA 0

    [String]$G__ActiveProfile         = Get-ActiveProfile
    [String]$G__ActiveProfileName     = Convert-ProfileFolderName
    [IO.DirectoryInfo]$G__ProfilePath = "$($G__GameRootDirectory.FullName)\profiles\$G__ActiveProfile"
    [IO.FileInfo]$G__ProfileUnit      = "$($G__ProfilePath.FullName)\profile.sii"

    Update-ProtectedVars

    . $G__EXEC_RESTART

    If (!$Updated) {
        [Byte]$Padding = 15

        Clear-Host
        Write-Host " Checking $($G__ScriptDetails.ShortVersion) version...`n"
        Write-Host (' ' + 'Installed'.PadRight($Padding) + 'Current'.PadRight($Padding) + 'Status')
        Write-Host ($G__UILine * [Console]::BufferWidth)
        Write-Host -NoNewline (' ' + "$G__ScriptVersion".PadRight($Padding))

        Write-Log INFO 'SelfUpdater : Checking repository for repo-script updates.'

        Try {
            If ($G__IsExperimental) {Throw 'Aborted. Current version is experimental.'}
            Write-Log INFO 'SelfUpdater : Fetching online repo-script content from repository as ByteStream.'
            [Byte[]]$UpdateBytes = (Get-ModRepoFile $G__RepositoryInfo.Script -UseIWR).Content
            Write-Log INFO 'SelfUpdater : Converting repo-script ByteStream content to UTF-8 line array.'
            [String[]]$UpdateContent = Get-UTF8Content -FromBytes $UpdateBytes

            Write-Log INFO 'SelfUpdater : Transferring embedded preference data to repo-script data indices.'
            ForEach ($Key in $G__DataIndices.Keys) {
                [String]$Value         = Get-Variable "G__$Key" -ValueOnly
                [UInt32]$Index         = $G__DataIndices.$Key.Index
                $UpdateContent[$Index] = New-EmbeddedValue $UpdateContent[$Index] $Value
            }
            Write-Log INFO 'SelfUpdater : Successfully transferred preference data to repo-script data indices.'

            Write-Log INFO 'SelfUpdater : Parsing repo-script version data.'
            [String]$UpdateVersion = Switch (Read-EmbeddedValue 0 -CustomData $UpdateContent) {Default {('0.0.0.0', $_)[[Bool]($_ -As [Version])]}}
            If ([Version]$UpdateVersion -gt $G__ScriptVersion) {

                Write-Log INFO "SelfUpdater : repo-script version '$UpdateVersion' - Update available."

                [ConsoleColor]$VersionColor, [String]$VersionText, [String]$ReturnValue = (([ConsoleColor]::Green, $UpdateVersion, 'Updated'), ([ConsoleColor]::Red, 'Parsing error', 'Repaired'))[$UpdateVersion -eq '0.0']

                Write-Host -NoNewline -ForegroundColor $VersionColor $VersionText.PadRight($Padding)
                
                Write-Log INFO 'SelfUpdater : Writing repo-script content to current script file.'
                Set-UTF8Content $G__ScriptPath $UpdateContent -NoNewline

                Write-Log INFO "SelfUpdater : Restarting to apply version '$UpdateVersion'."

                Unprotect-Variables

                Return $ReturnValue
            }
            Else {
                Write-Log INFO "SelfUpdater : repo-script version '$UpdateVersion' - Up to date."
                Write-Host -NoNewline $UpdateVersion.PadRight($Padding)
                Write-Host -ForegroundColor Green 'Up to date'
            }
            Write-Host "`n"
        }
        Catch {
            If ($_.Exception.Message -Like "*is experimental*") {
                Write-Log INFO "SelfUpdater : $($_.Exception.Message)"
                Write-Host -NoNewline -ForegroundColor Yellow '---'.PadRight($Padding)
                Switch (' ' * [Console]::CursorLeft) {Default {
                    Write-Host -ForegroundColor Yellow 'Automatic updates disabled for experimental versions.'
                    Write-Host -ForegroundColor Yellow ($_ + 'Get the latest version from GitHub:')
                    Write-Host -ForegroundColor DarkCyan ($_ + $G__ScriptDetails.GitHubFile)
                }}

                Write-Log INFO 'SelfUpdater : Displaying experimental version information.'

                Write-Host ("`n`n What's new:`n   " + ($G__UpdateNotes -Join "`n   ") + "`n")
                If ($G__KnownIssues) {Write-Host ("`n Known issues:`n   " + ($G__KnownIssues -Join "`n   ") + "`n")}
                [Void](Read-KeyPress ' Press any key to continue.' -Clear)
                
                Clear-Host
            }
            Else {
                Write-Log ERROR "SelfUpdater : $($_.Exception.Message)"
                Write-Host -ForegroundColor Red (Format-AndExportErrorData $_)
                Write-Host "`n"
                [Void](Read-KeyPress ' Press any key to continue.' -Clear)
                Clear-Host
            }
        }
    }
    ElseIf ($Updated -ne 'Restart') {
        Write-Log INFO 'SelfUpdater : Update complete. Displaying update information.'
        Write-Host -ForegroundColor Green $Updated
        Write-Host ("`n What's new:`n   " + ($G__UpdateNotes -Join "`n   ") + "`n")
        If ($G__KnownIssues) {Write-Host ("`n Known issues:`n   " + ($G__KnownIssues -Join "`n   ") + "`n")}
        [Void](Read-KeyPress ' Press any key to continue.' -Clear)
        Clear-Host
    }

    Remove-UnprotectedVars

    If ($Updated -ne 'Restart') {
        Show-LandingScreen
        Clear-HostFancy 19 0 10
    }
    Else {Remove-Variable Updated -EA 0}
    [Bool]$Save = $False
    While ($True) {If ((Invoke-Expression (Invoke-Menu -Saved:$Save)) -eq 'Menu') {Return 'Restart'}}

    Remove-Variable Save -EA 0
    Try {
        [Hashtable]$G__LoadOrderData, [String]$G__LoadOrderText = Get-LoadOrderData -Raw -Data
        [UInt16]$G__ActiveModsCount  = (($G__LoadOrderText -Split "`n", 2)[0] -Split ':', 2)[-1].Trim()
        [String[]]$G__ActiveModFiles = $G__LoadOrderData.GetEnumerator() | ForEach-Object {[IO.Path]::GetFileName($_.Value.SourcePath) | Where-Object {[IO.Path]::GetExtension($_) -eq '.scs'}}
        Update-ProtectedVars
        Write-Log INFO 'ModUpdateInit : Collected Load Order and active mod data. '
    }
    Catch [ApplicationException] {}

    Clear-Host
    Write-Host "`n    $($G__ScriptDetails['Title'])   v$G__ScriptVersion`n"
    Write-Host ($G__UILine * [Console]::BufferWidth)

    If ($G__NoUpdate) {
        Edit-ProfileLoadOrder

        Write-Host -ForegroundColor Green "`n Done`n"
        Write-Log INFO 'Session complete. Waiting for user input.'
        [Void](Read-KeyPress)
        Unprotect-Variables

        Write-Log INFO 'Exiting session.'

        Return
    }

    Write-Log INFO 'ModUpdateInit : Preparing mod update routine.'

    [PSObject]$G__OnlineData = [PSObject]::New()

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
        Write-Log INFO "ModUpdateInit : Fetching version data ('$($G__RepositoryInfo.$G__GameNameShort.VersionData)') from repository."
        $G__OnlineData = (Get-ModRepoFile $G__RepositoryInfo.$G__GameNameShort.VersionData -UseIWR).Content | ConvertFrom-JSON
        Write-Log INFO 'ModUpdateInit : Version data fetched successfully.'
    }
    Catch {Wait-WriteAndExit (" Unable to fetch version data from repository. Try again later.`n Reason: " + (Format-AndExportErrorData $_))}

    If ($G__ValidateInstall) {
        Start-Process "steam://validate/$G__GameAppID"
        Write-Log INFO 'ModUpdateInit : Started game file integrity check (Steam).'
        Write-Host ' Started Steam game file validation.'
        Start-Sleep 1
        Set-ForegroundWindow -Self
    }

    Update-ProtectedVars

    [String[]]$Names    = @()
    [String[]]$Versions = @('Installed')

    If ([IO.File]::Exists('versions.txt')) {
        Write-Log INFO 'ModUpdateInit : Parsing local version data from ''versions.txt'''
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
        Write-Log INFO "ModUpdateInit : Local version data successfully parsed. Entries: $($LocalMods.Keys.Count)"
    }
    $TotalMods        = $G__OnlineData.PSObject.Properties.Value.Count
    $LongestName      = ($Names + $G__OnlineData.PSObject.Properties.Value.Name | Sort-Object Length)[-1].Length + 3
    $L_LongestVersion = ($Versions | Sort-Object Length)[-1].Length + 3
    $E_LongestVersion = (@('Current') + $G__OnlineData.PSObject.Properties.Value.VersionStr | Sort-Object Length)[-1].Length + 3
    Write-Log INFO 'ModUpdateInit : Prepared text formatting data.'

    Write-Log INFO 'ModUpdateInit : Ready.'
    If ([IO.File]::Exists('progress.tmp')) {
        $PreviousProgress = Get-UTF8Content progress.tmp
        Remove-Item progress.tmp -Force

        Write-Log INFO 'ModUpdate : Previous session did not complete. Resuming previous session progress.'
    }

    

    Write-Host ("Active profile: $G__ActiveProfileName, load order: $G__LoadOrder".PadLeft([Console]::BufferWidth - 1) + "`n" + $G__ActiveProfile.PadLeft([Console]::BufferWidth - 1))
    Write-Host (' ' + 'No.'.PadRight(8) + 'Mod'.PadRight($LongestName) + 'Installed'.PadRight($L_LongestVersion) + 'Current'.PadRight($E_LongestVersion) + 'Status')
    Write-Host ($G__UILine * [Console]::BufferWidth)

    Write-Log INFO 'ModUpdate | Starting mod update routine.'
    ForEach ($CurrentMod in $G__OnlineData.PSObject.Properties.Value) {
        $ModCounter++
        
        $CurrentMod.Version      = [Version]$CurrentMod.Version
        [IO.FileInfo]$OldFile    = 'old_' + $CurrentMod.FileName
        [Hashtable]$LocalMod     = $LocalMods.($CurrentMod.Name)
        [ModRepairAction]$Repair = [ModRepairAction]::None # 0: None   1: Entry   2: File
        [String]$ModCountStr     = "$ModCounter".PadLeft(2) + "/$TotalMods"

        Write-Host -NoNewline (' ' + $ModCountStr.PadRight(8) + $CurrentMod.Title.PadRight($LongestName))

        [ModUpdateState]$Status = ([Bool]$LocalMod.Version, [IO.File]::Exists($CurrentMod.FileName) | Group-Object | Where-Object {$_.Name -eq 'True'}).Count
        Switch ($Status) {
            'Installing' {Write-Host -NoNewline '---'.PadRight($L_LongestVersion); Break}
            'Repairing'  {$Repair = ([ModRepairAction]::File, [ModRepairAction]::Entry)[![Bool]$LocalMod.Version]; Write-Host -NoNewline -ForegroundColor Red ('???', $LocalMod.VersionStr)[[Bool]$LocalMod.Version].PadRight($L_LongestVersion); Break}
            'Updating'   {Write-Host -NoNewline $LocalMod.VersionStr.PadRight($L_LongestVersion); Break}
            Default      {Write-Log WARN "'$($CurrentMod.Name)' : Unexpected ModUpdateState '$State'."; Write-Host -NoNewline '???'.PadRight($L_LongestVersion); Break}
        }
        
        Switch ($Repair) {
            'None'  {Write-Log INFO "'$($CurrentMod.Name)' : No local problems detected."; Break}
            'Entry' {Write-Log WARN "'$($CurrentMod.Name)' : Problem detected in local version data: No corresponding version data for existing file. Entry repair required."; Break}
            'File'  {Write-Log WARN "'$($CurrentMod.Name)' : Problem detected in local mod storage: Version data references missing file. Redownload required."; Break}
            Default {Write-Log WARN "'$($CurrentMod.Name)' : Unexpected ModRepairAction '$Repair'."; Break}
        }

        [ConsoleColor]$VersionColor = ([ConsoleColor]::Green, [ConsoleColor]::White)[($LocalMod.Version -ge $CurrentMod.Version)]
        Write-Host -NoNewline -ForegroundColor $VersionColor $CurrentMod.VersionStr.PadRight($E_LongestVersion)

        If ($CurrentMod.Name -In $PreviousProgress) {
            Write-Log INFO "'$($CurrentMod.Name)' : Skipped - Already processed."
            Write-Host -ForegroundColor Green 'Up to date'

            $NewVersions += ($CurrentMod.Name, $CurrentMod.VersionStr) -Join '='

            Continue
        }

        [UInt16]$XPos        = [Console]::CursorLeft
        [Hashtable]$WhXSplat = @{
            X       = $XPos
            Color   = [ConsoleColor]::Green
            Newline = $True
        }

        If ($LocalMod.Version -ge $CurrentMod.Version -Or $Repair -eq 'File') {

            If ($CurrentMod.FileName -NotIn $G__ActiveModFiles -And !$G__UpdateAll) {
                If ($Repair -eq 'File')  {Write-Log WARN "'$($CurrentMod.Name)' : Cannot perform repair - The file was skipped (not in load order)."}
                Else                     {Write-Log INFO "'$($CurrentMod.Name)' : Skipped - Not in load order."}
                Write-Host -ForegroundColor DarkGray 'Skipped - Not in load order'
    
                If (!$G__DeleteDisabled) {$NewVersions += ($CurrentMod.Name, $CurrentMod.VersionStr) -Join '='}
    
                Continue
            }

            Write-Host -NoNewline ("$([ModUpdateState]::Validating)...", "$Status...")[$Repair -ne 'None'] #[ModUpdateState]::Validating

            If (!(Test-FileHash $CurrentMod.FileName $CurrentMod.Hash $CurrentMod.Size)) {
                If ($Repair -eq 'None') {
                    Write-Log WARN "'$($CurrentMod.Name)' : Validation failed. Reinstalling."
                    Write-HostX $XPos -Color Red 'Validation failed.'
                    $Status = [ModUpdateState]::Reinstalling

                    Start-Sleep 1
                }
                Try   {$LocalMod['Version'] = [Version]'0.0'}
                Catch {[Hashtable]$LocalMod = @{Version = [Version]'0.0'}}
            }
            Else {
                [String]$ResultString = ('Up to date', 'Repaired')[$Repair -ne 'None']
                Write-Log INFO "'$($CurrentMod.Name)': $ResultString"
                Write-HostX @WhXSplat $ResultString

                $NewVersions += ($CurrentMod.Name, $CurrentMod.VersionStr) -Join '='

                If ([Bool]$Repair) {$Successes++}

                Continue
            }
        }
        If ($LocalMod.Version -lt $CurrentMod.Version -Or $Repair -eq 'Entry') {
            Try {
                Write-HostX $XPos 'Preparing...'
                If (!(Test-FileHash $CurrentMod.FileName $CurrentMod.Hash $CurrentMod.Size)) {

                    If ($CurrentMod.FileName -NotIn $G__ActiveModFiles -And !$G__UpdateAll) {
                        If ($Repair -eq 'File')  {Write-Log WARN "'$($CurrentMod.Name)' : Cannot perform repair - The file was skipped (not in load order)."}
                        Else                     {Write-Log INFO "'$($CurrentMod.Name)' : Skipped - Not in load order."}
                        Write-HostX $XPos -Color DarkGray 'Skipped - Not in load order' -Newline
            
                        If (!$G__DeleteDisabled) {$NewVersions += ($CurrentMod.Name, $CurrentMod.VersionStr) -Join '='}
            
                        Continue
                    }

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
                        'Installing'   {Write-HostX @WhXSplat "Installed      ($Result)"; Break}
                        'Repairing'    {Write-HostX @WhXSplat "Repaired       ($Result)"; Break}
                        'Updating'     {Write-HostX @WhXSplat "Updated        ($Result)"; Break}
                        'Reinstalling' {Write-HostX @WhXSplat "Reinstalled    ($Result)"; Break}
                        Default        {Write-HostX @WhXSplat "Unknown        ($Result)"; Break}
                    }
                }
                Else {
                    If ($Repair -eq 'Entry') {Write-Log INFO "'$($CurrentMod.Name)': Entry repair successful."}
                    Write-HostX @WhXSplat 'Repaired       '
                }

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

    [ConsoleColor]$ColorA = Switch ($Null) {{$Failures -eq 0} {[ConsoleColor]::Green} {$Failures -gt 0 -And $Successes -eq 0} {[ConsoleColor]::Red} {$Failures -gt 0 -And $Successes -gt 0} {[ConsoleColor]::Yellow}}
    [ConsoleColor]$ColorB = ([ConsoleColor]::White, [ConsoleColor]::Yellow, [ConsoleColor]::Red)[[Math]::Min(2, [Math]::Ceiling($Invalids / 2))]
    [Hashtable]$TextColor = @{ForegroundColor = $ColorA}

    [String]$S_PluralMod, [String]$F_PluralMod, [String]$I_PluralMod = Switch-GrammaticalNumber 'mod' $Successes, $Failures, $Invalids
    
    Write-Host @TextColor "`n Done`n"

    If ($Successes + $Failures -eq 0) {Write-Host @TextColor " All mods up to date - $TotalStr"}
    If ($Successes -gt 0)             {Write-Host @TextColor "   $Successes $S_PluralMod processed successfully - $TotalStr ($DownloadedStr)"}
    If ($Failures -gt 0)              {Write-Host @TextColor "   $Failures $F_PluralMod failed to process"}
    If ($Invalids -gt 0)              {Write-Host -ForegroundColor $ColorB "   $Invalids $I_PluralMod failed to validate"}
    If ($Failures + $Invalids -gt 0)  {Write-Host @TextColor "`n Exit and restart the updater to try again"}
    
    Write-Host "`n"
    Write-Log INFO 'Session completed. Waiting for user input before continuing to OnExit tasks.'

    [Void](Read-KeyPress " Press any key to$(('', " launch $G__GameNameShort $(('', "+ $($G__TSSETool.Name) ")[$G__StartSaveEditor])and")[$G__StartGame]) exit")
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
