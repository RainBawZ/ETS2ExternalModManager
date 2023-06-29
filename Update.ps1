#version=2.9.9
Param ([String]$Updated)
Function Sync-Ets2ModRepo {
    Param ([Switch]$Updated)

    Function Write-HostX {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory, Position = 1, ValueFromRemainingArguments)][String]$InputString,
            [Parameter(Mandatory, Position = 0)][ValidateScript({$_ -In (0..$Host.UI.RawUI.BufferSize.Width)})][Byte]$X,
            [ConsoleColor]$Color,
            [Switch]$Newline
        )
        [Byte]$InputLength = $InputString.Length
        [Hashtable]$WHSplat = @{}
        $WHSplat['Object']  = "$($InputString)$(-Join (' ' * ($Host.UI.RawUI.BufferSize.Width - $X - $InputLength)))"
        If (!$Newline) {$WHSplat['NoNewline']       = $True}
        If ($Color)    {$WHSplat['ForegroundColor'] = $Color}
        If ($Host.Name -NotLike '*ISE*') {[Console]::SetCursorPosition($X, $Host.UI.RawUI.CursorPosition.Y)}
        Write-Host @WHSplat
    }

    Function Protect-Variables      {If ($GLOBAL:PROTECTED) {Throw 'The object is already initialized'} Else {[String[]]$GLOBAL:PROTECTED = (Get-Variable).Name + 'PROTECTED'}}
    Function Update-ProtectedVars   {If ($GLOBAL:PROTECTED) {Add-ProtectedVars (Get-UnprotectedVars)}}
    Function Get-UnprotectedVars    {If ($GLOBAL:PROTECTED) {Return [String[]](Get-Variable -Exclude $GLOBAL:PROTECTED).Name}}
    Function Remove-UnprotectedVars {If ($GLOBAL:PROTECTED) {Switch (Get-UnprotectedVars) {$Null {Return} Default {Remove-Variable $_ -ErrorAction SilentlyContinue}}}}
    Function Unprotect-Variables    {If ($GLOBAL:PROTECTED) {Remove-Variable PROTECTED -Scope GLOBAL -ErrorAction Stop}}
    Function Add-ProtectedVars      {
        [CmdletBinding()]
        Param([Parameter(ValueFromPipeline)][String[]]$InputObject)
        If ($InputObject -And $GLOBAL:PROTECTED) {$GLOBAL:PROTECTED += $InputObject}
        $GLOBAL:PROTECTED = $GLOBAL:PROTECTED | Select-Object -Unique
    }

    Function Format-AndExportErrorData {
        [CmdletBinding()]
        Param ([Parameter(Mandatory)][Management.Automation.ErrorRecord]$Exception)
        [Collections.Generic.List[String]]$Export = @("`n")
        [String]$Message      = $Exception.Exception.Message
        [String]$Details      = $Exception.ErrorDetails.Message
        [String]$Position     = $Exception.InvocationInfo.PositionMessage
        [String]$ReturnString = ($Details, $Message)[($Message.Length -gt $Details.Length)] # ($False, $True)[(eval)]
        [Void]$Export.Add($Position)
        [Void]$Export.Add($Message)
        [Void]$Export.Add($Details)
        [Void]$Export.Add("$(-Join ('- ' * 30))-")

        Do {
            [Int]$Index = $Export.IndexOf('')
            If ($Index -ne -1) {$Export.RemoveAt($Index)}
        } While ('' -In $Export)

        If ($Export[2]) {
            If ([IO.File]::Exists('Error.log.txt')) {[DateTime]$LastWrite = (Get-Item 'Error.log.txt').LastWriteTime.ToString("yyyy.MM.dd HH:mm:ss")}
            Else                                    {[DateTime]$LastWrite = $GLOBAL:StartTime - (New-TimeSpan -Hours 1)}
            If ($GLOBAL:StartTime -gt $LastWrite) {Remove-Item 'Error.log.txt' -Force -ErrorAction SilentlyContinue}
            $Export -Join "`n" | Out-File 'Error.log.txt' -Append
        }

        Return $ReturnString
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
                {$_ -eq 'kB/s'} {($BytesPerSecond / 1kB)}
                {$_ -eq 'MB/s'} {($BytesPerSecond / 1MB)}
                {$_ -eq 'GB/s'} {($BytesPerSecond / 1GB)}
            }
        }
        Else {[Double]$ConvertedRate, [String]$UnitSymbol = If ($BytesPerSecond -lt 1MB) {($BytesPerSecond / 1kB), 'kB/s'} Else {($BytesPerSecond / 1MB), 'MB/s'}}
        Return [String](("$([Math]::Round($ConvertedRate, 2))", "$([Math]::Round($ConvertedRate))")[($UnitSymbol -eq 'B/s')] + " $UnitSymbol")
    }

    Function Get-ModRepoFile {
        [CmdletBinding(DefaultParameterSetName = 'NoIWR')]
        Param (
            [Parameter(Mandatory, Position = 0)][String]$File,
            [Parameter(ParameterSetName = 'NoIWR', Position = 1)][Byte]$X,
            [Parameter(ParameterSetName = 'NoIWR', Position = 2)][String]$State,
            [Parameter(Mandatory, ParameterSetName = 'IWR')][Switch]$UseIWR,
            [Parameter(ParameterSetName = 'IWR')][Switch]$Save,
            [String]$ContentType
        )

        [Uri]$Uri = "http://your.domain/modrepo/$($File)"

        If ($PSCmdlet.ParameterSetName -eq 'IWR') {
            [Hashtable]$IWRSplat = @{
                Uri             = $Uri
                UseBasicParsing = $True
            }
            If ($Save)        {$IWRSplat['OutFile']     = $File}
            If ($ContentType) {$IWRSplat['ContentType'] = $ContentType}
            Return Invoke-WebRequest @IWRSplat
        }

        [Net.HttpWebRequest]$HeaderRequest = [Net.WebRequest]::CreateHttp($Uri)
        $HeaderRequest.Method              = 'HEAD'
        $HeaderRequest.KeepAlive           = $False
        $HeaderRequest.Timeout             = 15000

        [Net.HttpWebRequest]$DownloadRequest = [Net.WebRequest]::CreateHttp($Uri)
        $DownloadRequest.Timeout             = 15000
        $DownloadRequest.ContentType         = ($ContentType, $Null)[[String]::IsNullOrWhiteSpace($ContentType)]

        [Net.HttpWebResponse]$Header = $HeaderRequest.GetResponse()
        [UInt64]$DownloadSize        = $Header.ContentLength; $Header.Dispose()
        [UInt32]$BufferSize          = [Math]::Pow(2, [Math]::Floor([Math]::Log([Math]::Min([Math]::Max(8192, $DownloadSize), [GC]::GetTotalMemory($False) / 10), 2)))
        [Byte[]]$Buffer              = New-Object Byte[] $BufferSize
        
        [DateTime]$IntervalStart       = (Get-Date).AddSeconds(-1)
        [Net.HttpWebResponse]$Download = $DownloadRequest.GetResponse()
        [IO.Stream]$DownloadStream     = $Download.GetResponseStream()
        [IO.FileStream]$FileStream     = New-Object IO.FileStream $File, 'Create'
        
        [UInt32]$BytesRead       = $DownloadStream.Read($Buffer, 0, $Buffer.Length)
        [UInt64]$BytesDownloaded = $BytesRead

        [UInt32]$Unit, [String]$Symbol, [Byte]$Decimals = Switch ($DownloadSize) {
            {$_ -lt 1000kB} {1kB, 'kB', 0; Break}
            {$_ -lt 1000MB} {1MB, 'MB', 0; Break}
            {$_ -ge 1000MB} {1GB, 'GB', 2; Break}
        }
        [String]$ConvertedDownload = "$([Math]::Round(($DownloadSize / $Unit), $Decimals)) $Symbol"

        [UInt32]$IntervalBytes, [Double]$ConvertedBytes, [Double]$IntervalLength, [String]$TransferRate = 0, 0, 0, '0 kB/s'

        While ($BytesRead -gt 0) {
            $FileStream.Write($Buffer, 0, $BytesRead)
            $BytesRead        = $DownloadStream.Read($Buffer, 0, $Buffer.Length)
            $BytesDownloaded += $BytesRead
            $ConvertedBytes   = [Math]::Round(($BytesDownloaded / $Unit), $Decimals)
            $IntervalLength   = (New-TimeSpan $IntervalStart (Get-Date)).TotalSeconds

            If ($IntervalLength -ge 1) {
                $TransferRate  = Measure-TransferRate $IntervalLength ($BytesDownloaded - $IntervalBytes)
                $IntervalBytes = $BytesDownloaded
                $IntervalStart = Get-Date
            }

            Write-HostX $X -Color Green "$State $("$ConvertedBytes".PadLeft(5))/$ConvertedDownload ($TransferRate)"
        }

        $Download.Dispose()
        $FileStream.Flush()
        $FileStream.Close()
        $FileStream.Dispose()
        $DownloadStream.Dispose()

        Return @("$ConvertedDownload", $BytesDownloaded)
    }

    Function Test-ModActive {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory, Position = 0)][String]$Log,
            [Parameter(Mandatory, Position = 1)][String]$Mod
        )
        If (![IO.File]::Exists($Log)) {Return $False}
        [String[]]$LogData = Get-Content $Log -Encoding UTF8
        ForEach ($Line in $LogData) {If ($Line -Match " \: \[mods\] Active local mod $($Mod) ") {Return $True}}
        Return $False
    }

    Function Test-ModHash {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory, Position = 0)][String]$File,
            [Parameter(Mandatory, Position = 1)][String]$Hash
        )
        Return [Bool]((Get-FileHash -Algorithm SHA1 $File).Hash -eq $Hash)
    }

    Function Test-ArrayNullOrEmpty {
        [CmdletBinding()]
        Param ([AllowEmptyCollection()][Object[]]$Array)
        If ($Null -eq $Array) {Return $True}
        Return ([Math]::Max($Array.IndexOf(''), $Array.IndexOf($Null)) -ne -1)
    }
    
    Function Wait-WriteAndExit {
        [CmdletBinding()]
        Param ([Parameter(Mandatory)][String]$InputObject)
        Write-Host -ForegroundColor Red $InputObject
        Unprotect-Variables
        [Void](Read-Host)
        Exit
    }

    Protect-Variables

    [Console]::CursorVisible     = $False
    [Version]$LocalVersion       = "2.9.9"
    $ProgressPreference          = [Management.Automation.ActionPreference]::SilentlyContinue
    [String]$GameRoot            = [IO.Path]::Combine([Environment]::GetFolderPath("MyDocuments"), 'Euro Truck Simulator 2')
    [String]$InstallDirectory    = [IO.Path]::Combine($GameRoot, 'mod')
    [String]$SaveEditorDirectory = [IO.Path]::Combine($GameRoot, 'TruckSaveEditor')
    [String]$GameLogPath         = [IO.Path]::Combine($GameRoot, 'game.log.txt')
    [String]$UpdaterScript       = $PSCommandPath
    $Host.UI.RawUI.WindowTitle   = "ETS2 Mod Updater - v$LocalVersion"

    [String[]]$UpdateNotes = @(
        '- Fixed issue where summary would always be represented in bytes if data was removed',
        '- Rounded summary to two or one decimal'
    )

    Update-ProtectedVars

    If (-Not [IO.Directory]::Exists($InstallDirectory)) {Wait-WriteAndExit "'$InstallDirectory' not found!"}
    If ($PSScriptRoot -ne $InstallDirectory)            {Wait-WriteAndExit "Please place the script in '$InstallDirectory'"}
    Set-Location $InstallDirectory

    If (!$Updated) {
        [DateTime]$GLOBAL:StartTime = (Get-Date).ToString("yyyy.MM.dd HH:mm:ss")

        Clear-Host
        Write-Host " Checking Updater version...`n"
        Write-Host ' Installed   Current   Status'
        Write-Host "$(-Join ('-' * $Host.UI.RawUI.BufferSize.Width))"
        Write-Host -NoNewline " $($LocalVersion.ToString().PadRight(12))"
        Try {
            [Byte[]]$DownloadedBytes = (Get-ModRepoFile 'Update.ps1' -UseIWR -ContentType 'text/plain; charset=utf8').Content
            [String]$DecodedBytes    = [Text.Encoding]::UTF8.GetString($DownloadedBytes)
            [Version]$LatestVersion  = (($DecodedBytes -Split "`n")[0] -Split '=')[1]

            If ($LocalVersion -lt $LatestVersion) {
                Write-Host -NoNewline -ForegroundColor Green $LatestVersion.ToString().PadRight(10)

                $DecodedBytes | Set-Content $UpdaterScript -Force

                Unprotect-Variables

                Return 'Updated'
            }
            Else {
                Write-Host -NoNewline $LatestVersion.ToString().PadRight(10)
                Write-Host -ForegroundColor Green 'Up to date'
            }
            Write-Host "`n"
        }
        Catch {Write-Host -ForegroundColor Red (Format-AndExportErrorData $_)}
    }
    Else {
        Write-Host -ForegroundColor Green 'Updated'
        Write-Host "`n What's new:`n   $($UpdateNotes -Join "`n   ")`n"
        Write-Host "$(-Join ('-' * $Host.UI.RawUI.BufferSize.Width))"
        Start-Sleep -Seconds 1
    }

    Remove-UnprotectedVars

    [Byte]$Failures                   = 0
    [Byte]$Invalids                   = 0
    [Byte]$Successes                  = 0
    [Byte]$LongestName                = 3
    [Byte]$L_LongestVersion           = 9
    [Byte]$E_LongestVersion           = 7
    [Int64]$DownloadedData            = 0
    [Int64]$TotalBytes                = 0
    [String[]]$NewVersions            = @()
    [Hashtable]$LocalMods             = @{}
    [Hashtable]$OnlineData            = @{}
    [Globalization.TextInfo]$TextInfo = (Get-Culture).TextInfo
    [Bool]$GameRunning                = 'eurotrucks2' -In (Get-Process).Name
    [Collections.Generic.List[String[]]]$Replace = @(
        @('Ai ', 'AI '),
        @('Bdf ', 'BDF ')
    )

    Update-ProtectedVars

    If ([IO.File]::Exists('versions.txt')) {
        [UInt64]$Line = 0
        ForEach ($RawData in (Get-Content 'versions.txt' -Encoding UTF8)) {
            $Line++
            [String[]]$ModData = ($RawData -Split '=', 3)[0..1]
            If (Test-ArrayNullOrEmpty $ModData) {
                Try     {Throw "versions.txt[$Line]: Invalid data"}
                Catch   {[Void](Format-AndExportErrorData $_)}
                Continue
            }
            [String]$Name, [Version]$Ver = $ModData
            $LocalMods[$Name] = [Hashtable]@{
                'FileName'   = "$($Name).scs"
                'Version'    = $Ver
                'VersionStr' = [String]$Ver
            }
            If ($Name.Length -gt $LongestName)                {$LongestName      = $Name.Length}
            If ($Ver.ToString().Length -gt $L_LongestVersion) {$L_LongestVersion = $Ver.ToString().Length}
        }
    }
    

    Try   {[String[]]$OnlineRawData = (Get-ModRepoFile 'versions.txt' -UseIWR -ContentType 'text/plain; charset=utf8').Content -Split "`n"}
    Catch {Wait-WriteAndExit "Unable to download version data. Try again later.`nReason: $(Format-AndExportErrorData $_)"}

    [UInt64]$Line = 0
    ForEach ($RawData in ($OnlineRawData | Sort-Object)) {
        $Line++
        If ([String]::IsNullOrWhiteSpace($RawData)) {Continue}
        If ($RawData.LastIndexOf(';') -eq -1) {
            Try     {Throw "OnlineRawData[$Line]: Missing line terminator"}
            Catch   {[Void](Format-AndExportErrorData $_)}
            Continue
        }
        [String[]]$ModData = $RawData.Substring(0, $RawData.LastIndexOf(';')) -Split "=", 5
        If (Test-ArrayNullOrEmpty $ModData) {
            Try     {Throw "OnlineRawData[$Line]: Malformed entry: One or more items are Null"}
            Catch   {[Void](Format-AndExportErrorData $_)}
            Continue
        }
        [String]$Name, [Version]$Ver, [Byte]$LoadIndex, [Byte]$IsActive, [String]$Hash = $ModData
        [String]$Title = $TextInfo.ToTitleCase($Name.Replace('_', ' '))
        ForEach ($String in $Replace) {$Title = $Title.Replace($String[0], $String[1])}
        $OnlineData[$Name] = [Hashtable]@{
            'Name'       = $Name
            'Title'      = $Title
            'FileName'   = "$($Name).scs"
            'Version'    = $Ver
            'VersionStr' = [String]$Ver
            'Hash'       = $Hash
            'Index'      = $LoadIndex
            'Active'     = [Bool]$IsActive
        }
        If ($Name.Length -gt $LongestName)                {$LongestName      = $Name.Length}
        If ($Ver.ToString().Length -gt $E_LongestVersion) {$E_LongestVersion = $Ver.ToString().Length}
    }

    $L_LongestVersion += 3
    $E_LongestVersion += 3
    $LongestName      += 3

    Write-Host "`n Looking for mod updates...`n"
    Write-Host " $('Mod'.PadRight($LongestName))$('Installed'.PadRight($L_LongestVersion))$('Current'.PadRight($E_LongestVersion))Status"
    Write-Host "$(-Join ('-' * $Host.UI.RawUI.BufferSize.Width))"

    ForEach ($CurrentMod in ($OnlineData.GetEnumerator() | Sort-Object Name).Value) {

        [String]$OldFile     = "old_$($CurrentMod.FileName)"
        [String]$Priority    = 'Load order: ' + ('Inactive', $CurrentMod.Index)[($CurrentMod.Active)]
        [Hashtable]$LocalMod = $LocalMods.($CurrentMod.Name)

        Write-Host -NoNewline " $($CurrentMod.Title.PadRight($LongestName))"

        If ($LocalMod.Version -And [IO.File]::Exists($CurrentMod.FileName)) {
            [String]$Status = 'Updating...'
            Write-Host -NoNewline $LocalMod.VersionStr.PadRight($L_LongestVersion)
        }
        Else {
            [String]$Status = 'Installing...'
            Write-Host -NoNewline '---'.PadRight($L_LongestVersion)
        }

        [ConsoleColor]$VersionColor = ("Green", "White")[($LocalMod.Version -ge $CurrentMod.Version)]
        Write-Host -NoNewline -ForegroundColor $VersionColor $CurrentMod.VersionStr.PadRight($E_LongestVersion)
        [Byte]$XPos = $Host.UI.RawUI.CursorPosition.X

        If ($LocalMod.Version -ge $CurrentMod.Version) {
            Write-Host -NoNewline 'Validating...'
            If (!(Test-ModHash $LocalMod.FileName $CurrentMod.Hash)) {
                Write-HostX $XPos -Color Red 'Validation failed.'
                Start-Sleep -Seconds 1
                [String]$Status      = 'Reinstalling...'
                $LocalMod['Version'] = [Version]"0.0"
            }
            Else {
                Write-HostX $XPos -Color Green 'Up to date' -Newline
                $NewVersions += "$($CurrentMod.Name)=$($CurrentMod.VersionStr)"
                Continue
            }
        }
        If ($LocalMod.Version -lt $CurrentMod.Version) {
            If ([IO.File]::Exists($CurrentMod.FileName)) {
                [Int64]$OriginalSize = Get-ItemPropertyValue $CurrentMod.FileName Length
                Rename-Item $CurrentMod.FileName $OldFile -Force -ErrorAction SilentlyContinue
            }
            Else {[Int64]$OriginalSize = 0}

            Try {
                If ($Status -eq 'Updating...' -And $GameRunning -And (Test-ModActive $GameLogPath $CurrentMod.Name)) {Throw 'Euro Truck Simulator 2 must be closed to update this mod.'}
                [String]$Result, [Int64]$NewSize = Get-ModRepoFile $CurrentMod.FileName $XPos $Status -ErrorAction Stop

                If ([IO.File]::Exists($OldFile)) {Remove-Item $OldFile -Force}

                Write-HostX $XPos 'Validating...'
                If (!(Test-ModHash $CurrentMod.FileName $CurrentMod.Hash)) {Throw 'Validation unsuccessful.'}
                Switch ($Status) {
                    'Updating...'     {Write-HostX $XPos -Color Green "Updated        ($Result)" -Newline}
                    'Installing...'   {Write-HostX $XPos -Color Green "Installed      ($Result, $Priority)" -Newline}
                    'Reinstalling...' {Write-HostX $XPos -Color Green "Reinstalled    ($Result)" -Newline}
                }
                $NewVersions    += "$($CurrentMod.Name)=$($CurrentMod.VersionStr)"
                $DownloadedData += ($NewSize - $OriginalSize)
                $Successes++
            }
            Catch {
                If ([IO.File]::Exists($CurrentMod.FileName)) {Remove-Item $CurrentMod.FileName -Force -ErrorAction SilentlyContinue}
                If ([IO.File]::Exists($OldFile))             {Rename-Item $OldFile $CurrentMod.FileName -Force -ErrorAction SilentlyContinue}
                $NewVersions += "$($CurrentMod.Name)=$($LocalMod.VersionStr)"
                $Failures++

                Write-HostX $XPos -Color Red "Failed: $(Format-AndExportErrorData $_)" -Newline
            }
        }
    }
    If (![IO.Directory]::Exists($SaveEditorDirectory)) {

        Write-Host -NoNewline " $('Save Editor'.PadRight($LongestName))$('---'.PadRight($L_LongestVersion))"
        Write-Host -NoNewline -ForegroundColor Green "$('---'.PadRight($E_LongestVersion))"

        [Byte]$XPos = $Host.UI.RawUI.CursorPosition.X

        Write-Host -NoNewline -ForegroundColor Green 'Installing...'

        [Console]::SetCursorPosition($XPos, $Host.UI.RawUI.CursorPosition.Y)

        Try {
            [Void](Get-ModRepoFile 'TruckSaveEditor.zip' -UseIWR -Save)

            Add-Type -Assembly "System.IO.Compression.FileSystem"
            [Void][IO.Directory]::CreateDirectory($SaveEditorDirectory)
            [System.IO.Compression.ZipFile]::ExtractToDirectory('TruckSaveEditor.zip', $SaveEditorDirectory)

            If ([IO.File]::Exists('TruckSaveEditor.zip')) {Remove-Item 'TruckSaveEditor.zip' -Force}

            Write-Host -ForegroundColor Green 'Installed          '
        }
        Catch {
            If ([IO.File]::Exists('TruckSaveEditor.zip'))     {Remove-Item 'TruckSaveEditor.zip' -Force}
            If ([IO.Directory]::Exists($SaveEditorDirectory)) {Remove-Item $SaveEditorDirectory -Recurse -Force}
            $Failures++

            Write-Host -ForegroundColor Red 'Failed              '
        }
    }

    $NewVersions -Join "`n" | Set-Content 'versions.txt'

    [String]$S_PluralMod  = 'mod' + ('s', '')[($Successes -eq 1)]
    [String]$F_PluralMod  = 'mod' + ('s', '')[($Failures -eq 1)]
    [String]$I_PluralMod  = 'mod' + ('s', '')[($Invalids -eq 1)] 
    [ConsoleColor]$ColorA = Switch ($Null) {{$Failures -eq 0} {"Green"} {$Failures -gt 0 -And $Successes -eq 0} {"Red"} {$Failures -gt 0 -And $Successes -gt 0} {"Yellow"}}
    [ConsoleColor]$ColorB = ("White", "Yellow", "Red")[[Math]::Min(2, [Math]::Ceiling($Invalids / 2))]
    [Hashtable]$TextColor = @{ForegroundColor = $ColorA}

    [String]$DownloadedStr = Switch ($DownloadedData) {
        {[Math]::Abs($_) -lt 1024}   {"$_ B"; Break}
        {[Math]::Abs($_) -lt 1024kB} {"$([Math]::Round(($_/1kB), 1)) kB"; Break}
        {[Math]::Abs($_) -lt 1024MB} {"$([Math]::Round(($_/1MB), 1)) MB"; Break}
        {[Math]::Abs($_) -ge 1024MB} {"$([Math]::Round(($_/1GB), 2)) GB"; Break}
    }
    If ($DownloadedData -gt 0) {$DownloadedStr = "+$($DownloadedStr)"}

    ForEach ($Filesize in (Get-ItemPropertyValue "*.scs" Length)) {$TotalBytes += $Filesize}
    [String]$TotalStr = Switch ($TotalBytes) {
        {$_ -lt 1024}   {"$_ B"; Break}
        {$_ -lt 1024kB} {"$([Math]::Round(($_/1kB), 1)) kB"; Break}
        {$_ -lt 1024MB} {"$([Math]::Round(($_/1MB), 1)) MB"; Break}
        {$_ -ge 1024MB} {"$([Math]::Round(($_/1GB), 2)) GB"; Break}
    }
    
    Write-Host @TextColor "`n Done`n"
    If (($Successes + $Failures) -eq 0) {Write-Host @TextColor ' All mods up to date'}
    If ($Successes -gt 0)               {Write-Host @TextColor " $Successes $S_PluralMod processed successfully - $TotalStr ($DownloadedStr)"}
    If ($Failures -gt 0)                {Write-Host @TextColor " $Failures $F_PluralMod failed to process"}
    If ($Invalids -gt 0)                {Write-Host -ForegroundColor $ColorB " $Invalids $I_PluralMod failed to validate"}
    If (($Failures + $Invalids) -gt 0)  {Write-Host @TextColor "`n Exit and restart the updater to try again"}

    [Void](Read-Host)
    Unprotect-Variables
    Return
}
If (!$Updated) {If (Sync-Ets2ModRepo) {& "$PSScriptRoot\Update.ps1" @('Updated')}}
Else {[Void](Sync-Ets2ModRepo -Updated)}
