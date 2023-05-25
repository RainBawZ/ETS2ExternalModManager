#version=2.8.4
Param ([String]$Updated)
Function Sync-Ets2ModRepo {
    Param ([Switch]$Updated)

    Function Write-HostX {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory, Position = 1, ValueFromRemainingArguments)][Object]$Object,
            [Parameter(Mandatory, Position = 0)][ValidateScript({$_ -In (0..$Host.UI.RawUI.BufferSize.Width)})][Byte]$X,
            [Switch]$NoNewline, [ConsoleColor]$ForegroundColor
        )
        [Hashtable]$WHSplat = @{Object = $Object}
        If ($NoNewline)       {$WHSplat['NoNewline']       = $True}
        If ($ForegroundColor) {$WHSplat['ForegroundColor'] = $ForegroundColor}
        [Console]::SetCursorPosition($X, $Host.UI.RawUI.CursorPosition.Y)
        Write-Host @WHSplat
    }

    Function Get-ModRepoFile {
        [CmdletBinding()]
        Param ([Parameter(Mandatory)][String]$File, [Byte]$XPos, [String]$State, [Switch]$UseIWR, [Switch]$Save)

        [Uri]$Uri = "http://your.online/ets2repo/$($File)"

        If ($UseIWR) {
            [Hashtable]$IWRSplat = @{
                Uri             = $Uri
                UseBasicParsing = $True
            }
            If ($Save) {$IWRSplat['OutFile'] = $File}
            Return Invoke-WebRequest @IWRSplat
        }

        Function Measure-TransferRate {
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory)][Double]$Duration,
                [Parameter(Mandatory)][UInt32]$Bytes,
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
            Else {[Double]$ConvertedRate, [String]$UnitSymbol = If ($BytesPerSecond -lt 1MB) {@(($BytesPerSecond / 1kB), 'kB/s')} Else {@(($BytesPerSecond / 1MB), 'MB/s')}}
            Return [String](("$([Math]::Round($ConvertedRate, 2))", "$([Math]::Round($ConvertedRate))")[($UnitSymbol -eq 'B/s')] + " $UnitSymbol")
        }

        $HeaderRequest, $DownloadRequest                 = [Net.HttpWebRequest]::Create($Uri), [Net.HttpWebRequest]::Create($Uri)
        $HeaderRequest.Method                            = 'HEAD'
        $HeaderRequest.KeepAlive                         = $False
        $HeaderRequest.Timeout, $DownloadRequest.Timeout = 15000, 15000

        [Net.HttpWebResponse]$Header = $HeaderRequest.GetResponse()
        [UInt64]$DownloadSize        = $Header.ContentLength; $Header.Dispose()
        [UInt32]$BufferSize          = [Math]::Pow(2, [Math]::Floor([Math]::Log([Math]::Min([Math]::Max(8192, $DownloadSize), [GC]::GetTotalMemory($False) / 10), 2)))
        $Buffer                      = [Byte[]]::New($BufferSize)

        [Net.HttpWebResponse]$Download = $DownloadRequest.GetResponse()
        $DownloadStream                = $Download.GetResponseStream()
        $FileStream                    = [IO.FileStream]::New($File, 'Create')
        [DateTime]$IntervalStart       = (Get-Date).AddSeconds(-1)
        [UInt32]$BytesRead             = $DownloadStream.Read($Buffer, 0, $Buffer.Length)
        [UInt64]$BytesDownloaded       = $BytesRead
        [UInt32]$IntervalBytes         = 0

        [UInt32]$Unit, [String]$Symbol, [UInt32]$ConvertedSize = If ($DownloadSize -lt 10000kB) {@(1kB, 'kB', ($DownloadSize / 1kB))} Else {@(1MB, 'MB', ($DownloadSize / 1MB))}
        
        While ($BytesRead -gt 0) {
            $FileStream.Write($Buffer, 0, $BytesRead)
            $BytesRead              = $DownloadStream.Read($Buffer, 0, $Buffer.Length)
            $BytesDownloaded       += $BytesRead
            [UInt32]$ConvertedBytes = $BytesDownloaded / $Unit
            [Double]$IntervalLength = (New-TimeSpan $IntervalStart (Get-Date)).TotalSeconds

            If ($IntervalLength -ge 1) {
                [String]$TransferRate = Measure-TransferRate -Duration $IntervalLength -Bytes ($BytesDownloaded - $IntervalBytes)
                $IntervalBytes        = $BytesDownloaded
                $IntervalStart        = Get-Date
            }

            Write-HostX -X $XPos -NoNewline -ForegroundColor Green -Object "$State $ConvertedBytes/$ConvertedSize $Symbol ($TransferRate)      "
        }

        $Download.Dispose()
        $FileStream.Flush()
        $FileStream.Close()
        $FileStream.Dispose()
        $DownloadStream.Dispose()

        Return [String]"$ConvertedSize $Symbol"
    }

    Function Wait-WriteAndExit {
        [CmdletBinding()]
        Param ([Parameter(Mandatory)][String]$InputObject)
        Write-Host -ForegroundColor Red $InputObject
        [Void](Read-Host)
        Exit
    }

    [Console]::CursorVisible     = $False
    [Version]$Version            = "2.8.4"
    $ProgressPreference          = [Management.Automation.ActionPreference]::SilentlyContinue
    [String]$InstallDirectory    = [IO.Path]::Combine([Environment]::GetFolderPath("MyDocuments"), 'Euro Truck Simulator 2', 'mod')
    [String]$SaveEditorDirectory = [IO.Path]::Combine((Get-Item $InstallDirectory).Parent.FullName, 'TruckSaveEditor')
    $Host.UI.RawUI.WindowTitle   = "ETS2 Mod Updater - v$Version"

    [String[]]$UpdateNotes = @(
        '- Added transfer rate to progress display',
        '- Added completion summary',
        '- Added update notes display when updating the updater (update updates update)',
        '- Download optimizations (more speed, more better)',
        '- Fixed issue with failed updates and installs being registered as successful',
        '- Improved user interface structure',
        '- Made error messages less likely to break user interface',
        '- Stability improvements and futureproofing'
    )

    If (-Not [IO.Directory]::Exists($InstallDirectory)) {Wait-WriteAndExit "'$InstallDirectory' not found!"}
    If ($PSScriptRoot -ne $InstallDirectory)            {Wait-WriteAndExit "Please place the script in '$InstallDirectory'"}
    Set-Location $InstallDirectory

    If (!$Updated) {
        Write-Host " Checking Updater version...`n"
        Write-Host ' Installed   Current   Status'
        Write-Host "$(-Join ('-' * $Host.UI.RawUI.BufferSize.Width))"
        Write-Host -NoNewline " $($Version.ToString().PadRight(12))"
        Try {
            [Byte[]]$UpdaterBytes    = (Get-ModRepoFile 'Update.ps1' -UseIWR).Content
            [String]$UpdaterText     = [Text.Encoding]::ASCII.GetString($UpdaterBytes)
            [Version]$UpdaterVersion = (($UpdaterText -Split "`n")[0] -Split '=')[1]

            If ($Version -lt $UpdaterVersion) {
                Write-Host -NoNewline -ForegroundColor Green $UpdaterVersion.ToString().PadRight(10)

                [Void](Get-ModRepoFile 'Update.ps1' -UseIWR -Save)
                Return 'Updated'
            }
            Else {
                Write-Host -NoNewline $UpdaterVersion.ToString().PadRight(10)
                Write-Host -ForegroundColor Green 'Up to date'
            }
            Write-Host "`n"
        }
        Catch {Write-Host -ForegroundColor Red 'File not found. Continuing.'}
    }
    Else {
        Write-Host -ForegroundColor Green 'Updated'
        Write-Host "`n What's new:`n   $($UpdateNotes -Join "`n   ")`n"
        Write-Host "$(-Join ('-' * $Host.UI.RawUI.BufferSize.Width))"
        Start-Sleep -Seconds 1
    }

    [Byte]$Failures                   = 0
    [Byte]$Successes                  = 0
    [Byte]$LongestName                = 3
    [Byte]$L_LongestVersion           = 9
    [Byte]$E_LongestVersion           = 7
    [String[]]$NewVersions            = @()
    [Hashtable]$Versions              = @{}
    [Hashtable]$OnlineVersions        = @{}
    [Globalization.TextInfo]$TextInfo = (Get-Culture).TextInfo
    [Bool]$GameRunning                = 'eurotrucks2' -In (Get-Process).Name
    [Collections.Generic.List[String[]]]$Replace = @(
        @('Ai ', 'AI '),
        @('Bdf ', 'BDF ')
    )
    [Hashtable]$F_Replace = @{
        'classic_cars_traffic_a.scs' = 'classic_cars_traffic_pack_a.scs'
        'classic_cars_traffic_b.scs' = 'classic_cars_traffic_pack_b.scs'
        'sport_cars_traffic_a.scs'   = 'sport_cars_traffic_pack_a.scs'
        'sport_cars_traffic_b.scs'   = 'sport_cars_traffic_pack_b.scs'
        'tuned_truck_traffic.scs'    = 'tuned_truck_traffic_pack.scs' 
    }
    If ([IO.File]::Exists('versions.txt')) {
        ForEach ($Entry in (Get-Content 'versions.txt')) {
            [String]$Name, [Version]$Ver = $Entry -Split '=', 2
            ForEach ($FName in $F_Replace.GetEnumerator().Name) {
                $FName = ($FName -Split '\.')[0]
                If ($Name -Like $FName) {$Name = $FName; Break}
            }
            $Versions[$Name] = $Ver
            If ($Name.Length -gt $LongestName)                {$LongestName      = $Name.Length}
            If ($Ver.ToString().Length -gt $L_LongestVersion) {$L_LongestVersion = $Ver.ToString().Length}
        }
    }
    Try   {[String[]]$OnlineVersionData = (Get-ModRepoFile 'versions.txt' -UseIWR).Content -Split "`n"}
    Catch {Wait-WriteAndExit "Unable to download version data. Try again later.`nReason: $($_.Exception.Message)"}
    ForEach ($Entry in $OnlineVersionData) {
        [String]$Name, [Version]$Ver = $Entry -Split '=', 2
        $OnlineVersions[$Name]       = $Ver

        If ($Name.Length -gt $LongestName)                {$LongestName      = $Name.Length}
        If ($Ver.ToString().Length -gt $E_LongestVersion) {$E_LongestVersion = $Ver.ToString().Length}
    }

    $L_LongestVersion += 3
    $E_LongestVersion += 3
    $LongestName      += 3

    Write-Host "`n Looking for mod updates...`n"
    Write-Host " $('Mod'.PadRight($LongestName))$('Installed'.PadRight($L_LongestVersion))$('Current'.PadRight($E_LongestVersion))Status"
    Write-Host "$(-Join ('-' * $Host.UI.RawUI.BufferSize.Width))"

    ForEach ($Entry in $F_Replace.GetEnumerator().Name) {If ([IO.File]::Exists($Entry)) {Rename-Item $Entry $F_Replace[$Entry]}}

    ForEach ($Entry in ($OnlineVersions.GetEnumerator() | Sort-Object 'Name').Name) {

        [String]$ModFile  = "$($Entry).scs"
        [String]$OldFile  = "old_$($ModFile)"
        [String]$ModTitle = $TextInfo.ToTitleCase($Entry.Replace('_', ' '))
        ForEach ($String in $Replace) {$ModTitle = $ModTitle.Replace($String[0], $String[1])}

        Write-Host -NoNewline " $($ModTitle.PadRight($LongestName))"

        If ($Versions[$Entry] -And [IO.File]::Exists($ModFile)) {
            Write-Host -NoNewline $Versions[$Entry].ToString().PadRight($L_LongestVersion)
            [String]$Status = 'Updating...'
        }
        Else {
            If (![IO.File]::Exists($ModFile)) {$Versions[$Entry] = [Version]"0.0"}
            Write-Host -NoNewline '---'.PadRight($L_LongestVersion)
            [String]$Status = 'Installing...'
        }

        If ($Versions[$Entry] -lt $OnlineVersions[$Entry]) {
            Write-Host -NoNewline -ForegroundColor Green $OnlineVersions[$Entry].ToString().PadRight($E_LongestVersion)

            [Byte]$XPos          = $Host.UI.RawUI.CursorPosition.X
            [String]$ClearString = "$(-Join (' ' * ($Host.UI.RawUI.BufferSize.Width - $XPos - 1)))"

            If ([IO.File]::Exists($ModFile)) {Rename-Item $ModFile $OldFile -Force -ErrorAction SilentlyContinue}

            Try {
                If ($Status -eq 'Updating...' -And $GameRunning) {Throw 'Euro Truck Simulator 2 needs to be closed to update mods.'}
                [String]$Result = Get-ModRepoFile $ModFile -XPos $XPos -State $Status -ErrorAction Stop

                If ([IO.File]::Exists($OldFile)) {Remove-Item $OldFile -Force}

                Write-HostX -X $XPos -NoNewline $ClearString
                Switch ($Status) {
                    'Updating...'   {Write-HostX -X $XPos -ForegroundColor Green "Updated       ($Result)"}
                    'Installing...' {Write-HostX -X $XPos -ForegroundColor Green "Installed     ($Result)"}
                }
                $NewVersions += "$($Entry)=$($OnlineVersions[$Entry].ToString())"
                $Successes++
            }
            Catch {
                If ([IO.File]::Exists($ModFile)) {Remove-Item $ModFile -Force -ErrorAction SilentlyContinue}
                If ([IO.File]::Exists($OldFile)) {Rename-Item $OldFile $ModFile -Force -ErrorAction SilentlyContinue}
                $Failures++

                Write-HostX -X $XPos -NoNewline $ClearString
                Write-HostX -X $XPos -ForegroundColor Red 'Failed'
                Write-Host " $($_.Exception.Message)"
            }
        }
        Else {
            Write-Host -NoNewline $OnlineVersions[$Entry].ToString().PadRight($E_LongestVersion)
            Write-Host -ForegroundColor Green 'Up to date'
            $NewVersions += "$($Entry)=$($OnlineVersions[$Entry].ToString())"
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

    $NewVersions -Join "`n" | Out-File 'versions.txt' -Force

    [String]$S_PluralMod  = 'mod' + ('s', '')[($Successes -eq 1)]
    [String]$F_PluralMod  = 'mod' + ('s', '')[($Failures -eq 1)]
    [ConsoleColor]$Color  = Switch ($Null) {{$Failures -eq 0} {"Green"} {$Failures -gt 0 -And $Successes -eq 0} {"Red"} {$Failures -gt 0 -And $Successes -gt 0} {"Yellow"}}
    [Hashtable]$TextColor = @{ForegroundColor = $Color}
    
    Write-Host @TextColor "`n Done`n"
    If (($Successes + $Failures) -eq 0) {Write-Host @TextColor ' All mods up to date'}
    If ($Successes -gt 0)               {Write-Host @TextColor " $Successes $S_PluralMod processed successfully"}
    If ($Failures -gt 0)                {Write-Host @TextColor " $Failures $F_PluralMod failed to process"}

    [Void](Read-Host)
    Return
}
If (!$Updated) {If (Sync-Ets2ModRepo) {& "$PSScriptRoot\Update.ps1" @('Updated')}}
Else {[Void](Sync-Ets2ModRepo -Updated)}
