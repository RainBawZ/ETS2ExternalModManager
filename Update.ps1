#version=2.8.5
Param ([String]$Updated)
Function Sync-Ets2ModRepo {
    Param ([Switch]$Updated)

    Function Write-HostX {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory, Position = 1, ValueFromRemainingArguments)][Object]$Object,
            [Parameter(Mandatory, Position = 0)][ValidateScript({$_ -In (0..$Host.UI.RawUI.BufferSize.Width)})][Byte]$X,
            [ConsoleColor]$Color,
            [Switch]$Newline
        )
        [Hashtable]$WHSplat = @{Object = $Object}
        If (!$Newline) {$WHSplat['NoNewline']       = $True}
        If ($Color)    {$WHSplat['ForegroundColor'] = $Color}
        [Console]::SetCursorPosition($X, $Host.UI.RawUI.CursorPosition.Y)
        Write-Host @WHSplat
    }

    Function Get-ModPriority {
        Param([Parameter(Mandatory)][String]$Mod)
        [Hashtable]$Priorities = @{
            ai_traffic_pack             = 38 + 1
            better_road_events          = 39 + 1
            brutal_traffic              = 19 + 1
            bus_traffic_pack            = 37 + 1
            classic_cars_traffic_pack_a = 29 + 1
            classic_cars_traffic_pack_b = 28 + 1
            military_cargo_pack_a       = 22 + 1
            military_cargo_pack_b       = 21 + 1
            military_cargo_pack_c       = 20 + 1
            motorcycle_traffic_pack_a   = 27 + 1
            motorcycle_traffic_pack_b   = 26 + 1
            painted_bdf_traffic_pack    = 35 + 1
            painted_truck_traffic_pack  = 34 + 1
            real_emergency_ai_pack_a    = 18 + 1
            real_emergency_ai_pack_b    = 17 + 1
            realistic_grass_textures    = 10 + 1
            russian_traffic_pack_a      = 25 + 1
            russian_traffic_pack_b      = 24 + 1
            sport_cars_traffic_pack_a   = 31 + 1
            sport_cars_traffic_pack_b   = 30 + 1
            taxi_traffic_pack           = 23 + 1
            trailers_traffic_pack       = 32 + 1
            truck_traffic_pack          = 36 + 1
            tuned_truck_traffic_pack    = 33 + 1
        }
        Return [Int16](($Priorities[$Mod] | Where-Object {$_}) - 1)
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

        [Uri]$Uri = "http://tams.pizza/ets2repo/$($File)"

        If ($PSCmdlet.ParameterSetName -eq 'IWR') {
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

        [Net.HttpWebRequest]$HeaderRequest = [Net.WebRequest]::CreateHttp($Uri)
        $HeaderRequest.Method              = 'HEAD'
        $HeaderRequest.KeepAlive           = $False
        $HeaderRequest.Timeout             = 15000

        [Net.HttpWebRequest]$DownloadRequest = [Net.WebRequest]::CreateHttp($Uri)
        $DownloadRequest.Timeout             = 15000

        [Net.HttpWebResponse]$Header = $HeaderRequest.GetResponse()
        [UInt64]$DownloadSize        = $Header.ContentLength; $Header.Dispose()
        [UInt32]$BufferSize          = [Math]::Pow(2, [Math]::Floor([Math]::Log([Math]::Min([Math]::Max(8192, $DownloadSize), [GC]::GetTotalMemory($False) / 10), 2)))
        [Byte[]]$Buffer              = New-Object Byte[] $BufferSize
        
        [DateTime]$IntervalStart       = (Get-Date).AddSeconds(-1)

        [Net.HttpWebResponse]$Download = $DownloadRequest.GetResponse()
        [IO.Stream]$DownloadStream     = $Download.GetResponseStream()
        [IO.FileStream]$FileStream     = New-Object IO.FileStream $File, 'Create'
        
        [UInt32]$BytesRead             = $DownloadStream.Read($Buffer, 0, $Buffer.Length)
        [UInt64]$BytesDownloaded       = $BytesRead

        [UInt32]$Unit, [String]$Symbol, [UInt32]$ConvertedSize = If ($DownloadSize -lt 10000kB) {1kB, 'kB', ($DownloadSize / 1kB)} Else {1MB, 'MB', ($DownloadSize / 1MB)}
        [UInt32]$IntervalBytes, [UInt32]$ConvertedBytes, [Double]$IntervalLength = 0, 0, 0
        [String]$TransferRate = '0 kB/s'

        While ($BytesRead -gt 0) {
            $FileStream.Write($Buffer, 0, $BytesRead)
            $BytesRead        = $DownloadStream.Read($Buffer, 0, $Buffer.Length)
            $BytesDownloaded += $BytesRead
            $ConvertedBytes   = $BytesDownloaded / $Unit
            $IntervalLength   = (New-TimeSpan $IntervalStart (Get-Date)).TotalSeconds

            If ($IntervalLength -ge 1) {
                $TransferRate  = Measure-TransferRate $IntervalLength ($BytesDownloaded - $IntervalBytes)
                $IntervalBytes = $BytesDownloaded
                $IntervalStart = Get-Date
            }

            Write-HostX $X -Color Green "$State $ConvertedBytes/$ConvertedSize $Symbol ($TransferRate)      "
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
    [Version]$Version            = "2.8.5"
    $ProgressPreference          = [Management.Automation.ActionPreference]::SilentlyContinue
    [String]$InstallDirectory    = [IO.Path]::Combine([Environment]::GetFolderPath("MyDocuments"), 'Euro Truck Simulator 2', 'mod')
    [String]$SaveEditorDirectory = [IO.Path]::Combine((Get-Item $InstallDirectory).Parent.FullName, 'TruckSaveEditor')
    $Host.UI.RawUI.WindowTitle   = "ETS2 Mod Updater - v$Version"

    [String[]]$UpdateNotes = @(
        '- Installed mods now displays required load priority upon completion',
        '- Download optimizations',
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
    If ([IO.File]::Exists('versions.txt')) {
        ForEach ($Entry in (Get-Content 'versions.txt')) {
            [String]$Name, [Version]$Ver = $Entry -Split '=', 2
            $Versions[$Name]             = $Ver
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

    ForEach ($Entry in ($OnlineVersions.GetEnumerator() | Sort-Object 'Name').Name) {

        [String]$ModFile  = "$($Entry).scs"
        [String]$OldFile  = "old_$($ModFile)"
        [String]$ModTitle = $TextInfo.ToTitleCase($Entry.Replace('_', ' '))
        [String]$Priority = Get-ModPriority $Entry
        If ([Int]$Priority -eq -1) {$Priority = '?'}
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
                [String]$Result = Get-ModRepoFile $ModFile $XPos $Status -ErrorAction Stop

                If ([IO.File]::Exists($OldFile)) {Remove-Item $OldFile -Force}

                Write-HostX $XPos $ClearString
                Switch ($Status) {
                    'Updating...'   {Write-HostX $XPos -Color Green "Updated       ($Result)" -Newline}
                    'Installing...' {Write-HostX $XPos -Color Green "Installed     ($Result, Load order: $Priority)" -Newline}
                }
                $NewVersions += "$($Entry)=$($OnlineVersions[$Entry].ToString())"
                $Successes++
            }
            Catch {
                If ([IO.File]::Exists($ModFile)) {Remove-Item $ModFile -Force -ErrorAction SilentlyContinue}
                If ([IO.File]::Exists($OldFile)) {Rename-Item $OldFile $ModFile -Force -ErrorAction SilentlyContinue}
                $Failures++

                Write-HostX $XPos $ClearString
                Write-HostX $XPos -Color Red 'Failed' -Newline
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
