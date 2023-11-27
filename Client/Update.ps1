#version=3.1.7
#profile=***GAME_PROFILE_PLACEHOLDER***;

# To select a different profile on next launch, replace line 2 with the following: 
#profile=***GAME_PROFILE_PLACEHOLDER***;

Param ([String]$Updated)
Function Sync-Ets2ModRepo {

    Param ([String]$Updated)

    Function Limit-Range {
        [CmdletBinding()]

        Param (
            [Parameter(Mandatory, Position = 0)][Double]$Value,
            [Parameter(Mandatory, Position = 1)][Double]$Min,
            [Parameter(Mandatory, Position = 2)][Double]$Max
        )

        If ($Min -gt $Max)      {Throw "Invalid range: $Min > $Max"}
        If ($Max -lt $Min)      {Throw "Invalid range: $Max < $Min"}

        If ($G__ClampAvailable) {Return [Math]::Clamp($Value, $Min, $Max)}

        Return $(If ($Value -lt $Min) {$Min} ElseIf ($Value -gt $Max) {$Max} Else {$Value})
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

        If ($InputString.Length -ge $InputLimit) {$InputString = "$($InputString.Substring(0, ($InputLimit - 5)))[...]"}

        [UInt16]$InputLength = $InputString.Length
        [Int]$RawPadLength   = $InputLimit - $InputLength
        [UInt16]$PadLength   = Limit-Range $RawPadLength 0 $BufferWidth

        [Hashtable]$WHSplat  = @{Object = "$InputString$(' ' * $PadLength)"}
        If (!$Newline)    {$WHSplat['NoNewline']       = $True}
        If ($Color)       {$WHSplat['ForegroundColor'] = $Color}

        If (!$G__ISEHost) {[Console]::SetCursorPosition($X, $Host.UI.RawUI.CursorPosition.Y)}

        Write-Host @WHSplat
    }

    Function Read-HostX {
        [CmdletBinding()]

        Param ([Parameter(Position = 0)][String]$Prompt)

        [String]$UserInput = If ($Prompt) {Read-Host $Prompt} Else {Read-Host}
        If (!$G__ISEHost) {[Console]::CursorVisible = $False}
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

        [Hashtable]$ErrorLogIO    = @{FilePath = 'Error.log.txt'; Encoding = 'UTF8'}

        [String]$Message          = $Exception.Exception.Message
        [String]$Details          = $Exception.ErrorDetails.Message

        [String]$ErrorLogEntryHeader = 'FATAL ERROR ON ' + (Get-Date -Format "yyyy.MM.dd, HH:mm:ss") + "WITH VERSION $G__LocalVersion :"
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
            [Parameter(ParameterSetName = 'IWR')][Switch]$Save,
            [String]$ContentType
        )

        [Uri]$Uri = "$G__RepositoryURL/$File"

        If ($PSCmdlet.ParameterSetName -eq 'IWR') {
            [Hashtable]$IWRSplat = @{
                Uri             = $Uri
                UseBasicParsing = $True
            }
            If ($Save)        {$IWRSplat['OutFile']     = $File}
            If ($ContentType) {$IWRSplat['ContentType'] = $ContentType}
            Return Invoke-WebRequest @IWRSplat
        }

        [Net.HttpWebRequest]$HeaderRequest   = [Net.WebRequest]::CreateHttp($Uri)
        $HeaderRequest.Method                = 'HEAD'
        $HeaderRequest.KeepAlive             = $False
        $HeaderRequest.Timeout               = 15000

        [Net.HttpWebRequest]$DownloadRequest = [Net.WebRequest]::CreateHttp($Uri)
        $DownloadRequest.Timeout             = 15000
        $DownloadRequest.ContentType         = ($ContentType, $Null)[[String]::IsNullOrWhiteSpace($ContentType)]

        [Net.HttpWebResponse]$Header   = $HeaderRequest.GetResponse()
        [UInt64]$DownloadSize          = $Header.ContentLength; $Header.Dispose()
        [UInt32]$BufferSize            = [Math]::Pow(2, [Math]::Floor([Math]::Log([Math]::Min($DownloadSize, [GC]::GetTotalMemory($False) / 10), 2)))
        [Byte[]]$Buffer                = New-Object Byte[] $BufferSize
        
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

    Function Test-ModActive {
        [CmdletBinding()]

        Param ([Parameter(Mandatory)][String]$Mod)

        If (![IO.File]::Exists($G__GameLogPath) -Or $G__GameProcess -NotIn (Get-Process).Name) {Return $False}

        ForEach ($Line in Get-Content $G__GameLogPath -Encoding UTF8) {If ($Line -Match " \: \[mods\] Active local mod $Mod ") {Return $True}}

        Return $False
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

    Function Compare-Hashtables {
        [CmdletBinding()]

        Param (
            [Parameter(Mandatory, Position = 0)][Hashtable]$Reference,
            [Parameter(Mandatory, Position = 1)][Hashtable]$Difference,
            [Switch]$CaseSensitive, [Switch]$AsBoolean
        )

        [Hashtable]$Comparison = @{}

        ForEach ($Entry in $Reference.GetEnumerator()) {
            If ($CaseSensitive) {If ($Entry.Key -CNotIn $Difference.Keys -Or $Difference[$Entry.Key] -Cne $Entry.Value) {
                If ($AsBoolean) {Return $False}
                $Comparison[$Entry.Key] = $Entry.Value
            }}
            ElseIf ($Entry.Key -NotIn $Difference.Keys -Or $Difference[$Entry.Key] -ne $Entry.Value) {
                If ($AsBoolean) {Return $False}
                $Comparison[$Entry.Key] = $Entry.Value
            }
        }

        If ($Match) {Return $True}
        Return $Comparison
    }
    
    Function Wait-WriteAndExit {
        [CmdletBinding()]

        Param ([String]$InputObject, [Switch]$Restart)

        Write-Host -ForegroundColor Red $InputObject
        Unprotect-Variables
        Wait-KeyPress
        If ($Restart) {
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
            [Parameter(ParameterSetName = 'Prompt')][Switch]$NoNewline
        )

        If ($PSCmdlet.ParameterSetName -eq 'Prompt') {
            [Hashtable]$PromptSplat = @{
                Object    = $Prompt
                NoNewline = [Bool]$NoNewline
            }
            If ($ForegroundColor) {$PromptSplat['ForegroundColor'] = $ForegroundColor}
            If ($BackgroundColor) {$PromptSplat['BackgroundColor'] = $BackgroundColor}
            Write-Host @PromptSplat
        }
        If (!$G__ISEHost) {[Void]$Host.UI.RawUI.ReadKey('NoEcho, IncludeKeyDown')}
        Else              {[Void](Read-HostX)}
    }

    Function Convert-ModSourceName {
        [CmdletBinding(DefaultParameterSetName = 'Default')]

        Param (
            [String]$Name,
            [Parameter(Mandatory, ParameterSetName = 'AsPath')][Switch]$AsPath,
            [Parameter(Mandatory, ParameterSetName = 'ModType')][Switch]$ModType
        )

        [String]$Type, [String]$Hex = $Name -Split '\.', 2

        If ($ModType)                           {Return $Type}
        If ([String]::IsNullOrWhiteSpace($Hex)) {Return ($Name, "$G__InstallDirectory\$Name.scs")[[Bool]$AsPath]}

        Return (($Name, [String][UInt32]"0x$Hex")[$Type -eq 'mod_workshop_package'], ("$G__InstallDirectory\$Name.scs", "$G__WorkshopPath\$([String][UInt32]"0x$Hex")")[$Type -eq 'mod_workshop_package'])[[Bool]$AsPath]
    }

    Function Convert-ProfileFolderName {
        [CmdletBinding()]

        Param ([String]$Directory)

        [String]$Directory = ($G__ActiveProfile, $Directory)[[Bool]$Directory]
        [Char[]]$Converted = For ([UInt16]$Index = 0; $Index -lt $Directory.Length; $Index += 2) {[Char][Byte]"0x$($Directory.Substring($Index, 2))"}

        Return $Converted -Join ''
    }

    Function ConvertTo-PlainTextProfileUnit {
        [CmdletBinding()]

        Param ([String]$File)

        [String]$File          = ($G__ProfileUnit, $File)[[Bool]$File]
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

    Function Get-WorkshopDirectory {
        [CmdletBinding()]

        [String]$SteamRoot = Get-ItemPropertyValue HKLM:\SOFTWARE\WOW6432Node\Valve\Steam InstallPath
        [String]$SteamLibs = [IO.Path]::Combine($SteamRoot, 'SteamApps', 'libraryfolders.vdf')

        [String]$Directory = ForEach ($Line in Get-Content $SteamLibs -Encoding UTF8) {
            If ($Line -Match '"path"')    {[String]$Path = ($Line -Split '"path"')[-1].Replace('"', '').Replace('\\', '\').TrimStart()}
            If ($Line -Match $G__SteamID) {[IO.Path]::Combine($Path, 'steamapps', 'workshop', 'content', $G__SteamID)}
        }

        Return $Directory
    }

    Function Get-ProfileUnitFormat {
        [CmdletBinding()]

        Param ([String]$Target)

        [String]$Target   = ($Target, $G__ProfileUnit)[[String]::IsNullOrWhiteSpace($Target)]
        [Byte[]]$UnitData = [IO.File]::ReadAllBytes($Target)

        Return ('Text', 'Binary')[0 -In $UnitData]
    }

    Function Get-GameUnitDecoder {
        [CmdletBinding()]

        [String]$Path     = [IO.Path]::Combine($Env:TEMP, 'sii_decrypt.exe')
        [String]$Checksum = (Get-ModRepoFile sii_decrypt.txt -UseIWR -ContentType 'text/plain; charset=utf8').Content

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
            [String]$Priority = Switch (($Entry -Split '\[|\]', 3)[1]) {
                {$_ -As [UInt16] -eq $_} {$_}
                Default                  {Continue}
            }
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
        If ($Raw) {
            [String]$UnitMods = $UnitMods -Join "`n"
            [String]$UnitData = $UnitData -Join "`n"
        }

        Return (($UnitMods, $UnitData), $UnitMods, $UnitData)[('All', 'Mods', 'Data').IndexOf($Return)]        
    }

    Function Enable-OnlineModList {
        [CmdletBinding()]

        Param ([String]$ProfileUnit)

        [String]$ProfileUnit = ($G__ProfileUnit, $ProfileUnit)[[Bool]$ProfileUnit]

        Write-Host -NoNewline (''.PadRight(4) + 'Downloading configuration...'.PadRight(35))
        [String]$ActiveMods      = (Get-ModRepoFile _active.txt -UseIWR -ContentType 'text/plain; charset=utf8').Content
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
        [UInt16]$ProfileModsCount                      = ($ProfileMods[0] -Split ':', 2)[-1].Trim()
        [Hashtable]$OldConfig                          = Get-ModData $ProfileMods
        [Hashtable]$NewConfig                          = Get-ModData $ActiveMods
        [Hashtable]$ConfigDiff                         = Compare-Hashtables $OldConfig $NewConfig

        If ($ConfigDiff.Count -gt 0) {
            $ProfileData -Join "`n" -Replace '<MODLIST_INSERTION_POINT>', $ActiveMods | Set-Content $ProfileUnit @G__SCGlobal
            Write-Host -ForegroundColor Green "OK - $ProfileModsCount > $ActiveModsCount"
            ForEach ($Entry in $ConfigDiff.GetEnumerator()) {Write-Host -ForegroundColor Green ("`n    '" + $Entry.Key + "' - '" + $Entry.Value +"'")}
        }
        Else {Write-Host -ForegroundColor Green 'Already applied'}

        [String[]]$MissingWorkshopMods = Foreach ($Key in $NewConfig.Keys | Where-Object {$NewConfig[$_].Type -eq 'mod_workshop_package'}) {
            [Hashtable]$Current = $NewConfig[$Key]
            If (!(Test-WorkshopModInstalled $Current.Source)) {
                Write-Host -ForegroundColor Yellow (''.PadRight(4) + "MISSING SUBSCRIPTION: " + $Current.Name)
                ('https://steamcommunity.com/sharedfiles/filedetails/?id=' + $Current.SourceName + '/')
            }
        }

        If ($MissingWorkshopMods) {
            Do {$UserInput = Read-HostX 'Open in browser? [Y/N]'} Until ($UserInput -Match '^(Y|N)$')
            Switch ($UserInput) {
                'Y' {ForEach ($Mod in $MissingWorkshopMods) {Start-DefaultWebBrowser $Mod}}
                'N' {Break}
            }
        }
    }

    Function Backup-ProfileUnit {
        [CmdletBinding()]

        [String]$Name       = ('profile_' + (Get-Date -Format yy-MM-dd_HHmmss))
        [String]$BackupFile = [IO.Path]::Combine($G__ProfilePath, "$Name.bak")

        Copy-Item $G__ProfileUnit $BackupFile

        Return $BackupFile
    }

    Function Select-Profile {
        [CmdletBinding()]

        [Hashtable]$Choices    = @{}
        [Byte]$Selected        = 1
        [String[]]$AllProfiles = (Get-ChildItem ([IO.Path]::Combine($G__GameRoot, 'profiles')) -Directory).Name | Sort-Object Length

        Clear-Host
        Write-Host ' SELECT PROFILE'
        Write-Host ('-' * $Host.UI.RawUI.BufferSize.Width)

        If (!$AllProfiles) {Throw 'No profiles detected!'}

        If ($AllProfiles.Count -eq 1) {
            [String]$Directory = $AllProfiles[0]
            Set-ActiveProfile $Directory

            Write-Host -ForegroundColor Green "$G__GameNameShort Profile '$(Convert-ProfileFolderName $Directory)' was applied automatically."
            Start-Sleep 2

            Return $Directory
        }

        [UInt16]$LongestDir                               = $AllProfiles[-1].Length + 3
        [Management.Automation.Host.Coordinates]$StartPos = $Host.UI.RawUI.CursorPosition

        Do {
            If (!$G__ISEHost) {[Console]::SetCursorPosition($StartPos.X, $StartPos.Y)}

            [Byte]$Iteration = 0

            ForEach ($Directory in $AllProfiles) {
                $Iteration++

                [String]$Name          = Convert-ProfileFolderName $Directory
                [Bool]$IsSelected      = $Iteration -eq $Selected
                $Choices["$Iteration"] = [Hashtable]@{
                    Directory = $Directory
                    Name      = $Name
                }

                Write-Host -NoNewline ' '
                Write-HostX 0 -Color ("DarkGray", "Green")[$IsSelected] " $(('   ', '>> ')[$IsSelected])$("$Iteration".PadRight(4)): $($Directory.PadRight($LongestDir))$Name " -Newline
            }
            Write-Host -NoNewline "`n * Enter a number "
            Write-Host -NoNewline -ForegroundColor Cyan "[1-$Iteration]"
            Write-Host -NoNewline ' and press '
            Write-Host -NoNewline -ForegroundColor Cyan '[ENTER]'
            Write-Host " to select your $G__GameNameShort profile."
            Write-Host -NoNewline ' * Press '
            Write-Host -NoNewline -ForegroundColor Cyan '[ENTER]'
            Write-Host " once more to confirm and apply.`n"
            Write-Host -NoNewline 'Enter profile: '
            [String]$UserInput = Read-HostX
            If ([String]::IsNullOrWhiteSpace($UserInput)) {
                Set-ActiveProfile $Choices["$Selected"].Directory
                Clear-Host
                Return $Choices["$Selected"].Directory
            }
            ElseIf ($UserInput -In $Choices.Keys) {$Selected = $UserInput}
        } While ($True)
    }

    Function Get-ActiveProfile {
        [CmdletBinding()]

        [String]$RawValue      = Get-Content $G__UpdaterScript -Encoding UTF8 -TotalCount ($G__ProfilePosition + 1) | Select-Object -Last 1
        [String]$Value         = ($RawValue -Split '=', 2)[1]
        [UInt16]$EndIndex      = ($Value.LastIndexOf(';'), $Value.Length)[$Value.LastIndexOf(';') -lt 0]
        [String]$StoredProfile = $Value.SubString(0, (Limit-Range $Value.LastIndexOf(';') $EndIndex $Value.Length))

        If ($StoredProfile -eq '***GAME_PROFILE_PLACEHOLDER***' -Or [String]::IsNullOrWhiteSpace($StoredProfile) -Or ![IO.Directory]::Exists([IO.Path]::Combine($G__GameRoot, 'profiles', $StoredProfile))) {$StoredProfile = Select-Profile}
        
        Return $StoredProfile
    }

    Function Set-ActiveProfile {
        [CmdletBinding()]

        Param ([Parameter(Mandatory)][String]$Directory)

        If ($Directory -ne $G__ActiveProfile) {
            [String[]]$InternalData            = Get-Content $G__UpdaterScript -Encoding UTF8
            $InternalData[$G__ProfilePosition] = "#profile=$Directory;"

            $InternalData -Join "`n" | Set-Content $G__UpdaterScript @G__SCGlobal

            $GLOBAL:G__ScriptRestart = $True
            [Void]$GLOBAL:G__ScriptRestart
        }
    }

    Function Start-DefaultWebBrowser {
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

    $ErrorActionPreference = [Management.Automation.ActionPreference]::Stop
    $ProgressPreference    = [Management.Automation.ActionPreference]::SilentlyContinue

    Trap {Wait-WriteAndExit "`n`nFATAL ERROR`n$(Format-AndExportErrorData $_)"}

    Protect-Variables

    [Version]$G__LocalVersion       = "3.1.7"
    [UInt32]$G__VersionPosition     = 0
    [UInt32]$G__ProfilePosition     = 1
    [String]$G__RepositoryURL       = 'http://your.domain/repository'
    [String]$G__UpdaterScript       = $PSCommandPath
    [Bool]$G__ISEHost               = $Host.Name -Like '*ISE*'
    [Bool]$G__ClampAvailable        = 'Clamp' -In [String[]][Math].GetMethods().Name
    [Hashtable]$G__SCGlobal         = @{Encoding = 'UTF8'; Force = $True}

    [UInt32]$G__SteamID             = 227300
    [String]$G__GameName            = 'Euro Truck Simulator 2'
    [String]$G__GameNameShort       = 'ETS2'
    [String]$G__GameProcess         = 'eurotrucks2'

    [String]$G__GameRoot            = [IO.Path]::Combine([Environment]::GetFolderPath('MyDocuments'), $G__GameName)
    [String]$G__GameLogPath         = [IO.Path]::Combine($G__GameRoot, 'game.log.txt')
    [String]$G__InstallDirectory    = [IO.Path]::Combine($G__GameRoot, 'mod')
    [String]$G__SaveEditorDirectory = [IO.Path]::Combine($G__GameRoot, 'TruckSaveEditor')
    [String]$G__WorkshopPath        = Get-WorkshopDirectory
    $Host.UI.RawUI.WindowTitle      = "$G__GameNameShort Mod Updater - v$G__LocalVersion"
    [Bool]$GLOBAL:G__ScriptRestart  = ($GLOBAL:G__ScriptRestart, $False)[$Null -eq $GLOBAL:G__ScriptRestart]
    [ScriptBlock]$G__EXEC_RESTART   = {If ($GLOBAL:G__ScriptRestart -eq $True) {Unprotect-Variables; Remove-Variable G__ScriptRestart -Scope GLOBAL -ErrorAction SilentlyContinue; Return 'Restarted'}}

    If (!$G__ISEHost)                                  {[Console]::CursorVisible = $False}
    If (![IO.Directory]::Exists($G__InstallDirectory)) {Wait-WriteAndExit "Cannot locate the $G__GameNameShort mod directory '$G__InstallDirectory' on the system.`nVerify that $G__GameName is correctly installed and try again."}
    If ($PSScriptRoot -ne $G__InstallDirectory)        {Wait-WriteAndExit "Startup aborted - Invalid script location.`n'$G__UpdaterScript' must be placed in '$G__InstallDirectory' to run."}
    Set-Location $G__InstallDirectory

    [String]$G__ActiveProfile       = Get-ActiveProfile
    [String]$G__ProfilePath         = [IO.Path]::Combine($G__GameRoot, 'profiles', $G__ActiveProfile)
    [String]$G__ProfileUnit         = [IO.Path]::Combine($G__ProfilePath, 'profile.sii')

    [String[]]$G__UpdateNotes = @(
        '- Improved error logging.'
        '- Improved script customization.'
        '- Fixed issue causing profile configurations to be needlessly applied.'
        '- Fixed issue causing the script to fail restarting after selecting a profile.'
        '- Fixed issue causing certain functions to report errors incorrectly.'
        '- Fixed issue causing text cursor to become visible after user input prompts.'
        '- Fixed issue where download progress in theory would not be saved upon completion.'
        '- Fixed errors when running in PowerShell ISE.'
        '- Minor optimizations.'
    )

    Update-ProtectedVars

    . $G__EXEC_RESTART

    If ($Updated -eq 'Restarted') {$Updated = $Null}

    If (!$Updated) {

        [Byte]$Padding = 15

        Clear-Host
        Write-Host " Checking Updater version...`n"
        Write-Host (' ' + 'Installed'.PadRight($Padding) + 'Current'.PadRight($Padding) + 'Status')
        Write-Host ('-' * $Host.UI.RawUI.BufferSize.Width)
        Write-Host -NoNewline (' ' + "$G__LocalVersion".PadRight($Padding))

        Try {
            [Byte[]]$DownloadedBytes = (Get-ModRepoFile Update.ps1 -UseIWR -ContentType 'text/plain; charset=utf8').Content
            [String[]]$DecodedString = [Text.Encoding]::UTF8.GetString($DownloadedBytes)
            [String]$VersionLine     = ($DecodedString -Split "`n")[$G__VersionPosition]
            [String]$VersionString   = $VersionLine.Substring($VersionLine.IndexOf('=') + 1)
            [Version]$LatestVersion  = ('0.0', $VersionString)[[Bool]($VersionString -As [Version])]
            [String]$SavedProfile    = ($DecodedString -Split "`n")[$G__ProfilePosition]
            $DecodedString           = $DecodedString -Replace [Regex]::Escape($SavedProfile), "#profile=$G__ActiveProfile;"

            If ($LatestVersion -gt $G__LocalVersion) {
                [ConsoleColor]$VersionColor, [String]$VersionText, [String]$ReturnValue = (("Green", "$LatestVersion", 'Updated'), ("Red", 'Parsing error', 'Repaired'))[$LatestVersion -eq '0.0']

                Write-Host -NoNewline -ForegroundColor $VersionColor $VersionText.PadRight($Padding)

                $DecodedString | Set-Content $G__UpdaterScript @G__SCGlobal

                Unprotect-Variables

                Return $ReturnValue
            }
            Else {
                Write-Host -NoNewline "$LatestVersion".PadRight($Padding)
                Write-Host -ForegroundColor Green 'Up to date'
            }

            Write-Host "`n"
        }
        Catch {Write-Host -ForegroundColor Red (Format-AndExportErrorData $_)}
    }
    Else {
        Write-Host -ForegroundColor Green $Updated
        Write-Host ("`n What's new:`n   " + ($G__UpdateNotes -Join "`n   ") + "`n")
        Write-Host ('-' * $Host.UI.RawUI.BufferSize.Width)
        Wait-KeyPress 'Press any key to continue.' -NoNewline
    }

    Remove-UnprotectedVars

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

            [String[]]$ModData = ($RawData -Split '=', 3)[0..1]
            If (Test-ArrayNullOrEmpty $ModData) {
                Try     {Throw "versions.txt[$Line]: Invalid data"}
                Catch   {[Void](Format-AndExportErrorData $_)}
                Continue
            }

            [String]$Name, [Version]$Ver = $ModData

            $LocalMods[$Name] = [Hashtable]@{
                'FileName'   = "$Name.scs"
                'Version'    = $Ver
                'VersionStr' = [String]$Ver
            }

            If ($Name.Length -gt $LongestName)       {$LongestName      = $Name.Length}
            If ("$Ver".Length -gt $L_LongestVersion) {$L_LongestVersion = "$Ver".Length}
        }
    }

    Try   {[PSCustomObject]$OnlineData = (Get-ModRepoFile versions.json -UseIWR -ContentType 'text/plain; charset=utf8').Content | ConvertFrom-JSON}
    Catch {Wait-WriteAndExit "Unable to download version data. Try again later.`nReason: $(Format-AndExportErrorData $_)"}

    ForEach ($Mod in $OnlineData.PSObject.Properties.Value) {
        If ($Mod.Name.Length -gt $LongestName)         {$LongestName      = $Mod.Name.Length}
        If ($Mod.Version.Length -gt $E_LongestVersion) {$E_LongestVersion = $Mod.Version.Length}
    }

    If ([IO.File]::Exists('progress.tmp')) {
        $PreviousProgress = Get-Content progress.tmp -Encoding UTF8
        Remove-Item progress.tmp -Force
    }

    $L_LongestVersion      += 3
    $E_LongestVersion      += 3
    $LongestName           += 3

    [String]$CurrentProfile = Convert-ProfileFolderName

    Write-Host ' Looking for mod updates...'
    Write-Host ("Active profile: $CurrentProfile".PadLeft($Host.UI.RawUI.BufferSize.Width - 1) + "`n" + $G__ActiveProfile.PadLeft($Host.UI.RawUI.BufferSize.Width - 1))
    Write-Host " $('Mod'.PadRight($LongestName))$('Installed'.PadRight($L_LongestVersion))$('Current'.PadRight($E_LongestVersion))Status"
    Write-Host ('-' * $Host.UI.RawUI.BufferSize.Width)

    ForEach ($CurrentMod in $OnlineData.PSObject.Properties.Value) {
        
        $CurrentMod.Version  = [Version]$CurrentMod.Version
        [String]$OldFile     = "old_$($CurrentMod.FileName)"
        [Hashtable]$LocalMod = $LocalMods.($CurrentMod.Name)
        [Byte]$Repair        = 0 # 0: No repair   1: Entry   2: File

        Write-Host -NoNewline " $($CurrentMod.Title.PadRight($LongestName))"

        [Byte]$StatusEval = ([Bool]$LocalMod.Version, [IO.File]::Exists($CurrentMod.FileName) | Group-Object | Where-Object {$_.Name -eq 'True'}).Count
        
        Switch ($StatusEval) {
            0 {
                [String]$Status = 'Installing...'
                Write-Host -NoNewline '---'.PadRight($L_LongestVersion)
            }
            1 {
                [String]$Status = 'Repairing...'
                $Repair         = (2, 1)[[Bool]$LocalMod.Version]
                Write-Host -NoNewline -ForegroundColor Red ('???', $LocalMod.VersionStr)[[Bool]$LocalMod.Version].PadRight($L_LongestVersion)
            }
            2 {
                [String]$Status = 'Updating...'
                Write-Host -NoNewline $LocalMod.VersionStr.PadRight($L_LongestVersion)
            }
        }

        [ConsoleColor]$VersionColor = ("Green", "White")[($LocalMod.Version -ge $CurrentMod.Version)]

        Write-Host -NoNewline -ForegroundColor $VersionColor $CurrentMod.VersionStr.PadRight($E_LongestVersion)
        If ($CurrentMod.Name -In $PreviousProgress) {
            Write-Host -NoNewline -ForegroundColor Green 'Up to date'
            $NewVersions += "$($CurrentMod.Name)=$($CurrentMod.VersionStr)"
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
                $NewVersions += "$($CurrentMod.Name)=$($CurrentMod.VersionStr)"
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

                $NewVersions    += "$($CurrentMod.Name)=$($CurrentMod.VersionStr)"
                $DownloadedData += $NewSize - $OriginalSize
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
    If (![IO.Directory]::Exists($G__SaveEditorDirectory)) {

        Write-Host -NoNewline " $('Save Editor'.PadRight($LongestName))$('---'.PadRight($L_LongestVersion))"
        Write-Host -NoNewline -ForegroundColor Green "$('---'.PadRight($E_LongestVersion))"

        [UInt16]$XPos = $Host.UI.RawUI.CursorPosition.X

        Write-Host -NoNewline -ForegroundColor Green 'Installing...'

        If (!$G__ISEHost) {[Console]::SetCursorPosition($XPos, $Host.UI.RawUI.CursorPosition.Y)}

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
    Write-Host "`n Configuring profile..."

    Enable-OnlineModList

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
    If (($Successes + $Failures) -eq 0) {Write-Host @TextColor " All mods up to date - $TotalStr"}
    If ($Successes -gt 0)               {Write-Host @TextColor "   $Successes $S_PluralMod processed successfully - $TotalStr ($DownloadedStr)"}
    If ($Failures -gt 0)                {Write-Host @TextColor "   $Failures $F_PluralMod failed to process"}
    If ($Invalids -gt 0)                {Write-Host -ForegroundColor $ColorB "   $Invalids $I_PluralMod failed to validate"}
    If (($Failures + $Invalids) -gt 0)  {Write-Host @TextColor "`n Exit and restart the updater to try again"}

    [Void](Read-HostX)
    Unprotect-Variables
    Return
}
If (!$Updated) {
    Switch (Sync-Ets2ModRepo) {
        {$_ -eq ''}    {& $PSCommandPath; Break}
        {$Null -ne $_} {& $PSCommandPath @($_); Break}
    }
}
Else {[Void](Sync-Ets2ModRepo -Updated $Updated)}
