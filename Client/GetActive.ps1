Function Get-ModRepoFile {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, Position = 0)][String]$File,
        [Parameter()][Switch]$Save,
        [String]$ContentType
    )

    [Uri]$Uri = "https://your.domain/repo/$File"

    [Hashtable]$IWRSplat = @{
        Uri             = $Uri
        UseBasicParsing = $True
    }
    If ($Save)        {$IWRSplat['OutFile']     = $File}
    If ($ContentType) {$IWRSplat['ContentType'] = $ContentType}
    Return Invoke-WebRequest @IWRSplat
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

Function Convert-ProfileFolderName {
    Param ([String]$Directory)
    [Char[]]$Converted = For ([UInt16]$Index = 0; $Index -lt $Directory.Length; $Index += 2) {[Char][Byte]"0x$($Directory.Substring($Index, 2))"}
    Return $Converted -Join ''
}

Function Get-GameUnitDecoder {
    [CmdletBinding()]
    [String]$Path     = [IO.Path]::Combine($Env:TEMP, 'sii_decrypt.exe')
    [String]$Checksum = (Get-ModRepoFile 'sii_decrypt.txt' -ContentType 'text/plain; charset=utf8').Content
    If (![IO.File]::Exists($Path))        {[IO.File]::WriteAllBytes($Path, [Byte[]](Get-ModRepoFile 'sii_decrypt.exe').Content)}
    If (!(Test-FileHash $Path $Checksum)) {Throw 'Unable to verify sii_decrypt.exe - Checksum mismatch'}
    Return $Path
}

Function Get-ProfileUnitFormat {
    [CmdletBinding()]
    Param ([Parameter(Mandatory)][String]$Target)
    [Byte[]]$UnitData = [IO.File]::ReadAllBytes($Target)
    Return ('Text', 'Binary')[0 -In $UnitData]
}

Function Read-PlainTextProfileUnit {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, Position = 0)][String]$ProfileUnit,
        [Parameter(Position = 1)][ValidateSet('Mods', 'Data', 'All')][String]$Return = 'All',
        [Switch]$Raw
    )
    [Bool]$Parse        = $False
    [String[]]$UnitMods = @()
    [String[]]$UnitData = @()
    
    ForEach ($Line in Get-Content $ProfileUnit -Encoding UTF8) {
        If ($Parse -And $Line -Match '^ customization: \d+$') {
            $Parse        = $False
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
    Return (@($UnitMods, $UnitData), $UnitMods, $UnitData)[('All', 'Mods', 'Data').IndexOf($Return)]        
}

Function ConvertTo-PlainTextProfileUnit {
    [CmdletBinding()]
    Param ([Parameter(Mandatory)][String]$Unit)
    [String]$UnitDecoder   = Get-GameUnitDecoder
    [Object]$DecoderResult = Invoke-Expression "& '$UnitDecoder' --on_file -i '$Unit'"
    Switch ($LASTEXITCODE) {
        0       {Break}
        1       {Break}
        Default {Throw $DecoderResult}
    }
}

Function Select-Profile {
    [CmdletBinding()]
    [Hashtable]$Choices    = @{}
    [Byte]$Selected        = 1
    [String[]]$AllProfiles = (Get-ChildItem -Directory).Name | Sort-Object Length
    [UInt16]$LongestDir    = $AllProfiles[-1].Length + 3
    If ($AllProfiles.Count -eq 1) {Return $AllProfiles[0]}
    If (!$AllProfiles)            {Throw 'No profiles detected!'}
    [Management.Automation.Host.Coordinates]$StartPos = $Host.UI.RawUI.CursorPosition
    Do {
        Clear-Host
        [Byte]$Iteration = 0
        ForEach ($Directory in $AllProfiles) {
            $Iteration++
            [String]$Name     = Convert-ProfileFolderName $Directory
            [Bool]$IsSelected = $Iteration -eq $Selected
            $Choices["$Iteration"] = [Hashtable]@{
                Directory = $Directory
                Name      = $Name
            }
            Write-Host -NoNewline ' '
            Write-Host -ForegroundColor ("DarkGray", "Green")[$IsSelected] " $(('   ', '>> ')[$IsSelected])$($Iteration.ToString().PadRight(4)): $($Directory.PadRight($LongestDir))$Name "
        }
        Write-Host -NoNewline "`n * Enter a number "
        Write-Host -NoNewline -ForegroundColor Cyan "[1-$Iteration]"
        Write-Host -NoNewline ' and press '
        Write-Host -NoNewline -ForegroundColor Cyan '[ENTER]'
        Write-Host ' to select your ETS2 profile.'
        Write-Host -NoNewline ' * Press '
        Write-Host -NoNewline -ForegroundColor Cyan '[ENTER]'
        Write-Host " once more to confirm and apply.`n"
        Write-Host -NoNewline 'Enter profile: '
        [String]$UserInput = Read-Host
        If ([String]::IsNullOrWhiteSpace($UserInput)) {
            Clear-Host
            Return $Choices["$Selected"]
        }
        ElseIf ($UserInput -In $Choices.Keys) {$Selected = $UserInput}
    } While ($True)
}

[Hashtable]$TargetProfile = Select-Profile
[String]$ProfileUnit      = [IO.Path]::Combine($TargetProfile.Directory, 'profile.sii')

Write-Host "Selected profile: $($TargetProfile.Name)`n"

Write-Host -NoNewline 'Testing profile.sii format... '
If ((Get-ProfileUnitFormat $ProfileUnit) -ne 'Text') {
    Write-Host -NoNewline -ForegroundColor Green 'Binary - Decoding... '
    ConvertTo-PlainTextProfileUnit $ProfileUnit -ErrorAction Stop
    Write-Host -ForegroundColor Green 'Done.'
}
Else {Write-Host -ForegroundColor Green 'Plaintext'}

Write-Host -NoNewline 'Collecting mod data... '
[String[]]$ModData = Read-PlainTextProfileUnit $ProfileUnit Mods
$ModData -Join "`n" | Set-Content _active.txt -Force -NoNewline
Write-Host -ForegroundColor Green "Done.`n"
Write-Host ($ModData -Join "`n")
[Void](Read-Host)
