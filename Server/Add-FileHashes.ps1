Set-Location $PSScriptRoot

# TODO: Deprecate versions.txt, use versions.json instead.

[Text.UTF8Encoding]$UTF8NoBOM     = New-Object Text.UTF8Encoding $False
[Globalization.TextInfo]$TextInfo = (Get-Culture).TextInfo

[Collections.Generic.List[String[]]]$Replace = @(
    @('Ai ', 'AI '),
    @('Bdf ', 'BDF '),
    @(' Rtd', ' RTD'),
    @(' Def', ' Def.'),
    @(' Vip', ' VIP'),
    @(' Dlc', ' DLC'),
    @(' Hs', ' HS'),
    @(' Xf', ' XF')
)

[String[]]$Files       = (Get-ChildItem "*.scs" -File).BaseName
[String[]]$VersionData = Get-Content 'versions.txt'
[String[]]$Existing    = ForEach ($Entry in $VersionData) {$Entry.Substring(0, $Entry.IndexOf('='))}

# Append new files
ForEach ($File in $Files) {
    If ($File -In $Existing) {Continue}
    $VersionData += "$($File)=N/A=1=1=A;"
}

# Determine longest file name
[Byte]$Longest = 0
ForEach ($Entry in $VersionData) {
    [UInt16]$Length = $Entry.Substring(0, $Entry.IndexOf('=')).Length
    $Longest = ($Longest, $Length)[$Length -gt $Longest]
}

$Longest += 15

# Check and update mods
[Array]::Sort($VersionData)
[Collections.Specialized.OrderedDictionary]$Mods = @{}
[String[]]$Entries                               = @()

ForEach ($Entry in $VersionData) {
    
    [String]$File, [String]$Ver, [String]$Index, [String]$Active, [String]$Hash = $Entry.Substring(0, $Entry.LastIndexOf(';')) -Split '=', 5

    Write-Host -NoNewline "Checking '$($File)'".PadRight($Longest)

    [String]$NewHash = (Get-FileHash -Algorithm SHA1 "$($File).scs").Hash

    If ($NewHash -ne $Hash) {

        [String]$Hash = $NewHash

        Write-Host -ForegroundColor DarkCyan 'Hash mismatch'

        [Bool]$ForceVer = $Ver -eq 'N/A'
        Do {
            [String]$NewVersion = ''
            $NewVersion         = Read-Host "   Version? ($($Ver))"
        } Until ($NewVersion -As [Version] -Or ($NewVersion -eq '' -And !$ForceVer))

        If ($NewVersion -ne '') {
            $OldVer = $Ver
            $Ver    = $NewVersion
            Write-Host -ForegroundColor Green "   $($OldVer.ToString()) -> $($Ver.ToString())"
        }
        Else {Write-Host -ForegroundColor Green '   Updated hash'}
    }
    Else {Write-Host -ForegroundColor Green 'OK'}

    $Entries += "$($File)=$($Ver)=0=1=$($Hash);"

    [String]$Title = $TextInfo.ToTitleCase($File.Replace('_', ' '))
    ForEach ($String in $Replace) {$Title = $Title.Replace($String[0], $String[1])}

    $Mods[$File] = [Hashtable]@{
        Name       = $File
        Title      = $Title
        FileName   = "$($File).scs"
        Version    = $Ver.ToString()
        VersionStr = $Ver.ToString()
        Index      = 0
        Active     = 1
        Hash       = $Hash
    }
}

Write-Host ''

Try {
    Write-Host -NoNewline 'Writing ''versions.json''...'.PadRight($Longest)

    [IO.File]::WriteAllLines('versions.json', ($Mods | ConvertTo-JSON -Compress), $UTF8NoBOM)

    If (Get-Content 'versions.json' -Delimiter "`0" | Select-String "[^`r]`n") {
        $Content = Get-Content 'versions.json'
        $Content | Set-Content 'versions.json'
    }

    Write-Host -ForegroundColor Green 'OK'
}
Catch {
    Write-Host -ForegroundColor Red 'Error'
    Write-Host $_.Exception.Message
}

Try {
    Write-Host -NoNewline 'Writing ''versions.txt''...'.PadRight($Longest)
    [IO.File]::WriteAllLines('versions.txt', ($Entries -Join "`n"), $UTF8NoBOM)
    If (Get-Content 'versions.txt' -Delimiter "`0" | Select-String "[^`r]`n") {
        $Content = Get-Content 'versions.txt'
        $Content | Set-Content 'versions.txt'
    }
    Write-Host -ForegroundColor Green 'OK'
}
Catch {
    Write-Host -ForegroundColor Red 'Error'
    Write-Host $_.Exception.Message
}
Write-Host -ForegroundColor Green "`nDone"
[Void](Read-Host)
