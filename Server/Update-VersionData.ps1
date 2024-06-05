<# GET VERSION FROM SCS MANIFEST
Param ([String]$Archive)
Write-Information $PID
Try {
 Add-Type -Assembly System.IO.Compression.FileSystem
 $ErrorActionPreference                    = "Stop"
 [IO.Compression.ZipArchive]$SCSArchive    = [IO.Compression.ZipFile]::OpenRead($Archive)
 [IO.Compression.ZipArchiveEntry]$Manifest = $SCSArchive.Entries | Where-Object {$_.FullName -eq 'manifest.sii'}
 If (!$Manifest) {Throw}
 [IO.Compression.DeflateStream]$Stream = $Manifest.Open()
 [Char[]]$Data  = @()
 [Bool]$HasData = $True
 While ($HasData) {
  Switch ($Stream.ReadByte()) {
   -1      {$HasData = $False; Break}
   Default {$Data += [Char]$_}
  }
 }
 [String]$SCSFileVersion = [Regex]::Match(($Data -Join ''), '(?<=package_version: ?"v?)\d+(\.\d+)+(?=")').Value
 If ([Version]::TryParse($SCSFileVersion, [Ref]$Null)) {Write-Output $SCSFileVersion} Else {Throw}
} Catch {Write-Output 'N/A'}
Finally {
 Try {$Stream.Close()}       Catch {}
 Try {$Stream.Dispose()}     Catch {}
 Try {$SCSArchive.Dispose()} Catch {}
}
#>

Set-Location $PSScriptRoot
[IO.Directory]::SetCurrentDirectory($PSScriptRoot)

[Globalization.TextInfo]$TextInfo = (Get-Culture).TextInfo

[String]$GetSCSFileVersion = (Get-Content Update-VersionData.ps1)[1..25] -Join "`n"

[Collections.Generic.List[String[]]]$Replace = @(
    @('Ai ', 'AI '),
    @('Bdf ', 'BDF '),
    @(' Rtd', ' RTD'),
    @(' Def', ' Def.'),
    @(' Vip', ' VIP'),
    @(' Dlc', ' DLC'),
    @(' Hs', ' HS'),
    @(' Xf', ' XF'),
    @(' Ng', ' NG'),
    @('Rjl ', 'RJL ')
)

[String[]]$Files = (Get-ChildItem *.scs -File).Name

If ([IO.File]::Exists('versions.json')) {
    [PSObject]$vData      = Get-Content versions.json -Raw -Encoding UTF8 | ConvertFrom-JSON
    [String[]]$vDataFiles = ($vData.PSObject.Properties.Name | Foreach-object {$vData.$_}).FileName
    [String[]]$AllFiles   = $Files + $vDataFiles | Select-Object -Unique | Sort-Object
}
Else {[String[]]$AllFiles = $Files}

[Byte]$Longest = ($AllFiles | Sort-Object Length)[-1].Length + 15

[Collections.Specialized.OrderedDictionary]$Mods = @{}

[Bool]$HasChanged = $False

ForEach ($File in $AllFiles) {

    Write-Host -NoNewline "Checking '$File'".PadRight($Longest)

    If (![IO.File]::Exists($File)) {
        $HasChanged = $True
        Write-Host -ForegroundColor Red 'Deleted: A corresponding file could not be found'
        Continue
    }

    [IO.FileInfo]$CurrentFile = Get-ChildItem $File -File

    [String]$Name = $CurrentFile.BaseName
    [UInt64]$Size = $CurrentFile.Length

    $SCSVerJob = Start-Job ([ScriptBlock]::create($GetSCSFileVersion)) -ArgumentList $CurrentFile.FullName
    $HashJob   = Start-Job ([ScriptBlock]::Create('Param ([String]$File) Write-Output (Get-FileHash -Algorithm SHA1 $File).Hash')) -ArgumentList $CurrentFile.FullName

    [String]$NewHash = Wait-Job $HashJob | Receive-Job

    [Int]$SCSVerJobPID = ($SCSVerJob | Get-Job).ChildJobs.Information.MessageData

    If ($vData.$Name) {
        [PSObject]$Data = $vData.$Name
        [String]$Ver    = $Data.Version
        [String]$Hash   = $Data.Hash
    }
    Else {[String]$Ver, [String]$Hash = 'N/A', ''}

    If ($Hash -ne $NewHash) {
        $SCSVerJob = Wait-Job $SCSVerJob -Timeout 3
        If ($SCSVerJob.State -ne 'Completed') {
            Stop-Process -Id $SCSVerJobPID -Force -ErrorAction SilentlyContinue
            [Void]($SCSVerJob | Remove-Job -Force -ErrorAction SilentlyContinue)
            [String]$NewVer = 'N/A'
        }
        Else {[String]$NewVer = $SCSVerJob | Receive-Job}

        $Hash = $NewHash

        Write-Host -ForegroundColor DarkCyan 'Hash mismatch'
        [Bool]$ForceVer = $Ver -eq 'N/A'

        Do {

            [String]$NewVersion = ''
            $NewVersion         = Read-Host "   Version? ($Ver - int: $NewVer)"

            If ($NewVersion -eq 'int' -And $NewVer -ne 'N/A') {$NewVersion = $NewVer}

        } Until ([Version]::TryParse($NewVersion, [Ref]$Null) -Or ($NewVersion -eq '' -And !$ForceVer))

        If ($NewVersion -ne '') {
            [String]$OldVer = $Ver
            [String]$Ver    = $NewVersion

            Write-Host -ForegroundColor Green "   $OldVer -> $Ver"
        }
        Else {Write-Host -ForegroundColor Green '   Updated hash'}
        $HasChanged = $True
    }
    Else {
        Stop-Process -Id $SCSVerJobPID -Force -ErrorAction SilentlyContinue
        [Void]($SCSVerJob | Remove-Job -Force -ErrorAction SilentlyContinue)
        Write-Host -ForegroundColor Green "OK - $Ver"
    }

    [String]$Title = $TextInfo.ToTitleCase($Name.Replace('_', ' '))

    ForEach ($String in $Replace) {$Title = $Title.Replace($String[0], $String[1])}

    $Mods[$Name] = [Hashtable]@{
        Name       = $Name
        Title      = $Title
        FileName   = $File
        Version    = $Ver
        VersionStr = $Ver
        Hash       = $Hash
        Size       = $Size
    }
}

Write-Host ''

If (!$HasChanged) {Exit}

Try {
    Write-Host -NoNewline 'Writing ''versions.json''...'.PadRight($Longest)

    $Mods | ConvertTo-JSON -Compress | Set-Content versions.json -NoNewline

    Write-Host -ForegroundColor Green 'OK'
}
Catch {
    Write-Host -ForegroundColor Red 'Error'
    Write-Host $_.Exception.Message
}

Write-Host -ForegroundColor Green "`nDone"

[Void](Read-Host)
Exit
