Set-Location $PSScriptRoot
[IO.Directory]::SetCurrentDirectory($PSScriptRoot)

[String]$Dir = (Get-Content information.json | ConvertFrom-JSON).OrderRoot -Replace '/', '\'
[String]$JSON = (Get-Content information.json | ConvertFrom-JSON).Orders -Replace '/', '\'


Try {
    Write-Host -NoNewline 'Writing ''load_orders.json''...'.PadRight($Longest)

    [String[]]$LoadOrders = (Get-ChildItem "$($Dir)*.cfg" -File).BaseName

    $LoadOrders | ConvertTo-JSON -Compress | Set-Content "$($Dir)$JSON" -NoNewline

    Write-Host -ForegroundColor Green 'OK'
}
Catch {
    Write-Host -ForegroundColor Red 'Error'
    Write-Host $_.Exception.Message
}

Write-Host -ForegroundColor Green "`nDone"

[Void](Read-Host)
