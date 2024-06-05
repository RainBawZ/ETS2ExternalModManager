Set-Location $PSScriptRoot
[IO.Directory]::SetCurrentDirectory($PSScriptRoot)

Try {
    Write-Host -NoNewline 'Writing ''load_orders.json''...'.PadRight($Longest)

    [String[]]$LoadOrders = (Get-ChildItem *.cfg -File).BaseName

    $LoadOrders | ConvertTo-JSON -Compress | Set-Content load_orders.json -NoNewline

    Write-Host -ForegroundColor Green 'OK'
}
Catch {
    Write-Host -ForegroundColor Red 'Error'
    Write-Host $_.Exception.Message
}

Write-Host -ForegroundColor Green "`nDone"

[Void](Read-Host)
