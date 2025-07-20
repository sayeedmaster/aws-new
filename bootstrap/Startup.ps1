if (Test-Path "C:\Bootstrap\RunSQL.flag") {
    Remove-Item "C:\Bootstrap\RunSQL.flag"
    $config = Get-Content "C:\Bootstrap\Config.json" | ConvertFrom-Json

    if ($config.SQLInstall) {
        . "C:\Bootstrap\Modules\Install-SQL.ps1"
        Install-SQLFromConfig -Config $config
    }
}