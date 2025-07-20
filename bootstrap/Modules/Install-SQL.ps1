function Install-SQLFromConfig {
    param ($Config)

    $bucketName = "my-bucket"
    $sqlMediaLocal = "C:\Bootstrap\Assets\SQL.iso"
    $sqlConfigLocal = "C:\Bootstrap\Assets\ConfigurationFile.ini"

    $mediaKey = $Config.SQLMediaUrl -replace "^s3://$bucketName/", ""
    $iniKey   = $Config.SQLConfigUrl -replace "^s3://$bucketName/", ""

    Read-S3Object -BucketName $bucketName -Key $mediaKey -File $sqlMediaLocal
    Read-S3Object -BucketName $bucketName -Key $iniKey -File $sqlConfigLocal

    Mount-DiskImage -ImagePath $sqlMediaLocal
    $drive = (Get-Volume -FileSystemLabel "SQL2019").DriveLetter
    Start-Process "$drive`:\setup.exe" -ArgumentList "/ConfigurationFile=$sqlConfigLocal /IAcceptSQLServerLicenseTerms /Q" -Wait
}