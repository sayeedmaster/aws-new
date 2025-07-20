function Join-DomainSafely {
    param ($Domain, $OU)
    $SecurePassword = Get-SSMParameterValue -Name "domain-join-password" -WithDecryption $true
    $Username = "DOMAIN\\joinuser"
    $Credential = New-Object System.Management.Automation.PSCredential($Username, $SecurePassword)
    Add-Computer -DomainName $Domain -OUPath $OU -Credential $Credential -Force
}