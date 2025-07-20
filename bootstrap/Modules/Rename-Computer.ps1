function Rename-ComputerSafely {
    param ($NewName)
    Rename-Computer -NewName $NewName -Force -Restart:$false
}