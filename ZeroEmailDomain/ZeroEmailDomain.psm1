$functionFolders = @('Private', 'Public')

foreach ($folder in $functionFolders) {
    $folderPath = Join-Path -Path $PSScriptRoot -ChildPath $folder
    if (-not (Test-Path -Path $folderPath -PathType Container)) {
        continue
    }

    Get-ChildItem -Path $folderPath -Filter '*.ps1' -File |
        Sort-Object -Property FullName |
        ForEach-Object {
            . $_.FullName
        }
}

Export-ModuleMember -Function 'Protect-ZeroEmailDomain'
