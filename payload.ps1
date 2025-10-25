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
