# alien-moment
![gallery](https://github.com/user-attachments/assets/8f194732-5280-425a-9ae1-a1b47b3e3efa)

https://youtu.be/ZkElLljTFJU

## Disclaimer
This repository is purely for educational purposes, we are not held liable for any crimes committed or damages incurred. Please use this in a virtual environment and NEVER on any of your personal devices.
## Inspiration
Microsoft just released their final update for Windows 10 this month (KB5066791), marking the end of support for many machines around the globe. People might find themselves debating on whether or not to switch to a different operating system, wondering what the potential damage could be of running an end of life machine. Our hope was to showcase why end of life machines are dangerous, as security flaws demonstrated by this malware will remain unpatched pretty much forever.  
## What it does
Provides a persistent access vector after establishing initial access. It establishes a reverse shell on a Kali Linux machine with meterpreter, forces the victim to have a specific desktop, and creates three administrative accounts on the workstation.
## How we built it
We utilized a GitHub repository that contains all of the files used within the project. A PowerShell script contained within a .bat file and the meterpreter payload.
## Challenges we ran into
We wanted to create more features on the attacker side, including custom desktops for each new administrator account . There was also a push to make the exploit an initial access vector through steganography, however, everything we tried was not very fruitful. Whenever we would merge the script as either a .bat or .ps1 file, even changing the .ps1 to a .exe, the code itself would corrupt and we were unable to package it in a .png. That was when we decided to change our exploit to a persistent access technique.
As for our custom desktops, we had spent a large amount of time on this throughout the night to implement it. We ran into so many issues as our idea was to have profiles created to our newly created admin accounts before they were booted up for the first time. This was the main hurdle as even just getting a wallpaper was giving issues for all users. We tried setting up a scheduled task for the users on first logon and then self delete, but our efforts were killed by bugs and Windows achitectural issues.
## Accomplishments that we're proud of
  - Getting past Windows Defender without it destroying our script before it can run
  - Kali integration for a reverse shell
  - Local admin account creation for all team users on affected computer.
## What we learned
There was a big learning curve with learning about custom desktops via scripting and steganography. While these parts of the project were unattainable within the time frame of the Hackathon, the knowledge gained from them is invaluable as we will be able to utilize them in future projects. Learning how to get past Windows Defender was also a very knowledgeable journey.
## What's next for AlienMoment
___Moment
