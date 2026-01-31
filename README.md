# Genshin Impact & Honkai:StarRail の FPS Unlocker

[切换为简体中文](README_zh_cn.md)

 - **This repo mod by 34736384's unlocker.** [34736384's unlocker](https://github.com/34736384/genshin-fps-unlock)

 - This tool helps you to unlock the 60 fps limit in the game
 - This is an external program which uses **WriteProcessMemory** to write the desired fps to the game
 - **Now must be unlocked by inject**
 - Does not require a driver for R/W access
 - Supports OS and CN version
 - Should work for future updates
 - If the source needs to be updated, I'll try to do it as soon as possible
 - You can download the compiled binary over at [Release](https://github.com/winTEuser/Genshin_StarRail_fps_unlocker/releases) if you don't want to compile it yourself

 ## Compiling
 - Use Visual Studio 2022 Community Edition or Vscode with MSVC

 ## Usage
 - Run the exe and click the game you want to open. 
 - If it is your first time running, unlocker will wait game start then antomatically to set game path . 
 - Place the compiled exe anywhere you want (except for the game folder)
 - Make sure your game is closed—the unlocker will automatically start the game for you
 - Run the exe as administrator, and leave the exe running
 >It requires adminstrator because the game needs to be started by the unlocker and the game requires such permission

### Default Hotkey
- **END**                                 ON/OFF
- **Right Ctrl + Up key**        (+20)
- **Right Ctrl + Right key**    (+2)
- **Right Ctrl + Down key**   (-20)
- **Right Ctrl + Left Key**       (-2)

## Command Line
 - unlocker.exe -[game] -[game argv...]
 - eg. unlocker.exe -Genshin -screen-width 3840 -screen-height 1620 -screen-fullscreen 1
 - eg. unlocker.exe -HKSR -???
 - Unlocker args can appear anywhere after `-[game]` and will be consumed by the unlocker.
 - All other args are passed through to the game process in the original order.
 - Set FPS target: "**-fps**" [value] (decimals allowed; rounded to int)
 - eg. unlocker.exe -Genshin -fps 120
 - If you want start with mobile UI add the arg "**-EnableMobileUI**"
 - unlocker.exe -[game] -EnableMobileUI -.......
 - DLL inject 
 - unlocker.exe -[game] -LoadLib [path]

## Inject
 - Now must be unlocked by inject 
 - Change game fps set(Not work for HKSR): **(open "IsHookGameSet" in hoyofps_config.ini)** 
 - 30 -> 60(open browser in game won't cause stalling)
 - 45 -> your fps target
 - 60 -> no limit


 ## Notes
 - HoYoverse (miHoYo) is well aware of this tool, and you will not get banned for using **ONLY** fps unlock.
 - If you are using other third-party plugins, you are doing it at your own risk.
 - Any artifacts from unlocking fps (e.g. stuttering) is **NOT** a bug of the unlocker


## Thanks
- **34736384**
- **xiaonian233**


