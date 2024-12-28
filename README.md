# IP Spoofer

Send packets with spoofed source/destination MAC/IP addresses.

This tool was made using Npcap, raw sockets (packet crafting/forging), C++ 26 and Visual Studio 2022 Compiler (in Jetbrains' IDE, CLion) on Windows 11.

To use this for yourself you'll need to edit the source/destination mac/ip variables and build the exe file yourself.

You'll also need to get your adapter name, which can be easily done using PowerShell and WMIC:<br>
```wmic nic get AdapterType,Name,Installed,Netenabled,GUID```

**This project is under GPL-3.0 license.**<br>
*If you appear to be using this code, please credit me.*

## Demo

### UDP

Spoofing configuration:<br>
![image](https://github.com/user-attachments/assets/a4ff046a-de96-4fa6-9475-eae3289ee439)<br>
Server reading:<br>
![image](https://github.com/user-attachments/assets/992f0e42-c172-4cbc-9fc5-2e1bcbc302f1)<br>
WireShark sniffing:<br>
![image](https://github.com/user-attachments/assets/16a6969d-3f57-4e23-a56a-af12997fdad6)<br>
