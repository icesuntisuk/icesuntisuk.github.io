### **Forensic**

## File forensic Tools
- **[AperiSolve.com](https://www.aperisolve.com/)**

- [File Signature or Magic number](https://www.garykessler.net/library/file_sigs.html)
- [Hex Editor for Windows](https://mh-nexus.de/en/hxd/)
- Check File type by command file
```bash
file test.wav
### check file 
string test.wav
### Used String with Grep
string test.wav | grep "flag{"
```
- Exiftool - Read and write meta information in files.
```bash
exiftool test.jpg
```

- Check files in file by binwalk 
```bash
binwalk file.zip
```

- Extract files in file by foremost
```bash
foremost file.zip
cd ./output
ls -la 
```
- [Audio Steganographic Decoder](https://futureboy.us/stegano/decinput.html)
- [PNG resize](https://entropymine.com/jason/tweakpng/)
- Zip-File bruteforce password
```bash
fcrackzip -v -u -D -p /usr/share/wordlist/rockyou.txt ./file.zip
```
- PDFcrack is tool for recovering passwords and content from PDF.
```bash
pdfcrack test.pdf -w /usr/share/wordlist/rockyou.txt
```

- [Check Geo location on Image](https://tool.geoimgr.com/)

---
## Disk Forensic Tools
- FTK Imager: data preview and imageing tool, such as: E01, DD, mem, etc. 
- Autopsy (อ่านว่า อา-ท็อป-ซี่) is opensource for analyze major file systems (NTFS, FAT, HFS+, Etx DD, E01)
---
## Memory Forensic 
- Volatility version 2 and 3 

```bash
# Step 1 check image profile 
.\vol.exe -f .\imagefile imageinfo

# Step 2 Use profile for command that you want 
.\vol.exe -f .\imagefile profile=WinXPSP2x86 iehistory

# Step 3 If you want to dump you can use process ID, for example is 2019 
.\vol.exe -f .\imagefile --profile=Win7SP0x64 memdump -p 2019 -D dump/
# หรือ 
 .\vol.exe -f .\imagefile memdump -p 2696 -D .

###########################################################################
        Supported Plugin Commands:
                amcache         Print AmCache information
                apihooks        Detect API hooks in process and kernel memory
                atoms           Print session and window station atom tables
                atomscan        Pool scanner for atom tables
                auditpol        Prints out the Audit Policies from HKLM\SECURITY\Policy\PolAdtEv
                bigpools        Dump the big page pools using BigPagePoolScanner
                bioskbd         Reads the keyboard buffer from Real Mode memory
                cachedump       Dumps cached domain hashes from memory
                callbacks       Print system-wide notification routines
                clipboard       Extract the contents of the windows clipboard
                cmdline         Display process command-line arguments
                cmdscan         Extract command history by scanning for _COMMAND_HISTORY
                connections     Print list of open connections [Windows XP and 2003 Only]
                connscan        Pool scanner for tcp connections
                consoles        Extract command history by scanning for _CONSOLE_INFORMATION
                crashinfo       Dump crash-dump information
                deskscan        Poolscaner for tagDESKTOP (desktops)
                devicetree      Show device tree
                dlldump         Dump DLLs from a process address space
                dlllist         Print list of loaded dlls for each process
                driverirp       Driver IRP hook detection
                drivermodule    Associate driver objects to kernel modules
                driverscan      Pool scanner for driver objects
                dumpcerts       Dump RSA private and public SSL keys
                dumpfiles       Extract memory mapped and cached files
                dumpregistry    Dumps registry files out to disk
                editbox         Displays information about Edit controls. (Listbox experimental.)
                envars          Display process environment variables
                eventhooks      Print details on windows event hooks
                evtlogs         Extract Windows Event Logs (XP/2003 only)
                filescan        Pool scanner for file objects
                gahti           Dump the USER handle type information
                gditimers       Print installed GDI timers and callbacks
                gdt             Display Global Descriptor Table
                getservicesids  Get the names of services in the Registry and return Calculated SID
                getsids         Print the SIDs owning each process
                handles         Print list of open handles for each process
                hashdump        Dumps passwords hashes (LM/NTLM) from memory
                hibinfo         Dump hibernation file information
                hivedump        Prints out a hive
                hivelist        Print list of registry hives.
                hivescan        Pool scanner for registry hives
                hpakextract     Extract physical memory from an HPAK file
                hpakinfo        Info on an HPAK file
                idt             Display Interrupt Descriptor Table
                iehistory       Reconstruct Internet Explorer cache / history
                imagecopy       Copies a physical address space out as a raw DD image
                imageinfo       Identify information for the image
                impscan         Scan for calls to imported functions
                joblinks        Print process job link information
                kdbgscan        Search for and dump potential KDBG values
                kpcrscan        Search for and dump potential KPCR values
                ldrmodules      Detect unlinked DLLs
                lsadump         Dump (decrypted) LSA secrets from the registry
                machoinfo       Dump Mach-O file format information
                malfind         Find hidden and injected code
                mbrparser       Scans for and parses potential Master Boot Records (MBRs)
                memdump         Dump the addressable memory for a process
                memmap          Print the memory map
                messagehooks    List desktop and thread window message hooks
                mftparser       Scans for and parses potential MFT entries
                moddump         Dump a kernel driver to an executable file sample
                modscan         Pool scanner for kernel modules
                modules         Print list of loaded modules
                multiscan       Scan for various objects at once
                mutantscan      Pool scanner for mutex objects
                notepad         List currently displayed notepad text
                objtypescan     Scan for Windows object type objects
                patcher         Patches memory based on page scans
                poolpeek        Configurable pool scanner plugin
                printkey        Print a registry key, and its subkeys and values
                privs           Display process privileges
                procdump        Dump a process to an executable file sample
                pslist          Print all running processes by following the EPROCESS lists
                psscan          Pool scanner for process objects
                pstree          Print process list as a tree
                psxview         Find hidden processes with various process listings
                qemuinfo        Dump Qemu information
                raw2dmp         Converts a physical memory sample to a windbg crash dump
                screenshot      Save a pseudo-screenshot based on GDI windows
                servicediff     List Windows services (ala Plugx)
                sessions        List details on _MM_SESSION_SPACE (user logon sessions)
                shellbags       Prints ShellBags info
                shimcache       Parses the Application Compatibility Shim Cache registry key
                shutdowntime    Print ShutdownTime of machine from registry
                sockets         Print list of open sockets
                sockscan        Pool scanner for tcp socket objects
                ssdt            Display SSDT entries
                strings         Match physical offsets to virtual addresses (may take a while, VERY verbose)
                svcscan         Scan for Windows services
                symlinkscan     Pool scanner for symlink objects
                thrdscan        Pool scanner for thread objects
                threads         Investigate _ETHREAD and _KTHREADs
                timeliner       Creates a timeline from various artifacts in memory
                timers          Print kernel timers and associated module DPCs
                truecryptmaster Recover TrueCrypt 7.1a Master Keys
                truecryptpassphrase     TrueCrypt Cached Passphrase Finder
                truecryptsummary        TrueCrypt Summary
                unloadedmodules Print list of unloaded modules
                userassist      Print userassist registry keys and information
                userhandles     Dump the USER handle tables
                vaddump         Dumps out the vad sections to a file
                vadinfo         Dump the VAD info
                vadtree         Walk the VAD tree and display in tree format
                vadwalk         Walk the VAD tree
                vboxinfo        Dump virtualbox information
                verinfo         Prints out the version information from PE images
                vmwareinfo      Dump VMware VMSS/VMSN information
                volshell        Shell in the memory image
                windows         Print Desktop Windows (verbose details)
                wintree         Print Z-Order Desktop Windows Tree
                wndscan         Pool scanner for window stations
                yarascan        Scan process or kernel memory with Yara signatures
###########################################################################
```

### การสร้าง Manual Profile  กรณี Version 2 
- ต้องเป็น Kernel Profile เดียวกันถึงจะสามารถอ่าน Mem ได้ 
- Lime memdump ใช้สำหรับ Dump Memory บน Linux [Linux Memory Extractor](https://github.com/504ensicsLabs/LiME)



```bash
# Step 1: ให้สังเกต EMiL มาจาก Lime แสดงว่ามาจาก Linux 
┌──(kali㉿kali)-[~/Desktop]
└─$ strings rpcactf_dump.mem | head
EMiL <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< อยู่ตรงนี้
PAMS
PAMS
4{,%$l
ZRr=
######

# Step 2: เราสามารถตรวจสอบ Linux Version ได้โดยใช้คำสั่ง ให้สังเกต OS ว่าใช้อะไร  
strings rpcactf_dump.mem | grep "Linux version"
---
Linux version 5.15.0-75-generic (buildd@lcy02-amd64-101) (gcc (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0, GNU ld (GNU Binutils for Ubuntu) 2.34) #82~20.04.1-Ubuntu SMP Wed Jun 7 19:37:37 UTC 2023 (Ubuntu 5.15.0-75.82~20.04.1-generic 5.15.99)
---

# Step 3: กรณีหาเจอแล้วเราสามารถใช้ https://github.com/volatilityfoundation/profiles เพื่อดู Version Profile ที่ตรงกัน 

# Step 4: เราสามารถ Dongrade Version ของ Kernel ได้โดยโหลด 2 ส่วนคือ Kernel และ Header 
sudo apt install linux-image-5.15.0-75-generic linux-headers-5.15.0-75-generic

# Step 5: ตรวจสอบบน /boot จะเห็น system.map-5.15.0
ls /boot/ 

# Step 6: Reboot
init 0

# Step 7: โดยให้เข้าไปยัง Boot Manager โดยการกด Del 

# Step 8:  จากนั้นเลือก Version Kernel 5.15.0-75 เพื่อให้ Boot ด้วย Kernel ตามที่เราต้องการ Downgrade 

# Step 9: ตรวจสอบ Kernel ปัจจุบัน
uname -a 

```
การสร้าง profile ใน Vol2 
```bash
# Step 1: ใช้ Tools สำหรับสร้าง Profiles 
cd ./volatility/tools/linux/

make 
####################################################
# กรณี ERROR
nano module.c
# เพิ่ม บรรทัดล่างสุด 
MODULE_LICENSE("GPL");
# save
####################################################
# หรือใช้คำสั่ง ECHO
echo 'MODULE_LICENSE("GPL");' >> module.c
####################################################

# Make ใหม่อีกครั้ง
make  
####################################################


# Step 2: โปรไฟล์ของ Vol 2 จะเป็นไฟล์นามสกลุ .zip โดยเราสามารถสร้างโปรไฟล์ ด้วยคำสั่งดังนี้ 
sudo zip Ubuntu_20.04-Linux5.15.zip module.dwarf /boot/System.map-5.15.0-75-generic 
```