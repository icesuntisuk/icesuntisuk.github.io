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
