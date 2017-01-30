# vtcheck
Check if any files in a directory are flagged on VirusTotal.  

## TL;DR  
Sometimes you want to check if files are flagged on VirusTotal without uploading the files. For example, if you want to see if your malware has been uploaded by someone else and don't want to be a complete fucking retard and get it flagged yourself.

## Howto
1. Install Requests.  
```
pip install requests
```
2. Get a VirusTotal API Key at [VirusTotal](https://www.virustotal.com/) by signing up.  
3. Run the script, pointing at a directory of files that you want to check for AV detections.

## Ejemplo
```
$ python vtalert.py ../linux.mirai/dlr/
[+] Running. This may take some time.
[+] Got 11 samples to check...
[*] Sample: ../linux.mirai/dlr/release/dlr.mips - Detections: 21/53
[*] Sample: ../linux.mirai/dlr/release/dlr.arm7 - Detections: 28/53
[*] Sample: ../linux.mirai/dlr/release/dlr.mpsl - Detections: 23/53
[*] Sample: ../linux.mirai/dlr/release/dlr.sh4 - Detections: 20/55
[*] Sample: ../linux.mirai/dlr/release/dlr.ppc - Detections: 21/53
^C
[!] CTRL+C Detected, quitting!
$ 
```

## Bitcoin?
You can support my work with Bitcoin: [1FYtTETvCHffo2KY4NpiT2bvPrVGhe4DKT](bitcoin:1FYtTETvCHffo2KY4NpiT2bvPrVGhe4DKT)
