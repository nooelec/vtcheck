#!/usr/bin/python
# vtalert by nooelec.
# alerts if any files are detected by AV.
# bitcoins: 1FYtTETvCHffo2KY4NpiT2bvPrVGhe4DKT
# github: github.com/nooelec/vtcheck
import requests
import hashlib
import signal
import json
import time
import sys
import os

debug = False
vt_api_key = "" # your key goes here

def signal_handler(signal, frame):
    print "\n[!] CTRL+C Detected, quitting!"
    sys.exit(0)

def check_samples(directory):
    samples = []
    for root, dirs, files in os.walk(directory, topdown=False):
        for name in files:
            samples.append(os.path.join(root, name))
    if len(samples) > 0:
        print "[+] Got %d samples to check..." %(len(samples))
    else:
        print "[-] No samples in those directories. Quitting!"
        sys.exit(0)
    for sample in samples:
        check_sample(sample)
        time.sleep(15) # get around rate limiting.

def check_sample(sample):
    hash = get_hash(sample)
    if debug:
        print "[*] Checking sample at %s with SHA1: %s" %(sample, hash)
    try:
        params = {'apikey': vt_api_key, 'resource': hash}
        headers = {"Accept-Encoding": "gzip, deflate"}
        r = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
    except Exception, e:
        if debug:
            print "[*] Backtrace: %s" %(str(e))
        return False
    if r.headers['Content-Length'] > 0:
        try:
            data = json.loads(r.text)
            if data['positives'] > 0:
                print "[*] Sample: %s - Detections: %d/%d" %(sample, data['positives'], data['total'])
            elif data['positives'] == 0:
                if debug:
                    print "[*] Sample: %s is NOT detected by any AV on VT!" %(sample)
        except Exception, e:
            if debug:
                print "[*] Backtrace: %s" %(str(e))
            pass

def get_hash(sample):
    sha1 = hashlib.sha1()
    with open(sample, "rb") as f:
        while True:
            data = f.read(1) # I can't remember why I picked 1 byte. oh, yeah, buffering fuckups
            if not data:
                break
            sha1.update(data)
        return sha1.hexdigest()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("To use: python vtalert.py /home/user/malware_samples/")
        sys.exit(0)
    print "[+] Running. This may take some time."
    signal.signal(signal.SIGINT, signal_handler)
    check_samples(directory=sys.argv[1])
