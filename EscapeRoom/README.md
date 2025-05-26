# EscapeRoom Lab

### Scenario

You as a SOC analyst belong to a company specializing in hosting web applications through KVM-based Virtual Machines. Over the weekend, one VM went down, and the site administrators fear this might be the result of malicious activity. They extracted a few logs from the environment in hopes that you might be able to determine what happened.

This challenge is a combination of several entry to intermediate-level tasks of increasing difficulty focusing on authentication, information hiding, and cryptography. Participants will benefit from entry-level knowledge in these fields, as well as knowledge of general Linux operations, kernel modules, a scripting language, and reverse engineering. Not everything may be as it seems. Innocuous files may turn out to be malicious so take precautions when dealing with any files from this challenge.

### Tool

- Wireshark

- John the Ripper

- IDA Pro

### Solution

#### Question 1: What service did the attacker use to gain access to the system?

The first thing you see when you open Wireshark is a lot of SSH packets.

![image](./assets/1.png)

When we check Protocol Hierarchy, we see that 17.8% is SSH

![image](./assets/2.png)

#### Question 2: What attack type was used to gain access to the system?(one word)

First of all, I filtered `ssh` to see what happended. Each connection attempt begins with protocol identification, followed by Key Exchange Init messages, then progresses through the Diffie-Hellman Group Exchange process. We see that there are many blocks like that repeatedly, so that mean the attacker try many-many time to connect to the server. That calls `bruteforce` attack

![image](./assets/3.png)

#### Question 3: What was the tool the attacker possibly used to perform this attack?

I search on Google to get the answer. I tried some answer to get the correct answer

![image](./assets/4.png)

#### Question 4: How many failed attempts were there?

As previous solution for question 2, we know that each connection attempt has same process which identify the connection (Such as: Diffie-Hellman Group Exchange `Request -> Group -> Init -> ...`). So I rely on it to count the connection attempt.

![image](./assets/5.png)

![image](./assets/6.png)

There are 53 packets, so there are 52 fail attempts and 1 success

#### Question 5: What credentials (username:password) were used to gain access? Refer to shadow.log and sudoers.log

We see that `shadow.log` contain the hash information of account users. I used `John the Ripper` tool to crack the password by using wordlist `rockyou.txt`.

![image](./assets/7.png)

![image](./assets/8.png)

I wait 10 min, it's still 3 cracked password so let's start. The tool cracked 3 account and I tried all of these. The attacker gain access by `manager` account

#### Question 6: What other credentials (username:password) could have been used to gain access also have SUDO privileges? Refer to shadow.log and sudoers.log.

I checked the `sudoers.log`, cracked password account `sean` is the member of the admin group may gain root privileges.

![image](./assets/9.png)

#### Question 7: What is the tool used to download malicious files on the system?

The attacker download the file so, I will filter `HTTP` packet. We can find the answer in `User-Agent` of first `HTTP` packet.

![image](./assets/10.png)

#### Question 8: How many files the attacker download to perform malware installation?

Continue follow the `HTTP` packet, we see that there are 3: 2 ELF files and 1 bash

![image](./assets/11.png)

![image](./assets/12.png)

![image](./assets/13.png)

#### Question 9: What is the main malware MD5 hash?

There are 2 ELF file, let's upload it to Virustotal.

![image](./assets/14.png)

![image](./assets/15.png)

We see that, `.\2` is a rootkit - The type of malware designed to provide privileged access to a computer. Rootkits typically modify the OS's core functionality to conceal malicious activities and maintain persistence, in this case is maybe `.\1`

![image](./assets/16.png)

#### Question 10: What file has the script modified so the malware will start upon reboot?

We read bash script `.\3` to know the answer.

![image](./assets/17.png)

#### Question 11: Where did the malware keep local files?

We see that attacker rename `1` to `mail` and put it on `/var/mail/`

![image](./assets/18.png)

#### Question 12: What is missing from ps.log?

We know that the attacker configured malware to run when computer startup, but in `ps.log` is not have any process of it (`/var/mail/mail`). Maybe the rootkit `.\2` make it dissapear. 

![image](./assets/19.png)

#### Question 13: What is the main file that used to remove this information from ps.log?

As the previous question solution, the rootkit `.\2` maybe do sth do make the `/var/mail/mail` dissapear on `ps.log`. In the bash script we confirmed it. The attacker rename it to `sysmod.ko`

![image](./assets/20.png)

#### Question 14: Inside the Main function, what is the function that causes requests to those servers?

Well, malware analyst time. I use IDA Pro to do it. But first DetectItEasy detect the file has a packer `UPX` so I will use `upx -d ./1` to unpack it

![image](./assets/21.png)

![image](./assets/22.png)

Load it into IDA Pro, we see a function name ``. The name says it all, function to make request to server

![image](./assets/23.png)

![image](./assets/24.png)

#### Question 15: One of the IP's the malware contacted starts with 17. Provide the full IP

We can check it on Wireshark: `Statistics > Endpoints`

![image](./assets/25.png)

#### Question 16: How many files the malware requested from external servers?

In addition to the 3 files the attacker downloaded earlier, the following are the file which are requested

![image](./assets/26.png)

#### Question 17: What are the commands that the malware was receiving from attacker servers? Format: comma-separated in alphabetical order

We continue analyst the malware `./1`. In the `decryptMessage()` function, we see that there are 2 suspicious `if` condition. We change comparative value to character, we will see the answer.

![image](./assets/27.png)

![image](./assets/28.png)

I think

- The `NOP` (No Operation): instructs the malware to remain dormant, perhaps as a keep-alive signal or to avoid detection

- The `RUN`: maybe instructs the malware to load/execute payload to do malicious action

That's all


### Final Answer

| Question | Answer |
|---|----|
| Question 1 | `SSH` | 
| Question 2 | `bruteforce` | 
| Question 3 | `Hydra` |
| Question 4 | `52` |
| Question 5 | `manager:forgot`|
| Question 6 | `sean:spectre` |
| Question 7 | `wget` |
| Question 8 | `3` |
| Question 9 | `772b620736b760c1d736b1e6ba2f885b` |
| Question 10 | `/etc/rc.local` |
| Question 11 | `/var/mail/` |
| Question 12 | `/var/mail/mail` |
| Question 13 | `sysmod.ko` |
| Question 14 | `requestFile` |
| Question 15 | `174.129.57.253` |
| Question 16 | `9` |
| Question 17 | `NOP,RUN` |