# Hack The Box

## Crouton

To complete hackthebox challenges, I repurposed an old Asus Chromebook to boot into `kali-linux` using [Crouton](https://github.com/dnschneid/crouton).

This proved tricky given my Asus (C100) is built on an `armv7l` architectrue, but I thought it would be fun to figure out how to make it work, and believe it or not it runs faster than doing it in a VM in `VirtualBox`.

#### Getting Around the Firewall

`ChromeOS` has some particular firewall rules that need to be worked around. In order to use the Hack the Box `openvpn` and execute any sort of reverse shell exploit, it's necessary to modify the `iptables` config on the machine. While you could set it to accept all incoming traffic, I just specified a single port (i.e. if you're running some sort of msf command, this would be the `LPORT` value):

As `root` in the `ChromeOS` `chronos` shell:

```
sudo iptables -I INPUT -p tcp --dport [port] -j ACCEPT
```

If you want to disable this, you can just remove the rule. List them via:

```
iptables -L INPUT --line-numbers
```

Which would look something like...

```
Chain INPUT (policy ACCEPT) 
    num  target prot opt source destination
    1    ACCEPT     udp  --  anywhere  anywhere             udp dpt:domain 
    2    ACCEPT     tcp  --  anywhere  anywhere             tcp dpt:domain 
    3    ACCEPT     udp  --  anywhere  anywhere             udp dpt:bootps 
    4    ACCEPT     tcp  --  anywhere  anywhere             tcp dpt:bootps
```

Then if the rule you want to delete is in line 2, run:

```
sudo iptables -D INPUT 2
```

#### Configuring the VPN

From `ChromeOS` in a shell as `chronos@localhost` run:

```
sudo stop shill
sudo start shill BLACKLISTED_DEVICES=tun0
```

After this, you'll need to enter `chroot`, since I'm running `kali-rolling` that's the namespace, so:

```
sudo enter-chroot -n kali-rolling
```

Once in `chroot`, make sure you're in a working directory with you `.ovpn` file, then run:

```
sudo openvpn --mktun --dev tun0
```

Then:

```
sudo openvpn --config [*.ovpn] --dev tun0
```

It's important you run the `openvpn` commands separately (as opposed to w/ `&&`), otherwise the connection will fail to establish and error out.

#### Running kali on ChromeOS

To start `kali` on my machine, I run `sudo enter-chroot -n kali-rolling -t xfce -` as `chronos@localhost` in a `ChromeOS` shell (which you get on a Chromebook by running `Ctrl+Alt+T` then typing `shell`). The command I'm using here may not work for you depending on the distribution you've installed through `crouton`.

With that done, one of the really cool things about `crouton` is how you can seamlessly hop between the `kali` os and `chromeos` by typing `Ctrl+Alt+Shift+Left Arrow` and `Ctrl+Alt+Shift+Right Arrow` which makes it easy to toggle between your two OS environments.

If this isn't working for you, it's possible you haven't properly started `kali` (or had an issue installing it). 

*Protip*: Once I had `kali` up and running, installing `chromium` for a web browser made life much easier.

**Other Useful Tools To Install**:
- `nmap`
- `msfconsole`
- `dnsutils`
- `vim`
- `tmux`
- `john`

---

### Challenges

Writeups for the various completed challenges and scripts for them are in the dedicated directories in this repository. I'm going to omit the actual flags found in the `.txt` files as well as some other sensitive spoiler info so as not to spoil the machines for anyone else.


