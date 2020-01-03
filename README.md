# hack the box

## crouton bc masochism


To complete hackthebox challenges, I repurposed an old Asus Chromebook to boot into `kali-linux` using [Crouton](https://github.com/dnschneid/crouton).

This proved tricky given my Asus (C100) is built on an `armv7l` architectrue, but I thought it would be fun to figure out how to make it work, and believe it or not it runs faster than doing it in a VM in `VirtualBox`.

#### getting around the firewall

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

#### configuring the vpn

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

---

### challenges

Writeups for the various completed challenges and scripts for them are in the dedicated directories in this repository. I'm going to omit the actual flags found in the `.txt` files so as not to spoil the game for anyone else.

