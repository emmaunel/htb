#!/bin/bash

curl -v -i -s -k -X $'GET' \
    -H $'Host: localhost:52846' -H $'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:71.0) Gecko/20100101 Firefox/71.0' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate' -H $'Connection: close' -H $'Cookie: PHPSESSID=jimmy' -H $'Upgrade-Insecure-Requests: 1' \
    -b $'PHPSESSID=jimmy' \
    $'http://localhost:52846/main.php'