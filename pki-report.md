# PKI Lab — Jarrett Chen

## 1. Web Server Setup

I started by setting up a small webpage with nginx on my Mac. The page contains the marker `JARRETT-PKI-TOKEN-4b72` so I could find it in the capture. There is also a `notes.txt` file with a fake Wi-Fi password and a `/login` page that replies `login ok for jarrett`. The login uses the name in the `u` query parameter and never checks the password. All the credentials in this lab are fake.

The HTTP server ran on `127.0.0.1:8080`, and HTTPS used port 9443 because an earlier Python server was already using 8443. I connected using `localhost`, which refers to my own Mac. That also gave me a hostname to look for in the HTTPS handshake.

The capture script used curl to request the page, open the notes file, and send the fake login:

```sh
curl --ipv4 http://localhost:8080/
curl --ipv4 http://localhost:8080/notes.txt
curl --ipv4 -d 'username=jarrett&password=lab-only-fake-pass' \
  'http://localhost:8080/login?u=jarrett'
```

I ran the capture script. Since the client and server were both on my Mac, it captured the loopback interface, `lo0`, with the filter `tcp port 8080 or tcp port 9443`. The traffic was saved separately as `http.pcap` and `https.pcap`, which contain 36 and 114 packets. The packet numbers in this report refer to those two files.

## 2. Why HTTP Is Insecure

HTTP sends messages without encrypting them. In `http.pcap`, packet 5 is the request for the main page and packet 7 is the response. Following TCP stream 0 shows the request, headers, and HTML:

```http
GET / HTTP/1.1
Host: localhost:8080
User-Agent: curl/8.7.1
Accept: */*


HTTP/1.1 200 OK
Server: nginx/1.28.3
Date: Mon, 26 Oct 2026 01:40:19 GMT
Content-Type: text/html
Content-Length: 418
Last-Modified: Mon, 26 Oct 2026 00:34:56 GMT
Connection: keep-alive
ETag: "6adea030-1a2"
Accept-Ranges: bytes

<!doctype html>
<html><head><title>Jarrett's PKI Lab</title></head>
<body>
<h1>PKI Lab Test Page</h1>
<p>This page is served by nginx for my PKI assignment.</p>
<p>Test marker: JARRETT-PKI-TOKEN-4b72</p>
<form method="POST" action="/login?u=jarrett">
<input name="username" value="jarrett"><input name="password" value="lab-only-fake-pass"><button>Log in</button>
</form>
<a href="/notes.txt">notes</a>
</body></html>
```

The notes request is packet 17 and the response is packet 19. Its body contains:

```text
PKI lab notes: these are fake demonstration credentials.
Wi-Fi name: Example-Lab-Network
Wi-Fi password: fake-wifi-73ac
```

The fake login request is packet 29, and the response is packet 31. Following TCP stream 2 gives:

```http
POST /login?u=jarrett HTTP/1.1
Host: localhost:8080
User-Agent: curl/8.7.1
Accept: */*
Content-Length: 44
Content-Type: application/x-www-form-urlencoded

username=jarrett&password=lab-only-fake-pass
HTTP/1.1 200 OK
Server: nginx/1.28.3
Date: Mon, 26 Oct 2026 01:40:19 GMT
Content-Type: text/plain
Content-Length: 21
Connection: keep-alive

login ok for jarrett
```

These packets show why HTTP is insecure. Anyone who can capture the traffic can read which pages were requested and what came back. Packet 29 even shows `username=jarrett&password=lab-only-fake-pass` with no key needed, and the headers give away the curl and nginx versions.

HTTP also doesn't protect against someone changing the messages or pretending to be the server, though this lab only tested whether the contents were readable. Since I used loopback, this traffic never left my Mac.

## 3. HTTPS Upgrade

I used OpenSSL to create a 2048-bit RSA private key and a self-signed certificate:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 30 \
  -keyout work/nginx-private/localhost.key \
  -out outputs/nginx-pki/localhost.crt \
  -config work/nginx-private/san.cnf
```

The certificate's subject and issuer both say `CN=localhost` because it is self-signed. It lists `localhost` and `127.0.0.1` as the name and address it can be used for. I kept the private key outside the submission folder. nginx was configured to use the certificate and key:

```nginx
listen 127.0.0.1:8080;
listen 127.0.0.1:9443 ssl;
server_name localhost;
ssl_protocols TLSv1.2 TLSv1.3;
ssl_certificate /Users/jarrettchen/Documents/2026-10-25/can-2/outputs/nginx-pki/localhost.crt;
ssl_certificate_key /Users/jarrettchen/Documents/2026-10-25/can-2/work/nginx-private/localhost.key;
```

The first HTTPS request failed because curl didn't trust the self-signed certificate:

```text
curl: (60) SSL certificate problem: unable to get local issuer certificate
```

The script then used `--cacert` to tell curl to trust this certificate for the request, and these worked:

```sh
curl --ipv4 --cacert localhost.crt https://localhost:9443/
curl --ipv4 --cacert localhost.crt https://localhost:9443/notes.txt
curl --ipv4 --cacert localhost.crt \
  -d 'username=jarrett&password=lab-only-fake-pass' \
  'https://localhost:9443/login?u=jarrett'
```

`--cacert` only tells curl which certificate to trust for that request. It doesn't add anything to the macOS Keychain. [curl's documentation](https://curl.se/docs/sslcerts.html) helped me see that difference.

After the capture, I approved adding the certificate to my login keychain. I checked its SHA-256 fingerprint and set its SSL option to Always Trust:

```text
C5:E7:60:15:A4:4E:9F:42:0A:D3:C1:9E:7B:95:DC:23:0E:B5:E5:69:2F:2C:6E:79:5A:42:3E:EE:CD:48:4A:05
```

Keychain then showed it as trusted for my account, and Chrome loaded `https://localhost:9443/` without a certificate warning. This happened after the capture, which is why the saved file includes the failed attempt and the successful `--cacert` requests.

A public CA won't issue a publicly trusted certificate for `localhost`, because it points to everyone's own computer instead of a name with one owner. A local server could still use a certificate for a real domain if its owner proves control of that domain. Let's Encrypt's localhost explanation (https://letsencrypt.org/docs/certificates-for-localhost/) helped me understand this.

## 4. HTTP vs. HTTPS Comparison

The script requested the same page, notes file, and fake login over HTTP and HTTPS. The main difference is whether the contents can be read in the capture.

| Resource | Readable HTTP evidence | HTTPS evidence without session keys |
|---|---|---|
| Index page | GET packet 5; response packet 7 exposes the marker and HTML. | TCP stream 1; client Application Data packet 23 and server Application Data packet 30. |
| Notes | GET packet 17; response packet 19 exposes the fake Wi-Fi password. | TCP stream 2; client Application Data packet 49 and server Application Data packet 56. |
| Fake login | POST packet 29 exposes the password; response packet 31. | TCP stream 3; client Application Data packet 76 and server Application Data packet 82. |

I matched the HTTPS packets to the script's requests by direction and order. Since these curl connections weren't decrypted, the table lists the likely request and response packets. The paths and page contents are hidden. Packet 30, for example, is just encrypted data:

```text
TLSv1.3 Record Layer: Application Data Protocol: Application Data
Opaque Type: Application Data (23)
Length: 673
Encrypted Application Data […]: 7cd0f4cbb5f35c6fb86bb7ac9c748b874368046163b51f8c38ce4ed38df9062a45cfdb63df88d407f3546f11f3a0e655ff94df9fbddfe27d48b75f86bbf7aa98ebecbe15e1b940ff0cb47f2ed40bb0603e82c403de11a153aa0cf9573571c83f1a78a75cae86b
```

The marker and fake password are readable in HTTP but don't appear as text anywhere in the HTTPS capture. I have to be a little careful with the Application Data label, though, since TLS 1.3 also uses it for encrypted handshake messages and alerts.

My understanding is that the certificate helps authenticate the server, while the handshake sets up secrets that protect the traffic. The certificate doesn't encrypt the pages itself; TLS uses symmetric session keys for that.

## 5. Handshake Interpretation

The first HTTP connection starts with this TCP three-way handshake:

```text
1	55915 → 8080 [SYN] Seq=0 Win=65535 Len=0 MSS=16344 WS=64 TSval=1708009716 TSecr=0 SACK_PERM
2	8080 → 55915 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=16344 WS=64 TSval=982260801 TSecr=1708009716 SACK_PERM
3	55915 → 8080 [ACK] Seq=1 Ack=1 Win=408320 Len=0 TSval=1708009716 TSecr=982260801
```

Packet 1 is the client asking to start a connection. Packet 2 is the server acknowledging that and sending its own starting sequence number. Packet 3 is the client acknowledging the server's reply. That sets up the TCP connection, but nothing is encrypted yet.

In the first successful HTTPS connection, packets 12–14 set up TCP, packet 16 is ClientHello, and packet 18 is ServerHello. These are the relevant lines from their packet details:

```text
Packet 16 (ClientHello):
    Handshake Type: Client Hello (1)
    Extension: supported_versions (len=9) TLS 1.3, TLS 1.2, TLS 1.1, TLS 1.0
    Extension: key_share (len=38) x25519
        Key Share Entry: Group: x25519, Key Exchange length: 32
    Extension: server_name (len=14) name=localhost
        Server Name: localhost

Packet 18 (ServerHello):
    Handshake Type: Server Hello (2)
    Cipher Suite: TLS_CHACHA20_POLY1305_SHA256 (0x1303)
    Extension: supported_versions (len=2) TLS 1.3
        Supported Version: TLS 1.3 (0x0304)
    Extension: key_share (len=36) x25519
        Key Share Entry: Group: x25519, Key Exchange length: 32
```

ClientHello starts the TLS negotiation. It lists the versions and cipher suites the client supports, includes its key share, and names the server it wants to reach. ServerHello gives the server's choices and its own key share. Here the server chose TLS 1.3 and `TLS_CHACHA20_POLY1305_SHA256`, with X25519 for the key exchange. The RSA key in the certificate helps prove the server's identity, and ChaCha20-Poly1305 protects the traffic.

One confusing detail is that a record can say TLS 1.2 even though the chosen version is TLS 1.3. The `supported_versions` field in ServerHello shows the version that was actually selected.

I can't point to a readable Certificate message in this connection. TLS 1.3 encrypts the handshake messages after ServerHello, including the certificate, so without decrypting the connection I can't identify it from an Application Data label alone. I read through [the TLS 1.3 specification](https://www.rfc-editor.org/rfc/rfc8446.html) to understand why.

## 6. What Still Leaks Over HTTPS

**Hostname and IP.** Packet 16 still shows `Server Name: localhost` in the SNI extension, and the destination IP, `127.0.0.1`, is visible too. HTTPS doesn't hide where a connection is going. An IP alone doesn't always point to one website, though, since many sites can share one.

**Sizes and timing.** Packet 23 is 155 bytes at 0.063802 seconds into the capture, and packet 30 is 734 bytes at 0.064052 seconds, about 0.000250 seconds later. Someone watching can still see how much data is sent, which way it goes, and how fast the server replies. These sizes include headers and overhead, not just the page, so they might help someone guess what's happening but don't show the page text.

**DNS.** A normal unencrypted DNS lookup can reveal the hostname before HTTPS even starts. Encrypted DNS hides the lookup from people on the network, though the resolver still sees the name. My capture only included the server's TCP ports and used localhost, so it has no evidence of a DNS lookup either way.

**ECH.** My understanding is that Encrypted Client Hello hides the real hostname inside ClientHello when both sides support it. It wouldn't hide IP addresses, packet sizes, timing, or separate unencrypted DNS lookups. In my capture `localhost` is still readable in packet 16, so ECH wasn't hiding anything.

## 7. Reflection & Tinkering

The certificate was the first thing that didn't work. My first HTTPS request failed with `curl: (60) SSL certificate problem: unable to get local issuer certificate`, because creating the certificate wasn't enough for curl to trust it. The script then used `--cacert localhost.crt` and the requests worked. Afterward I approved importing the certificate into my Mac's login keychain and set its SSL option to Always Trust, and Chrome loaded the page without a warning. That helped me see that creating a certificate and trusting it are separate steps.

I also hit an nginx error before the server would start: `unknown directive "return"`. I sent Codex a screenshot, and it found that the nginx build was missing the module for that directive. It rebuilt nginx with the module, and I reopened the launcher. I also got confused because starting the server didn't start the capture. My first screenshot only showed the server running, so I had to open the separate capture launcher to record any traffic.

The biggest difference I saw was how much HTTP gives away. In `http.pcap` I could read the fake login password right in packet 29, while in `https.pcap` the same login is just encrypted Application Data. I expected HTTPS to hide the hostname too, so I was surprised by what I found. Codex had said SNI could still expose the server name, and I wanted to check that myself. I opened `https.pcap` in Wireshark, filtered on `frame.number == 16`, and expanded the ClientHello's `server_name` extension. Under Server Name Indication it said `Server Name: localhost`. So for my capture, HTTPS encrypted the page contents but the hostname was still readable in the handshake.

## 8. (Extra credit) Decrypted TLS

For extra credit, the script made one more HTTPS connection using OpenSSL and saved its session secrets with `-keylogfile`:

```sh
printf 'GET /?capture=extra-credit HTTP/1.1\r\nHost: localhost:9443\r\nUser-Agent: PKI-Lab-OpenSSL\r\nConnection: close\r\n\r\n' | \
  openssl s_client -connect 127.0.0.1:9443 -servername localhost \
    -CAfile localhost.crt -verify_return_error \
    -keylogfile session.keys -quiet -ign_eof
``` 

I checked the capture against the matching key log. In TCP/TLS stream 4, Wireshark could read the GET in packet 100 and the `200 OK` response in packet 106. The recovered conversation was:

```http
GET /?capture=extra-credit HTTP/1.1
Host: localhost:9443
User-Agent: PKI-Lab-OpenSSL
Connection: close


HTTP/1.1 200 OK
Server: nginx/1.28.3
Date: Mon, 26 Oct 2026 01:40:19 GMT
Content-Type: text/html
Content-Length: 418
Last-Modified: Mon, 26 Oct 2026 00:34:56 GMT
Connection: close
ETag: "6adea030-1a2"
Accept-Ranges: bytes

<!doctype html>
<html><head><title>Jarrett's PKI Lab</title></head>
<body>
<h1>PKI Lab Test Page</h1>
<p>This page is served by nginx for my PKI assignment.</p>
<p>Test marker: JARRETT-PKI-TOKEN-4b72</p>
<form method="POST" action="/login?u=jarrett">
<input name="username" value="jarrett"><input name="password" value="lab-only-fake-pass"><button>Log in</button>
</form>
<a href="/notes.txt">notes</a>
</body></html>
```

This shows why the session secrets matter. Wireshark could read the traffic afterward only because the client saved them. Someone who captured just the packets wouldn't have the secrets and couldn't decrypt it this way. The key log only covers this OpenSSL connection, not the earlier curl requests.

## Appendix: AI usage

I ran the lab on my Mac: I started the nginx server and the capture launchers, ran the OpenSSL commands to create the certificate, sent screenshots when something broke, checked the certificate’s SHA-256 fingerprint and trusted it in Keychain, decrypted the extra-credit connection in Wireshark, and confirmed the SNI field in the capture myself. I used Codex for nginx and certificate setup, the capture scripts, troubleshooting, packet interpretation, and drafting and revising the report. I also used Claude to reword some passages.

### 1. Troubleshooting nginx

**Me:** The server launcher shows `unknown directive "return"`. What does that mean?

**Codex:** The nginx build is missing the rewrite module, which provides the `return` directive used by the fake login endpoint. Rebuild nginx with that module enabled, then reopen the launcher.

**Result:** I supplied a screenshot of the error. Codex corrected its initial build, and I relaunched the server successfully. I also initially confused starting the server with starting the capture. After opening the separate capture launcher, it saved the HTTP and HTTPS files.

### 2. HTTPS upgrade and certificate trust

**Me:** How do I create a self-signed certificate for localhost and get nginx and the client to accept it?

**Codex:** Include `localhost` and `127.0.0.1` in the certificate’s subject alternative names, then generate the key and certificate:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 30 \
  -keyout work/nginx-private/localhost.key \
  -out outputs/nginx-pki/localhost.crt \
  -config work/nginx-private/san.cnf
```

Configure nginx to use those files for HTTPS on port 9443.

Result: Codex gave me the certificate command and nginx settings, and I ran them myself.

**Problem:** The first HTTPS request failed with:

```text
curl: (60) SSL certificate problem: unable to get local issuer certificate
```

**Codex:** Creating the certificate does not automatically make it trusted. Use `--cacert localhost.crt` for the curl request. For browser access, import the certificate into macOS Keychain, check its fingerprint, and enable SSL trust.

**Result:** The scripted requests using --cacert succeeded. I approved adding the certificate to my login keychain, checked its fingerprint, and set SSL to Always Trust myself. Chrome then loaded the HTTPS page without a certificate warning.

### 3. Interpreting the captures

**Me:** How do I explain the TCP handshake and the ClientHello and ServerHello in my captures?

**Codex:** In `http.pcap`, packets 1–3 are SYN, SYN/ACK, and ACK. The client starts the connection, the server acknowledges it and sends its own starting sequence number, and the client acknowledges the server. TCP is then established, but the traffic is not encrypted.

In the first successful HTTPS connection, packet 16 is ClientHello and packet 18 is ServerHello. ClientHello offers versions, cipher suites, a key share, and the requested hostname. ServerHello selects TLS 1.3, `TLS_CHACHA20_POLY1305_SHA256`, and X25519. The RSA certificate key helps authenticate the server, while symmetric session keys protect the application traffic.

**Me:** Why can I still see localhost, but not a readable Certificate message?

**Codex:** The hostname is visible in the ClientHello’s SNI extension. TLS 1.3 encrypts the certificate and later handshake messages after ServerHello. IP addresses, packet sizes, and timing also remain visible even when the application contents are encrypted.

### 4. Verification and extra credit

**My verification:** I checked the claim that HTTPS could still expose the hostname. I opened `https.pcap`, filtered on `frame.number == 16`, and expanded ClientHello → `server_name` → Server Name Indication. I found `Server Name: localhost` and supplied a screenshot showing the field. This confirmed the claim for my capture.

**Me:** How can Wireshark decrypt my own HTTPS traffic?

**Codex:** Save the client’s session secrets before making the connection, then load the matching key log in Wireshark’s TLS settings. This lab used OpenSSL’s `-keylogfile` option.

**Result**: Codex prepared the OpenSSL command. I loaded the saved secrets into Wireshark myself and recovered the GET in packet 100 and the HTTP 200 response in packet 106. The plaintext is in section 8.