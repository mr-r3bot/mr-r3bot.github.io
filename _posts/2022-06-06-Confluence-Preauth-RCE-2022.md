---
layout: post
title:  "Confluence Preauth RCE 0day: A look into bypass isSafeExpression check ( CVE-2022-26134 ) "
date:   2022-06-06 16:00:00 +0700
categories: research
author: Quang Vo
tags: 0day, cve-2022-26134
description: Research analysis and develop a working exploit poc script 
---

## Introduction & Environment setup

CVE-2022-26134 is an Preauth RCE ( OGNL injection vulnerability ) in Confluence Server. As there are a lot of technical analysis and payload about the vulnerability already, while the payload works on most of confluence server versions, but it won't work in Confluence server version 7.18.0 because the dev team has added some additional check for safe expression. So in this post, I will focus on the bypass `isSafeExpression` of Confluence version 7.18.0.

For environment setup, I download Confluence server version 7.18.0 on: [https://www.atlassian.com/software/confluence/download-archives](https://www.atlassian.com/software/confluence/download-archives)

For Postgres database, I use docker to quickly spin up the postgresdb:
```text
version: '3.4'
services:
        db:
                image: postgres:latest
                environment:
                        - POSTGRES_PASSWORD=postgres
                        - POSTGRES_DB=confluence
                        - POSTGRES_USER=postgres
                ports:
                        - 5432:5432
```

## Technical Analysis

Rapid7 Team did a great job on publishing the [blog post](https://www.rapid7.com/blog/post/2022/06/02/active-exploitation-of-confluence-cve-2022-26134/) and the exploit payload, here's the payload that I copied from their blog

```java
${(#a=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec("whoami").getInputStream(),"utf-8")).(@com.opensymphony.webwork.ServletActionContext@getResponse().setHeader("X-Cmd-Response",#a))}
```

But when I try that payload on Confluence version 7.18.0, it didn't work. So I add remote debugger to add breakpoints to see what is the difference between their version and mine.


Based on security advisories from Confluence, I download the `xwork-1.0.3-atlassian-10.jar` from their website and start to diffing patches, it's easy to identify  `ActionChainResult.class`  is where our vulnerability lies at.

![image](https://user-images.githubusercontent.com/37280106/172528678-4bed14c4-bc8d-4809-99ae-1c49d86fa9c2.png)

How an attacker provided URI can cause the vulnerability is well-explained and mentioned in this [blog post](https://www.rapid7.com/blog/post/2022/06/02/active-exploitation-of-confluence-cve-2022-26134/) ( you can go to their blog if you curious about the call stack to reach to our vulnerable code ), I just want to quickly note that because of this piece of code:

```java
public static String getNamespaceFromServletPath(String servletPath) {
    servletPath = servletPath.substring(0, servletPath.lastIndexOf("/"));
    return servletPath;
}
```

Every payload that you send must end with `/` , otherwise it won't reach the vulnerable code path. I learned that from my own experience after trying to figure it out why the breakpoint won't hit when I send the payload 

Our call stack to vulnerable code so far:
```
TextParseUtil.translateVariables(this.namespace, stack);
        OgnlValueStack.findValue
```

Content of `OgnlValueStack.findValue`
![image](https://user-images.githubusercontent.com/37280106/172530117-33346b6c-7804-483a-ae1f-1dfdcc2eaee6.png)

