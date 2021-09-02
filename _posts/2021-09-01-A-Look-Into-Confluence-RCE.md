---
layout: post
title:  "A look into CVE-2021-26084 Confluence RCE "
date:   2021-09-01 16:00:00 +0700
categories: research
author: Quang Vo
toc: true
description: Research analysis and develop a working exploit poc script 
---

## OGNL Injection on Confluence

- Twitter is always the best place to keep up-to-date with the newest CVE or exploit. CVE-2021-26084 caught my eyes because the bug was critical and Jira Confluence 
is one of the most common software for IT companies ( I think ?, because all of the companies I worked for, they all use Jira confluence ).
- I don't have much chance to review Java-based product and I've been avoiding doing research on Java-based product, so I think this is a good time to start and it's a Web application bug - my expertise ;). 

Reference:
- Amazing write-up from [@iamnoooob](https://twitter.com/iamnoooob): https://github.com/httpvoid/writeups/blob/main/Confluence-RCE.md

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

