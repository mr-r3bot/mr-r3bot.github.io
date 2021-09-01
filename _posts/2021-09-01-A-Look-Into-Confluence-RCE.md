---
layout: post
title:  "A look into CVE-2021-26084 Confluence RCE "
date:   2021-09-01 16:00:00 +0700
categories: research
author: Quang Vo
description: Research analysis and develop a working exploit poc script 
---

## OGNL Injection on Confluence

- Twitter is always the best place to keep up-to-date with the newest CVE or exploit. CVE-2021-26084 caught my eyes because the bug was critical and Jira Confluence 
is one of the most common software for IT companies ( I think ?, because all of the companies I worked for, they all use Jira confluence ).
- I don't have much chance to review Java-based product and I've been avoiding doing research on Java-based product, so I think this is a good time to start and it's a Web application bug - my expertise ;). 

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


### The bug
