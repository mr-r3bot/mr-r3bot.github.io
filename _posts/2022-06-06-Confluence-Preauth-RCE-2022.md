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

## Analysis
