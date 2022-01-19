---
layout: post
title:  "Analyze Java deserialization gadget chains - For learning purpose"
date:   2022-01-19 16:00:00 +0700
categories: research
author: Quang Vo
tags: java, deserialization
description: Research
---

## Introduction 
Most of people have heard about Java deserialization apocalypse. There are great tools out there for hunting deserialization vulnerabilities out there, to name a fews:
- The famous [ysoserial](https://github.com/frohoff/ysoserial)
- The same [ysoserial](https://github.com/pwntester/ysoserial.net) but for C# .NET
- [Gadgetinspector](https://github.com/JackOfMostTrades/gadgetinspector)

While in those tools, payloads are already there for us to use. But I believe the best way to learn and remember what we learnt are by actually understanding it, that's why I write this blog, to help me remember and understand it more and also for who want to know about this.

In this blog, we are going to dive in some of the famous gadget chain to see what's in there and how it's work.

IDE I use in this blog will be [IntelliJ IDEA Ultimate](https://www.jetbrains.com/idea/) so that we can debug line by line of codes, you can use the community version, it's fine.

## CommonsCollections5 gadget chain

In ysoserial, there are 7 different gadget chains relate to `CommonsCollection` . In this blog post,, I'll use `commons-collection version 3.2.1` .

Here is what the gadget chain look like from `ysoserial` : 

```java
BadAttributeValueExpException.readObject()
  TiedMapEntry.toString()
    TiedMapEntry.getValue()
      LazyMap.get()
        ChainedTransformer.transform()
          ConstantTransformer.transform()
          InvokerTransformer.transform()
            Method.invoke()
              Class.getMethod()
          InvokerTransformer.transform()
            Method.invoke()
              Runtime.getRuntime()
          InvokerTransformer.transform()
            Method.invoke()
```

We will write some Java code to trigger the gadget chain and debug it:

```java

```
