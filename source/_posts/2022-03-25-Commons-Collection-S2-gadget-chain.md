---
layout: post
title:  "Analyze Java deserialization: CommonsCollections2 gadget chain ( part 2 )"
date:   2022-03-25 16:00:00 +0700
categories: research
author: Quang Vo
tags: java, deserialization
description: Research
---

# Introduction - CommonsCollections2 gadget chain analysis
To continue part 1, we will analyze **CommonsCollections2** gadget chain next. This gadget chain is interesting because it introduces some new concepts ( to me ) about trampolines and sink holes. 

Gadget chain ( copied from ysoserial ):
```text
ObjectInputStream.readObject()
			PriorityQueue.readObject()
				...
					TransformingComparator.compare()
						InvokerTransformer.transform()
							Method.invoke()
								Runtime.exec()
```

Payload generator by ysoserial:

![image](https://user-images.githubusercontent.com/37280106/160421862-65e45e16-c00d-43bc-873c-4aac28f525e1.png)

We will break the gadget into 2 parts :
- The PriorityQueue gadget
- The TemplatesImpl gadget

## The PriorityQueue gadget 

`java.util.PriorityQueue` is a built-in Java class that implements a priority queue that can be ordered by a custom comparator. It implements `Serializable` interface and have a custom deserialization function `readObject()`, this is very crucial to our gadget chain. 

The gadget chain start at `PriorityQueue.readObject()` 

Implementation of `PriorityQueue.readObject()` :

![image](https://user-images.githubusercontent.com/37280106/160623598-36e8480a-e567-43da-a76e-962ac0a5ee25.png)

For every `Object` in the `PriorityQueue`, it will call method `readObject()` and then call to `this.heapify()`

In `this.heapify()` function, we have a trampolines:
```
heapify() -> siftDown() -> siftDownComparator() -> comparator.compare(obj1, obj2) 
```

The final function called in the `heapify()` trampolines is `comparator.compare(obj1,obj2)` . Looking back at the gadget chain code, we can easily identify the value of our comparator 

```java
final PriorityQueue<Object> queue = new PriorityQueue<Object>(2,new TransformingComparator(transformer));
```

- `comparator.compare(obj1, obj2)` is equivalent to `TransformingComparator.compare(obj1,obj2)` 

Let's place a breakpoint at `TransformingComparator.compare(obj1, obj2 )`  so we can examine the value of each variables to have a better understanding how the gadget chain actually run.

![image](https://user-images.githubusercontent.com/37280106/160627891-71a67437-cc62-41f1-b7d0-f7ccf1ba18d1.png)

As you can see in the picture:
- `obj1: 1` and `obj: 2` ( this is because we call `queue.add(1)` twice in the code ).
- `this.transformer` is `InvokerTransformer` 

This is because `TransformerComparator` needs a `Transformer` class, and we "give" it `InvokerTransformer` in the beginning of our gadget chain

```java
final InvokerTransformer transformer = new InvokerTransformer("toString", new Class[0], new Object[0]);

final PriorityQueue<Object> queue = new PriorityQueue<Object>(2,new TransformingComparator(transformer));
```

- `this.transformer.transform` will turn into `InvokerTransformer.transform(obj)` 

![image](https://user-images.githubusercontent.com/37280106/160632394-7834d331-8cd7-434b-b256-3a175c899709.png)

If you read the part 1, you will see the similarity, the function that we want to pay close attention to is: `method.invoke(input, this.iArgs)`. It belongs to the **Java Reflection API**, it allows us to **invoke methods on a class**.

So now we know that, at the end of this `PriorityQueue` gadget chain, we are able to **invoke any methods on any class** , our path to Remote Code Execution is getting closer.

The next line in gadget chain code:
```
// switch method called by comparator
Reflections.setFieldValue(transformer, "iMethodName", "newTransformer");
```

Again, **Java Reflection API** is used here, to set the value of `iMethodName` in `InvokerTransformer` to `newTransformer`, previously the `iMethodName` was `toString` 

Before the `Reflections.setFieldValue` call:

![image](https://user-images.githubusercontent.com/37280106/160745138-9efbc4c1-7fc7-425f-94b8-8a4628056f0f.png)

After the `setFieldValue` is called:

![image](https://user-images.githubusercontent.com/37280106/160745179-9ab52963-75e0-4691-a9cb-92bed761d7f5.png)

Why do we need to set `iMethodName` to `newTransformer` ?. This method is very crucial for our next gadget chain, it helps us to be able to achieve RCE. We will move to **the TemplatesImpl** gadget to see how is this function is used to achieve RCE.


## The TemplatesImpl gadget 

`org.apache.xalan.xsltc.trax.TemplatesImpl` ( TemplatesImpl ) is normally used for XML parsing. What is interesting about this class, is that it holds an array of objects
in bytecode in the variable _bytecodes. A call to defineTransletClasses() will read this bytecode and initialize the
classes. Note that whereas serialized objects can only contain values, bytecode is much more powerful as it can include
code.

Here our gadget will be:
```
getOutputProperties() -> newTransformer() -> getTransletInstance() -> defineTransletClasses()
```

![image](https://user-images.githubusercontent.com/37280106/160748874-06a69bac-a81b-4c4e-b685-0b87f71f7118.png)

*newTransformer call getTransletInstance*

Implementation of *getTransletInstance*
![image](https://user-images.githubusercontent.com/37280106/160748992-429fa922-1ef7-45a8-9d5f-cc6970728638.png)

Finally, it will load classes defined in `__bytecodes` 

After provided bytecodes in TemplateImpl to achieve RCE, we add TemplateImpl to our PrioriyQueue and have it serialized.

![image](https://user-images.githubusercontent.com/37280106/160749386-85b01425-6fa2-485a-861e-927c5d2066a5.png)

## Deserialization process

During the deserialization process, the function `TransformerComparator.compare(obj1, obj2 )` is called again

![image](https://user-images.githubusercontent.com/37280106/160749625-b6f4f0bc-3aaa-4472-8633-a176bb70fb51.png)

With values:
- `obj1` is `TemplatesImpl` ( because we switch the content of queue )
- `obj2` is still `1`
- `this.transformer` is `InvokerTransformer`

=> `this.transformer.transform(obj1)` will become `InvokerTransformer.transform(TemplatesImpl)`. Which will lead us to this function

![image](https://user-images.githubusercontent.com/37280106/160749943-67b6ee9b-259f-43ea-b590-70ed25b9bdc9.png)

With values:
- input: `TemplatesImpl` 
- cls: `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`
- method: `cls.getMethod(this.iMethodName, this.iParamsType)` will be equivalent to `TemplatesImpl.getMethod("newTransformer", Class[0]` => `newTransformer` 

And finally the function: `method.invoke(input, this.iArgs)` will invoke `newTransformer()` method of `TemplatesImpl` and trigger our chain, build class from bytecodes

Result:

![image](https://user-images.githubusercontent.com/37280106/160750317-7133eb8a-6100-4285-a8a4-95d2e69d0978.png)


