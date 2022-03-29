---
layout: post
title:  "Analyze Java deserialization CommonsCollections2 gadget chain ( part 2 )"
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


## The TemplatesImpl gadget 

