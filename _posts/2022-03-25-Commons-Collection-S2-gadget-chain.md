---
layout: post
title:  "Analyze Java deserialization CommonsCollection gadget chain ( part 2 )"
date:   2022-03-25 16:00:00 +0700
categories: research
author: Quang Vo
tags: java, deserialization
description: Research
---

# Introduction 
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

## Gadget chain analysis


