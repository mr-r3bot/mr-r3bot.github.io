---
layout: post
title:  "Analyze Java deserialization gadget chain ( part 2 )"
date:   2022-03-25 16:00:00 +0700
categories: research
author: Quang Vo
tags: java, deserialization
description: Research
---

# Introduction 
To continue part 1, we will analyze **CommonsCollections2** gadget chain. This gadget chain is interesting because it introduces some new concepts ( to me ) about trampolines and sink holes. 

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
