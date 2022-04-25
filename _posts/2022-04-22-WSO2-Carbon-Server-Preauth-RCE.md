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

### 2. Decompile codebase and debug

To gather all the jar files and decompile them at once, I used this simple command:
```bash
find . -type f -name "*.jar" | xargs -n 1 -P 20 -I {} mv {} wso2-decompiled/
```

This will gather all the jar files, and then move it to folder `wso2-decompiled` , then after that, we can throw them all in **IntelliJ** and let it decompile for us.

Content of module: `org.wso2.carbon.ui.transport.fileupload`

![image](https://user-images.githubusercontent.com/37280106/164597868-2806cd5f-bd56-4fc6-a2c9-86bf3a614d1f.png)



## Proof-of-concept

