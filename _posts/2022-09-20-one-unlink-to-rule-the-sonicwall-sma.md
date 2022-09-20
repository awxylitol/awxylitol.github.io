---
layout: post
title: One Unlink to Rule The SonicWall SMA
---

# One Unlink to Rule The SonicWall SMA

## Abstract

In this blog post, I will show you how a weak arbitrary file deletion bug can be exploited to remotely take over a SonicWall SMA server as admin.

## Backgroud
> SonicWall Secure Mobile Access (SMA) is a unified secure access gateway that enables organizations to provide access to any application, anytime, from anywhere and any devices, including managed and unmanaged.

It is offered in two forms, either as a rack-mounted server, or as a VM appliance.

The following analysis is done on firmware `10.2.0.6-32sv`, though `10.2.0.7-34sv` is also affected.

## Unlink Bug

One of the best ways to find new bugs is to analyze old bugs first.

Based on [this](https://blog.scrt.ch/2020/02/11/sonicwall-sra-and-sma-vulnerabilties/) blog post, SonicWall SMA seems to be prone to many types of simple bugs.

Though with the `10.0` firmware update, stack cookie mitigation is added, which renders stack buffer overflow bugs pretty much useless.

So during my analysis, logical bugs are what I mainly looked for.

When reproducing [CVE-2019-7483](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-7483), an unauthenticated Directory Traversal vulnerability in the `handleWAFRedirect` CGI which allows the user to test for the presence of a file on the server, something strange happened: the `hdl` file under `/tmp/` is deleted despite the request is not unauthenticated.

Let's follow the main function in `handleWAFRedirect` cgi.

![check](/images/sonicwall_check.png "check")

First, `v33`, the filename set by `hdl`, is printed into `name`, then `isPathStartFromDir()` is called to make sure the canonical path indeed starts from `/tmp`.

![isPathStartFromDir](/images/sonicwall_isPathStartFromDir.png "isPathStartFromDir")

The purpose of this check I believe is to eliminate any Directory Traversal bugs.

If `hdl` is set to something like `../etc/passwd`, then `isPathStartFromDir()` will fail, and the code jumps to `LABEL_4`.

Following `LABEL_4` are some value assignments which should not cause any side effects.

Next, `v33`, the filename controlled by user, is used again to get `name` and `unlink(name)` will delete arbitrary filename set by user.

![sonicwall_unlink](/images/sonicwall_unlink.png "sonicwall_unlink")

Seems like a strong pre-authentication arbitrary file deletion primitive right ?

Unfortunately, CGI files run as the less privileged `nobody` in Apache, so the files we can delete are quite limited.

Side note: with the help of my colleague, I was able to locate the root cause, and for that I am very grateful.

## Exploit

To exploit this relatively weak primitive, we could delete some configuration files to affect the state machine and get the OS to reboot or something similar.

Since we can only delete files as `nobody`, first we should find out all these files or directories by running the commands below:

```
find / -type d  -user nobody
find -L / -type d -perm 777
```

One file `/etc/EasyAccess/var/conf/persist.db` seems pretty interesting, so I deleted it with this bug, and after about 6 minutes, the OS started to reboot.

Once the reboot process was finished, I was greeted with the setup page and was able to login with the factory default `admin/password`.

It seems that `persist.db` is used to save newly added username, passwords and other information after initialization, and by deleting it, we successfully altered the state machine of SMA into factory mode.

What is even better is that the network configuration information like the IP address is not affected by the deletion.

So theoretically we can exploit this bug to delete the `persist.db` on any Internet-facing SMA instance to get it reboot into factory mode automatically while retaining subsequent Internet access to it and login as `admin/password`.

To make the exploit chain complete, I managed to find a post-authentication command injection [bug](https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0022) to get a fully working remote shell.

Since `10.2.0.6-32sv` still uses `Linux 3.1.0`, it should be relatively easy to get root privilege by exploiting N-day bugs like [Dirty COW](https://en.wikipedia.org/wiki/Dirty_COW).


## Summary

To me, the main takeaway is that during bug hunting, never ignore those trivial strange behaviors because in computer science, things tend to have a logical explanations behind. 

Besides, logical bugs are really fun to exploit and sometimes a little bit of luck is all you need.

## Reference
* [https://blog.scrt.ch/2020/02/11/sonicwall-sra-and-sma-vulnerabilties/](https://blog.scrt.ch/2020/02/11/sonicwall-sra-and-sma-vulnerabilties/)
* [https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0021](https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0021)
* [https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0022](https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0022)
* [https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2019-0018](https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2019-0018)
