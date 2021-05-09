---
layout: post
title: EmbedThis Appweb NPD Bug
---

# EmbedThis Appweb NPD Bug

## Summary

A npd bug in EmbedThis [Appweb](https://www.embedthis.com/appweb/download.html) Community Edition __latest__ Version 8.2.1 will lead to server crash.

> Appweb and GoAhead are embedded web servers that are embedded in hundreds of millions of devices and applications. This includes printers, routers, switches, IP phones, mobile applications, data acquisition, military applications, WIFI gateways, factory automation, medical devices and many more.

## Analysis

The bug exists in `src/http/httpLib.c`

```
static void parseUri(HttpStream *stream)
    hostname = rx->hostHeader ? rx->hostHeader : stream->host->name;
```

When a  HTTP request without a valid Host header is processed by the `parseUri()`, `rx->hostHeader` should be `0x00`, so `hostname = stream->host->name`.

However, `stream->host` is also `0x00`, thus `stream->host->name` will dereference a null pointer and the appweb process will crash due to segfault.

## Reproduce

To reproduce this bug, build Appweb Community Edition Version 8.2.1 with make on a x64 Linux Distro, run the server with `./appweb --verbose . 127.0.0.1:8081`, and send the poc to it with `cat npd.txt | nc 127.0.0.1 8081`, and a segmentation fault should be expected.

![segfault](/images/appweb_npd.png "segfault")
