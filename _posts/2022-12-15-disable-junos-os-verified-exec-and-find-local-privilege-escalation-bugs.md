---
layout: post
title: Disable Junos OS Verified Exec and Find Local Privilege Escalation Bugs
---

# Disable Junos OS Verified Exec and Find Local Privilege Escalation Bugs

## Summary
In this blog post, I will show you how to break the chain of trust on [Junos OS](https://en.wikipedia.org/wiki/Junos_OS) to run arbitrary binary, e.g., gdbserver, to ease the debugging process, 
and show you the methodology I applied in finding [CVE-2021-31359](https://nvd.nist.gov/vuln/detail/CVE-2021-31359) and [CVE-2021-31360](https://nvd.nist.gov/vuln/detail/CVE-2021-31360), two bugs I reported to Juniper back in 2020.

## Junos OS vMX KVM Install

First, download the trial version of [vMX](https://www.juniper.net/us/en/dm/vmx-trial-download.html).

The KVM version `vMX Evaluation 18.2R1.9` is used here, and it is installed on a PC with an Intel processor.

The host OS is Ubuntu 18.04 64 bit desktop.

You may follow the latest tutorial [here](https://www.juniper.net/documentation/us/en/software/vmx/vmx-getting-started/topics/topic-map/vmx-installing-on-kvm.html).

Note that QEMU with Libvirt is required.

![vMX Architecture](/images/juniper_vmx.png "vMX Architecture")

Run `sudo ./vmx.sh --start` to start vMX, and connect to the VCP(Virtual Control Panel) with `./vmx.sh --console vcp vmx1`.

To access the VCP login interface, send `Ctrl + ]`.

More commands to control the vMX can be found [here](https://www.juniper.net/documentation/us/en/software/vmx/vmx-getting-started/topics/topic-map/vmx-deploying-on-kvm.html).

## Verified Exec
Taken from [here](https://www.juniper.net/documentation/us/en/software/junos/junos-install-upgrade/topics/concept/veriexec.html).
>Veriexec provides the kernel with a digitally signed manifest consisting of a set of fingerprints for all the executables and other files that should remain immutable. The veriexec loader feeds the contents of the manifest to the kernel only if the digital signature of the manifest is successfully verified. The kernel can then verify if a file matches its fingerprint. If veriexec is being enforced, only executables with a verified fingerprint will run. The protected files cannot be written to, modified, or changed.

Basically, it means that on a recent version of Junos OS, you can not run your own binary, which makes it quite challenging to set up a debugging environment.

## Break Chain of Trust
Based on my research, Verified Exec can not be disabled on most Junos OS platforms.

> Some Junos OS platforms offer an optional version of Junos OS with veriexec enforcement disabled (referred to as Junos Enhanced Automation or Junos Flex).

The only officially supported one is `Junos Flex`, although the access to it can be quite limited, and I am not sure if vMX is supported.

The good news is that the vMX Junos OS runs on QEMU like any other Guest OS, so it does not have a security anchor like Android or iOS, which means the code integrity of the earliest stage is not protected.

In theory, we can patch the bootloader to disable Verified Exec offline.

But first, we need to locate the code which enforces Verified Exec.

### Locate the Code

After weeks of debugging and reverse engineering, I found it best to change some checking logic in the kernel.

![the patch](/images/juniper_veriexec_kernel_patch.png "the patch")

By simply chaning `jz` to `jmp`, the returned value of `mac_veriexec_in_state()` is effectively discarded, and `mac_veriexec_check_image_fingerprint()` returns success everytime.

With the kernel image modified, Junos OS will refuse to boot, which means some earlier stage of the booting process must have checked the integrity of the kernel image.

### Disable the Check

Since Junos OS is [based](https://www.juniper.net/documentation/us/en/software/junos/junos-install-upgrade/topics/topic-map/junos-os-overview.html) on FreeBSD, the disk file `junos-vmx-x86-64-18.2R1.9.qcow2` has 3 partitions: `oam`, `junos`, `swap`. The files we need to modify are located in the `junos` partition.

You can download a fully loaded FreeBSD disk like [this](https://download.freebsd.org/releases/VM-IMAGES/12.3-RELEASE/amd64/Latest/FreeBSD-12.3-RELEASE-amd64.qcow2.xz) one.

And boot it with the disk file of Junos OS attached.

```
sudo qemu-system-x86_64 ./FreeBSD-12.1-RELEASE-amd64.qcow2  -drive file=./junos-vmx-x86-64-18.2R1.9.qcow2
```

Inside the FreeBSD vm, mount the `junos` partition with `mount /dev/ada1p3 ./junos` and modify the files necessary to disable the check on the kernel image.

1. replace the original kernel image with the patched one, `cp ./kernel_patch ./junos/packages/db/os-kernel-xen-x86-64-20201028.e1cef1d_builder_stable_11/boot/kernel`;

2. `cd ./junos/packages/db/os-kernel-xen-x86-64-20201028.e1cef1d_builder_stable_11/`;

3. get the __sha256__ hash of the __patched__ kernel file, `sha256 ./boot/kernel`, and in `./package.xml`, change the `<sha256>[new sha256]</sha256>` inside `<file name="kernel">` accordingly;

4. get the __sha1__ hash for the now modified `./package.xml` with `sha1sum ./package.xml`, and change the sha1 value in `./manifest` like `package.xml sha1=[new sha1]` accordingly.

After `umount ./junos` and powering down the FreeBSD vm, we can finally enjoy the Junos OS without the limitation of Veriexec.

## Bugs I Found

Now that we have broken Veriexec, tools like gdbserver or strace can be used on Junos OS to help us hunt bugs.

Inspired by the [works](https://starlabs.sg/advisories/21/21-0256/) from [hi_im_d4rkn3ss](https://twitter.com/hi_im_d4rkn3ss), I mainly focused on local privilege escalation bugs.

To start, create an user with the minimum privileges like a user in the `read-only` class. More about the login classes on Junos OS can be found [here](https://www.juniper.net/documentation/us/en/software/junos/user-access/topics/topic-map/junos-os-login-class.html).

### Denial of Service Bug

I logged in as the newly created user and played with every options or settings I could find in the hope of getting some crash.

Accidentally, I found that with the `save dhcp-security-snoop [file]` command, files that were only writable by root could be overwritten. 

This means if some important files were overwritten, the Junos OS may automatically power off and even refuses to boot up the next time.

In the end, this bug got a CVSS score of 7.1 and was assigned [CVE-2021-31360](https://nvd.nist.gov/vuln/detail/CVE-2021-31360).

### Local Privilege Escalation Bug

It turned out this dhcp attack interface seemed promising.

So I spent more time trying to figure out the root cause of the DoS bug and also hoped to find some better bugs.

One thing worth mentioning is that the actual handlers of some commands are separate processes running on Junos OS and the `mgd` process works as the dispatcher and talks to these processes through an IPC mechanism.

Therefore, given a specific command, it may take some debugging and sometimes guessing to finally locate the handler process.

The `dhcp-security-snoop` command is handled by the `jdhcpd` process which runs with the root privilege.

The approach I took was to locate the corresponding function of a cli command first and audit it later.

![fscanf](/images/juniper_fscanf.png "fscanf")

During the audit process, it occurred to me that `fscanf()` will keep copying from `v83`, the opened file stream created by `fopen(file, "r");`, until a `\t` character.

Since `file` is actually the file in `load dhcp-security-snoop [file]` which is fully controlled by the user, we can overflow the stack buffer `v120` with anything of our choice.

The `jdhcpd` binary is built without basic mitigation like PIE and stack canary, so this bug can be easily exploited to achieve local privilege escalation to root.

## Conclusion

It surprised me that an OS used on many high value routers and switches should have such easy to find bugs and the lack of mitigations made the situation even worse.

Although no longer work on router bug hunting, I choose to write this blog post after nearly two years in the hope that it may be of help to someone in the future.

After all, a root shell means half of the work is done in the IoT security research business.

## Reference
* [https://supportportal.juniper.net/s/article/2021-10-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-Local-Privilege-Escalation-and-Denial-of-Service](https://supportportal.juniper.net/s/article/2021-10-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-Local-Privilege-Escalation-and-Denial-of-Service)
* [https://www.juniper.net/documentation/us/en/software/vmx/vmx-getting-started/topics/topic-map/vmx-installing-on-kvm.html](https://www.juniper.net/documentation/us/en/software/vmx/vmx-getting-started/topics/topic-map/vmx-installing-on-kvm.html)
* [https://starlabs.sg/advisories/21/21-0256/](https://starlabs.sg/advisories/21/21-0256/)
