---
layout: post
title: Rogue CDB - Escaping from VMware Workstation Through the Disk Controller
---

# Rogue CDB: Escaping from VMware Workstation Through the Disk Controller

## Introduction

This blog post will talk about the background information, root cause, exploitation primitives, processes, and techniques of a heap buffer OOB read/write bug [CVE-2023-20872](https://www.vmware.com/security/advisories/VMSA-2023-0008.html) inside the emulated disk controllers on VMware Workstation. A session was presented at the [HITBSecConf2023 Phuket](https://conference.hitb.org/hitbsecconf2023hkt/session/rogue-cdb-escaping-from-vmware-workstation-through-the-disk-controller/) and the slide is available [here](https://conference.hitb.org/hitbsecconf2023hkt/materials/D1T2%20-%20Rogue%20CDB%20Escaping%20from%20VMware%20Workstation%20Through%20the%20Disk%20Controller%20-%20Wenxu%20Yin.pdf).

It was fixed in VMware Workstation [17.0.1 Build 21139696](https://www.vmware.com/security/advisories/VMSA-2023-0008.html) and in this post all screenshots and demonstrations are based on the Windows version of 17.0.0 Build 20800274 except for the part "COP on Linux". The Guest VM is Ubuntu 18.04 x64 from [OSBoxes](https://www.osboxes.org/ubuntu/).

## Background Information

### Disk Controller
A disk controller is typically plugged into one of the PCI/PCIe slots on the motherboard and sits between the driver in the OS and the disks. The most common form of connectors are SCSI (Small Computer System Interface), SATA (Serial AT Attachment) and IDE (Integrated Drive Electronics).

<img src="/images/rogue_cdb/Seagate_ST11R-1693205483015.jpg" style="zoom: 10%;" />

In the case of a hypervisor, the emulated disk controller is exposed to the Guest OS via the emulated PCI interface, and the hard disk itself is merely a large file stored on the Host OS.

When creating a new "Virtual Machine" with VMware Workstation, you have several SCSI controllers to choose from, like LSI Logic or Paravirtualized SCSI.

<img src="/images/rogue_cdb/scsi_controllers.PNG" style="zoom: 33%;" />

The implementation of LSI Logic is actually modeled after the Broadcom / LSI 53c1030 PCI-X Fusion-MPT Dual Ultra320 SCSI disk controller in the real world. While the PVSCSI (Paravirtualized SCSI) is a paravirtualized device without any real world counterpart and is designed by VMware to reduce the overhead of emulation and to maximize performance.

### SCSI & CDB

SCSI is a protocol used principally to talk to storage devices such as hard disks and tape drives. The SCSI standards define commands, protocols, electrical, optical and logical interfaces. Parallel SCSI (formally, SCSI Parallel Interface, or SPI) is the earliest of the interface implementations in the SCSI family. SAS (Serial Attached SCSI) is a point-to-point serial protocol. SAS replaces the older Parallel SCSI.

In SCSI standards for transferring data between computers and peripheral devices, often computer storage, commands are sent in a CDB (Command Descriptor Block). Each CDB can be a total of `6`, `10`, `12`, or `16` bytes, but later versions of the SCSI standard also allow for **variable-length** CDBs. 

<img src="/images/rogue_cdb/cdb_6.PNG" style="zoom: 50%;" />

As is shown above, the first byte of a SCSI CDB is an operation code that specifies the command that the application client is requesting the device server to perform.

The following picture shows that the [correlation](https://www.t10.org/lists/op-num.htm) between the value of an operation code and the length of the CDB command.

<img src="/images/rogue_cdb/operation_codes_by_group.PNG" style="zoom:50%;" />

For example, if the operation code is `0x3` from Group 0 which means `REQUEST SENSE`, then the length of the CDB should be `0x6`.

<img src="/images/rogue_cdb/opcode_example.PNG" style="zoom:38%;" />

### VMware's Implementation

#### Inside the Guest VM

Inside a 64 bit Linux Guest VM on VMware Workstation, the default hard disk controller is "LSI Logic / Symbios Logic 53c1030 PCI-X Fusion-MPT Dual Ultra320 SCSI". Its real world counterpart is made by LSI Corporation. The lspci command is from the `pciutils` package.

<img src="/images/rogue_cdb/lspci.PNG" style="zoom:38%;" />

As is shown in the screenshot above, the [B/D/F](https://wiki.xenproject.org/wiki/Bus:Device.Function_(BDF)_Notation) for the LSI Logic controller is `00:10.0`.

<img src="/images/rogue_cdb/mptspi.PNG" style="zoom:38%;" />

With `lspci -kvvv -s 00:10.0`, we can see that the driver on Linux is **mptspi** and the device has three BAR (Base Address Register). The first one, BAR0, is a PMIO (Port-Mapped I/O) which starts from `0x1400` and has a size of 256 bytes. The rest two, BAR1 and BAR3, are MMIO (Memory-Mapped I/O) at `0xFEB80000` and `0xFEBA0000`. These are the interfaces to interact with the emulated LSI Logic disk controller device on VMware Workstation.

One of the most important data structures used to talk to this disk controller is **MSG_SCSI_IO_REQUEST**. On Linux Kernel 6.1.19, the definition for it can be found in `drivers/message/fusion/lsi/mpi_init.h` and `drivers/message/fusion/lsi/mpi.h`.

<img src="/images/rogue_cdb/msg_scsi_io.PNG" style="zoom:38%;" />

<img src="/images/rogue_cdb/sge_io_union.PNG" style="zoom:38%;" />

<img src="/images/rogue_cdb/sge_simple_union.PNG" style="zoom:38%;" />

#### The Processing of CDB

The processing of the CDB sent from the Guest VM starts in the "RPC" Handler `sub_140178900()` for the LSI SCSI Controller inside which `sub_14025B550()` is called.

<img src="/images/rogue_cdb/lsi_rpc.PNG" style="zoom:50%;" />

Here, `a2` should be `MSG_SCSI_IO_REQUEST` from the Guest VM and **v6** is malloced to store the overall SCSI CDB request.

<img src="/images/rogue_cdb/lsi_process.PNG" style="zoom:50%;" />

Then **v6** is passed to the generic SCSI CDB handler function `sub_1402129A0()` which also handles SCSI CDB from other disk controllers like PVSCSI, BusLogic, etc.

<img src="/images/rogue_cdb/call_scsi-1693209888287.PNG" style="zoom: 50%;" />

For example, in the case of PVSCSI, the structure is `v7`.

<img src="/images/rogue_cdb/pvscsi.PNG" style="zoom:50%;" />

Next, in `sub_1402129A0()`, `a2` is **v6**. Check is done in `sub_140211F30()`. If it passes, the CDB is sent to the respective handler functions of different SCSI devices, like CD drive or hard disk in `sub_14021BEC0()`.

<img src="/images/rogue_cdb/scsi_flow.PNG" style="zoom:50%;" />

Inside `sub_14021BEC0()`, handler functions for respective disk controllers are called and they are registered when these devices are initialized in the booting process of the Guest VM.

<img src="/images/rogue_cdb/scsi_last.PNG" style="zoom:50%;" />

#### The Validation of CDB

Inside `sub_140211F30()`, `a3` is the **v6** structure. `v5 = *(unsigned int *)(a3 + 48)` is the **CDB Length** set by the Guest VM in the structure `MSG_SCSI_IO_REQUEST` . `*(unsigned __int8 **)(a3 + 40)` is the CDB array which is also controlled by the Guest VM, and `v7 = **(unsigned __int8 **)(a3 + 40)` is the **Operation Code**. v8 is the supposed **CDB Length** of the CDB based on its **Operation Code**.

Inside the `byte_1409D9238` array, we have the **CDB Length** of different **Operation Code** groups, from Group 0 of `0x6` bytes to Group 7 of `0x41` bytes.

<img src="/images/rogue_cdb/cdb_group_array.PNG" style="zoom: 67%;" />

As we can see, the **CDB Length** and the **Operation Code** have to be consistent. If not, this CDB command will be discarded. For example, the **CDB Length **of a CDB with the **Operation Code** from Group 3 is assumed to be `0x40`.

<img src="/images/rogue_cdb/scsi_cdblen_check.PNG" style="zoom: 50%;" />

## The Bug

### Root Cause

Assumption is broken with the introduction of newer specifications.

<img src="/images/rogue_cdb/CVE-2023-20872.PNG" style="zoom: 50%;" />

Inside `sub_14080D870()`, a function that processes CDB sent to a CDROM device, `a3` is the **CDB Length** which can be `0x6`, `0xA`, `0xC`, `0x10`, `0x40`, `0x41`. `a2` is the CDB. `v16` is a chunk with the size of `0x158` since `sub_140603000()` is a simple wrapper of `malloc()`. The `v16 + 0x138` is supposed to be the array of size `0x10` to store the CDB command from `a2` and `a3` is the corresponding **CDB Length**. As the addresses of `v16 + 0x148` and `v16 + 0x150` are used to store other parameters, `a9` and `a10`.

If we send a CDB with the **Operation Code** of `0x60` from Group 3 and with the **CDB Length** of `0x40`, then this CDB will pass the consistency check in `sub_140211F30()` and lead to a heap buffer overflow because the assumed maximum length of CDB is obviously `0x10`.

<img src="/images/rogue_cdb/cdrom_scene.PNG" style="zoom: 50%;" />

With [Page Heap](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/gflags-and-pageheap) enabled, the **vmx** process crashes at `memcpy()`.

<img src="/images/rogue_cdb/crash.PNG" style="zoom:50%;" />

### The Fix

The fix for this bug is pretty straightforward. On VMware Workstation 17.0.1 Build 21139696, it checks the **Operation Code** Group first, then check the consistency between the **CDB Length** and the **Operation Code**. A CDB with the **CDB Length** of `0x40` or `0x41` is simply **rejected**.

<img src="/images/rogue_cdb/fix.PNG" style="zoom:50%;" />

### Exploit Primitives

With Page Heap enabled and a breakpoint set at `memcpy()`, `dst/rcx` is the **0x158** chunk **v16** + offset **0x138** malloced in `sub_14080D870()`. `src/rdx` is the **0x4228** chunk **v6** + offset **0x41F8** malloced in the LSI Logic function `sub_14025B550()`. The third parameter `r8`, the length, is `0x40`. For a CDB with an **Operation Code** from Group 6 or 7, the length is `0x41`.

<img src="/images/rogue_cdb/mem_analysis.PNG" style="zoom: 50%;" />

#### OOB Read

Inside `sub_14025B550()`, a call to `sub_14071E390()` returns **v6**, the src **0x4228** chunk + **8**.

<img src="/images/rogue_cdb/src_malloc.PNG" style="zoom: 50%;" />


The address of `src` is `v6 + 0x41F0` which equals to the **0x4228** chunk with the offset of `0x41F8`.

<img src="/images/rogue_cdb/src_memcpy_new.PNG" style="zoom:50%;" />

The first `0x20` bytes of OOB read occurs **within** the `src` chunk of size **0x4228** at offset `0x4208` right after the `0x10` bytes of the benign CDB array. As is shown in the **MSG_SCSI_IO_REQUEST** structure, `DataLength(U32)`, `SenseBufferLowAddr(U32)`, `SGL(FlagsLength(U32)` and `Address64(U64))` are stored after the `CDB[16]`. That is `0x14` bytes and some `0xC` bytes at the end of the `src` chunk will also be read.

<img src="/images/rogue_cdb/mem_layout_fix.png" style="zoom: 50%;" />

Another `0x10` bytes from the **following** chunk will also be read. Since the `src` is a `0x4228` chunk, it should be always on a Non-LFH heap on Windows 10.

#### OOB Write

The first `0x10` bytes of OOB write happens within the `dst` chunk `v16` of `0x158`. That is from the offset `0x148` to the end of `0x158`.

<img src="/images/rogue_cdb/v16.png" style="zoom: 25%;" />

The rest `0x20` bytes will be written into the following chunk. Since the `dst` is a `0x158` chunk, it **may** be on LFH on Windows 10. So this OOB write primitive allows us to write at least `0x18` bytes into the following chunk besides the `8` bytes of chunk header.

#### Arbitrary Call

At the end of the function  `sub_14080D870()` where the `memcpy()` OOB happens, the `0x158` **v16** chunk is passed to `sub_140839B60()` along with a function pointer `sub_14080DAA0()`.

<img src="/images/rogue_cdb/call1.PNG" style="zoom: 50%;" />



<img src="/images/rogue_cdb/call2.PNG" style="zoom:50%;" />

Here, `a9` is `sub_14080DAA0()` and `a10` is **v16**, the `0x158` chunk.

<img src="/images/rogue_cdb/call3.PNG" style="zoom:50%;" />

Next, inside `sub_14080DAA0()`, an indirect function call is made. With [CFG (Control Flow Guard)](https://learn.microsoft.com/en-us/windows/win32/secbp/control-flow-guard) enabled for the Windows version of VMware Workstation, the function pointer is stored in `rax` but the parameters remain in the same registers as in the [Microsoft x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170). The function pointer used is `v16->func_ptr ` at `rbx + 0x148`, and the second parameter to it is `v16->second_param` at `rbx + 0x150`.

With the OOB write primitive, we already have control over the function pointer and its second parameter, giving us a powerful arbitrary call primitive.

<img src="/images/rogue_cdb/arbitrary_call_diagram.PNG" style="zoom:50%;" />

Besides, as is shown in the assembly code above, if we overflow `v16->func_ptr ` with `0`, the arbitrary call will not happen which gives the opportunity to defeat the ASLR mitigation first.

## The Code Execution

### Linear vmem

On a 64 bit Linux Guest VM with `4` GB of memory, the physical address space usually looks like this: 

<img src="/images/rogue_cdb/iomem.PNG" style="zoom:50%;" />

The physical memory address space is not continuous like from `0x00000000` to `0xffffffff`. Here, it is "divided" into two parts: 3 GB of `0x00000000` to `0xbfffffff` and 1 GB of `0x100000000` to `0x13fffffff`. This design makes sense because peripherals usually need to have their MMIO addresses at an area from `0xc0000000` to `0xffffffff` for compatible reasons.

<img src="/images/rogue_cdb/mem_v2.drawio.png" style="zoom: 50%;" />

On the host, the physical memory of the guest is mapped to a `.vmem` file stored in the same folder as the Guest VM which is also mapped into the the address space of the corresponding **vmx** process. 

```assembly
0`7fff0000  1`7fff0000  1`00000000  MEM_MAPPED  MEM_COMMIT  PAGE_READWRITE  MappedFile "\Device\HarddiskVolume4\Ubuntu 18.04.6 64bit\564d0a6b-e0e0-8175-1c8e-b007e2be2d10.vmem"
```

Workstation takes a similar approach as [QEMU](http://www.phrack.org/issues/70/5.html#article), so the GPA (Guest Physical Address) and its corresponding HVA (Host Virtual Address) have a **linear** relationship. In the case of DMA, the **vmx** process has to translate the GPA sent by the guest drivers to its own address space. For example, if the Guest VM sends a GPA of `0x0 + 0x1000`, it will be translated to a HVA of `0x7FFF0000 + 0x1000`. While if you write something at the physical address of `0x100001000` inside the guest, then you have to read it out at `0x7fff0000 + 0xc0001000 = 0x13fff1000` in the address space of **vmx**.

### COP on Linux

The Linux version of VMware Workstation does not have the CFG mitigation like the Windows version does. Since we already have control `rip` and `rsi`, ROP (Return Oriented Programming) is the obvious choice, COP (Call Oriented Programming) to be more precise.

<img src="/images/rogue_cdb/call_on_linux.PNG" style="zoom: 50%;" />

Searching for something like `mov rdi, rsi` with `ropper --file vmware-vmx --search "mov rdi, rsi"` gave us this.

<img src="/images/rogue_cdb/call_gadget.PNG" style="zoom: 50%;" />

`rsi/rdi` points to `/usr/bin/gnome-calculator`, and the last function to be called, `gadget_ptr`,  is set to `system()` at `.plt`.

<img src="/images/rogue_cdb/linux_struct.PNG" style="zoom: 50%;" />

Unfortunately, due to the [stack alignment requirement](https://stackoverflow.com/questions/49391001/why-does-the-x86-64-amd64-system-v-abi-mandate-a-16-byte-stack-alignment) on x86-64 Linux, we can not call `system()` directly. Luckily, this gadget solves the issue.

<img src="/images/rogue_cdb/call_system.PNG" style="zoom: 50%;" />

With the linear vmem mapping in mind, `rsi` is set to `0x00007fff55000000` which is inside the **vmem** map at the offset of `0x6d000000`, and we can put our exploit code at the physical address of `0x6d000000` inside the Guest VM directly.

<img src="/images/rogue_cdb/exp_linux.png" style="zoom:;" />

### Bypass CFG on Windows

Without triggering this bug, the original handler function stored at `v16->func_ptr` is `sub_14028EC90()`.

<img src="/images/rogue_cdb/orig_call.PNG" style="zoom:50%;" />

I was playing with the arbitrary call primitive with the `func_ptr` overflowed with `0` when a crash happened since the OOB write had destroyed some chunks on the heap. One of the functions from the backtrace looks interesting, if ONLY I could find one that uses the second parameter like this.

<img src="/images/rogue_cdb/luck.PNG" style="zoom: 50%;" />

It is the original handler function! And `a1` is not used at all.

<img src="/images/rogue_cdb/orig_call_2.PNG" style="zoom:50%;" />


With the second parameter already under our control, we can make another arbitrary call and we do not even have to control `v16->func_ptr` which effectively makes this a **Data-Only Exploitation**.

We can point `rdx` to **vmem** to arrange the required elements of the `a2` structure in the Guest VM directly.
For example, by setting `a2` to `0x7FFF0000 + 0x1000`, we can write to the physical address of `0x1000` in the Guest VM.

<img src="/images/rogue_cdb/cfg.drawio.png" style="zoom:50%;" />

Finally, with `a2[2]` set to `KERNEL32!WinExec()`, `a2[1]` set to the address of `calc.exe` and `a2[3]` set to `1(SW_SHOWNORMAL)`, we have the final `a2[2](a2[1], a2[3])` which is `KERNEL32!WinExec("calc.exe", 1)`.

<img src="/images/rogue_cdb/cfg.drawio-1680000438698.png" style="zoom:50%;" />

And there you have it, the calculator.

<img src="/images/rogue_cdb/exp_win.png"  />

## References

- [https://en.wikipedia.org/wiki/Disk_controller](https://en.wikipedia.org/wiki/Disk_controller)
- [SCSI Commands Reference Manual](https://www.seagate.com/files/staticfiles/support/docs/manual/Interface%20manuals/100293068j.pdf)
- [https://www.t10.org/lists/op-num.htm](https://www.t10.org/lists/op-num.htm)
- [https://www.t10.org/lists/op-num.htm](http://www.phrack.org/issues/70/5.html)
