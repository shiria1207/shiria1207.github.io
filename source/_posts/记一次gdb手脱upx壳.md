---
title: 记一次gdb手脱upx壳
tags:
  - ctf
  - reverse
  - gdb
  - upx
  - elf
categories: reverse
keywords:
  - gdb
  - 脱壳
  - upx
  - 逆向
  - ctf
abbrlink: 2b9bac68
date: 2026-08-20 20:25:13
updated:
description:
---

# 记一次gdb手脱upx壳

# 前言

upx是一种常见的开源免费壳，所谓保护壳，即将原程序的代码段和数据段压缩，然后给程序中额外加入解压的代码，是常用的代码保护技术。壳只负责压缩隐藏源代码，不改变程序功能，因此程序正常运行时必须先解压缩源代码到内存中，然后再按照普通程序运行的流程执行。所以脱壳的通常思路是，运行程序到完全解压缩结束，通常是OEP（original entry point），然后dump 内存。

> upx在官方github仓库可以下载到压缩和解压缩程序，常规的逆向题通常是用upx压缩后，修改二进制字节删去upx特征值，使得官方脚本失效。熟悉可执行文件结构可以尝试修复upx结构，然后用官方脚本脱壳。但还是得掌握手脱upx技巧，避免官方脚本无法脱壳然后和题目干瞪眼，当然，我新手时期也曾有过不会脱壳然后ida单步调试到脱壳后程序的经历
> 
> 

在之前几次接触upx时，我主要是使用高级调试器操作。

PE文件使用x64dbg，运行程序会停在一个假的OEP，upx壳执行之前通常会保存原始栈帧，所以在假OEP附近找一下push rsp rbp rsi rdi，通常就是准备解压缩的时候，在这一段栈空间下一个硬件访问断点，等触发断点的时候就是pop这4个寄存器的时候，这时候解压缩已经完成，在做收尾工作，找到rip附近的一次大跳（比如jmp 0x500字节以上），就是跳向真正的程序OEP，然后用x64dbg的scyall（工具栏很像美元图标的那个） dump内存即可。这应该是最方便的手动脱壳法了，但是只能用作PE和dll文件。

elf文件使用linux端ida pro调试（也可以win ida \+ remote linux debug），想模仿上文下硬件断点但断点总是触发不了，所以得手动跟踪，这部分网上有很多教程这里不再赘述。

这次校内的师傅出了一道题，upx壳elf，做了点魔改，让ida识别其为so文件，导致ida无法直接运行调试，因此我被迫回归最原始的脱壳手法——gdb调试脱壳。

# 脱壳过程

## 基于断点调试的脱壳

原理和用ida调试差不多，只是操作上要麻烦很多，而且实操的时候断点不触发，直接缴械投降

## 基于catch syscall read的脱壳方法

- UPX 解压是纯用户态操作，不触发 syscall，壳自己不会碰 `read()`。但解压完成后，动态链接器 `ld.so` 必须通过 `read()` 系统调用加载 `libc`，因此在read\(\)处下断点正好是刚脱壳完的时候。‘

```Plain Text
gdb ./a_sip_of_tea    #gdb载入程序
...
pwndbg> starti    #单步运行程序，停在入口
...
pwndbg> catch syscall read
Catchpoint 1 (syscall 'read' [0])
pwndbg> bl
Num     Type           Disp Enb Address    What
1       catchpoint     keep y              syscall "read"
```

继续运行

![image\.png](image%203.png)

看不太懂，反正就是已经停在了read\(\)调用的入口。这时候解压缩完成，查看映射：

![image\.png](image%201.png)

查看elf头处字节验证

```Plain Text
pwndbg> x/4bx 0x00007ffff7f12000
0x7ffff7f12000: 0x7f    0x45    0x4c    0x46     # --> .ELF 
```

elf头会记录program header的位置和数量

|字段|偏移|含义|
|---|---|---|
|e\_phoff|\+32 \(8B\)|program headers 表从哪开始|
|e\_phnum|\+56 \(2B\)|共多少条 program header|

查看elf头信息

![image\.png](image.png)

得到e\_phoff = 0x40, e\_phnum = 0x0f，即 program headers 从 0x7ff\.\.\.12000\+0x40 开始，一共15条，每条56字节。每一条program header的结构如下：

|偏移|字段|大小|说明|
|---|---|---|---|
|0|p\_type|4B|类型 \(1=PT\_LOAD，6 = PT\_PHDR, 3 = PT\_INTERP\)|
|4|p\_flags|4B|权限 \(R=4, W=2, X=1\)，\(RW=6, RX=5, RWX=7\)|
|8|p\_offset|8B|文件中的偏移|
|16|p\_vaddr|8B|虚拟地址|
|32|p\_filesz|8B|文件中的大小|

> 没提及的几个字段分别为物理地址，内存中大小和段对齐方式
> 
> 

查看program headers，筛选出p\_type = PT\_LOAD = 1的header，这个程序中为4条

![image\.png](image%204.png)

整理一下

|PHDR|p\_flags|p\_offset|p\_vaddr|p\_filesz|说明|
|---|---|---|---|---|---|
|2|4 \(R\)|0x0|0x0|0x918|Elf header\+辅助段|
|3|5 \(RX\)|0x1000|0x1000|0xbdf69|\.text代码段|
|4|4 \(R\)|0xbf000|0xbf000|0x268|\.rodata段|
|5|6 \(RW\)|0xbfda0|0xc0da0|0x2c4|\.data段\+GOT表|

将这几段分别dump下来（注意边界用的是虚拟地址），补`\x00`拼接（这边直接抄了参考文章的脚本，用ai写一个也是可以的），即可得到几乎完整的ELF文件

```Plain Text
pwndbg> dump memory dump1 0x7ffff7f12000+0x0 0x7ffff7f12000+0x918
pwndbg> dump memory dump2 0x7ffff7f12000+0x1000 0x7ffff7f12000+0xbef69
pwndbg> dump memory dump3 0x7ffff7f12000+0xbf000 0x7ffff7f12000+0xbf000+0x268
pwndbg> dump memory dump4 0x7ffff7f12000+0xc0da0 0x7ffff7f12000+0xc0da0+0x2c4
```

```Python
#!/usr/bin/env python3
"""拼接 dump 出来的 PT_LOAD 段 → 完整 ELF，自动段间补零。

用法:
    python3 cat_segments.py output.elf dump1:0x0 dump2:0x1000 dump3:0x2000 dump4:0x2dd0

    参数格式: 文件名:文件偏移(hex)
    顺序任意，脚本自动按 offset 排序。
"""

import sys

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} output.elf dump1:0x0 dump2:0x1000 ...")
        sys.exit(1)

    output = sys.argv[1]
    segments = []

    for arg in sys.argv[2:]:
        fname, offset_str = arg.rsplit(":", 1)
        offset = int(offset_str, 0)
        segments.append((fname, offset))

    # 按文件偏移排序
    segments.sort(key=lambda x: x[1])

    pos = 0
    with open(output, "wb") as out:
        for fname, offset in segments:
            data = open(fname, "rb").read()
            if pos < offset:
                gap = offset - pos
                out.write(b"\x00" * gap)
                print(f"  [gap] {hex(pos)} ~ {hex(offset)} ({gap}B zero-fill)")
            out.write(data)
            print(f"  [seg] {fname} → offset {hex(offset)} ({len(data)}B)")
            pos = offset + len(data)

        # 尾部填充到最后一页边界（可选，一般不需要）
        if pos % 0x1000 != 0:
            tail = 0x1000 - (pos % 0x1000)
            out.write(b"\x00" * tail)
            print(f"  [pad] page-align: +{tail}B zero-fill")

    import os
    os.chmod(output, 0o755)
    print(f"[+] {output} ({pos} bytes) — chmod +x done, run ./{output}")

if __name__ == "__main__":
    main()

```

```Python
$ python cat_segments.py unpack_elf dump1:0x0 dump2:0x1000 dump3:0xbf000 dump4:0xbfda0
  [seg] dump1 → offset 0x0 (2328B)
  [gap] 0x918 ~ 0x1000 (1768B zero-fill)
  [seg] dump2 → offset 0x1000 (778089B)
  [gap] 0xbef69 ~ 0xbf000 (151B zero-fill)
  [seg] dump3 → offset 0xbf000 (616B)
  [gap] 0xbf268 ~ 0xbfda0 (2872B zero-fill)
  [seg] dump4 → offset 0xbfda0 (708B)
  [pad] page-align: +3996B zero-fill
[+] unpack_elf (786532 bytes) — chmod +x done, run ./unpack_elf
```

此时打开导入ida时可能会报错一点点小问题，但运行和查看原二进制代码均可以正常进行

![image\.png](image%202.png)

至此gdb手脱upx壳完成。当然这只是逆向的第一步，后续品尝这个程序也是~~相当的美味~~啊

[参考文章: https://bbs\.kanxue\.com/thread\-291633\.htm](https://bbs\.kanxue\.com/thread\-291633\.htm)




