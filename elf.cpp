
#include "elf.h"

ELF::ELF(const std::string& path) : m_path(path)
{
    if(!reader.load(path))
    {
        std::cerr << "Can't find or process ELF file " << path << std::endl;
        exit(-1);
    }

    std::cout << "[*] '" << m_path << "'" << std::endl;
    std::cout << "    Arch:     "
    << machines[reader.get_machine()] 
    << "-"
    << (reader.get_class() == ELFCLASS32 ? "32" : "64")
    << "-"
    << endians[reader.get_encoding()]
    << std::endl;

    std::cout << "    RELRO:    " << get_relro() << std::endl;
    std::cout << "    Stack:    " << get_canary() << std::endl;
    std::cout << "    NX:       " << get_nx() << std::endl;
    std::cout << "    PIE:      " << get_pie() << std::endl;
}

std::string ELF::get_relro()
{
    std::string relro{"No RELRO"};

    // search segment headers
    for(ELFIO::Elf_Half i{0}; i < reader.segments.size(); ++i)
    {
        ELFIO::segment* seg = reader.segments[i];
        if(PT_GNU_RELRO == seg->get_type())
        {
            relro = "Partial RELRO";
            break;
        }
    }

    // search dynamic sections
    for(ELFIO::Elf_Half i{0}; i < reader.sections.size(); ++i )
    {
        ELFIO::section* sec = reader.sections[i];
        if(SHT_DYNAMIC == sec->get_type())
        {
            ELFIO::dynamic_section_accessor dynamic(reader, sec);
            for(ELFIO::Elf_Xword i{0}; i < dynamic.get_entries_num(); ++i)
            {
                ELFIO::Elf_Xword tag{0};
                ELFIO::Elf_Xword value{0};
                std::string str;
                dynamic.get_entry(i, tag, value, str);
                if(DT_FLAGS == tag && value == DF_BIND_NOW)
                {
                    relro = "Full RELRO";
                    break;
                }
            }
        }
    }
    return relro;
}

std::string ELF::get_canary()
{
    std::string canary{"No canary found"};

    //
    // canary check
    //
    get_symbols();
    for(const auto& [symbol, addr] : symbols)
    {
        if(symbol.find("__stack_chk_fail") != std::string::npos)
        {
            canary = "Canary found";
            break;
        }
    }
    return canary;
}

std::string ELF::get_nx()
{
    std::string nxbit{"NX disabled"};
    for(ELFIO::Elf_Half i = 0; i < reader.segments.size(); ++i)
    {
        ELFIO::segment *seg = reader.segments[i];
        if(PT_GNU_STACK == seg->get_type() && 7 != seg->get_flags())
        {
            nxbit = "NX enabled";
            break;
        }
    }
    return nxbit;
}

std::string ELF::get_pie()
{
    std::string pie;

    if(ET_EXEC == reader.get_type()){pie = "No PIE";}
    else {pie = "Not ELF file";}

    // search dynamic sections
    bool find{false};
    for(ELFIO::Elf_Half i{0}; i < reader.sections.size(); ++i )
    {
        ELFIO::section* sec = reader.sections[i];
        if(SHT_DYNAMIC == sec->get_type())
        {
            find = true;
            ELFIO::dynamic_section_accessor dynamic(reader, sec);
            for(ELFIO::Elf_Xword i{0}; i < dynamic.get_entries_num(); ++i)
            {
                ELFIO::Elf_Xword tag{0};
                ELFIO::Elf_Xword value{0};
                std::string str;
                dynamic.get_entry(i, tag, value, str);
                if(DT_DEBUG == tag)
                {
                    if(ET_DYN == reader.get_type())
                    {
                        pie = "PIE enabled";
                    }
                }
            }
        }
    }
    if(!find)
    {
        if(ET_DYN == reader.get_type())
        {
            pie = "DSO";
        }
    }
    return pie;
}

void ELF::get_symbols()
{
    std::unordered_map<std::string, ELFIO::Elf64_Addr> relocations;
    for(ELFIO::Elf_Half i = 0; i < reader.sections.size(); ++i)
    {
        ELFIO::section* sec = reader.sections[i];
        if(SHT_SYMTAB == sec->get_type() || SHT_DYNSYM == sec->get_type())
        {
            ELFIO::symbol_section_accessor symbol(reader, sec);
            for(ELFIO::Elf_Xword i = 0; i < symbol.get_symbols_num(); ++i)
            {
                std::string name;
                ELFIO::Elf64_Addr value{0};
                ELFIO::Elf_Xword  size{0};
                unsigned char bind{0};
                unsigned char type{0};
                ELFIO::Elf_Half section{0};
                unsigned char other{0};
                symbol.get_symbol(i, name, value, size, bind, type, section, other);
                if(!name.empty())
                {
                    symbols.emplace(name, value);
                }
            }
        }
        // add relocation info
        else if(SHT_RELA == sec->get_type() || SHT_REL == sec->get_type())
        {
            ELFIO::relocation_section_accessor reloc(reader, sec);
            for(ELFIO::Elf_Xword i = 0; i < reloc.get_entries_num(); ++i)
            {
                ELFIO::Elf64_Addr offset{0};
                ELFIO::Elf_Xword info{0};    // index of .dynsym;
                ELFIO::Elf_Word symbol;
                ELFIO::Elf_Word type{0};
                std::string symbolName;
                reloc.get_entry(i, offset, info, symbol, type, symbolName);
                relocations.emplace(symbolName, offset);
            }
        }
    }   // end of for

    for(const auto& [name, address] : relocations)
    {
        if(auto it = symbols.find(name); it != symbols.end())
        {
            it->second = relocations[name];
        }
    }
}

int ELF::got(const std::string& name)
{
    if(symbols.find(name) != symbols.end())
    {
        return symbols[name];
    }
    return 0;
}
