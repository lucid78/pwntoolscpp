#include "elf.h"
#include "elfio/elfio_dump.hpp"

ELF::ELF(const std::string& path) : m_path(path)
{
    if(!reader.load(path))
    {
        std::cerr << "Can't find or process ELF file " << path << std::endl;
        exit(-1);
    }
   
    // ELFIO::dump::header( std::cout, reader );
    // ELFIO::dump::section_headers( std::cout, reader );
    // ELFIO::dump::segment_headers( std::cout, reader );
    // ELFIO::dump::symbol_tables( std::cout, reader );
    // ELFIO::dump::notes( std::cout, reader );
    // ELFIO::dump::modinfo( std::cout, reader );
    // ELFIO::dump::dynamic_tags( std::cout, reader );
    // ELFIO::dump::section_datas( std::cout, reader );
    // ELFIO::dump::segment_datas( std::cout, reader );

    parse_elf();
    check_sec();
}



int ELF::got(const std::string& name)
{
    if(m_gots.find(name) != m_gots.end())
    {
        return m_gots[name];
    }
    return 0;
}

void ELF::got()
{
    for(const auto& [name, addr] : m_gots)
    {
        std::stringstream stream;
        stream << name << std::setw(30 - name.length()) << "0x" << std::hex << addr;
        std::cout << stream.str() << std::endl;
    }
}

int ELF::plt(const std::string& name)
{
    if(m_plts.find(name) != m_plts.end())
    {
        return m_plts[name];
    }
    return 0;
}

void ELF::plt()
{
    for(const auto& [name, addr] : m_plts)
    {
        std::stringstream stream;
        stream << name << std::setw(30 - name.length()) << "0x" << std::hex << addr;
        std::cout << stream.str() << std::endl;
    }
}

int ELF::symbols(const std::string& name)
{
    if(m_symbols.find(name) != m_symbols.end())
    {
        return m_symbols[name];
    }
    return 0;

    // const auto& width{reader.get_class() == ELFCLASS32 ? 8 : 16};
    // for(const auto& [name, addr] : m_symbols)
    // {
    //     std::stringstream stream;
    //     stream << name << std::setw(40 - name.length()) << "0x" << std::setw(width) << std::setfill('0') << std::hex << addr;
    //     std::cout << stream.str() << std::endl;
    // }
}

void ELF::symbols()
{
    const auto& width{reader.get_class() == ELFCLASS32 ? 8 : 16};
    for(const auto& [name, addr] : m_symbols)
    {
        std::stringstream stream;
        stream << name << std::setw(40 - name.length()) << "0x" << std::setw(width) << std::setfill('0') << std::hex << addr;
        std::cout << stream.str() << std::endl;
    }
}

void ELF::address()
{
    std::cout  << "0x" << std::hex << reader.get_entry() << std::endl;
}

const std::string ELF::hex(const int& addr)
{
    std::stringstream stream;
    stream << "0x" << std::setw(8) << std::setfill('0') << std::hex << addr;
    return stream.str();
}

void ELF::functions()
{
    // const auto& width{reader.get_class() == ELFCLASS32 ? 8 : 16};
    for(const auto& [name, func] : m_functions)
    {
        std::stringstream stream;
        stream << name << std::setw(30 - name.length()) << "0x" << std::hex << func.addr << "    0x" << std::hex << func.size;
        std::cout << stream.str() << std::endl;
    }
}

//
// private
//

void ELF::check_sec()
{
    std::cout << "[*] '" << m_path << "'" << std::endl;
    std::cout << "    Arch:     "
    << machines[reader.get_machine()] 
    << "-"
    << (reader.get_class() == ELFCLASS32 ? "32" : "64")
    << "-"
    << endians[reader.get_encoding()]
    << std::endl;

    std::cout << "    RELRO:    " << m_relro << std::endl;
    std::cout << "    Stack:    " << m_canary << std::endl;
    std::cout << "    NX:       " << m_nxbit << std::endl;
    std::cout << "    PIE:      " << m_pie << std::endl;
}

void ELF::parse_elf()
{
    if(ET_EXEC == reader.get_type()){m_pie = "No PIE";}
    else {m_pie = "Not ELF file";}

    // search segment headers
    for(ELFIO::Elf_Half i{0}; i < reader.segments.size(); ++i)
    {
        ELFIO::segment* seg = reader.segments[i];
        if(PT_GNU_RELRO == seg->get_type())
        {
            m_relro = "Partial RELRO";
        }
        else if(PT_GNU_STACK == seg->get_type() && 7 != seg->get_flags())
        {
            m_nxbit = "NX enabled";
        }
        else if(PT_LOAD == seg->get_type() && 5 == seg->get_flags())
        {
            m_vaddr = seg->get_virtual_address();
        }
    }   // end of for


    // get plt information
    ELFIO::Elf_Xword plt_entry_size{0};
    ELFIO::Elf_Xword plt_vma_address{0};
    for(ELFIO::Elf_Half i{0}; i < reader.sections.size(); ++i)
    {
        ELFIO::section* sec = reader.sections[i];
        if(!sec->get_name().compare(".plt"))
        {
            plt_entry_size = sec->get_addr_align();
            plt_vma_address = sec->get_address();
            break;
        }
    }

    // search dynamic sections
    bool find{false};
    std::unordered_map<std::string, ELFIO::Elf64_Addr> relocations;
    for(ELFIO::Elf_Half i{0}; i < reader.sections.size(); ++i)
    {
        ELFIO::section* sec = reader.sections[i];
        switch(sec->get_type())
        {
        case SHT_DYNAMIC:
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
                    m_relro = "Full RELRO";
                }
                else if(DT_DEBUG == tag)
                {
                    find = true;
                    if(ET_DYN == reader.get_type())
                    {
                        m_pie = "PIE enabled";
                    }
                }
            }
            break;
        }
        case SHT_SYMTAB:
        case SHT_DYNSYM:
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
                // std::cout << i << " => [name:" << name << "],[value:" << value << "],[size:" << size << "],[bind:" << (int)bind << "],[type:" << (int)type << "],[section:" << section << "],[other:" << other << "]" << std::endl;
                if(!name.empty())
                {
                    m_symbols.emplace(name, value);
                }

                if(static_cast<int>(type) == STT_FUNC && 0 != size)
                {
                    m_functions.emplace(name, FUNCTION{name, value, size});
                }
            }
            break;
        }
        case SHT_RELA:
        case SHT_REL:
        {
            ELFIO::relocation_section_accessor reloc(reader, sec);
            for(ELFIO::Elf_Xword i = 0; i < reloc.get_entries_num(); ++i)
            {
                ELFIO::Elf64_Addr offset{0};
                ELFIO::Elf_Xword info{0};
                ELFIO::Elf_Word symbol;
                ELFIO::Elf_Word type{0};
                std::string symbolName;
                reloc.get_entry(i, offset, info, symbol, type, symbolName);
                relocations.emplace(symbolName, offset);
                m_plts.emplace(symbolName, plt_vma_address + (i + 1) * plt_entry_size);
            }
            break;
        }
        }   // end of switch
    }   // end of for
    if(!find)
    {
        if(ET_DYN == reader.get_type())
        {
            m_pie = "DSO";
        }
    }

    for(const auto& [name, addr] : relocations)
    {
        if(auto it{m_symbols.find(name)}; it != m_symbols.end())
        {
            it->second = relocations[name];
        }
    }

    static const ELFIO::Elf_Xword MAX_DATA_ENTRIES{64};
    const auto& width{reader.get_class() == ELFCLASS32 ? 4 : 8};
    #define DUMP_HEX_FORMAT( width ) std::setw( width ) << std::setfill( '0' ) << std::hex << std::right
    for(ELFIO::Elf_Half i{0}; i < reader.sections.size(); ++i)
    {
        ELFIO::section* sec = reader.sections[i];
        if(!sec->get_name().compare(".rel.plt"))
        {
            if(const char* pdata{sec->get_data()}; pdata)
            {
                // 4byte씩 읽기
                std::cout << "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::" << std::endl;
                for(ELFIO::Elf_Xword j{0}; j < std::min(sec->get_size(), MAX_DATA_ENTRIES); ++j)
                {
                    // char addr[4] = {0};
                    // memcpy(addr, &pdata + j, 4);
                    // std::cout << "0x" << std::hex << addr << std::endl;


                    // std::cout << " " << DUMP_HEX_FORMAT( 2 ) << ( pdata[j] & 0x000000FF );
                    std::stringstream stream;
                    stream << std::setw(2) << std::setfill('0') << "0x" << pdata[j];
                    std::cout << stream.str() << std::endl;
                }
                std::cout << "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::" << std::endl;
                std::cout << sec->get_name() << " " << sec->get_address() << std::endl;
                m_gots.emplace(sec->get_name(), sec->get_address());
            }
            break;
        }
    }   // end of for




    // ELFIO::Elf_Half n = reader.sections.size();
    // for ( ELFIO::Elf_Half i = 1; i < n; ++i ) { // For all sections
    //     ELFIO::section* sec = reader.sections[i];
    //     if ( sec->get_type() == SHT_NOBITS ) {
    //         continue;
    //     }
    //     if(sec->get_name().compare(".rel.plt")) {continue;}
    //     std::cout << sec->get_name() << std::endl;
    //     const char* pdata = sec->get_data();
    //     if ( pdata ) {
    //         ELFIO::Elf_Xword i;
    //         for ( i = 0; i < std::min( sec->get_size(), MAX_DATA_ENTRIES ); ++i ) {
                
    //             std::cout << " " << DUMP_HEX_FORMAT( 2 ) << ( pdata[i] & 0x000000FF );

                
    //         }
            
    //             std::cout << std::endl;
            
    //     }
    // }







    for(const auto& [symbol, addr] : m_symbols)
    {
        if(symbol.find("__stack_chk_fail") != std::string::npos)
        {
            m_canary = "Canary found";
            break;
        }
    }
}


