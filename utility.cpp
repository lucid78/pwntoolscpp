
#include "utility.h"

UTILITY::UTILITY(){}
UTILITY::~UTILITY(){}

const std::string UTILITY::conv_ascii(std::string hex)
{
    std::string ascii{""};
    for(size_t i = 0; i < hex.length(); i += 2)
    {
        const auto part{hex.substr(i, 2)};
        char ch = stoul(part, nullptr, 16);
        ascii += ch;
    }
    return ascii;
}

const std::string UTILITY::p32(const int& number)
{
    const int reversed{boost::endian::endian_reverse(number)};
    return conv_ascii((boost::format("%x") % reversed).str());
}

