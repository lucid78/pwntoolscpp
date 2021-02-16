#ifndef UTILITY_H
#define UTILITY_H

#pragma once
#include <sstream>
#include <iomanip>

#include <boost/endian/buffers.hpp>
#include <boost/format.hpp>

class UTILITY
{
public:
    UTILITY();
    ~UTILITY();
    const std::string p32(const int& number);
    const std::string conv_ascii(std::string hex);
    const std::string hex(const int& addr);
    const std::string str(const int& num);
};

#endif // UTILITY_H
