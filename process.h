#ifndef PROCESS_H
#define PROCESS_H

#pragma once

#include <iostream>
#include <mutex>
#include <string>
#include <boost/process.hpp>
#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <boost/chrono.hpp>

class PROCESS
{
private:
    std::string m_path;
    boost::asio::io_context io;
    boost::process::async_pipe input;
    boost::process::async_pipe output;
    boost::process::async_pipe error;
    boost::process::child c;
    boost::system::error_code ec;

    std::recursive_mutex lock;
    const int buffer_length{4096};

public:
    PROCESS(const std::string& _path);
    PROCESS(const std::string& _path, const std::vector<std::string>& args);
    ~PROCESS();

    const std::string recv_until(const std::string& delim);
    size_t send(const std::string& data);
    size_t send_line(const std::string& data);
    void interactive();

private:
    void init();
    const std::string buffer_to_string(const boost::asio::streambuf &buffer, const size_t& size);
    void read_at_once();
    void locked_output(const std::string& s);
    void dump_hex(const void* data, size_t size);
};

#endif // PROCESS_H