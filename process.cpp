
#include "process.h"

PROCESS::PROCESS(const std::string& _path)
    : m_path(_path),
      input(io),
      output(io),
      error(io),
      c(m_path,
        boost::process::std_out > output,
        boost::process::std_in < input,
        boost::process::std_err > error,
        io)
{
    init();
}

PROCESS::PROCESS(const std::string& _path, const std::vector<std::string>& args)
    : m_path(_path),
      input(io),
      output(io),
      error(io),
      c(m_path,
        boost::process::args(args),
        boost::process::std_out > output,
        boost::process::std_in < input,
        boost::process::std_err > error,
        io)
{
    init();
}

PROCESS::~PROCESS()
{
    std::cout << "[*] Stopping process... pid is " << std::to_string(c.id()) << std::endl;
    c.terminate();
}

const std::string PROCESS::recv_until(const std::string& delim)
{
    std::string str;
    boost::asio::streambuf buf;
    buf.prepare(buffer_length);
    if(const auto size{boost::asio::read_until(output, buf, delim, ec)}; size != 0)
    {
        if(ec && ec != boost::asio::error::eof)
        {
            throw boost::system::system_error(ec);
        }
        str += buffer_to_string(buf, size);
        buf.consume(size);
    }
    return str;
}

size_t PROCESS::send(const std::string& data)
{
    const auto length{boost::asio::write(input, boost::asio::buffer(data, data.length()), ec)};
    if(ec && ec != boost::asio::error::eof){throw boost::system::system_error(ec);}
    
    std::lock_guard<std::recursive_mutex> guard(lock);
    std::stringstream stream;
    stream << "0x" << std::hex << length;
    std::cout << std::endl;
    std::cout << "Sent " << std::hex << stream.str() << " bytes:" << std::endl;
    dump_hex(data.c_str(), data.size());
    
    return length;
}

size_t PROCESS::send_line(const std::string& data)
{
    auto str{data};
    str.append("\n");
    return send(str);
}

void PROCESS::interactive()
{
    locked_output("[*] Switching to interactive mode");
    while(true)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        lock.lock();
        std::cout << "$ ";
        lock.unlock();

        std::string s;
        std::getline(std::cin, s);
        if(s.empty()) continue;
        send_line(s);
        read_at_once();
    }
}

void PROCESS::init()
{
    std::cout << "[*] Starting process... pid is " << std::to_string(c.id()) << std::endl;
    // read_at_once();
    io.run();
}

const std::string PROCESS::buffer_to_string(const boost::asio::streambuf &buffer, const size_t& size)
{
    return {buffers_begin(buffer.data()), buffers_begin(buffer.data()) + size};
}

void PROCESS::read_at_once()
{
    boost::thread out_thread([&]()
    {
        boost::asio::streambuf buf;
        buf.prepare(buffer_length);
        if(const auto size{boost::asio::read(output, buf, boost::asio::transfer_at_least(1), ec)}; size != 0)
        {
            locked_output(buffer_to_string(buf, size));
            buf.consume(size);
        }
    });
    out_thread.try_join_for(boost::chrono::milliseconds(200));
    
    boost::thread error_thread([&]()
    {
        boost::asio::streambuf buf;
        buf.prepare(buffer_length);
        if(const auto size{boost::asio::read(error, buf, boost::asio::transfer_at_least(10), ec)}; size != 0)
        {
            locked_output(buffer_to_string(buf, size));
            buf.consume(size);
        }
    });
    error_thread.try_join_for(boost::chrono::milliseconds(200));
}

void PROCESS::locked_output(const std::string& s)
{
    std::lock_guard<std::recursive_mutex> guard(lock);
    std::cout << s << std::endl;
}

void PROCESS::dump_hex(const void* data, size_t size)
{
    char ascii[17] = {0};
    for(size_t i = 0; i < size; ++i)
    {
        printf("%02X ", ((unsigned char*)data)[i]);
        if(((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~')
        {
            ascii[i % 16] = ((unsigned char*)data)[i];
        }
        else
        {
            ascii[i % 16] = '.';
        }
        if((i+1) % 8 == 0 || i+1 == size)
        {
            printf(" ");
            if ((i+1) % 16 == 0)
            {
                printf("|  %s \n", ascii);
            }
            else if (i+1 == size)
            {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8)
                {
                    printf(" ");
                }
                for (size_t j = (i+1) % 16; j < 16; ++j)
                {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
    std::cout << std::endl;
}