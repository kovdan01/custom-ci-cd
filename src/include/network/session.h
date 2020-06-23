#ifndef NETWORK_SESSION_H
#define NETWORK_SESSION_H

#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/http.hpp>

#include <memory>
#include <mutex>

namespace my
{

using boost::asio::ip::tcp;
using boost::beast::http::response;
using boost::beast::http::string_body;

class Session : public std::enable_shared_from_this<Session>
{
public:
    Session(tcp::socket socket);
    void start();

private:
    struct SessionData
    {
        std::shared_ptr<std::string> repo;
        std::shared_ptr<std::string> branch;
        std::shared_ptr<std::string> params;
    };

    enum class Distributive
    {
        ARCH_LINUX_BASE,
    };

    std::optional<SessionData> get_data();

    std::string get_build_config(const std::shared_ptr<std::string>& repo,
                                 const std::shared_ptr<std::string>& branch);

    Distributive convert_distrib_name(const std::string& name);

    std::string process_build_config(const std::string& repo, const std::string& branch, const std::string& env_vars_json,
                                     const std::string& build_config, std::ostream& stream);

    void run_docker(const std::string& distrib, const std::string& command_filename);

    void do_read();
    void do_write(const std::string& str);

    tcp::socket m_socket;

    static constexpr std::size_t BUFFER_SIZE = 1024;
    char m_buffer[BUFFER_SIZE];
    std::string m_temp_str;

    std::mutex m_filename_check_lock;
};

} // namespace my

#endif // NETWORK_SESSION_H
