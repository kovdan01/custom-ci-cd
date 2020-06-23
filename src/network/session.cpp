#include "network/session.h"
#include "utils/thread_pool.h"
#include "utils/json.hpp"

#include <boost/asio/ssl.hpp>
#include <boost/asio/connect.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/version.hpp>
#include <boost/process/child.hpp>
#include <boost/process/io.hpp>

#include <iostream>
#include <optional>
#include <filesystem>

namespace my
{

Session::Session(tcp::socket socket)
    : m_socket(std::move(socket))
{
}

void Session::start()
{
    do_read();
}

std::uint16_t read_uint16(char* buffer)
{
    union
    {
        char buf[2];
        std::uint16_t val;
    };
    buf[0] = buffer[0];
    buf[1] = buffer[1];
    return val;
}

std::uint32_t read_uint32(char* buffer)
{
    union
    {
        char buf[4];
        std::uint32_t val;
    };
    buf[0] = buffer[0];
    buf[1] = buffer[1];
    buf[2] = buffer[2];
    buf[3] = buffer[3];
    return val;
}

std::optional<Session::SessionData> Session::get_data()
{
    constexpr std::size_t REPO_SIZE_BYTES = 2;
    constexpr std::size_t BRANCH_SIZE_BYTES = 2;
    constexpr std::size_t JSON_SIZE_BYTES = 4;

    auto check_size = [this](std::size_t size) -> bool
    {
        return (size <= m_temp_str.size());
    };

    std::size_t   repo_size_begin   = 0;
    std::size_t   repo_data_begin   = REPO_SIZE_BYTES;
    if (!check_size(repo_data_begin))
        return std::nullopt;

    std::uint16_t repo_size         = read_uint16(m_temp_str.data() + repo_size_begin);
    std::size_t   branch_size_begin = repo_data_begin + repo_size;
    std::size_t   branch_data_begin = branch_size_begin + BRANCH_SIZE_BYTES;
    if (!check_size(branch_data_begin))
        return std::nullopt;

    std::uint16_t branch_size       = read_uint16(m_temp_str.data() + branch_size_begin);
    std::size_t   json_size_begin   = branch_data_begin + branch_size;
    std::size_t   json_data_begin   = json_size_begin + JSON_SIZE_BYTES;
    if (!check_size(json_data_begin))
        return std::nullopt;

    std::uint32_t json_size         = read_uint32(m_temp_str.data() + json_size_begin);
    if (!check_size(json_data_begin + json_size))
        return std::nullopt;

    auto repo   = std::make_shared<std::string>(m_temp_str.data() + repo_data_begin,   repo_size);
    auto branch = std::make_shared<std::string>(m_temp_str.data() + branch_data_begin, branch_size);
    auto json   = std::make_shared<std::string>(m_temp_str.data() + json_data_begin,   json_size);

    return SessionData{std::move(repo), std::move(branch), std::move(json)};
}

struct HttpException : public std::exception
{
};

std::string Session::get_build_config(const std::shared_ptr<std::string>& repo,
                                      const std::shared_ptr<std::string>& branch)
{
    static const std::string github_host = "raw.githubusercontent.com";
    const std::string path = "/" + *repo + "/" + *branch + "/.build-config.json";

    namespace ba = boost::asio;
    ba::io_context io_context;
    ba::ip::tcp::resolver resolver(io_context);
    ba::ssl::context ctx(ba::ssl::context::sslv23);
    ctx.set_default_verify_paths();

    ba::ssl::stream<ba::ip::tcp::socket> socket(io_context, ctx);
    ba::connect(socket.lowest_layer(), resolver.resolve(github_host, "https"));

    socket.lowest_layer().set_option(ba::ip::tcp::no_delay(true));
    socket.set_verify_mode(ba::ssl::verify_peer);
    socket.set_verify_callback(ba::ssl::rfc2818_verification(github_host));
    socket.handshake(ba::ssl::stream<boost::asio::ip::tcp::socket>::client);

    namespace http = boost::beast::http;
    http::request<http::string_body> request(http::verb::get, path, 11);
    request.set(http::field::host, github_host);
    request.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
    http::write(socket, request);

    boost::beast::flat_buffer buffer;
    http::response<http::string_body> response;
    http::read(socket, buffer, response);

    unsigned int result_int = response.result_int();
    if (result_int / 100 != 2 && result_int / 100 != 3) // fail
    {
        std::ostringstream msg;
        msg << "HTTP Error when connecting to " << github_host << path << std::endl;
        msg << "Result: " << response.result() << std::endl;
        msg << "Body:" << std::endl << response.body() << std::endl;
        do_write(msg.str());
        throw HttpException{};
    }

    return response.body();
}

struct UnknownDistrib : public std::exception
{
};

Session::Distributive Session::convert_distrib_name(const std::string& name)
{
    if (name == "arch")
        return Distributive::ARCH_LINUX_BASE;
    // some other distros...

    do_write("Unknown distributive name " + name + "\n");
    throw UnknownDistrib{};
}

struct JsonKeyAbsence : public std::exception
{
};

std::string Session::process_build_config(const std::string& repo, const std::string& branch, const std::string& env_vars_json,
                                          const std::string& build_config, std::ostream& stream)
{
    nlohmann::json config;
    {
        std::stringstream sstream;
        sstream << build_config;
        sstream >> config;
    }
    nlohmann::json env_vars;
    {
        std::stringstream sstream;
        sstream << env_vars_json;
        sstream >> env_vars;
    }

    std::map<std::string, std::string> private_vars = env_vars;
    for (const auto& [var, value] : private_vars)
        stream << "export " << var << "=" << value << " && ";

    auto check_key = [this, &config](const std::string& key) -> void
    {
        if (!config.contains(key))
        {
            do_write("Error: .build-config.json should contain " + key + " key\n");
            throw JsonKeyAbsence{};
        }
    };

    const std::string distrib_key    = "distrib";
    const std::string pre_build_key  = "pre-build";
    const std::string build_key      = "build";
    const std::string post_build_key = "post-build";

    check_key(distrib_key);
    check_key(pre_build_key);
    check_key(build_key);
    check_key(post_build_key);

    Distributive distrib = convert_distrib_name(config[distrib_key]);

    std::vector<std::string> public_vars = { "export CI_CD_BRANCH=" + branch };
    std::vector<std::string> init;

    switch (distrib)
    {
    case Distributive::ARCH_LINUX_BASE:
        init = { "pacman -Sy --noconfirm", "pacman -S git --noconfirm" };
        break;
    }

    std::vector<std::string> pre_build   = config[pre_build_key];
    std::vector<std::string> sources     = { "git clone --single-branch --branch " + branch + " https://github.com/" + repo + ".git repo",
                                             "cd repo"};
    std::vector<std::string> build       = config[build_key];
    std::vector<std::string> post_build  = config[post_build_key];

    auto add_group = [&stream](const std::string& group_name, const std::vector<std::string>& elements)
    {
        stream << "echo && echo " << group_name << " && echo && ";
        for (const std::string& cmd : elements)
        {
            stream << "echo \\> '" << cmd << "' && ";
            stream << cmd << " && ";
        }
    };

    add_group("SET PUBLIC ENV VARIABLES", public_vars);
    add_group("INIT DOCKER",              init);
    add_group("PRE-BUILD ACTIONS",        pre_build);
    add_group("GETTING SOURCES",          sources);
    add_group("BUILD ACTIONS",            build);
    add_group("POST-BUILD ACTIONS",       post_build);

    stream << "exit\n";

    switch (distrib)
    {
    case Distributive::ARCH_LINUX_BASE:
        return "archlinux";
    }

    // Suppress compiler warning "control reaches end of non-void function"
    std::terminate();
}

void Session::run_docker(const std::string& distrib, const std::string& command_filename)
{
    namespace bp = boost::process;
    bp::ipstream out;
    bp::ipstream err;

    bp::child docker("docker run -i " + distrib, bp::std_out > out, bp::std_err > err, bp::std_in < command_filename);

    std::string line;
    while (docker.running() && std::getline(out, line))
        do_write(line + "\n");

    docker.wait();
    std::stringstream err_sstream;
    err_sstream << err.rdbuf();
    if (!err_sstream.str().empty())
        do_write("STDERR: " + err_sstream.str() + "\n");
}

void Session::do_read()
{
    auto self(shared_from_this());
    m_socket.async_read_some(boost::asio::buffer(m_buffer, BUFFER_SIZE),
        [this, self](boost::system::error_code ec, std::size_t length)
        {
            if (ec)
                return;

            m_temp_str += std::string(m_buffer, length);
            std::optional<SessionData> opt_data = get_data();
            if (opt_data == std::nullopt) // not all data received
            {
                do_read();
                return;
            }

            auto repo   = opt_data->repo;
            auto branch = opt_data->branch;
            auto json   = opt_data->params;

            auto job = [this, repo, branch, json, self]()
            {
                std::string build_config;
                try
                {
                    build_config = get_build_config(repo, branch);
                }
                catch (const HttpException&)
                {
                    return;
                }

                std::string distrib;
                const std::string command_filename = "commands";
                std::filesystem::path command_filename_path(command_filename);
                {
                    std::ofstream command_file;
                    {
                        std::size_t i = 0;
                        std::lock_guard lock(m_filename_check_lock);
                        while (std::filesystem::exists(command_filename_path))
                        {
                            ++i;
                            command_filename_path = command_filename + std::to_string(i);
                        }
                        command_file.open(command_filename_path);
                    }
                    try
                    {
                        distrib = process_build_config(*repo, *branch, *json, build_config, command_file);
                    }
                    catch (const nlohmann::json::exception&)
                    {
                        do_write("File .build-config.json is not a valid build configuration!\n");
                        std::filesystem::remove(command_filename_path);
                        return;
                    }
                    catch (const UnknownDistrib&)
                    {
                        std::filesystem::remove(command_filename_path);
                        return;
                    }
                    catch (const JsonKeyAbsence&)
                    {
                        std::filesystem::remove(command_filename_path);
                        return;
                    }
                }
                run_docker(distrib, command_filename);
                std::filesystem::remove(command_filename_path);
            };

            progschj::ThreadPool::get_instance()->enqueue(job);
        });
}

void Session::do_write(const std::string& str)
{
    auto self(shared_from_this());
    boost::asio::async_write(m_socket, boost::asio::buffer(str.c_str(), str.size()),
        [self](boost::system::error_code /*ec*/, std::size_t /*length*/)
        {
        });
}

} // namespace my
