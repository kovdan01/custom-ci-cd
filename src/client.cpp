#include "data/serialization.h"

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/write.hpp>
#include <boost/program_options.hpp>

#include <iostream>
#include <utility>
#include <fstream>
#include <sstream>

struct Context
{
    std::string ip;
    short port;
    std::string repo;
    std::string branch;
    std::string env_json_filename;
};

struct Help : public std::exception
{
};

struct Error : public std::exception
{
};

Context parse_command_options(int argc, char* argv[])
{
    namespace po = boost::program_options;
    po::options_description opt_desc("Allowed options");
    opt_desc.add_options()
        ("help",                                                                  "Print this message")
        ("ip",     po::value<std::string>()->required(),                          "Server ip")
        ("port",   po::value<short>()->required(),                                "Server port")
        ("repo",   po::value<std::string>()->required(),                          "Github repository in format <user>/<repo>")
        ("branch", po::value<std::string>()->required()->default_value("master"), "Repository branch")
        ("env",    po::value<std::string>(),                                      "Json filename with environment variables (e.g. tokens)")
    ;

    po::variables_map var_map;
    try
    {
        auto parsed = po::command_line_parser(argc, argv)
            .options(opt_desc)
            .run();
        po::store(parsed, var_map);
        if (var_map.count("help") != 0)
        {
            std::cout << opt_desc << "\n";
            throw Help{};
        }
        po::notify(var_map);
    }
    catch (const po::error& error)
    {
        std::cerr << "Error while parsing command-line arguments: "
                  << error.what() << "\nPlease use --help to see help message\n";
        throw Error{};
    }

    std::string ip     = var_map["ip"].    as<std::string>();
    short       port   = var_map["port"].  as<short>();
    std::string repo   = var_map["repo"].  as<std::string>();
    std::string branch = var_map["branch"].as<std::string>();
    std::string env_json_filename;
    if (var_map.count("env") != 0)
        env_json_filename = var_map["env"].as<std::string>();

    return Context{std::move(ip), port, std::move(repo), std::move(branch), std::move(env_json_filename)};
}

int main(int argc, char* argv[]) try
{
    Context context;
    try
    {
        context = parse_command_options(argc, argv);
    }
    catch (const Help&)
    {
        return 0;
    }
    catch (const Error&)
    {
        return 1;
    }

    std::string json_content;
    {
        std::ifstream istream(context.env_json_filename);
        std::stringstream buffer;
        buffer << istream.rdbuf();
        json_content = buffer.str();
    }

    namespace ba = boost::asio;
    std::locale::global(std::locale(""));

    try
    {
        ba::io_context io_context;

        ba::ip::tcp::endpoint ep(ba::ip::address::from_string(context.ip), context.port);
        ba::ip::tcp::socket sock(io_context);

        sock.connect(ep);

        std::size_t repo_size = context.repo.size();
        std::size_t branch_size = context.branch.size();
        std::size_t json_size = json_content.size();

        if (repo_size   > std::numeric_limits<my::repo_sizeof_t>::max())
            throw std::invalid_argument("Too long repository name");
        if (branch_size > std::numeric_limits<my::branch_sizeof_t>::max())
            throw std::invalid_argument("Too long branch name");
        if (json_size   > std::numeric_limits<my::json_sizeof_t>::max())
            throw std::invalid_argument("Too big json file");

        std::string repo_size_str  (my::write_bytes(static_cast<my::repo_sizeof_t>  (repo_size)).  data(), sizeof(my::repo_sizeof_t));
        std::string branch_size_str(my::write_bytes(static_cast<my::branch_sizeof_t>(branch_size)).data(), sizeof(my::branch_sizeof_t));
        std::string json_size_str  (my::write_bytes(static_cast<my::json_sizeof_t>  (json_size)).  data(), sizeof(my::json_sizeof_t));
        std::string query = repo_size_str + context.repo + branch_size_str + context.branch + json_size_str + json_content;

        ba::write(sock, ba::buffer(query, query.size()));

        boost::system::error_code ec;
        while (!ec)
        {
            char data[1024];
            size_t len = sock.read_some(ba::buffer(data), ec);
            std::cout << std::string{data, len};
            std::cout.flush();
        }
    }
    catch (const boost::system::system_error& e)
    {
        std::cout << e.what() << std::endl;
        return 1;
    }

    return 0;
}
catch (const std::exception& e)
{
    std::cerr << e.what() << '\n';
    return 1;
}
