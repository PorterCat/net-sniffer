#pragma once

#include <optional>
#include <stdexcept>
#include <cstring>
#include <array>

namespace SimpleSniffer
{
enum InetProtocols : uint16_t
{
    None = 0,
    Udp  = 1 << 0,
    Tcp  = 1 << 1,
    All  = 0xFFFF,
};

static InetProtocols ProtocolNameToProtocol(const char *name)
{
    std::array<char, 16> nameBuff;
    nameBuff.fill('\0');
    int n = nameBuff.size() - 1;
    std::strncpy(nameBuff.data(), name, n);
    for (char &c : nameBuff)
        c = std::toupper(c);

    if (std::strncmp("TCP", nameBuff.data(), n) == 0)
        return InetProtocols::Tcp;
    else if (std::strncmp("UDP", nameBuff.data(), n) == 0)
        return InetProtocols::Udp;
    else
        return InetProtocols::None;
}

struct Arguments
{
    std::optional<uint16_t> PortToListen;
    InetProtocols           ProtocolsToListen;
};

static int StoiWithErrorPrefix(const char *str, const char *errorMessagePrefix)
{
    try
    {
        int res = std::stoi(str);
        return res;
    }
    catch (const std::invalid_argument &e)
    {
        std::string parseErrorMsg(e.what());
        std::string errorMsg = errorMessagePrefix + parseErrorMsg;
        throw std::invalid_argument{ errorMsg };
    }
}

static void ParseOption(const char *option, const char *value, Arguments &args)
{
    constexpr const char *PortOption     = "-port";
    constexpr const char *ProtocolOption = "-protocol";

    std::array<char, 16> optionNameBuffer;
    optionNameBuffer.fill('\0');
    int nopt = optionNameBuffer.size() - 1;
    std::strncpy(optionNameBuffer.data(), option, nopt);
    for (char &c : optionNameBuffer)
        c = std::tolower(c);

    std::array<char, 16> valueStringBuffer;
    valueStringBuffer.fill('\0');
    int nval = valueStringBuffer.size() - 1;
    std::strncpy(valueStringBuffer.data(), value, nval);
    for (char &c : valueStringBuffer)
        c = std::tolower(c);

    if (std::strncmp(PortOption, optionNameBuffer.data(), nopt) == 0)
    {
        int port = StoiWithErrorPrefix(value, "Failed to parse port: ");
        if (port < 0 && port > UINT16_MAX)
            throw std::invalid_argument("Port out of bounds");
        args.PortToListen = port;
    }
    else if (std::strncmp(ProtocolOption, optionNameBuffer.data(), nopt) == 0)
    {
        args.ProtocolsToListen = ProtocolNameToProtocol(value);
        if (args.ProtocolsToListen == InetProtocols::None)
        {
            throw std::invalid_argument("Unsupported protocol '" + std::string(value) + '\'');
        }
    }
    else
    {
        throw std::invalid_argument("Unrecognized option '" + std::string(option) + '\'');
    }
}

static Arguments ParseArguments(int argc, char **argv)
{
    Arguments parsedArgs{};
    parsedArgs.PortToListen      = std::nullopt;
    parsedArgs.ProtocolsToListen = InetProtocols::All;
    if (argc == 1)
        return parsedArgs;

    // One or two options
    if (argc == 3 || argc == 5)
    {
        // First option
        ParseOption(argv[1], argv[2], parsedArgs);

        // Second option
        if (argc == 5)
            ParseOption(argv[3], argv[4], parsedArgs);
    }
    else
    {
        std::string programName(argv[0]);
        throw std::invalid_argument(
            "Invalid arguments\n"
            "Usage: '" +
            programName + " -port <value> -protocol <name>'");
    }

    return parsedArgs;
}
} // namespace SimpleSniffer
