#include <algorithm>
#include <csignal>
#include <iostream>
#include <vector>

#include "ArgumentsParsing.hpp"
#include "NetHelpers.hpp"
#include "PacketsParsing.hpp"

using namespace SimpleSniffer;

bool          gExitRequested    = false;
constexpr int ReceiveBufferSize = UINT16_MAX;

void RequestExit(int) { gExitRequested = true; }

int main(int argc, char **argv)
try
{
    Arguments args = ParseArguments(argc, argv);

    std::vector<uint8_t> receiveBuffer(ReceiveBufferSize);

    std::vector<int> sockets = CreateRawSockets(args.ProtocolsToListen, args.PortToListen);
    std::vector<int> readSockets(sockets.size()), errorSockets(sockets.size());

    sighandler_t signalRes = std::signal(SIGINT, RequestExit);
    if (signalRes == SIG_ERR)
        throw std::runtime_error("Failed to set SIGINT handler");

    PacketsCount packetsCount{};
    while (Select(sockets, readSockets, errorSockets), !gExitRequested)
    {
        for (int errorSocket : errorSockets)
        {
            std::cerr << "Error at socket '" << errorSocket << "':";
            std::cerr << std::strerror(errno) << '\n';

            auto errorSocketIt = std::find(sockets.begin(), sockets.end(), errorSocket);
            sockets.erase(errorSocketIt);
            CloseSocket(errorSocket);
        }

        for (int readSocket : readSockets)
        {
            sockaddr  addr;
            socklen_t saddrSize = sizeof(addr);
            int       received =
                recvfrom(readSocket, receiveBuffer.data(), ReceiveBufferSize, 0, &addr, &saddrSize);
            if (received < 0)
            {
                std::string errnoStr(std::strerror(errno));
                throw std::runtime_error{ "Failed to receive package: " + errnoStr };
            }
            DumpPacket(receiveBuffer, packetsCount, args);
        }
    }
    for (int readSocket : readSockets)
    {
        CloseSocket(readSocket);
    }
    if ((args.ProtocolsToListen & InetProtocols::Udp) != 0)
        std::cout << "Got " << packetsCount.Udp << " UDP packets\n";
    if ((args.ProtocolsToListen & InetProtocols::Tcp) != 0)
        std::cout << "Got " << packetsCount.Tcp << " TCP packets\n";
    std::cout << "Total: " << packetsCount.GetTotal() << '\n';
    return 0;
}
catch (std::exception &err)
{
    std::cerr << "ERROR: " << err.what() << '\n';
    return 1;
}
