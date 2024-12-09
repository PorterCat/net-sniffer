#pragma once

#include <array>
#include <cstdint>
#include <iostream>
#include <vector>

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <arpa/inet.h>
#include "ArgumentsParsing.hpp"

namespace SimpleSniffer
{
struct PacketsCount
{
    size_t Udp, Tcp;
    size_t GetTotal() { return Udp + Tcp; }
};

static bool ShouldCount(uint16_t dstPort, Arguments args)
{
    return !(args.PortToListen.has_value() && ntohs(dstPort) != args.PortToListen.value());
}

static void DumpTransportPacket(
    const char *name, const char *srcIp, uint16_t srcPort, const char *dstIp, uint16_t dstPort, size_t size)
{
    std::cout << "Received " << name << " packet " << srcIp << ':' << srcPort
              << " > " << dstIp << ':' << dstPort << " of size " << size << '\n';
}

static void DumpPacket(const std::vector<uint8_t> &data, PacketsCount &packetsCount, Arguments args)
{
    const iphdr *ipHeader = reinterpret_cast<const iphdr *>(data.data());
    
    std::array<char, 64> srcAddrBuff, dstAddrBuff;
    srcAddrBuff.fill('\0');
    inet_ntop(AF_INET, &ipHeader->saddr, srcAddrBuff.data(), srcAddrBuff.size());
    dstAddrBuff.fill('\0');
    inet_ntop(AF_INET, &ipHeader->daddr, dstAddrBuff.data(), dstAddrBuff.size());

    uint16_t    ipHeaderSize              = ipHeader->ihl * 4;
    const void *transportProtoHeaderStart = data.data() + ipHeaderSize;
    if (ipHeader->protocol == IPPROTO_UDP)
    {
        const udphdr *udpHeader = reinterpret_cast<const udphdr *>(transportProtoHeaderStart);
        if (ShouldCount(udpHeader->uh_dport, args))
        {
            packetsCount.Udp++;
            DumpTransportPacket(
                "UDP",
                srcAddrBuff.data(),
                ntohs(udpHeader->uh_sport),
                dstAddrBuff.data(),
                ntohs(udpHeader->uh_dport),
                ntohs(ipHeader->tot_len));
        }
    }
    else if (ipHeader->protocol == IPPROTO_TCP)
    {
        const tcphdr *tcpHeader = reinterpret_cast<const tcphdr *>(transportProtoHeaderStart);
        if (ShouldCount(tcpHeader->th_dport, args))
        {
            packetsCount.Tcp++;
            DumpTransportPacket(
                "TCP",
                srcAddrBuff.data(),
                ntohs(tcpHeader->th_sport),
                dstAddrBuff.data(),
                ntohs(tcpHeader->th_dport),
                ntohs(ipHeader->tot_len));
        }
    }
}
} // namespace SimpleSniffer
