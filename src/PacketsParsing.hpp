#pragma once

#include <array>
#include <cstdint>
#include <iostream>
#include <vector>
#include <array>

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

static bool ContainsWord(const uint8_t* data, size_t data_len, const std::string& word) 
{
    if (word.empty() || data_len < word.size()) return false;
    return std::search(
        data, data + data_len,
        word.begin(), word.end()
    ) != (data + data_len);
}

static void DumpPacket(const std::vector<uint8_t> &data, PacketsCount &packetsCount, Arguments args)
{
    const iphdr* ipHeader = reinterpret_cast<const iphdr*>(data.data());
    
    size_t ipHeaderSize = ipHeader->ihl * 4;
    if (data.size() < ipHeaderSize) return;

    const uint8_t* transportHeader = data.data() + ipHeaderSize;
    const uint8_t* payload = transportHeader;
    size_t payloadSize = data.size() - ipHeaderSize;

    const char* protoName = "";
    uint16_t srcPort = 0, dstPort = 0;
    size_t transportHeaderSize = 0;

    if (ipHeader->protocol == IPPROTO_UDP) {
        protoName = "UDP";
        const udphdr* udp = reinterpret_cast<const udphdr*>(transportHeader);
        srcPort = ntohs(udp->uh_sport);
        dstPort = ntohs(udp->uh_dport);
        transportHeaderSize = sizeof(udphdr);
    } 
    else if (ipHeader->protocol == IPPROTO_TCP) {
        protoName = "TCP";
        const tcphdr* tcp = reinterpret_cast<const tcphdr*>(transportHeader);
        srcPort = ntohs(tcp->th_sport);
        dstPort = ntohs(tcp->th_dport);
        transportHeaderSize = tcp->th_off * 4;
    }
    
    if (data.size() >= ipHeaderSize + transportHeaderSize) 
    {
        payload = transportHeader + transportHeaderSize;
        payloadSize = data.size() - ipHeaderSize - transportHeaderSize;
    }

    if (!ShouldCount(dstPort, args)) return;
    
    bool wordOK = true;
    if (args.WordToSearch) {
        wordOK = ContainsWord(payload, payloadSize, *args.WordToSearch);
    }

    if (wordOK) 
    {
        std::array<char, INET_ADDRSTRLEN> srcAddr{}, dstAddr{};
        inet_ntop(AF_INET, &ipHeader->saddr, srcAddr.data(), srcAddr.size());
        inet_ntop(AF_INET, &ipHeader->daddr, dstAddr.data(), dstAddr.size());

        (ipHeader->protocol == IPPROTO_UDP ? packetsCount.Udp : packetsCount.Tcp)++;
        DumpTransportPacket(
            protoName,
            srcAddr.data(),
            srcPort,
            dstAddr.data(),
            dstPort,
            data.size()
        );
    }
}

} // namespace SimpleSniffer
