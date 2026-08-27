#pragma once

#include "Network/NetworkEnums.h"

#include <string>

class NetworkPeer {
public:
    enum class DataStatus : int {
        HasData = 0,
        NoData = 1
    };

    enum class Reliability : int {
        Reliable = 0,
        ReliableOrdered = 1,
        Unreliable = 2,
        UnreliableSequenced = 3
    };

    struct NetworkStatus {
        int mCurrentPing;
        int mAveragePing;
        int mCurrentPacketLoss;
        int mAveragePacketLoss;

        NetworkStatus() : mCurrentPing(0), mAveragePing(0), mCurrentPacketLoss(0), mAveragePacketLoss(0) {}
    };

    virtual ~NetworkPeer() = default;

    virtual void sendPacket(const std::string &data, Reliability reliability, Compressibility compressibility) = 0;

    virtual DataStatus receivePacket(std::string &outData) = 0;

    virtual NetworkStatus getNetworkStatus() const = 0;

    virtual void update() {}

    virtual void flush() {}
};
