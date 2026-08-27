#pragma once

#include "Network/NetworkPeer.h"

#include <deque>
#include <memory>

class BatchedNetworkPeer : public NetworkPeer {
public:
    explicit BatchedNetworkPeer(std::shared_ptr<NetworkPeer> peer);

    void sendPacket(const std::string &data, Reliability reliability, Compressibility compressibility) override;

    DataStatus receivePacket(std::string &outData) override;

    NetworkStatus getNetworkStatus() const override;

    void update() override;

    void flush() override;

private:
    bool _unbatch(const std::string &batch);

    std::shared_ptr<NetworkPeer> mPeer;

    static const size_t MAX_BATCH_SIZE = 1024 * 1024;

    std::string mBatchBuffer;
    Reliability mBatchReliability;
    Compressibility mBatchCompressibility;

    std::deque<std::string> mIncomingPackets;
};
