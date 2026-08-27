#pragma once

#include "Network/NetworkPeer.h"

#include <memory>

class CompressedNetworkPeer : public NetworkPeer {
public:
    enum class CompressionAlgorithm : unsigned char {
        ZLib = 0,
        Snappy = 1,
        None = 0xff
    };

    static const unsigned char GAME_PACKET_ID = 0xfe;

    explicit CompressedNetworkPeer(std::shared_ptr<NetworkPeer> peer);

    void enableCompression(CompressionAlgorithm algorithm, unsigned short threshold);

    void disableCompression();

    bool isCompressionEnabled() const { return mCompressionEnabled; }

    void sendPacket(const std::string &data, Reliability reliability, Compressibility compressibility) override;

    DataStatus receivePacket(std::string &outData) override;

    NetworkStatus getNetworkStatus() const override;

    void update() override;

    void flush() override;

private:
    static bool _compress(const std::string &input, std::string &outData);

    static bool _decompress(const char *data, size_t length, std::string &outData);

    std::shared_ptr<NetworkPeer> mPeer;
    CompressionAlgorithm mAlgorithm;
    unsigned short mCompressionThreshold;
    bool mCompressionEnabled;
};
