#pragma once

#include "Network/NetworkIdentifier.h"
#include "Network/NetworkPeer.h"

#include <rtc/rtc.hpp>

#include <deque>
#include <memory>
#include <mutex>
#include <string>

namespace nethernet {
    extern const size_t MAX_MESSAGE_SIZE;
    extern const char *RELIABLE_CHANNEL_LABEL;
    extern const char *UNRELIABLE_CHANNEL_LABEL;

    enum class ChannelReliability : int {
        Reliable = 0,
        Unreliable = 1,
        Count = 2
    };

    class Connection : public NetworkPeer, public std::enable_shared_from_this<Connection> {
    public:
        Connection(const NetworkIdentifier &id, std::shared_ptr<rtc::PeerConnection> peerConnection);

        ~Connection() override;

        void sendPacket(const std::string &data, Reliability reliability, Compressibility compressibility) override;

        DataStatus receivePacket(std::string &outData) override;

        NetworkStatus getNetworkStatus() const override;

        const NetworkIdentifier &getNetworkIdentifier() const { return mId; }

        bool attachChannel(const std::shared_ptr<rtc::DataChannel> &channel);

        bool areChannelsReady() const;

        bool isClosed() const;

        void close();

    private:
        struct ChannelState {
            std::shared_ptr<rtc::DataChannel> mChannel;
            std::string mBuffer;
            unsigned char mSegments = 0;
            bool mOpen = false;
        };

        void _markOpen(ChannelReliability reliability);

        void _onBinary(ChannelReliability reliability, const std::byte *data, size_t size);

        void _fail(const std::string &reason);

        NetworkIdentifier mId;
        std::shared_ptr<rtc::PeerConnection> mPeerConnection;

        mutable std::mutex mMutex;
        ChannelState mChannels[(int) ChannelReliability::Count];
        std::deque<std::string> mIncoming;
        std::mutex mWriteMutex;
        bool mClosed;
    };
}
