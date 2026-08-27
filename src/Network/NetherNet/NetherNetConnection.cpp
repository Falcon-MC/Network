#include "Network/NetherNet/NetherNetConnection.h"

#include "Core/Debug/BedrockLog.h"

namespace nethernet {

    const size_t MAX_MESSAGE_SIZE = 262143;
    const char *RELIABLE_CHANNEL_LABEL = "ReliableDataChannel";
    const char *UNRELIABLE_CHANNEL_LABEL = "UnreliableDataChannel";

    namespace {
        const size_t MAX_SEGMENTS = 256;
    }

    Connection::Connection(const NetworkIdentifier &id, std::shared_ptr<rtc::PeerConnection> peerConnection)
            : mId(id), mPeerConnection(std::move(peerConnection)), mClosed(false) {
    }

    Connection::~Connection() {
        close();
    }

    bool Connection::attachChannel(const std::shared_ptr<rtc::DataChannel> &channel) {
        const std::string label = channel->label();
        const rtc::Reliability reliability = channel->reliability();

        ChannelReliability kind;

        if (label == RELIABLE_CHANNEL_LABEL) {
            if (reliability.unordered || reliability.maxRetransmits.has_value() ||
                reliability.maxPacketLifeTime.has_value())
                return false;

            kind = ChannelReliability::Reliable;
        } else if (label == UNRELIABLE_CHANNEL_LABEL) {
            if (!reliability.maxRetransmits.has_value() || reliability.maxRetransmits.value() != 0 ||
                reliability.maxPacketLifeTime.has_value())
                return false;

            kind = ChannelReliability::Unreliable;
        } else {
            return false;
        }

        {
            std::lock_guard<std::mutex> lock(mMutex);

            if (mClosed || mChannels[(int) kind].mChannel != nullptr)
                return false;

            mChannels[(int) kind].mChannel = channel;
            mChannels[(int) kind].mOpen = channel->isOpen();
        }

        std::weak_ptr<Connection> self = shared_from_this();

        channel->onOpen([self, kind]() {
            const std::shared_ptr<Connection> connection = self.lock();
            if (connection == nullptr)
                return;

            connection->_markOpen(kind);
        });

        channel->onClosed([self, kind]() {
            const std::shared_ptr<Connection> connection = self.lock();
            if (connection == nullptr)
                return;

            connection->_fail(kind == ChannelReliability::Reliable
                              ? "ReliableDataChannel closed by remote peer"
                              : "UnreliableDataChannel closed by remote peer");
        });

        channel->onMessage([self, kind](rtc::binary data) {
                               const std::shared_ptr<Connection> connection = self.lock();
                               if (connection == nullptr)
                                   return;

                               connection->_onBinary(kind, data.data(), data.size());
                           },
                           [self](rtc::string) {
                               const std::shared_ptr<Connection> connection = self.lock();
                               if (connection == nullptr)
                                   return;

                               connection->_fail("unexpected text message on data channel");
                           });

        return true;
    }

    void Connection::_markOpen(ChannelReliability reliability) {
        std::lock_guard<std::mutex> lock(mMutex);
        mChannels[(int) reliability].mOpen = true;
    }

    void Connection::_onBinary(ChannelReliability reliability, const std::byte *data, size_t size) {
        if (size < 2) {
            _fail("data channel message shorter than 2 bytes");
            return;
        }

        const unsigned char segments = (unsigned char) data[0];

        if (reliability == ChannelReliability::Unreliable && segments > 0) {
            _fail("unexpected segment count on UnreliableDataChannel");
            return;
        }

        bool invalidSegments = false;

        {
            std::lock_guard<std::mutex> lock(mMutex);

            if (mClosed)
                return;

            ChannelState &state = mChannels[(int) reliability];

            if (state.mSegments > 0 && (unsigned char) (state.mSegments - 1) != segments) {
                invalidSegments = true;
            } else {
                state.mSegments = segments;
                state.mBuffer.append((const char *) data + 1, size - 1);

                if (segments == 0) {
                    mIncoming.push_back(std::string());
                    mIncoming.back().swap(state.mBuffer);
                }
            }
        }

        if (invalidSegments)
            _fail("invalid promised segments");
    }

    void Connection::sendPacket(const std::string &data, Reliability reliability, Compressibility compressibility) {
        (void) reliability;
        (void) compressibility;

        std::shared_ptr<rtc::DataChannel> channel;

        {
            std::lock_guard<std::mutex> lock(mMutex);

            if (mClosed)
                return;

            channel = mChannels[(int) ChannelReliability::Reliable].mChannel;
        }

        if (channel == nullptr || !channel->isOpen())
            return;

        size_t totalSegments = (data.size() + MAX_MESSAGE_SIZE - 1) / MAX_MESSAGE_SIZE;
        if (totalSegments == 0)
            totalSegments = 1;

        if (totalSegments > MAX_SEGMENTS) {
            LOG_ERROR(LogAreaID::Network, "NetherNet message of %zu bytes requires %zu segments (max %zu)",
                      data.size(), totalSegments, MAX_SEGMENTS);
            return;
        }

        std::lock_guard<std::mutex> lock(mWriteMutex);

        size_t remaining = totalSegments - 1;
        size_t offset = 0;

        for (size_t index = 0; index < totalSegments; index++) {
            size_t length = data.size() - offset;
            if (length > MAX_MESSAGE_SIZE)
                length = MAX_MESSAGE_SIZE;

            std::string segment;
            segment.reserve(length + 1);
            segment.push_back((char) (unsigned char) remaining);
            segment.append(data, offset, length);

            if (!channel->send((const std::byte *) segment.data(), segment.size())) {
                LOG_WARN(LogAreaID::Network, "NetherNet segment could not be queued for %s",
                         mId.toString().c_str());
            }

            offset += length;

            if (remaining > 0)
                remaining--;
        }
    }

    NetworkPeer::DataStatus Connection::receivePacket(std::string &outData) {
        std::lock_guard<std::mutex> lock(mMutex);

        if (mIncoming.empty())
            return DataStatus::NoData;

        outData = std::move(mIncoming.front());
        mIncoming.pop_front();
        return DataStatus::HasData;
    }

    NetworkPeer::NetworkStatus Connection::getNetworkStatus() const {
        return NetworkStatus();
    }

    bool Connection::areChannelsReady() const {
        std::lock_guard<std::mutex> lock(mMutex);

        for (int i = 0; i < (int) ChannelReliability::Count; i++) {
            if (mChannels[i].mChannel == nullptr || !mChannels[i].mOpen)
                return false;
        }

        return true;
    }

    bool Connection::isClosed() const {
        std::lock_guard<std::mutex> lock(mMutex);
        return mClosed;
    }

    void Connection::_fail(const std::string &reason) {
        {
            std::lock_guard<std::mutex> lock(mMutex);

            if (mClosed)
                return;
        }

        LOG_WARN(LogAreaID::Network, "NetherNet connection %s failed: %s", mId.toString().c_str(), reason.c_str());
        close();
    }

    void Connection::close() {
        std::shared_ptr<rtc::DataChannel> channels[(int) ChannelReliability::Count];
        std::shared_ptr<rtc::PeerConnection> peerConnection;

        {
            std::lock_guard<std::mutex> lock(mMutex);

            if (mClosed)
                return;

            mClosed = true;

            for (int i = 0; i < (int) ChannelReliability::Count; i++) {
                channels[i] = mChannels[i].mChannel;
                mChannels[i].mChannel.reset();
                mChannels[i].mBuffer.clear();
            }

            peerConnection = mPeerConnection;
        }

        for (int i = 0; i < (int) ChannelReliability::Count; i++) {
            if (channels[i] != nullptr)
                channels[i]->close();
        }

        if (peerConnection != nullptr)
            peerConnection->close();
    }
}
