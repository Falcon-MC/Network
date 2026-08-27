#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>

namespace nethernet {

    struct ServerData {
        static const uint8_t VERSION = 7;
        static const int32_t CONNECTION_TYPE_LAN_SIGNALING = 4;

        std::string mServerName = "Falcon";
        int32_t mProtocol = 0;
        std::string mGameVersion;
        std::string mLevelName = "Bedrock level";
        int32_t mGameType = 0;
        int32_t mPlayerCount = 0;
        int32_t mMaxPlayerCount = 20;
        bool mEditorWorld = false;
        bool mHardcore = false;
        bool mAcceptsOnlineAuth = false;
        bool mAcceptsSelfSignedAuth = true;
        std::string mNonce;

        std::string encode() const;
    };

    class DiscoveryCrypto {
    public:
        static std::string encrypt(const std::string &payload);

        static bool decrypt(const std::string &ciphertext, std::string &out);

        static std::string checksum(const std::string &payload);

    private:
        static const std::string &key();
    };

    class DiscoveryListener {
    public:
        typedef std::function<bool(const std::string &networkID, const std::string &offer, std::string &answer,
                                   int &errorCode)> OfferHandler;
        typedef std::function<ServerData()> ServerDataProvider;

        DiscoveryListener();

        ~DiscoveryListener();

        bool start(uint64_t networkId, const ServerDataProvider &serverData, const OfferHandler &offerHandler);

        void stop();

        bool isRunning() const { return mRunning.load(); }

    private:
        void _run();

        void _handleDatagram(const std::string &buffer, const void *from, unsigned int fromLength);

        void _sendResponse(const void *from, unsigned int fromLength);

        void _sendMessage(uint64_t recipientId, const std::string &signalData, const void *from,
                          unsigned int fromLength);

        std::thread mThread;
        std::atomic<bool> mRunning;
        long long mSocket;
        uint64_t mNetworkId;
        ServerDataProvider mServerData;
        OfferHandler mOfferHandler;
    };

}
