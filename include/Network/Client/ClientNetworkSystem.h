#pragma once

#include "Network/BedrockConnection.h"
#include "Network/Client/ClientConnectionRequest.h"
#include "Network/NetworkEnums.h"

#include <atomic>
#include <memory>
#include <string>

class MinecraftAuthentication;

class PacketCodecContext;

namespace nethernet {
    class Signaling;
}

enum class NetherNetSignalingType : int {
    Lan = 0,
    WebSocket = 1,
    JsonRpc = 2
};

struct NetherNetTarget {
    std::string mNetworkId;
    NetherNetSignalingType mSignalingType = NetherNetSignalingType::Lan;
    std::shared_ptr<nethernet::Signaling> mSignaling;
    bool mAllowIdentitylessServer = false;
    bool mDisableTrickleIce = false;
};

struct ClientConnectionSettings {
    std::string mHost;
    unsigned short mPort = 19132;
    int mProtocolVersion = 0;
    std::string mGameVersion;
    ClientIdentityData mIdentity;
    ClientData mClientData;
    MinecraftAuthentication *mAuthentication = nullptr;
    bool mLegacyAuthentication = false;
    bool mKeepXboxIdentityData = false;
    bool mEnableClientCache = false;
    int mChunkRadius = 16;
    unsigned int mTimeoutMs = 30000;
    const std::atomic<bool> *mCancel = nullptr;
    const PacketCodecContext *mCodecContext = nullptr;
    TransportLayer mTransportLayer = TransportLayer::RakNet;
    NetherNetTarget mNetherNet;
    bool mDeferSpawn = false;
};

struct ClientConnectionResult {
    std::unique_ptr<BedrockConnection> mConnection;
    ClientIdentityData mIdentity;
    ClientData mClientData;
    std::string mError;
};

class ClientNetworkSystem {
public:
    static ClientConnectionResult dial(const ClientConnectionSettings &settings);
};
