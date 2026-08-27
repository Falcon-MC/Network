#pragma once

#include "Network/Connector.h"
#include "Network/NetherNet/NetherNetConnection.h"
#include "Network/NetherNet/NetherNetCredentials.h"
#include "Network/NetherNet/NetherNetDiscovery.h"
#include "Network/NetherNet/NetherNetIdentity.h"
#include "Network/NetherNet/NetherNetSignalingServer.h"
#include "Network/RakPeerHelper.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

class NetherNetInstance : public Connector {
public:
    NetherNetInstance(RakPeerHelper::IPSupportInterface &ipSupport, bool isServer);

    ~NetherNetInstance() override;

    bool host(const ConnectionDefinition &definition) override;

    void disconnect() override;

    void runEvents() override;

    std::shared_ptr<NetworkPeer> getPeerForUser(const NetworkIdentifier &id) override;

    TransportLayer getNetworkType() const override { return TransportLayer::NetherNet; }

    bool isIPv4Supported() const override;

    bool isIPv6Supported() const override;

    void setCredentials(const nethernet::Credentials &credentials);

    void setTlsCertificate(const std::string &certificatePath, const std::string &privateKeyPath);

    void setServerDataProvider(const std::function<nethernet::ServerData()> &provider) {
        mServerDataProvider = provider;
    }

    const ConnectionDefinition &getConnectionDefinition() const { return mConnectionDefinition; }

private:
    bool _negotiate(const std::string &networkID, const std::string &offer, std::string &answer, int &errorCode);

    RakPeerHelper::IPSupportInterface &mIpSupport;
    ConnectionDefinition mConnectionDefinition;
    nethernet::SignalingServer mSignaling;
    nethernet::DiscoveryListener mDiscovery;
    nethernet::Identity mIdentity;
    nethernet::Credentials mCredentials;
    std::function<nethernet::ServerData()> mServerDataProvider;
    uint64_t mNetworkId = 0;

    std::mutex mMutex;
    std::vector<std::shared_ptr<nethernet::Connection>> mPending;
    std::unordered_map<NetworkIdentifier, std::shared_ptr<nethernet::Connection>, NetworkIdentifier::Hasher> mPeers;

    unsigned long long mNextConnectionID;
    bool mIsServer;
    bool mIsHosting;
};
