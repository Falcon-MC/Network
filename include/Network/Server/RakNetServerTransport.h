#pragma once

#include "Network/Client/ClientTransport.h"
#include "RakNet/RakPeerInterface.h"

#include <atomic>

class RakNetServerTransport : public ClientTransport {
public:
    RakNetServerTransport(RakNet::RakPeerInterface *rakPeer, const RakNet::RakNetGUID &guid);

    void runEvents() override;

    void close() override;

    bool isConnected() const override;

    DisconnectFailReason getCloseReason() const override;

    void markClosed(DisconnectFailReason reason);

private:
    RakNet::RakPeerInterface *mRakPeer;
    RakNet::RakNetGUID mGuid;
    std::atomic<bool> mConnected;
    std::atomic<int> mCloseReason;
};
