#include "Network/Server/RakNetServerTransport.h"

RakNetServerTransport::RakNetServerTransport(RakNet::RakPeerInterface *rakPeer, const RakNet::RakNetGUID &guid)
        : mRakPeer(rakPeer), mGuid(guid), mConnected(true), mCloseReason((int) DisconnectFailReason::Unknown) {
}

void RakNetServerTransport::runEvents() {
}

void RakNetServerTransport::close() {
    if (!mConnected.exchange(false))
        return;

    mCloseReason.store((int) DisconnectFailReason::Disconnected);
    mRakPeer->CloseConnection(mGuid, true);
}

bool RakNetServerTransport::isConnected() const {
    return mConnected.load();
}

DisconnectFailReason RakNetServerTransport::getCloseReason() const {
    return (DisconnectFailReason) mCloseReason.load();
}

void RakNetServerTransport::markClosed(DisconnectFailReason reason) {
    mCloseReason.store((int) reason);
    mConnected.store(false);
}
