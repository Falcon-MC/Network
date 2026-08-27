#include "Network/NetherNet/NetherNetInstance.h"

#include "Core/Debug/BedrockLog.h"
#include "Network/NetherNet/NetherNetDescription.h"
#include "Network/NetherNet/NetherNetSignal.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <chrono>
#include <condition_variable>
#include <random>

namespace {

    const int GATHERING_TIMEOUT_SECONDS = 15;
    const char *IDENTITY_DOMAIN = "self";

    unsigned long long randomNetworkID() {
        std::random_device device;
        std::mt19937_64 engine(device());
        return engine();
    }

    const char *setupRoleName(rtc::Description::Role role) {
        switch (role) {
            case rtc::Description::Role::Active:
                return "active";
            case rtc::Description::Role::Passive:
                return "passive";
            default:
                return "actpass";
        }
    }

}

NetherNetInstance::NetherNetInstance(RakPeerHelper::IPSupportInterface &ipSupport, bool isServer)
        : mIpSupport(ipSupport), mNextConnectionID(randomNetworkID()), mIsServer(isServer), mIsHosting(false) {
}

NetherNetInstance::~NetherNetInstance() {
    disconnect();
}

bool NetherNetInstance::isIPv4Supported() const {
    return true;
}

bool NetherNetInstance::isIPv6Supported() const {
    return false;
}

void NetherNetInstance::setCredentials(const nethernet::Credentials &credentials) {
    std::lock_guard<std::mutex> lock(mMutex);
    mCredentials = credentials;
}

void NetherNetInstance::setTlsCertificate(const std::string &certificatePath, const std::string &privateKeyPath) {
    mSignaling.setCertificate(certificatePath, privateKeyPath);
}

bool NetherNetInstance::host(const ConnectionDefinition &definition) {
    if (mIsHosting)
        return false;

    if (!mIsServer) {
        LOG_ERROR(LogAreaID::Network, "NetherNet client mode is not implemented");
        return false;
    }

    mConnectionDefinition = definition;

    if (!mIdentity.generate(IDENTITY_DOMAIN)) {
        LOG_ERROR(LogAreaID::Network, "Failed to generate the NetherNet server identity key");
        return false;
    }

    const nethernet::SignalingServer::OfferHandler handler =
            [this](const std::string &networkID, const std::string &offer, std::string &answer, int &errorCode) {
                return _negotiate(networkID, offer, answer, errorCode);
            };

    if (!mSignaling.start(definition.mIPv4Address, definition.mPort, handler))
        return false;

    unsigned char rawId[8];
    RAND_bytes(rawId, sizeof(rawId));
    mNetworkId = 0;
    for (size_t i = 0; i < sizeof(rawId); i++)
        mNetworkId |= ((uint64_t) rawId[i]) << (i * 8);

    const nethernet::DiscoveryListener::ServerDataProvider dataProvider =
            [this]() {
                if (mServerDataProvider)
                    return mServerDataProvider();

                return nethernet::ServerData();
            };

    mDiscovery.start(mNetworkId, dataProvider, handler);

    mIsHosting = true;
    return true;
}

void NetherNetInstance::disconnect() {
    if (!mIsHosting)
        return;

    mDiscovery.stop();
    mSignaling.stop();

    std::vector<std::shared_ptr<nethernet::Connection>> connections;

    {
        std::lock_guard<std::mutex> lock(mMutex);

        for (const std::shared_ptr<nethernet::Connection> &connection: mPending)
            connections.push_back(connection);

        for (const auto &entry: mPeers)
            connections.push_back(entry.second);

        mPending.clear();
        mPeers.clear();
    }

    for (const std::shared_ptr<nethernet::Connection> &connection: connections)
        connection->close();

    mIsHosting = false;
}

std::shared_ptr<NetworkPeer> NetherNetInstance::getPeerForUser(const NetworkIdentifier &id) {
    std::lock_guard<std::mutex> lock(mMutex);

    const auto it = mPeers.find(id);
    return it == mPeers.end() ? nullptr : it->second;
}

bool NetherNetInstance::_negotiate(const std::string &networkID, const std::string &offer, std::string &answer,
                                   int &errorCode) {
    const std::vector<nethernet::Fingerprint> remoteFingerprints = nethernet::Description::parseFingerprints(offer);

    if (remoteFingerprints.empty()) {
        LOG_WARN(LogAreaID::Network, "NetherNet offer has no a=fingerprint line, rejecting identity assertion");
        errorCode = nethernet::ErrorCodeFailedToSetRemoteDescription;
        return false;
    }

    nethernet::IdentityData identity;
    std::string failure;

    if (!nethernet::Description::parseIdentity(offer, identity, failure)) {
        if (!failure.empty()) {
            LOG_WARN(LogAreaID::Network, "NetherNet identity assertion rejected: %s", failure.c_str());
            errorCode = nethernet::ErrorCodeIdentityVerificationFailed;
            return false;
        }

        LOG_WARN(LogAreaID::Network, "NetherNet offer carries no identity assertion, rejecting anonymous client");
        errorCode = nethernet::ErrorCodeIdentityVerificationFailed;
        return false;
    }

    if (!identity.isValid()) {
        LOG_WARN(LogAreaID::Network, "NetherNet identity assertion is malformed");
        errorCode = nethernet::ErrorCodeIdentityVerificationFailed;
        return false;
    }

    EVP_PKEY *publicKey = nethernet::Identity::claimPublicKey(identity.mAssertionToken, failure);
    if (publicKey == nullptr) {
        LOG_WARN(LogAreaID::Network, "NetherNet client token rejected: %s", failure.c_str());
        errorCode = nethernet::ErrorCodeIdentityVerificationFailed;
        return false;
    }

    const std::string remotePayload = nethernet::Description::generateFingerprintsPayload(remoteFingerprints);
    const bool verified = nethernet::Identity::verifyDetached(publicKey, identity.mAssertionFingerprints,
                                                              remotePayload);
    EVP_PKEY_free(publicKey);

    if (!verified) {
        LOG_WARN(LogAreaID::Network, "NetherNet fingerprints assertion could not be verified");
        errorCode = nethernet::ErrorCodeIdentityVerificationFailed;
        return false;
    }

    rtc::Configuration configuration;
    configuration.maxMessageSize = nethernet::MAX_MESSAGE_SIZE + 1;

    {
        std::lock_guard<std::mutex> lock(mMutex);

        for (const nethernet::IceServer &server: mCredentials.mIceServers) {
            for (const std::string &url: server.mUrls) {
                rtc::IceServer entry(url);
                entry.username = server.mUsername;
                entry.password = server.mPassword;
                configuration.iceServers.push_back(entry);
            }
        }
    }

    unsigned long long connectionID;

    {
        std::lock_guard<std::mutex> lock(mMutex);
        connectionID = mNextConnectionID++;
    }

    std::shared_ptr<rtc::PeerConnection> peerConnection;

    try {
        peerConnection = std::make_shared<rtc::PeerConnection>(configuration);
    } catch (const std::exception &error) {
        LOG_ERROR(LogAreaID::Network, "Failed to create a NetherNet peer connection: %s", error.what());
        errorCode = nethernet::ErrorCodeFailedToCreatePeerConnection;
        return false;
    }

    const NetworkIdentifier id(networkID, connectionID);
    const std::shared_ptr<nethernet::Connection> connection =
            std::make_shared<nethernet::Connection>(id, peerConnection);

    std::weak_ptr<nethernet::Connection> weak = connection;

    peerConnection->onDataChannel([weak](std::shared_ptr<rtc::DataChannel> channel) {
        const std::shared_ptr<nethernet::Connection> target = weak.lock();
        if (target == nullptr) {
            channel->close();
            return;
        }

        if (!target->attachChannel(channel)) {
            LOG_WARN(LogAreaID::Network, "Rejecting unexpected NetherNet data channel %s", channel->label().c_str());
            target->close();
        }
    });

    std::shared_ptr<std::mutex> gatherMutex = std::make_shared<std::mutex>();
    std::shared_ptr<std::condition_variable> gatherSignal = std::make_shared<std::condition_variable>();
    std::shared_ptr<bool> gathered = std::make_shared<bool>(false);

    peerConnection->onGatheringStateChange([gatherMutex, gatherSignal, gathered](
            rtc::PeerConnection::GatheringState state) {
        if (state != rtc::PeerConnection::GatheringState::Complete)
            return;

        {
            std::lock_guard<std::mutex> lock(*gatherMutex);
            *gathered = true;
        }

        gatherSignal->notify_all();
    });

    try {
        peerConnection->setRemoteDescription(rtc::Description(offer, rtc::Description::Type::Offer));
    } catch (const std::exception &error) {
        LOG_WARN(LogAreaID::Network, "Failed to apply the NetherNet offer: %s", error.what());
        connection->close();
        errorCode = nethernet::ErrorCodeFailedToSetRemoteDescription;
        return false;
    }

    {
        std::unique_lock<std::mutex> lock(*gatherMutex);

        if (peerConnection->gatheringState() == rtc::PeerConnection::GatheringState::Complete)
            *gathered = true;

        if (!*gathered) {
            gatherSignal->wait_for(lock, std::chrono::seconds(GATHERING_TIMEOUT_SECONDS),
                                   [gathered]() { return *gathered; });
        }

        if (!*gathered) {
            lock.unlock();
            LOG_WARN(LogAreaID::Network, "Timed out gathering local NetherNet candidates");
            connection->close();
            errorCode = nethernet::ErrorCodeNegotiationTimeoutWaitingForResponse;
            return false;
        }
    }

    const std::optional<rtc::Description> local = peerConnection->localDescription();
    if (!local.has_value()) {
        LOG_WARN(LogAreaID::Network, "NetherNet peer connection produced no local description");
        connection->close();
        errorCode = nethernet::ErrorCodeFailedToCreateAnswer;
        return false;
    }

    const rtc::Description &localDescription = local.value();
    const std::optional<rtc::CertificateFingerprint> localFingerprint = localDescription.fingerprint();

    if (!localFingerprint.has_value()) {
        LOG_ERROR(LogAreaID::Network, "NetherNet answer has no DTLS fingerprint");
        connection->close();
        errorCode = nethernet::ErrorCodeFailedToCreateAnswer;
        return false;
    }

    if (!localDescription.iceUfrag().has_value() || !localDescription.icePwd().has_value()) {
        LOG_ERROR(LogAreaID::Network, "NetherNet answer has no ICE credentials");
        connection->close();
        errorCode = nethernet::ErrorCodeFailedToCreateAnswer;
        return false;
    }

    if (localDescription.role() == rtc::Description::Role::ActPass) {
        LOG_ERROR(LogAreaID::Network, "NetherNet answer resolved to an illegal actpass DTLS role");
        connection->close();
        errorCode = nethernet::ErrorCodeFailedToCreateAnswer;
        return false;
    }

    nethernet::Fingerprint answerFingerprint;
    answerFingerprint.mAlgorithm = rtc::CertificateFingerprint::AlgorithmIdentifier(
            localFingerprint.value().algorithm);
    answerFingerprint.mValue = localFingerprint.value().value;

    const std::vector<nethernet::Fingerprint> localFingerprints(1, answerFingerprint);

    if (!mIdentity.issueToken()) {
        LOG_ERROR(LogAreaID::Network, "Failed to issue the NetherNet server token");
        connection->close();
        errorCode = nethernet::ErrorCodeIdentityVerificationFailed;
        return false;
    }

    const std::string localPayload = nethernet::Description::generateFingerprintsPayload(localFingerprints);
    const std::string assertion = mIdentity.signDetached(localPayload);

    if (assertion.empty()) {
        LOG_ERROR(LogAreaID::Network, "Failed to sign the NetherNet DTLS fingerprints");
        connection->close();
        errorCode = nethernet::ErrorCodeIdentityVerificationFailed;
        return false;
    }

    nethernet::IdentityData localIdentity;
    localIdentity.mAssertionFingerprints = assertion;
    localIdentity.mAssertionToken = mIdentity.getToken();
    localIdentity.mIdpDomain = mIdentity.getDomain();
    localIdentity.mIdpProtocol = "default";

    nethernet::AnswerParameters parameters;
    parameters.mSessionId = randomNetworkID();
    parameters.mUsernameFragment = localDescription.iceUfrag().value();
    parameters.mPassword = localDescription.icePwd().value();
    parameters.mFingerprints = localFingerprints;
    parameters.mSetupRole = setupRoleName(localDescription.role());
    parameters.mEncodedIdentity = nethernet::Description::encodeIdentity(localIdentity);

    for (const rtc::Candidate &candidate: localDescription.candidates())
        parameters.mCandidates.push_back(candidate.candidate());

    if (parameters.mCandidates.empty()) {
        LOG_WARN(LogAreaID::Network, "NetherNet answer carries no ICE candidate, the client cannot connect back");
        connection->close();
        errorCode = nethernet::ErrorCodeFailedToCreateAnswer;
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(mMutex);
        mPending.push_back(connection);
    }

    answer = nethernet::Description::buildAnswer(parameters);
    return true;
}

void NetherNetInstance::runEvents() {
    if (!mIsHosting)
        return;

    std::vector<std::shared_ptr<nethernet::Connection>> ready;
    std::vector<std::shared_ptr<nethernet::Connection>> dropped;

    {
        std::lock_guard<std::mutex> lock(mMutex);

        for (size_t i = 0; i < mPending.size();) {
            const std::shared_ptr<nethernet::Connection> &connection = mPending[i];

            if (connection->isClosed()) {
                mPending.erase(mPending.begin() + (long) i);
                continue;
            }

            if (connection->areChannelsReady()) {
                ready.push_back(connection);
                mPending.erase(mPending.begin() + (long) i);
                continue;
            }

            i++;
        }

        for (auto it = mPeers.begin(); it != mPeers.end();) {
            if (it->second->isClosed()) {
                dropped.push_back(it->second);
                it = mPeers.erase(it);
                continue;
            }

            ++it;
        }
    }

    for (const std::shared_ptr<nethernet::Connection> &connection: ready) {
        const NetworkIdentifier &id = connection->getNetworkIdentifier();

        if (mCallbacks != nullptr && !mCallbacks->onValidateIncomingConnection(id)) {
            connection->close();
            continue;
        }

        {
            std::lock_guard<std::mutex> lock(mMutex);
            mPeers[id] = connection;
        }

        if (mCallbacks != nullptr)
            mCallbacks->onNewIncomingConnection(id, connection);
    }

    for (const std::shared_ptr<nethernet::Connection> &connection: dropped) {
        if (mCallbacks != nullptr) {
            mCallbacks->onConnectionClosed(connection->getNetworkIdentifier(), DisconnectFailReason::Disconnected,
                                           toString(DisconnectFailReason::Disconnected));
        }
    }
}
