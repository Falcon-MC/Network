#include "Network/Client/ClientNetworkSystem.h"

#include "Core/Debug/BedrockLog.h"
#include "Network/Auth/MinecraftAuthentication.h"
#include "Network/Client/RakNetClient.h"
#include "Network/Crypto/EncryptionHandshake.h"
#include "Network/Crypto/KeyPair.h"
#include "Protocol/Packets/ChunkRadiusUpdatedPacket.h"
#include "Protocol/Packets/ClientCacheStatusPacket.h"
#include "Protocol/Packets/ClientToServerHandshakePacket.h"
#include "Protocol/Packets/ItemRegistryPacket.h"
#include "Protocol/Packets/LoginPacket.h"
#include "Protocol/Packets/NetworkSettingsPacket.h"
#include "Protocol/Packets/PlayStatusPacket.h"
#include "Protocol/Packets/RequestChunkRadiusPacket.h"
#include "Protocol/Packets/RequestNetworkSettingsPacket.h"
#include "Protocol/Packets/ResourcePackClientResponsePacket.h"
#include "Protocol/Packets/ResourcePackStackPacket.h"
#include "Protocol/Packets/ResourcePacksInfoPacket.h"
#include "Protocol/Packets/ServerToClientHandshakePacket.h"
#include "Protocol/Packets/SetLocalPlayerAsInitializedPacket.h"
#include "Protocol/Packets/StartGamePacket.h"

#include <chrono>
#include <initializer_list>
#include <thread>
#include <utility>
#include <vector>

namespace {

    const int IDLE_WAIT_MS = 2;
    const int COMPRESSION_NONE_ID = 0xffff;

    class LoginSequence {
    public:
        LoginSequence(BedrockConnection &connection, const ClientConnectionSettings &settings,
                      const KeyPair &key, std::string authJson, std::string clientJwt)
                : mConnection(connection), mSettings(settings), mKey(key), mAuthJson(std::move(authJson)),
                  mClientJwt(std::move(clientJwt)), mDone(false), mWaitingForSpawn(false),
                  mGameDataReceived(false), mChunkRadius(0) {
        }

        bool run(std::string &outError) {
            _expect({MinecraftPacketIds::NetworkSettings, MinecraftPacketIds::PlayStatus});

            RequestNetworkSettingsPacket request;
            request.mProtocolVersion = mSettings.mProtocolVersion;
            mConnection.send(request);
            mConnection.flush();

            const auto start = std::chrono::steady_clock::now();
            std::string payload;

            while (!mDone) {
                if (mSettings.mCancel != nullptr && mSettings.mCancel->load()) {
                    outError = "dial cancelled";
                    return false;
                }

                const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - start).count();

                if (elapsed >= (long long) mSettings.mTimeoutMs) {
                    outError = "dial timed out";
                    return false;
                }

                mConnection.update();

                bool received = false;

                while (!mDone && mConnection.receiveRaw(payload)) {
                    received = true;

                    if (!_receive(std::move(payload), outError))
                        return false;
                }

                if (mConnection.isClosed()) {
                    outError = "connection closed: " + mConnection.getDisconnectReason();
                    return false;
                }

                if (!received)
                    std::this_thread::sleep_for(std::chrono::milliseconds(IDLE_WAIT_MS));
            }

            mConnection.setGameData(mStartGame, mItemRegistry, mChunkRadius);

            for (std::string &deferred: mDeferred)
                mConnection.deferRaw(std::move(deferred));

            mDeferred.clear();
            return true;
        }

    private:
        void _expect(std::initializer_list<MinecraftPacketIds> ids) {
            mExpected.assign(ids.begin(), ids.end());
        }

        bool _isExpected(MinecraftPacketIds id) const {
            for (MinecraftPacketIds expected: mExpected) {
                if (expected == id)
                    return true;
            }

            return false;
        }

        template<class PacketType>
        std::shared_ptr<PacketType> _decode(std::string payload, std::string &outError) const {
            std::shared_ptr<Packet> packet = mConnection.decode(std::move(payload));
            std::shared_ptr<PacketType> typed = std::dynamic_pointer_cast<PacketType>(packet);

            if (typed == nullptr)
                outError = std::string("could not decode ") + PacketType().getName();

            return typed;
        }

        bool _receive(std::string payload, std::string &outError) {
            MinecraftPacketIds id;
            if (!BedrockConnection::peekPacketId(payload, id))
                return true;

            if (!_isExpected(id)) {
                mDeferred.push_back(std::move(payload));
                return true;
            }

            bool handled = false;

            switch (id) {
                case MinecraftPacketIds::NetworkSettings:
                    handled = _handleNetworkSettings(std::move(payload), outError);
                    break;

                case MinecraftPacketIds::ServerToClientHandshake:
                    handled = _handleServerToClientHandshake(std::move(payload), outError);
                    break;

                case MinecraftPacketIds::PlayStatus:
                    handled = _handlePlayStatus(std::move(payload), outError);
                    break;

                case MinecraftPacketIds::ResourcePacksInfo:
                    handled = _handleResourcePacksInfo(std::move(payload), outError);
                    break;

                case MinecraftPacketIds::ResourcePackStack:
                    handled = _handleResourcePackStack(std::move(payload), outError);
                    break;

                case MinecraftPacketIds::DimensionData:
                    mDeferred.push_back(std::move(payload));
                    handled = true;
                    break;

                case MinecraftPacketIds::StartGame:
                    handled = _handleStartGame(std::move(payload), outError);
                    break;

                case MinecraftPacketIds::ItemRegistry:
                    handled = _handleItemRegistry(std::move(payload), outError);
                    break;

                case MinecraftPacketIds::ChunkRadiusUpdated:
                    handled = _handleChunkRadiusUpdated(std::move(payload), outError);
                    break;

                default:
                    handled = true;
                    break;
            }

            mConnection.flush();
            return handled;
        }

        bool _handleNetworkSettings(std::string payload, std::string &outError) {
            std::shared_ptr<NetworkSettingsPacket> packet = _decode<NetworkSettingsPacket>(std::move(payload),
                                                                                           outError);
            if (packet == nullptr)
                return false;

            const int algorithm = (int) packet->mCompressionAlgorithm;

            if (algorithm == (int) CompressedNetworkPeer::CompressionAlgorithm::ZLib) {
                mConnection.enableCompression(CompressedNetworkPeer::CompressionAlgorithm::ZLib,
                                              packet->mCompressionThreshold);
            } else if (algorithm == COMPRESSION_NONE_ID) {
                mConnection.enableCompression(CompressedNetworkPeer::CompressionAlgorithm::None,
                                              packet->mCompressionThreshold);
            } else {
                outError = "unsupported compression algorithm " + std::to_string(algorithm);
                return false;
            }

            _expect({MinecraftPacketIds::ServerToClientHandshake, MinecraftPacketIds::PlayStatus});

            LoginPacket login;
            login.mProtocolVersion = mSettings.mProtocolVersion;
            login.mAuthJwt = std::move(mAuthJson);
            login.mClientJwt = std::move(mClientJwt);
            mConnection.send(login);
            mConnection.flush();
            return true;
        }

        bool _handleServerToClientHandshake(std::string payload, std::string &outError) {
            std::shared_ptr<ServerToClientHandshakePacket> packet =
                    _decode<ServerToClientHandshakePacket>(std::move(payload), outError);
            if (packet == nullptr)
                return false;

            EncryptionKey key{};
            if (!EncryptionHandshake::acceptServerToken(packet->mJwt, mKey, key)) {
                outError = "could not verify the server handshake token";
                return false;
            }

            if (!mConnection.enableEncryption(key)) {
                outError = "could not enable encryption";
                return false;
            }

            ClientToServerHandshakePacket response;
            mConnection.send(response);
            return true;
        }

        bool _handlePlayStatus(std::string payload, std::string &outError) {
            std::shared_ptr<PlayStatusPacket> packet = _decode<PlayStatusPacket>(std::move(payload), outError);
            if (packet == nullptr)
                return false;

            switch (packet->mStatus) {
                case PlayStatusPacket::Status::LoginSuccess: {
                    ClientCacheStatusPacket cacheStatus;
                    cacheStatus.mSupported = mSettings.mEnableClientCache;
                    mConnection.send(cacheStatus);

                    _expect({MinecraftPacketIds::ResourcePacksInfo});
                    return true;
                }

                case PlayStatusPacket::Status::PlayerSpawn:
                    mWaitingForSpawn = true;
                    _tryFinalise();
                    return true;

                case PlayStatusPacket::Status::LoginFailedClientOld:
                    outError = "client outdated";
                    break;

                case PlayStatusPacket::Status::LoginFailedServerOld:
                    outError = "server outdated";
                    break;

                case PlayStatusPacket::Status::LoginFailedInvalidTenant:
                    outError = "invalid edu edition game owner";
                    break;

                case PlayStatusPacket::Status::LoginFailedEditionMismatchEduToVanilla:
                    outError = "cannot join an edu edition game on vanilla";
                    break;

                case PlayStatusPacket::Status::LoginFailedEditionMismatchVanillaToEdu:
                    outError = "cannot join a vanilla game on edu edition";
                    break;

                case PlayStatusPacket::Status::FailedServerFullSubClient:
                    outError = "server full";
                    break;

                case PlayStatusPacket::Status::EditorToVanillaMismatch:
                    outError = "cannot join a vanilla game on editor";
                    break;

                case PlayStatusPacket::Status::VanillaToEditorMismatch:
                    outError = "cannot join an editor game on vanilla";
                    break;

                default:
                    outError = "unknown play status " + std::to_string((int) packet->mStatus);
                    break;
            }

            mConnection.close(outError);
            return false;
        }

        bool _handleResourcePacksInfo(std::string payload, std::string &outError) {
            std::shared_ptr<ResourcePacksInfoPacket> packet = _decode<ResourcePacksInfoPacket>(std::move(payload),
                                                                                               outError);
            if (packet == nullptr)
                return false;

            _expect({MinecraftPacketIds::ResourcePackStack});

            ResourcePackClientResponsePacket response;
            response.mStatus = ResourcePackClientResponsePacket::Status::HaveAllPacks;
            mConnection.send(response);
            return true;
        }

        bool _handleResourcePackStack(std::string payload, std::string &outError) {
            std::shared_ptr<ResourcePackStackPacket> packet = _decode<ResourcePackStackPacket>(std::move(payload),
                                                                                               outError);
            if (packet == nullptr)
                return false;

            _expect({MinecraftPacketIds::DimensionData, MinecraftPacketIds::StartGame});

            ResourcePackClientResponsePacket response;
            response.mStatus = ResourcePackClientResponsePacket::Status::Completed;
            mConnection.send(response);
            return true;
        }

        bool _handleStartGame(std::string payload, std::string &outError) {
            mStartGame = _decode<StartGamePacket>(std::move(payload), outError);
            if (mStartGame == nullptr)
                return false;

            _expect({MinecraftPacketIds::ItemRegistry});
            return true;
        }

        bool _handleItemRegistry(std::string payload, std::string &outError) {
            mItemRegistry = _decode<ItemRegistryPacket>(std::move(payload), outError);
            if (mItemRegistry == nullptr)
                return false;

            RequestChunkRadiusPacket request;
            request.mRadius = mSettings.mChunkRadius;
            request.mMaxRadius = mSettings.mChunkRadius;
            mConnection.send(request);

            _expect({MinecraftPacketIds::ChunkRadiusUpdated, MinecraftPacketIds::PlayStatus});
            return true;
        }

        bool _handleChunkRadiusUpdated(std::string payload, std::string &outError) {
            std::shared_ptr<ChunkRadiusUpdatedPacket> packet =
                    _decode<ChunkRadiusUpdatedPacket>(std::move(payload), outError);
            if (packet == nullptr)
                return false;

            if (packet->mRadius < 1) {
                outError = "expected chunk radius of at least 1, got " + std::to_string(packet->mRadius);
                return false;
            }

            _expect({MinecraftPacketIds::PlayStatus});

            mChunkRadius = packet->mRadius;
            mGameDataReceived = true;
            _tryFinalise();
            return true;
        }

        void _tryFinalise() {
            if (!mWaitingForSpawn || !mGameDataReceived)
                return;

            mWaitingForSpawn = false;
            mGameDataReceived = false;

            SetLocalPlayerAsInitializedPacket initialized;
            initialized.mRuntimeActorId = mStartGame != nullptr ? mStartGame->mRuntimeActorId : 0;
            mConnection.send(initialized);
            mConnection.flush();

            mDone = true;
        }

        BedrockConnection &mConnection;
        const ClientConnectionSettings &mSettings;
        const KeyPair &mKey;
        std::string mAuthJson;
        std::string mClientJwt;
        std::vector<MinecraftPacketIds> mExpected;
        std::vector<std::string> mDeferred;
        std::shared_ptr<StartGamePacket> mStartGame;
        std::shared_ptr<ItemRegistryPacket> mItemRegistry;
        bool mDone;
        bool mWaitingForSpawn;
        bool mGameDataReceived;
        int mChunkRadius;
    };

}

ClientConnectionResult ClientNetworkSystem::dial(const ClientConnectionSettings &settings) {
    ClientConnectionResult result;
    result.mIdentity = settings.mIdentity;
    result.mClientData = settings.mClientData;

    std::shared_ptr<KeyPair> key = KeyPair::generate();
    if (key == nullptr) {
        result.mError = "generating ECDSA key failed";
        return result;
    }

    const bool online = settings.mAuthentication != nullptr;
    MinecraftAuthenticationResult authentication;

    if (online) {
        if (!settings.mAuthentication->authenticate(*key, settings.mLegacyAuthentication, authentication,
                                                    result.mError))
            return result;

        result.mIdentity.mDisplayName = authentication.mDisplayName;
        result.mIdentity.mIdentity = authentication.mIdentity;
        result.mIdentity.mXuid = authentication.mXuid;
        result.mIdentity.mTitleId = authentication.mTitleId;
    }

    std::shared_ptr<RakNetClient> transport = std::make_shared<RakNetClient>();
    if (!transport->connect(settings.mHost, settings.mPort, settings.mTimeoutMs, settings.mCancel, result.mError))
        return result;

    std::unique_ptr<BedrockConnection> connection(
            new BedrockConnection(BedrockConnection::Side::Client, transport->getPeer(), transport));
    connection->setCodecContext(settings.mCodecContext);

    ClientConnectionRequest::applyIdentityDefaults(result.mIdentity);

    const std::string serverAddress = settings.mHost + ":" + std::to_string(settings.mPort);
    ClientConnectionRequest::applyClientDefaults(result.mClientData, serverAddress, result.mIdentity.mDisplayName,
                                                 settings.mGameVersion);

    std::string authJson;
    std::string clientJwt;

    if (!online) {
        if (!settings.mKeepXboxIdentityData) {
            result.mIdentity.mXuid.clear();
            result.mIdentity.mTitleId.clear();
        }

        if (!ClientConnectionRequest::createOffline(result.mIdentity, result.mClientData, *key,
                                                    settings.mLegacyAuthentication, authJson, clientJwt,
                                                    result.mError)) {
            connection->close(result.mError);
            return result;
        }
    } else {
        result.mClientData.mDeviceOS = ClientData::DEVICE_ANDROID;
        result.mClientData.mGameVersion = settings.mGameVersion;

        if (!ClientConnectionRequest::createOnline(authentication.mChainJson, authentication.mMultiplayerToken,
                                                   result.mClientData, *key, settings.mLegacyAuthentication,
                                                   authJson, clientJwt, result.mError)) {
            connection->close(result.mError);
            return result;
        }
    }

    LoginSequence sequence(*connection, settings, *key, std::move(authJson), std::move(clientJwt));

    if (!sequence.run(result.mError)) {
        LOG_WARN(LogAreaID::Network, "Could not connect to %s: %s", serverAddress.c_str(), result.mError.c_str());
        connection->close(result.mError);
        return result;
    }

    result.mConnection = std::move(connection);
    return result;
}
