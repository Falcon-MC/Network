#include "Network/BedrockConnection.h"

#include "Network/Client/RakNetClient.h"
#include "Network/Crypto/KeyPair.h"
#include "Protocol/MinecraftPackets.h"
#include "Protocol/Packets/DisconnectPacket.h"
#include "Protocol/Packets/ItemRegistryPacket.h"
#include "Protocol/Packets/ServerToClientHandshakePacket.h"
#include "Protocol/Packets/StartGamePacket.h"

#include <utility>

BedrockConnection::BedrockConnection(Side side, std::shared_ptr<NetworkPeer> transport,
                                     std::shared_ptr<RakNetClient> clientTransport)
        : mSide(side), mTransport(std::move(transport)), mClientTransport(std::move(clientTransport)),
          mClientDriver(mClientTransport),
          mDefaultCodecContext(mDefaultBlockDefinitions, mDefaultItemDefinitions),
          mCodecContext(&mDefaultCodecContext), mChunkRadius(0), mClosed(false) {
    mEncryptedPeer = std::make_shared<EncryptedNetworkPeer>(mTransport);
    mCompressedPeer = std::make_shared<CompressedNetworkPeer>(mEncryptedPeer);
    mBatchedPeer = std::make_shared<BatchedNetworkPeer>(mCompressedPeer);
}

BedrockConnection::BedrockConnection(Side side, std::shared_ptr<NetworkPeer> transport,
                                     std::shared_ptr<ClientTransport> clientDriver)
        : mSide(side), mTransport(std::move(transport)), mClientDriver(std::move(clientDriver)),
          mDefaultCodecContext(mDefaultBlockDefinitions, mDefaultItemDefinitions),
          mCodecContext(&mDefaultCodecContext), mChunkRadius(0), mClosed(false) {
    mEncryptedPeer = std::make_shared<EncryptedNetworkPeer>(mTransport);
    mCompressedPeer = std::make_shared<CompressedNetworkPeer>(mEncryptedPeer);
    mBatchedPeer = std::make_shared<BatchedNetworkPeer>(mCompressedPeer);
}

BedrockConnection::~BedrockConnection() {
    close("connection destroyed");
}

void BedrockConnection::setCodecContext(const PacketCodecContext *context) {
    mCodecContext = context != nullptr ? context : &mDefaultCodecContext;
}

void BedrockConnection::enableCompression(CompressedNetworkPeer::CompressionAlgorithm algorithm,
                                          unsigned short threshold) {
    mBatchedPeer->flush();
    mCompressedPeer->enableCompression(algorithm, threshold);
}

bool BedrockConnection::enableEncryption(const EncryptionKey &key) {
    mBatchedPeer->flush();
    return mEncryptedPeer->enableEncryption(key);
}

bool BedrockConnection::startServerEncryption(const KeyPair &serverKey, const std::string &clientPublicKeyBase64) {
    std::string jwt;
    EncryptionKey key{};

    if (!EncryptionHandshake::createServerToken(serverKey, clientPublicKeyBase64, jwt, key))
        return false;

    ServerToClientHandshakePacket handshake;
    handshake.mJwt = std::move(jwt);
    send(handshake);

    return enableEncryption(key);
}

bool BedrockConnection::isCompressionEnabled() const {
    return mCompressedPeer->isCompressionEnabled();
}

bool BedrockConnection::isEncryptionEnabled() const {
    return mEncryptedPeer->isEncryptionEnabled();
}

NetworkPeer::Reliability BedrockConnection::toPeerReliability(const Packet &packet) {
    switch (packet.mReliability) {
        case Packet::Reliability::Reliable:
            return NetworkPeer::Reliability::Reliable;
        case Packet::Reliability::Unreliable:
            return NetworkPeer::Reliability::Unreliable;
        case Packet::Reliability::UnreliableSequenced:
            return NetworkPeer::Reliability::UnreliableSequenced;
        default:
            return NetworkPeer::Reliability::ReliableOrdered;
    }
}

Compressibility BedrockConnection::toPeerCompressibility(const Packet &packet) {
    return packet.mCompressible == Packet::Compressibility::Incompressible
           ? Compressibility::Incompressible
           : Compressibility::Compressible;
}

bool BedrockConnection::peekPacketId(const std::string &payload, MinecraftPacketIds &outId) {
    uint32_t header = 0;
    int shift = 0;

    for (size_t index = 0; index < payload.size() && shift < 35; ++index, shift += 7) {
        const unsigned char byte = (unsigned char) payload[index];
        header |= (uint32_t) (byte & 0x7f) << shift;

        if ((byte & 0x80) == 0) {
            outId = (MinecraftPacketIds) (header & 0x3ff);
            return true;
        }
    }

    return false;
}

void BedrockConnection::send(const Packet &packet) {
    if (mClosed.load())
        return;

    mSendStream.reset();
    packet.writeWithHeader(mSendStream, *mCodecContext);
    mBatchedPeer->sendPacket(mSendStream.getBuffer(), toPeerReliability(packet), toPeerCompressibility(packet));
}

void BedrockConnection::sendRaw(const std::string &payload, NetworkPeer::Reliability reliability,
                                Compressibility compressibility) {
    if (mClosed.load())
        return;

    mBatchedPeer->sendPacket(payload, reliability, compressibility);
}

void BedrockConnection::deferRaw(std::string payload) {
    mDeferred.push_back(std::move(payload));
}

void BedrockConnection::_handleDisconnectPacket(std::string payload) {
    std::string message = "disconnected by the remote system";

    std::shared_ptr<Packet> packet = decode(std::move(payload));
    const DisconnectPacket *disconnect = dynamic_cast<const DisconnectPacket *>(packet.get());

    if (disconnect != nullptr && !disconnect->mMessageSkipped && !disconnect->mKickMessage.empty())
        message = disconnect->mKickMessage;

    close(message);
}

bool BedrockConnection::receiveRaw(std::string &outPayload) {
    if (!mDeferred.empty()) {
        outPayload = std::move(mDeferred.front());
        mDeferred.pop_front();
        return true;
    }

    if (mClosed.load())
        return false;

    for (;;) {
        if (mBatchedPeer->receivePacket(outPayload) != NetworkPeer::DataStatus::HasData) {
            if (mEncryptedPeer->hasFailed())
                close("invalid encrypted packet received");
            else if (mClientDriver != nullptr && !mClientDriver->isConnected())
                close(toString(mClientDriver->getCloseReason()));

            return false;
        }

        MinecraftPacketIds id;
        if (!peekPacketId(outPayload, id))
            continue;

        if (id == MinecraftPacketIds::Disconnect) {
            _handleDisconnectPacket(std::move(outPayload));
            return false;
        }

        return true;
    }
}

std::shared_ptr<Packet> BedrockConnection::decode(std::string payload) const {
    MinecraftPacketIds id;
    if (!peekPacketId(payload, id))
        return nullptr;

    std::shared_ptr<Packet> packet = MinecraftPackets::createPacket(id);
    if (packet == nullptr)
        return nullptr;

    ReadOnlyBinaryStream stream(std::move(payload));

    try {
        packet->readHeader(stream);
        packet->read(stream, *mCodecContext);
    } catch (...) {
        return nullptr;
    }

    return packet;
}

std::shared_ptr<Packet> BedrockConnection::receive() {
    std::string payload;

    while (receiveRaw(payload)) {
        std::shared_ptr<Packet> packet = decode(std::move(payload));
        if (packet != nullptr)
            return packet;
    }

    return nullptr;
}

void BedrockConnection::update() {
    if (mClientDriver != nullptr)
        mClientDriver->runEvents();

    if (!mClosed.load())
        mBatchedPeer->update();
}

void BedrockConnection::flush() {
    if (mClosed.load())
        return;

    mBatchedPeer->flush();
}

void BedrockConnection::disconnect(const std::string &message, int reason) {
    if (mClosed.load())
        return;

    DisconnectPacket packet;
    packet.mReason = reason;
    packet.mMessageSkipped = message.empty();
    packet.mKickMessage = message;
    packet.mFilteredMessage = message;

    send(packet);
    flush();
    close(message.empty() ? "disconnected" : message);
}

void BedrockConnection::close(const std::string &reason) {
    if (mClosed.exchange(true))
        return;

    {
        std::lock_guard<std::mutex> guard(mReasonMutex);
        mDisconnectReason = reason;
    }

    mBatchedPeer->flush();

    if (mClientDriver != nullptr)
        mClientDriver->close();
}

std::string BedrockConnection::getDisconnectReason() const {
    std::lock_guard<std::mutex> guard(mReasonMutex);
    return mDisconnectReason;
}

NetworkPeer::NetworkStatus BedrockConnection::getNetworkStatus() const {
    return mBatchedPeer->getNetworkStatus();
}

void BedrockConnection::setGameData(std::shared_ptr<StartGamePacket> startGame,
                                    std::shared_ptr<ItemRegistryPacket> itemRegistry, int chunkRadius) {
    mStartGame = std::move(startGame);
    mItemRegistry = std::move(itemRegistry);
    mChunkRadius = chunkRadius;
}
