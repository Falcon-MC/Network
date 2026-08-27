#include "Network/NetherNet/NetherNetDiscovery.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

#endif

#include "Core/Debug/BedrockLog.h"
#include "Core/Utility/BinaryStream.h"
#include "Core/Utility/ReadOnlyBinaryStream.h"
#include "Network/NetherNet/NetherNetSignal.h"

#include <cstring>
#include <vector>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#ifdef _WIN32
typedef SOCKET FalconDiscoverySocket;
#define FALCON_DISCOVERY_INVALID_SOCKET INVALID_SOCKET
#define FALCON_DISCOVERY_CLOSE_SOCKET ::closesocket
#else
typedef int FalconDiscoverySocket;
#define FALCON_DISCOVERY_INVALID_SOCKET (-1)
#define FALCON_DISCOVERY_CLOSE_SOCKET ::close
#endif

namespace nethernet {

    namespace {

        const uint16_t DISCOVERY_PORT = 7551;
        const uint64_t APPLICATION_ID = 0xdeadbeefull;
        const size_t CHECKSUM_LENGTH = 32;
        const size_t HEADER_PADDING = 8;

        const uint16_t PACKET_REQUEST = 0x00;
        const uint16_t PACKET_RESPONSE = 0x01;
        const uint16_t PACKET_MESSAGE = 0x02;

        std::string toHex(const std::string &data) {
            static const char digits[] = "0123456789abcdef";
            std::string out;
            out.reserve(data.size() * 2);

            for (unsigned char byte: data) {
                out.push_back(digits[byte >> 4]);
                out.push_back(digits[byte & 0x0f]);
            }

            return out;
        }

        void putLengthPrefixedBytes(BinaryStream &stream, const std::string &value) {
            stream.putLInt((uint32_t) value.size());
            stream.put(value);
        }

        std::string getLengthPrefixedBytes(ReadOnlyBinaryStream &stream) {
            const uint32_t length = stream.getLInt();
            return stream.get(length);
        }

    }

    const std::string &DiscoveryCrypto::key() {
        static const std::string value = []() {
            unsigned char seed[8];
            for (size_t i = 0; i < 8; i++)
                seed[i] = (unsigned char) ((APPLICATION_ID >> (i * 8)) & 0xff);

            unsigned char digest[SHA256_DIGEST_LENGTH];
            SHA256(seed, sizeof(seed), digest);
            return std::string(reinterpret_cast<const char *>(digest), SHA256_DIGEST_LENGTH);
        }();

        return value;
    }

    std::string DiscoveryCrypto::encrypt(const std::string &payload) {
        EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
        if (context == nullptr)
            return std::string();

        std::string output;
        output.resize(payload.size() + EVP_MAX_BLOCK_LENGTH);

        int length = 0;
        int total = 0;
        bool ok = EVP_EncryptInit_ex(context, EVP_aes_256_ecb(), nullptr,
                                     reinterpret_cast<const unsigned char *>(key().data()), nullptr) == 1;

        if (ok && EVP_EncryptUpdate(context, reinterpret_cast<unsigned char *>(&output[0]), &length,
                                    reinterpret_cast<const unsigned char *>(payload.data()),
                                    (int) payload.size()) == 1) {
            total = length;
            if (EVP_EncryptFinal_ex(context, reinterpret_cast<unsigned char *>(&output[0]) + total, &length) == 1)
                total += length;
            else
                ok = false;
        } else {
            ok = false;
        }

        EVP_CIPHER_CTX_free(context);
        if (!ok)
            return std::string();

        output.resize((size_t) total);
        return output;
    }

    bool DiscoveryCrypto::decrypt(const std::string &ciphertext, std::string &out) {
        EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
        if (context == nullptr)
            return false;

        std::string output;
        output.resize(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);

        int length = 0;
        int total = 0;
        bool ok = EVP_DecryptInit_ex(context, EVP_aes_256_ecb(), nullptr,
                                     reinterpret_cast<const unsigned char *>(key().data()), nullptr) == 1;

        if (ok && EVP_DecryptUpdate(context, reinterpret_cast<unsigned char *>(&output[0]), &length,
                                    reinterpret_cast<const unsigned char *>(ciphertext.data()),
                                    (int) ciphertext.size()) == 1) {
            total = length;
            if (EVP_DecryptFinal_ex(context, reinterpret_cast<unsigned char *>(&output[0]) + total, &length) == 1)
                total += length;
            else
                ok = false;
        } else {
            ok = false;
        }

        EVP_CIPHER_CTX_free(context);
        if (!ok)
            return false;

        output.resize((size_t) total);
        out = output;
        return true;
    }

    std::string DiscoveryCrypto::checksum(const std::string &payload) {
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int length = 0;

        HMAC(EVP_sha256(), key().data(), (int) key().size(),
             reinterpret_cast<const unsigned char *>(payload.data()), payload.size(), digest, &length);

        return std::string(reinterpret_cast<const char *>(digest), length);
    }

    std::string ServerData::encode() const {
        BinaryStream stream;
        stream.putByte(VERSION);
        stream.putString(mServerName);
        stream.putVarInt(mProtocol);
        stream.putString(mGameVersion);
        stream.putString(mLevelName);
        stream.putVarInt(mPlayerCount);
        stream.putVarInt(mMaxPlayerCount);
        stream.putVarInt(mGameType);
        stream.putBool(mEditorWorld);
        stream.putBool(mHardcore);
        stream.putBool(mAcceptsOnlineAuth);
        stream.putBool(mAcceptsSelfSignedAuth);

        std::string nonce = mNonce;
        if (nonce.empty()) {
            unsigned char raw[16];
            RAND_bytes(raw, sizeof(raw));
            nonce = toHex(std::string(reinterpret_cast<const char *>(raw), sizeof(raw)));
        }

        stream.putString(nonce);
        stream.putVarInt(CONNECTION_TYPE_LAN_SIGNALING);
        return stream.getBuffer();
    }

    namespace {

        std::string marshal(uint16_t packetId, uint64_t senderId, const std::string &payloadBytes) {
            BinaryStream body;
            body.putLShort(packetId);
            body.putLLong(senderId);
            body.put(std::string(HEADER_PADDING, '\0'));
            body.put(payloadBytes);

            const std::string buffer = body.getBuffer();

            BinaryStream framed;
            framed.putLShort((uint16_t) (buffer.size() + 2));
            framed.put(buffer);

            const std::string payload = framed.getBuffer();
            return DiscoveryCrypto::checksum(payload) + DiscoveryCrypto::encrypt(payload);
        }

        bool unmarshal(const std::string &bytes, uint16_t &packetId, uint64_t &senderId, std::string &payloadOut) {
            if (bytes.size() < CHECKSUM_LENGTH)
                return false;

            std::string payload;
            if (!DiscoveryCrypto::decrypt(bytes.substr(CHECKSUM_LENGTH), payload))
                return false;

            if (DiscoveryCrypto::checksum(payload) != bytes.substr(0, CHECKSUM_LENGTH))
                return false;

            try {
                ReadOnlyBinaryStream stream(payload);
                stream.getLShort();
                packetId = stream.getLShort();
                senderId = stream.getLLong();
                stream.get(HEADER_PADDING);
                payloadOut = stream.getRemaining();
            } catch (const std::exception &) {
                return false;
            }

            return true;
        }

    }

    DiscoveryListener::DiscoveryListener() : mRunning(false), mSocket(FALCON_DISCOVERY_INVALID_SOCKET), mNetworkId(0) {
    }

    DiscoveryListener::~DiscoveryListener() {
        stop();
    }

    bool DiscoveryListener::start(uint64_t networkId, const ServerDataProvider &serverData,
                                  const OfferHandler &offerHandler) {
        if (mRunning.load())
            return false;

        mNetworkId = networkId;
        mServerData = serverData;
        mOfferHandler = offerHandler;

        FalconDiscoverySocket descriptor = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (descriptor == FALCON_DISCOVERY_INVALID_SOCKET) {
            LOG_WARN(LogAreaID::Network, "Failed to create the NetherNet discovery socket");
            return false;
        }

        int reuse = 1;
        setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, (const char *) &reuse, sizeof(reuse));

        int broadcast = 1;
        setsockopt(descriptor, SOL_SOCKET, SO_BROADCAST, (const char *) &broadcast, sizeof(broadcast));

        struct sockaddr_in address;
        std::memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_ANY);
        address.sin_port = htons(DISCOVERY_PORT);

        if (bind(descriptor, (struct sockaddr *) &address, sizeof(address)) != 0) {
            LOG_WARN(LogAreaID::Network, "Failed to bind the NetherNet discovery socket to port %d", DISCOVERY_PORT);
            FALCON_DISCOVERY_CLOSE_SOCKET(descriptor);
            return false;
        }

        mSocket = (long long) descriptor;
        mRunning.store(true);
        mThread = std::thread(&DiscoveryListener::_run, this);

        LOG_INFO(LogAreaID::Network, "NetherNet listening for LAN discovery on port %d", DISCOVERY_PORT);
        return true;
    }

    void DiscoveryListener::stop() {
        if (!mRunning.load())
            return;

        mRunning.store(false);

        if (mSocket != FALCON_DISCOVERY_INVALID_SOCKET) {
            FALCON_DISCOVERY_CLOSE_SOCKET((FalconDiscoverySocket) mSocket);
            mSocket = FALCON_DISCOVERY_INVALID_SOCKET;
        }

        if (mThread.joinable())
            mThread.join();
    }

    void DiscoveryListener::_run() {
        std::vector<char> buffer(65535);

        while (mRunning.load()) {
            struct timeval timeout;
            timeout.tv_sec = 0;
            timeout.tv_usec = 250000;

            fd_set readable;
            FD_ZERO(&readable);
            FD_SET((FalconDiscoverySocket) mSocket, &readable);

            const int ready = select((int) mSocket + 1, &readable, nullptr, nullptr, &timeout);
            if (ready <= 0)
                continue;

            struct sockaddr_storage from;
            std::memset(&from, 0, sizeof(from));
            socklen_t fromLength = sizeof(from);

            const long long received = recvfrom((FalconDiscoverySocket) mSocket, buffer.data(), (int) buffer.size(), 0,
                                                (struct sockaddr *) &from, &fromLength);
            if (received <= 0)
                continue;

            _handleDatagram(std::string(buffer.data(), (size_t) received), &from, (unsigned int) fromLength);
        }
    }

    void DiscoveryListener::_handleDatagram(const std::string &buffer, const void *from, unsigned int fromLength) {
        uint16_t packetId = 0;
        uint64_t senderId = 0;
        std::string payload;

        if (!unmarshal(buffer, packetId, senderId, payload))
            return;

        if (senderId == mNetworkId)
            return;

        if (packetId == PACKET_REQUEST) {
            _sendResponse(from, fromLength);
            return;
        }

        if (packetId != PACKET_MESSAGE)
            return;

        try {
            ReadOnlyBinaryStream stream(payload);
            const uint64_t recipientId = stream.getLLong();
            const std::string data = getLengthPrefixedBytes(stream);

            if (recipientId != mNetworkId || data.empty() || data == "Ping")
                return;

            Signal signal;
            if (!signal.parse(data))
                return;

            if (signal.mType != SIGNAL_TYPE_OFFER)
                return;

            std::string answer;
            int errorCode = 0;
            if (!mOfferHandler(signal.mNetworkID, signal.mData, answer, errorCode))
                return;

            Signal response;
            response.mType = SIGNAL_TYPE_ANSWER;
            response.mConnectionID = signal.mConnectionID;
            response.mData = answer;
            response.mNetworkID = std::to_string(mNetworkId);

            _sendMessage(senderId, response.toString(), from, fromLength);
        } catch (const std::exception &) {
        }
    }

    void DiscoveryListener::_sendResponse(const void *from, unsigned int fromLength) {
        BinaryStream payload;
        const std::string application = mServerData().encode();
        const std::string hex = toHex(application);
        putLengthPrefixedBytes(payload, hex);

        const std::string datagram = marshal(PACKET_RESPONSE, mNetworkId, payload.getBuffer());
        sendto((FalconDiscoverySocket) mSocket, datagram.data(), (int) datagram.size(), 0,
               (const struct sockaddr *) from, (socklen_t) fromLength);
    }

    void DiscoveryListener::_sendMessage(uint64_t recipientId, const std::string &signalData,
                                         const void *from, unsigned int fromLength) {
        BinaryStream payload;
        payload.putLLong(recipientId);
        putLengthPrefixedBytes(payload, signalData);

        const std::string datagram = marshal(PACKET_MESSAGE, mNetworkId, payload.getBuffer());
        sendto((FalconDiscoverySocket) mSocket, datagram.data(), (int) datagram.size(), 0,
               (const struct sockaddr *) from, (socklen_t) fromLength);
    }

}
