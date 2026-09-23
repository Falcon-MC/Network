#include "Network/EncryptedNetworkPeer.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <cstring>

namespace {

    const size_t CHECKSUM_SIZE = 8;
    const size_t IV_KEY_BYTES = 12;
    const uint8_t IV_COUNTER_START = 2;

    evp_cipher_ctx_st *createCipher(const EncryptionKey &key) {
        uint8_t iv[16] = {};
        std::memcpy(iv, key.data(), IV_KEY_BYTES);
        iv[15] = IV_COUNTER_START;

        EVP_CIPHER_CTX *cipher = EVP_CIPHER_CTX_new();
        if (cipher == nullptr)
            return nullptr;

        if (EVP_EncryptInit_ex(cipher, EVP_aes_256_ctr(), nullptr, key.data(), iv) != 1) {
            EVP_CIPHER_CTX_free(cipher);
            return nullptr;
        }
        return cipher;
    }

    bool applyKeyStream(evp_cipher_ctx_st *cipher, char *data, size_t length) {
        int written = 0;
        return EVP_EncryptUpdate(cipher, (unsigned char *) data, &written, (const unsigned char *) data,
                                 (int) length) == 1
               && (size_t) written == length;
    }

}

EncryptedNetworkPeer::EncryptedNetworkPeer(std::shared_ptr<NetworkPeer> peer) : mPeer(std::move(peer)) {
}

EncryptedNetworkPeer::~EncryptedNetworkPeer() {
    EVP_CIPHER_CTX_free(mEncryptCipher);
    EVP_CIPHER_CTX_free(mDecryptCipher);
    EVP_MD_CTX_free(mSendDigest);
    EVP_MD_CTX_free(mReceiveDigest);
    OPENSSL_cleanse(mKey.data(), mKey.size());
}

bool EncryptedNetworkPeer::enableEncryption(const EncryptionKey &key) {
    if (mEncryptCipher != nullptr)
        return false;

    mSendDigest = EVP_MD_CTX_new();
    mReceiveDigest = EVP_MD_CTX_new();
    mEncryptCipher = createCipher(key);
    mDecryptCipher = createCipher(key);
    if (mSendDigest == nullptr || mReceiveDigest == nullptr || mEncryptCipher == nullptr
        || mDecryptCipher == nullptr) {
        EVP_CIPHER_CTX_free(mEncryptCipher);
        EVP_CIPHER_CTX_free(mDecryptCipher);
        EVP_MD_CTX_free(mSendDigest);
        EVP_MD_CTX_free(mReceiveDigest);
        mEncryptCipher = nullptr;
        mDecryptCipher = nullptr;
        mSendDigest = nullptr;
        mReceiveDigest = nullptr;
        return false;
    }

    mKey = key;
    mSendCounter = 0;
    mReceiveCounter = 0;
    return true;
}

void EncryptedNetworkPeer::sendPacket(const std::string &data, Reliability reliability,
                                      Compressibility compressibility) {
    if (mEncryptCipher == nullptr) {
        mPeer->sendPacket(data, reliability, compressibility);
        return;
    }

    const size_t offset = mPeer->usesGamePacketId() ? 1 : 0;
    if (data.size() < offset)
        return;

    uint8_t checksum[CHECKSUM_SIZE];
    if (!_checksum(mSendDigest, mSendCounter++, data.data() + offset, data.size() - offset, checksum))
        return;

    mSendBuffer.assign(data);
    mSendBuffer.append((const char *) checksum, CHECKSUM_SIZE);
    if (!applyKeyStream(mEncryptCipher, &mSendBuffer[offset], mSendBuffer.size() - offset))
        return;

    mPeer->sendPacket(mSendBuffer, reliability, compressibility);
}

NetworkPeer::DataStatus EncryptedNetworkPeer::receivePacket(std::string &outData) {
    const DataStatus status = mPeer->receivePacket(outData);
    if (status != DataStatus::HasData || mDecryptCipher == nullptr || mFailed)
        return mFailed ? DataStatus::NoData : status;

    const size_t offset = mPeer->usesGamePacketId() ? 1 : 0;
    if (outData.size() < offset + CHECKSUM_SIZE) {
        mFailed = true;
        return DataStatus::NoData;
    }

    if (!applyKeyStream(mDecryptCipher, &outData[offset], outData.size() - offset)) {
        mFailed = true;
        return DataStatus::NoData;
    }

    const size_t payloadSize = outData.size() - offset - CHECKSUM_SIZE;
    uint8_t expected[CHECKSUM_SIZE];
    if (!_checksum(mReceiveDigest, mReceiveCounter++, outData.data() + offset, payloadSize, expected)
        || CRYPTO_memcmp(expected, outData.data() + offset + payloadSize, CHECKSUM_SIZE) != 0) {
        mFailed = true;
        return DataStatus::NoData;
    }

    outData.resize(offset + payloadSize);
    return DataStatus::HasData;
}

NetworkPeer::NetworkStatus EncryptedNetworkPeer::getNetworkStatus() const {
    return mPeer->getNetworkStatus();
}

void EncryptedNetworkPeer::update() {
    mPeer->update();
}

void EncryptedNetworkPeer::flush() {
    mPeer->flush();
}

bool EncryptedNetworkPeer::usesGamePacketId() const {
    return mPeer->usesGamePacketId();
}

bool EncryptedNetworkPeer::_checksum(evp_md_ctx_st *digest, uint64_t counter, const char *data, size_t length,
                                     uint8_t out[8]) {
    uint8_t counterBytes[8];
    for (size_t index = 0; index < sizeof(counterBytes); ++index)
        counterBytes[index] = (uint8_t) (counter >> (index * 8));

    uint8_t hash[EVP_MAX_MD_SIZE];
    unsigned int digestLength = 0;
    const bool hashed = EVP_DigestInit_ex(digest, EVP_sha256(), nullptr) == 1
                        && EVP_DigestUpdate(digest, counterBytes, sizeof(counterBytes)) == 1
                        && EVP_DigestUpdate(digest, data, length) == 1
                        && EVP_DigestUpdate(digest, mKey.data(), mKey.size()) == 1
                        && EVP_DigestFinal_ex(digest, hash, &digestLength) == 1;
    if (!hashed || digestLength < CHECKSUM_SIZE)
        return false;

    std::memcpy(out, hash, CHECKSUM_SIZE);
    return true;
}
