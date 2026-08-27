#include "Network/CompressedNetworkPeer.h"

#include <zlib.h>

namespace {

    const int RAW_DEFLATE_WINDOW_BITS = -15;
    const size_t MAX_DECOMPRESSED_SIZE = 8 * 1024 * 1024;

}

CompressedNetworkPeer::CompressedNetworkPeer(std::shared_ptr<NetworkPeer> peer)
        : mPeer(std::move(peer)), mAlgorithm(CompressionAlgorithm::ZLib), mCompressionThreshold(1),
          mCompressionEnabled(false) {}

void CompressedNetworkPeer::enableCompression(CompressionAlgorithm algorithm, unsigned short threshold) {
    mAlgorithm = algorithm;
    mCompressionThreshold = threshold;
    mCompressionEnabled = true;
}

void CompressedNetworkPeer::disableCompression() {
    mCompressionEnabled = false;
}

bool CompressedNetworkPeer::_compress(const std::string &input, std::string &outData) {
    z_stream stream{};

    if (deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, RAW_DEFLATE_WINDOW_BITS, 8, Z_DEFAULT_STRATEGY) != Z_OK)
        return false;

    outData.resize(deflateBound(&stream, (uLong) input.size()));

    stream.next_in = (Bytef *) input.data();
    stream.avail_in = (uInt) input.size();
    stream.next_out = (Bytef *) &outData[0];
    stream.avail_out = (uInt) outData.size();

    const int result = deflate(&stream, Z_FINISH);
    const size_t written = outData.size() - stream.avail_out;
    deflateEnd(&stream);

    if (result != Z_STREAM_END)
        return false;

    outData.resize(written);
    return true;
}

bool CompressedNetworkPeer::_decompress(const char *data, size_t length, std::string &outData) {
    z_stream stream{};

    if (inflateInit2(&stream, RAW_DEFLATE_WINDOW_BITS) != Z_OK)
        return false;

    stream.next_in = (Bytef *) data;
    stream.avail_in = (uInt) length;

    outData.clear();

    char buffer[16384];
    int result;

    do {
        stream.next_out = (Bytef *) buffer;
        stream.avail_out = (uInt) sizeof(buffer);

        result = inflate(&stream, Z_NO_FLUSH);

        if (result != Z_OK && result != Z_STREAM_END && result != Z_BUF_ERROR) {
            inflateEnd(&stream);
            return false;
        }

        outData.append(buffer, sizeof(buffer) - stream.avail_out);

        if (outData.size() > MAX_DECOMPRESSED_SIZE) {
            inflateEnd(&stream);
            return false;
        }
    } while (result != Z_STREAM_END && stream.avail_in > 0);

    inflateEnd(&stream);
    return result == Z_STREAM_END;
}

void CompressedNetworkPeer::sendPacket(const std::string &data, Reliability reliability,
                                       Compressibility compressibility) {
    if (data.empty())
        return;

    std::string payload;
    payload.push_back((char) GAME_PACKET_ID);

    if (!mCompressionEnabled) {
        payload.append(data);
        mPeer->sendPacket(payload, reliability, compressibility);
        return;
    }

    const bool shouldCompress = compressibility == Compressibility::Compressible &&
                                mAlgorithm == CompressionAlgorithm::ZLib &&
                                data.size() >= mCompressionThreshold;

    std::string compressed;
    if (shouldCompress && _compress(data, compressed)) {
        payload.push_back((char) CompressionAlgorithm::ZLib);
        payload.append(compressed);
    } else {
        payload.push_back((char) CompressionAlgorithm::None);
        payload.append(data);
    }

    mPeer->sendPacket(payload, reliability, compressibility);
}

NetworkPeer::DataStatus CompressedNetworkPeer::receivePacket(std::string &outData) {
    std::string payload;

    for (;;) {
        if (mPeer->receivePacket(payload) == DataStatus::NoData)
            return DataStatus::NoData;

        if (payload.size() < 2 || (unsigned char) payload[0] != GAME_PACKET_ID)
            continue;

        const char *body = payload.data() + 1;
        size_t bodyLength = payload.size() - 1;

        if (!mCompressionEnabled) {
            outData.assign(body, bodyLength);
            return DataStatus::HasData;
        }

        const CompressionAlgorithm algorithm = (CompressionAlgorithm) (unsigned char) body[0];
        body += 1;
        bodyLength -= 1;

        if (algorithm == CompressionAlgorithm::None) {
            outData.assign(body, bodyLength);
            return DataStatus::HasData;
        }

        if (algorithm != CompressionAlgorithm::ZLib)
            continue;

        if (!_decompress(body, bodyLength, outData))
            continue;

        return DataStatus::HasData;
    }
}

NetworkPeer::NetworkStatus CompressedNetworkPeer::getNetworkStatus() const {
    return mPeer->getNetworkStatus();
}

void CompressedNetworkPeer::update() {
    mPeer->update();
}

void CompressedNetworkPeer::flush() {
    mPeer->flush();
}
