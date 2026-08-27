#include "Network/BatchedNetworkPeer.h"

#include "Core/Utility/BinaryStream.h"
#include "Core/Utility/ReadOnlyBinaryStream.h"

BatchedNetworkPeer::BatchedNetworkPeer(std::shared_ptr<NetworkPeer> peer)
        : mPeer(std::move(peer)), mBatchReliability(Reliability::ReliableOrdered),
          mBatchCompressibility(Compressibility::Compressible) {}

void BatchedNetworkPeer::sendPacket(const std::string &data, Reliability reliability,
                                    Compressibility compressibility) {
    if (data.empty())
        return;

    if (compressibility == Compressibility::Incompressible)
        mBatchCompressibility = Compressibility::Incompressible;

    mBatchReliability = reliability;

    BinaryStream stream;
    stream.putUnsignedVarInt((uint32_t) data.size());

    mBatchBuffer.append(stream.getBuffer());
    mBatchBuffer.append(data);

    if (mBatchBuffer.size() >= MAX_BATCH_SIZE)
        flush();
}

void BatchedNetworkPeer::flush() {
    if (!mBatchBuffer.empty()) {
        mPeer->sendPacket(mBatchBuffer, mBatchReliability, mBatchCompressibility);

        mBatchBuffer.clear();
        mBatchCompressibility = Compressibility::Compressible;
    }

    mPeer->flush();
}

bool BatchedNetworkPeer::_unbatch(const std::string &batch) {
    ReadOnlyBinaryStream stream(batch);

    try {
        while (!stream.feof()) {
            const uint32_t length = stream.getUnsignedVarInt();
            if (length == 0)
                return false;

            mIncomingPackets.push_back(stream.get(length));
        }
    } catch (const BinaryDataException &) {
        return false;
    }

    return true;
}

NetworkPeer::DataStatus BatchedNetworkPeer::receivePacket(std::string &outData) {
    for (;;) {
        if (!mIncomingPackets.empty()) {
            outData = std::move(mIncomingPackets.front());
            mIncomingPackets.pop_front();
            return DataStatus::HasData;
        }

        std::string batch;
        if (mPeer->receivePacket(batch) == DataStatus::NoData)
            return DataStatus::NoData;

        _unbatch(batch);
    }
}

NetworkPeer::NetworkStatus BatchedNetworkPeer::getNetworkStatus() const {
    return mPeer->getNetworkStatus();
}

void BatchedNetworkPeer::update() {
    mPeer->update();
}
