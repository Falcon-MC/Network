#include "RakNet/RakPeer.h"
#include "RakNet/MessageIdentifiers.h"

#include <chrono>

#include <cstdlib>
#include <random>

namespace RakNet {

    static uint64_t GenerateGUID() {
        std::random_device randomDevice;
        std::mt19937_64 generator(((uint64_t) randomDevice() << 32) ^ GetTimeUS());
        return generator();
    }

    RakPeerInterface *RakPeerInterface::GetInstance() {
        return new RakPeer();
    }

    void RakPeerInterface::DestroyInstance(RakPeerInterface *instance) {
        delete instance;
    }

    RakPeer::RakPeer()
            : endThreads(true), myGuid(GenerateGUID()), maximumNumberOfPeers(0),
              maximumIncomingConnections(0), nextSystemIndex(0) {}

    RakPeer::~RakPeer() {
        Shutdown(0);
    }

    StartupResult RakPeer::Startup(unsigned int maxConnections, SocketDescriptor *socketDescriptors,
                                   unsigned int socketDescriptorCount) {
        if (!endThreads)
            return RAKNET_ALREADY_STARTED;

        if (maxConnections == 0)
            return INVALID_MAX_CONNECTIONS;

        if (socketDescriptors == nullptr || socketDescriptorCount == 0)
            return INVALID_SOCKET_DESCRIPTORS;

        const RNS2BindResult bindResult = socket.Bind(socketDescriptors[0].hostAddress, socketDescriptors[0].port,
                                                      socketDescriptors[0].socketFamily);
        if (bindResult != BR_SUCCESS)
            return SOCKET_FAILED_TO_BIND;

        maximumNumberOfPeers = maxConnections;
        if (maximumIncomingConnections > maxConnections)
            maximumIncomingConnections = (unsigned short) maxConnections;

        endThreads = false;
        networkThread = std::thread(&RakPeer::UpdateNetworkLoop, this);

        return RAKNET_STARTED;
    }

    void RakPeer::Shutdown(unsigned int blockDuration) {
        if (endThreads)
            return;

        if (blockDuration > 0) {
            const TimeMS startTime = GetTimeMS();
            while (GetTimeMS() - startTime < blockDuration) {
                std::lock_guard<std::mutex> guard(remoteSystemMutex);
                bool dataWaiting = false;
                for (auto &entry: remoteSystemList) {
                    if (entry.second->reliabilityLayer.IsOutgoingDataWaiting()) {
                        dataWaiting = true;
                        break;
                    }
                }
                if (!dataWaiting)
                    break;
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }

        endThreads = true;

        if (networkThread.joinable())
            networkThread.join();

        socket.Close();

        {
            std::lock_guard<std::mutex> guard(remoteSystemMutex);
            remoteSystemList.clear();
        }

        {
            std::lock_guard<std::mutex> guard(packetQueueMutex);
            for (Packet *packet: packetQueue)
                DeallocatePacket(packet);
            packetQueue.clear();
        }
    }

    void RakPeer::SetMaximumIncomingConnections(unsigned short numberAllowed) {
        maximumIncomingConnections = numberAllowed;
    }

    unsigned short RakPeer::NumberOfConnections() const {
        std::lock_guard<std::mutex> guard(remoteSystemMutex);
        return NumberOfConnectionsUnlocked();
    }

    unsigned short RakPeer::NumberOfConnectionsUnlocked() const {
        unsigned short count = 0;
        for (auto &entry: remoteSystemList) {
            if (entry.second->connectMode == IS_CONNECTED)
                count++;
        }
        return count;
    }

    void RakPeer::SetOfflinePingResponse(const char *data, unsigned int length) {
        std::lock_guard<std::mutex> guard(offlinePingResponseMutex);
        offlinePingResponse.assign((const unsigned char *) data, (const unsigned char *) data + length);
    }

    Packet *RakPeer::AllocPacket(unsigned int dataSize, const SystemAddress &systemAddress, const RakNetGUID &guid) {
        Packet *packet = new Packet();
        packet->data = new unsigned char[dataSize];
        packet->length = dataSize;
        packet->bitSize = BYTES_TO_BITS(dataSize);
        packet->systemAddress = systemAddress;
        packet->guid = guid;
        packet->deleteData = true;
        packet->wasGeneratedLocally = false;
        return packet;
    }

    void RakPeer::DeallocatePacket(Packet *packet) {
        if (!packet)
            return;

        if (packet->deleteData)
            delete[] packet->data;
        delete packet;
    }

    void RakPeer::PushBackPacket(Packet *packet) {
        std::lock_guard<std::mutex> guard(packetQueueMutex);
        packetQueue.push_back(packet);
    }

    Packet *RakPeer::Receive() {
        std::lock_guard<std::mutex> guard(packetQueueMutex);

        if (packetQueue.empty())
            return nullptr;

        Packet *packet = packetQueue.front();
        packetQueue.pop_front();
        return packet;
    }

    RakPeer::RemoteSystemStruct *RakPeer::GetRemoteSystemFromSystemAddress(const SystemAddress &systemAddress) const {
        auto it = remoteSystemList.find(systemAddress);
        return it == remoteSystemList.end() ? nullptr : it->second.get();
    }

    RakPeer::RemoteSystemStruct *RakPeer::GetRemoteSystemFromGUID(const RakNetGUID &guid) const {
        for (auto &entry: remoteSystemList) {
            if (entry.second->guid == guid)
                return entry.second.get();
        }
        return nullptr;
    }

    SystemAddress RakPeer::GetSystemAddressFromGuid(const RakNetGUID input) const {
        std::lock_guard<std::mutex> guard(remoteSystemMutex);

        RemoteSystemStruct *remoteSystem = GetRemoteSystemFromGUID(input);
        return remoteSystem ? remoteSystem->systemAddress : UNASSIGNED_SYSTEM_ADDRESS;
    }

    RakNetGUID RakPeer::GetGuidFromSystemAddress(const SystemAddress input) const {
        std::lock_guard<std::mutex> guard(remoteSystemMutex);

        RemoteSystemStruct *remoteSystem = GetRemoteSystemFromSystemAddress(input);
        return remoteSystem ? remoteSystem->guid : UNASSIGNED_RAKNET_GUID;
    }

    ConnectionState RakPeer::GetConnectionState(const AddressOrGUID systemIdentifier) {
        std::lock_guard<std::mutex> guard(remoteSystemMutex);

        RemoteSystemStruct *remoteSystem = systemIdentifier.rakNetGuid == UNASSIGNED_RAKNET_GUID
                                           ? GetRemoteSystemFromSystemAddress(systemIdentifier.systemAddress)
                                           : GetRemoteSystemFromGUID(systemIdentifier.rakNetGuid);

        return remoteSystem ? remoteSystem->connectMode : IS_NOT_CONNECTED;
    }

    int RakPeer::GetAveragePing(const AddressOrGUID systemIdentifier) {
        std::lock_guard<std::mutex> guard(remoteSystemMutex);

        RemoteSystemStruct *remoteSystem = systemIdentifier.rakNetGuid == UNASSIGNED_RAKNET_GUID
                                           ? GetRemoteSystemFromSystemAddress(systemIdentifier.systemAddress)
                                           : GetRemoteSystemFromGUID(systemIdentifier.rakNetGuid);

        return remoteSystem ? (int) remoteSystem->reliabilityLayer.GetAveragePing() : -1;
    }

    void RakPeer::SetTimeoutTime(TimeMS timeMS, const SystemAddress target) {
        std::lock_guard<std::mutex> guard(remoteSystemMutex);

        if (target == UNASSIGNED_SYSTEM_ADDRESS) {
            for (auto &entry: remoteSystemList)
                entry.second->reliabilityLayer.SetTimeoutTime(timeMS);
            return;
        }

        RemoteSystemStruct *remoteSystem = GetRemoteSystemFromSystemAddress(target);
        if (remoteSystem)
            remoteSystem->reliabilityLayer.SetTimeoutTime(timeMS);
    }

    void RakPeer::SendImmediate(RemoteSystemStruct *remoteSystem, const char *data, unsigned int length,
                                PacketPriority priority, PacketReliability reliability, unsigned char orderingChannel,
                                TimeMS time) {
        remoteSystem->reliabilityLayer.Send(data, BYTES_TO_BITS(length), priority, reliability, orderingChannel, time);
    }

    uint32_t RakPeer::Send(const char *data, int length, PacketPriority priority, PacketReliability reliability,
                           char orderingChannel, const AddressOrGUID systemIdentifier, bool broadcast) {
        if (data == nullptr || length <= 0)
            return 0;

        const TimeMS time = GetTimeMS();

        std::lock_guard<std::mutex> guard(remoteSystemMutex);

        if (broadcast) {
            uint32_t sent = 0;
            for (auto &entry: remoteSystemList) {
                if (entry.second->connectMode != IS_CONNECTED)
                    continue;
                SendImmediate(entry.second.get(), data, (unsigned int) length, priority, reliability,
                              (unsigned char) orderingChannel, time);
                sent++;
            }
            return sent;
        }

        RemoteSystemStruct *remoteSystem = systemIdentifier.rakNetGuid == UNASSIGNED_RAKNET_GUID
                                           ? GetRemoteSystemFromSystemAddress(systemIdentifier.systemAddress)
                                           : GetRemoteSystemFromGUID(systemIdentifier.rakNetGuid);

        if (!remoteSystem || remoteSystem->connectMode != IS_CONNECTED)
            return 0;

        SendImmediate(remoteSystem, data, (unsigned int) length, priority, reliability,
                      (unsigned char) orderingChannel, time);
        return 1;
    }

    void RakPeer::CloseConnection(const AddressOrGUID target, bool sendDisconnectionNotification,
                                  unsigned char orderingChannel, PacketPriority disconnectionNotificationPriority) {
        std::lock_guard<std::mutex> guard(remoteSystemMutex);

        RemoteSystemStruct *remoteSystem = target.rakNetGuid == UNASSIGNED_RAKNET_GUID
                                           ? GetRemoteSystemFromSystemAddress(target.systemAddress)
                                           : GetRemoteSystemFromGUID(target.rakNetGuid);

        if (!remoteSystem)
            return;

        CloseConnectionInternal(remoteSystem->systemAddress, sendDisconnectionNotification, orderingChannel,
                                disconnectionNotificationPriority);
    }

    void RakPeer::CloseConnectionInternal(const SystemAddress &systemAddress, bool sendDisconnectionNotification,
                                          unsigned char orderingChannel, PacketPriority priority) {
        RemoteSystemStruct *remoteSystem = GetRemoteSystemFromSystemAddress(systemAddress);
        if (!remoteSystem)
            return;

        if (sendDisconnectionNotification && remoteSystem->connectMode == IS_CONNECTED) {
            const unsigned char messageId = ID_DISCONNECTION_NOTIFICATION;
            SendImmediate(remoteSystem, (const char *) &messageId, 1, priority, RELIABLE_ORDERED, orderingChannel,
                          GetTimeMS());

            remoteSystem->connectMode = IS_DISCONNECTING;
            remoteSystem->reliabilityLayer.Update(&socket, systemAddress, remoteSystem->MTUSize, GetTimeMS());
        }

        remoteSystemList.erase(systemAddress);
    }

    bool RakPeer::IsOfflineMessageMagic(const unsigned char *data, unsigned int length, unsigned int offset) {
        if (length < offset + sizeof(OFFLINE_MESSAGE_DATA_ID))
            return false;
        return memcmp(data + offset, OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID)) == 0;
    }

    void RakPeer::SendOfflineMessage(const BitStream &bitStream, const SystemAddress &systemAddress) {
        socket.Send((const char *) bitStream.GetData(), (int) bitStream.GetNumberOfBytesUsed(), systemAddress);
    }

    RakPeer::RemoteSystemStruct *RakPeer::AssignSystemAddressToRemoteSystemList(const SystemAddress &systemAddress,
                                                                               int mtuSize, TimeMS time) {
        if (remoteSystemList.size() >= maximumNumberOfPeers)
            return nullptr;

        std::unique_ptr<RemoteSystemStruct> remoteSystem(new RemoteSystemStruct());
        remoteSystem->systemAddress = systemAddress;
        remoteSystem->systemAddress.systemIndex = nextSystemIndex++;
        remoteSystem->MTUSize = mtuSize;
        remoteSystem->connectMode = IS_CONNECTING;
        remoteSystem->connectionTime = time;
        remoteSystem->weStartedTheConnection = false;
        remoteSystem->reliabilityLayer.Reset(mtuSize);

        RemoteSystemStruct *result = remoteSystem.get();
        remoteSystemList[systemAddress] = std::move(remoteSystem);
        return result;
    }

    bool RakPeer::ProcessOfflineNetworkPacket(const RNS2RecvStruct &recvStruct, TimeMS time) {
        const unsigned char *data = (const unsigned char *) recvStruct.data;
        const unsigned int length = (unsigned int) recvStruct.bytesRead;
        const SystemAddress &systemAddress = recvStruct.systemAddress;

        BitStream in((unsigned char *) recvStruct.data, length, false);

        unsigned char messageId;
        if (!in.Read(messageId))
            return false;

        switch (messageId) {
            case ID_UNCONNECTED_PING:
            case ID_UNCONNECTED_PING_OPEN_CONNECTIONS: {
                if (!IsOfflineMessageMagic(data, length, 1 + 8))
                    return false;

                uint64_t pingTime;
                if (!in.Read(pingTime))
                    return false;

                in.IgnoreBytes(sizeof(OFFLINE_MESSAGE_DATA_ID));

                std::lock_guard<std::mutex> guard(offlinePingResponseMutex);

                BitStream out;
                out.Write((unsigned char) ID_UNCONNECTED_PONG);
                out.Write(pingTime);
                out.Write(myGuid.g);
                out.WriteAlignedBytes(OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID));
                out.Write((uint16_t) offlinePingResponse.size());
                if (!offlinePingResponse.empty())
                    out.WriteAlignedBytes(offlinePingResponse.data(), (unsigned int) offlinePingResponse.size());

                SendOfflineMessage(out, systemAddress);
                return true;
            }

            case ID_OPEN_CONNECTION_REQUEST_1: {
                if (!IsOfflineMessageMagic(data, length, 1))
                    return false;

                in.IgnoreBytes(sizeof(OFFLINE_MESSAGE_DATA_ID));

                unsigned char protocolVersion;
                if (!in.Read(protocolVersion))
                    return false;

                if (protocolVersion != RAKNET_PROTOCOL_VERSION) {
                    BitStream out;
                    out.Write((unsigned char) ID_INCOMPATIBLE_PROTOCOL_VERSION);
                    out.Write((unsigned char) RAKNET_PROTOCOL_VERSION);
                    out.WriteAlignedBytes(OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID));
                    out.Write(myGuid.g);
                    SendOfflineMessage(out, systemAddress);
                    return true;
                }

                int mtuSize = (int) length + UDP_HEADER_SIZE;
                if (mtuSize < MINIMUM_MTU_SIZE)
                    mtuSize = MINIMUM_MTU_SIZE;
                if (mtuSize > MAXIMUM_MTU_SIZE)
                    mtuSize = MAXIMUM_MTU_SIZE;

                BitStream out;
                out.Write((unsigned char) ID_OPEN_CONNECTION_REPLY_1);
                out.WriteAlignedBytes(OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID));
                out.Write(myGuid.g);
                out.Write((unsigned char) 0);
                out.Write((uint16_t) mtuSize);

                SendOfflineMessage(out, systemAddress);
                return true;
            }

            case ID_OPEN_CONNECTION_REQUEST_2: {
                if (!IsOfflineMessageMagic(data, length, 1))
                    return false;

                in.IgnoreBytes(sizeof(OFFLINE_MESSAGE_DATA_ID));

                SystemAddress bindingAddress;
                uint16_t mtuSize;
                uint64_t clientGuid;

                if (!in.Read(bindingAddress) || !in.Read(mtuSize) || !in.Read(clientGuid))
                    return false;

                if (mtuSize < MINIMUM_MTU_SIZE)
                    mtuSize = MINIMUM_MTU_SIZE;
                if (mtuSize > MAXIMUM_MTU_SIZE)
                    mtuSize = MAXIMUM_MTU_SIZE;

                std::lock_guard<std::mutex> guard(remoteSystemMutex);

                RemoteSystemStruct *remoteSystem = GetRemoteSystemFromSystemAddress(systemAddress);

                if (remoteSystem && remoteSystem->guid.g == clientGuid) {
                    BitStream out;
                    out.Write((unsigned char) ID_ALREADY_CONNECTED);
                    out.WriteAlignedBytes(OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID));
                    out.Write(myGuid.g);
                    SendOfflineMessage(out, systemAddress);
                    return true;
                }

                if (remoteSystem)
                    remoteSystemList.erase(systemAddress);

                if (NumberOfConnectionsUnlocked() >= maximumIncomingConnections) {
                    BitStream out;
                    out.Write((unsigned char) ID_NO_FREE_INCOMING_CONNECTIONS);
                    out.WriteAlignedBytes(OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID));
                    out.Write(myGuid.g);
                    SendOfflineMessage(out, systemAddress);
                    return true;
                }

                remoteSystem = AssignSystemAddressToRemoteSystemList(systemAddress, mtuSize, time);
                if (!remoteSystem) {
                    BitStream out;
                    out.Write((unsigned char) ID_NO_FREE_INCOMING_CONNECTIONS);
                    out.WriteAlignedBytes(OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID));
                    out.Write(myGuid.g);
                    SendOfflineMessage(out, systemAddress);
                    return true;
                }

                remoteSystem->guid = RakNetGUID(clientGuid);

                BitStream out;
                out.Write((unsigned char) ID_OPEN_CONNECTION_REPLY_2);
                out.WriteAlignedBytes(OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID));
                out.Write(myGuid.g);
                out.Write(systemAddress);
                out.Write((uint16_t) mtuSize);
                out.Write((unsigned char) 0);

                SendOfflineMessage(out, systemAddress);
                return true;
            }

            default:
                return false;
        }
    }

    void RakPeer::ProcessNetworkPacket(const RNS2RecvStruct &recvStruct, TimeMS time) {
        if (recvStruct.bytesRead <= 0)
            return;

        const unsigned char firstByte = (unsigned char) recvStruct.data[0];

        if ((firstByte & 0x80) == 0) {
            ProcessOfflineNetworkPacket(recvStruct, time);
            return;
        }

        std::lock_guard<std::mutex> guard(remoteSystemMutex);

        RemoteSystemStruct *remoteSystem = GetRemoteSystemFromSystemAddress(recvStruct.systemAddress);
        if (!remoteSystem)
            return;

        ProcessConnectedPacket(remoteSystem, recvStruct, time);
    }

    void RakPeer::ProcessConnectedPacket(RemoteSystemStruct *remoteSystem, const RNS2RecvStruct &recvStruct,
                                         TimeMS time) {
        if (!remoteSystem->reliabilityLayer.HandleSocketReceiveFromConnectedPlayer(recvStruct.data,
                                                                                  (unsigned int) recvStruct.bytesRead,
                                                                                  time))
            return;

        for (;;) {
            InternalPacket *internalPacket = remoteSystem->reliabilityLayer.Receive();
            if (!internalPacket)
                break;

            if (ParseConnectedMessage(remoteSystem, internalPacket, time)) {
                delete internalPacket;
                continue;
            }

            Packet *packet = AllocPacket(BITS_TO_BYTES(internalPacket->dataBitLength), remoteSystem->systemAddress,
                                         remoteSystem->guid);
            memcpy(packet->data, internalPacket->data.data(), packet->length);
            packet->bitSize = internalPacket->dataBitLength;

            delete internalPacket;
            PushBackPacket(packet);
        }
    }

    bool RakPeer::ParseConnectedMessage(RemoteSystemStruct *remoteSystem, InternalPacket *internalPacket, TimeMS time) {
        if (internalPacket->data.empty())
            return true;

        const unsigned char messageId = internalPacket->data[0];

        BitStream in(internalPacket->data.data(), BITS_TO_BYTES(internalPacket->dataBitLength), false);
        in.IgnoreBytes(1);

        switch (messageId) {
            case ID_CONNECTION_REQUEST: {
                uint64_t clientGuid;
                uint64_t requestTime;

                if (!in.Read(clientGuid) || !in.Read(requestTime))
                    return true;

                remoteSystem->guid = RakNetGUID(clientGuid);

                BitStream out;
                out.Write((unsigned char) ID_CONNECTION_REQUEST_ACCEPTED);
                out.Write(remoteSystem->systemAddress);
                out.Write((uint16_t) remoteSystem->systemAddress.systemIndex);

                for (int i = 0; i < MAXIMUM_NUMBER_OF_INTERNAL_IDS; i++)
                    out.Write(UNASSIGNED_SYSTEM_ADDRESS);

                out.Write(requestTime);
                out.Write((uint64_t) time);

                SendImmediate(remoteSystem, (const char *) out.GetData(), out.GetNumberOfBytesUsed(),
                              IMMEDIATE_PRIORITY, RELIABLE_ORDERED, 0, time);
                return true;
            }

            case ID_NEW_INCOMING_CONNECTION: {
                if (remoteSystem->connectMode == IS_CONNECTED)
                    return true;

                remoteSystem->connectMode = IS_CONNECTED;

                Packet *packet = AllocPacket(1, remoteSystem->systemAddress, remoteSystem->guid);
                packet->data[0] = ID_NEW_INCOMING_CONNECTION;
                PushBackPacket(packet);
                return true;
            }

            case ID_CONNECTED_PING: {
                uint64_t pingTime;
                if (!in.Read(pingTime))
                    return true;

                BitStream out;
                out.Write((unsigned char) ID_CONNECTED_PONG);
                out.Write(pingTime);
                out.Write((uint64_t) time);

                SendImmediate(remoteSystem, (const char *) out.GetData(), out.GetNumberOfBytesUsed(),
                              IMMEDIATE_PRIORITY, UNRELIABLE, 0, time);
                return true;
            }

            case ID_CONNECTED_PONG:
                return true;

            case ID_DETECT_LOST_CONNECTIONS:
                return true;

            case ID_DISCONNECTION_NOTIFICATION: {
                remoteSystem->connectMode = IS_DISCONNECTED;
                remoteSystem->reliabilityLayer.KillConnection();

                Packet *packet = AllocPacket(1, remoteSystem->systemAddress, remoteSystem->guid);
                packet->data[0] = ID_DISCONNECTION_NOTIFICATION;
                PushBackPacket(packet);
                return true;
            }

            default:
                return false;
        }
    }

    void RakPeer::UpdateNetworkLoop() {
        RNS2RecvStruct recvStruct;

        while (!endThreads) {
            while (socket.RecvFrom(&recvStruct, 5))
                ProcessNetworkPacket(recvStruct, GetTimeMS());

            const TimeMS time = GetTimeMS();

            std::lock_guard<std::mutex> guard(remoteSystemMutex);

            for (auto it = remoteSystemList.begin(); it != remoteSystemList.end();) {
                RemoteSystemStruct *remoteSystem = it->second.get();
                remoteSystem->reliabilityLayer.Update(&socket, remoteSystem->systemAddress, remoteSystem->MTUSize,
                                                      time);

                if (remoteSystem->reliabilityLayer.IsDeadConnection()) {
                    if (remoteSystem->connectMode == IS_CONNECTED) {
                        Packet *packet = AllocPacket(1, remoteSystem->systemAddress, remoteSystem->guid);
                        packet->data[0] = ID_CONNECTION_LOST;
                        PushBackPacket(packet);
                    }

                    it = remoteSystemList.erase(it);
                    continue;
                }

                ++it;
            }
        }
    }

}
