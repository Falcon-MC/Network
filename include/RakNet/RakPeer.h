#pragma once

#include "raknet/RakNetSocket2.h"
#include "raknet/RakPeerInterface.h"
#include "raknet/ReliabilityLayer.h"

#include <atomic>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

namespace RakNet {

    class RakPeer : public RakPeerInterface {
    public:
        struct RemoteSystemStruct {
            SystemAddress systemAddress;
            RakNetGUID guid;
            ReliabilityLayer reliabilityLayer;
            int MTUSize;
            ConnectionState connectMode;
            TimeMS connectionTime;
            bool weStartedTheConnection;

            RemoteSystemStruct()
                    : MTUSize(MAXIMUM_MTU_SIZE), connectMode(IS_PENDING), connectionTime(0),
                      weStartedTheConnection(false) {}
        };

        RakPeer();

        ~RakPeer() override;

        StartupResult Startup(unsigned int maxConnections, SocketDescriptor *socketDescriptors,
                              unsigned int socketDescriptorCount) override;

        void Shutdown(unsigned int blockDuration) override;

        bool IsActive() const override { return endThreads == false; }

        void SetMaximumIncomingConnections(unsigned short numberAllowed) override;

        unsigned short GetMaximumIncomingConnections() const override { return maximumIncomingConnections; }

        unsigned short NumberOfConnections() const override;

        uint32_t Send(const char *data, int length, PacketPriority priority, PacketReliability reliability,
                      char orderingChannel, const AddressOrGUID systemIdentifier, bool broadcast) override;

        Packet *Receive() override;

        void DeallocatePacket(Packet *packet) override;

        void CloseConnection(const AddressOrGUID target, bool sendDisconnectionNotification,
                             unsigned char orderingChannel = 0,
                             PacketPriority disconnectionNotificationPriority = LOW_PRIORITY) override;

        ConnectionState GetConnectionState(const AddressOrGUID systemIdentifier) override;

        void SetOfflinePingResponse(const char *data, unsigned int length) override;

        RakNetGUID GetMyGUID() const override { return myGuid; }

        SystemAddress GetSystemAddressFromGuid(const RakNetGUID input) const override;

        RakNetGUID GetGuidFromSystemAddress(const SystemAddress input) const override;

        int GetAveragePing(const AddressOrGUID systemIdentifier) override;

        void SetTimeoutTime(TimeMS timeMS, const SystemAddress target) override;

    private:
        typedef std::unordered_map<SystemAddress, std::unique_ptr<RemoteSystemStruct>, SystemAddressHash> RemoteSystemList;

        void UpdateNetworkLoop();

        void ProcessNetworkPacket(const RNS2RecvStruct &recvStruct, TimeMS time);

        bool ProcessOfflineNetworkPacket(const RNS2RecvStruct &recvStruct, TimeMS time);

        void ProcessConnectedPacket(RemoteSystemStruct *remoteSystem, const RNS2RecvStruct &recvStruct, TimeMS time);

        bool ParseConnectedMessage(RemoteSystemStruct *remoteSystem, InternalPacket *internalPacket, TimeMS time);

        unsigned short NumberOfConnectionsUnlocked() const;

        RemoteSystemStruct *GetRemoteSystemFromSystemAddress(const SystemAddress &systemAddress) const;

        RemoteSystemStruct *GetRemoteSystemFromGUID(const RakNetGUID &guid) const;

        RemoteSystemStruct *AssignSystemAddressToRemoteSystemList(const SystemAddress &systemAddress, int mtuSize,
                                                                  TimeMS time);

        void CloseConnectionInternal(const SystemAddress &systemAddress, bool sendDisconnectionNotification,
                                     unsigned char orderingChannel, PacketPriority priority);

        void SendImmediate(RemoteSystemStruct *remoteSystem, const char *data, unsigned int length,
                           PacketPriority priority, PacketReliability reliability, unsigned char orderingChannel,
                           TimeMS time);

        void SendOfflineMessage(const BitStream &bitStream, const SystemAddress &systemAddress);

        void PushBackPacket(Packet *packet);

        Packet *AllocPacket(unsigned int dataSize, const SystemAddress &systemAddress, const RakNetGUID &guid);

        static bool IsOfflineMessageMagic(const unsigned char *data, unsigned int length, unsigned int offset);

        RakNetSocket2 socket;
        std::thread networkThread;
        std::atomic<bool> endThreads;

        mutable std::mutex remoteSystemMutex;
        RemoteSystemList remoteSystemList;

        std::mutex packetQueueMutex;
        std::deque<Packet *> packetQueue;

        std::vector<unsigned char> offlinePingResponse;
        std::mutex offlinePingResponseMutex;

        RakNetGUID myGuid;
        unsigned int maximumNumberOfPeers;
        unsigned short maximumIncomingConnections;
        SystemIndex nextSystemIndex;
    };

}
