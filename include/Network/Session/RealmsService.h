#pragma once

#include "Network/Session/SessionConnectionTarget.h"

#include <atomic>
#include <string>
#include <vector>

class MinecraftAuthentication;

struct RealmDescription {
    long long mId = 0;
    std::string mName;
    std::string mOwner;
    std::string mState;
    bool mExpired = false;
};

struct RealmAddress {
    std::string mAddress;
    std::string mNetworkProtocol;
    bool mPendingUpdate = false;

    bool toTarget(SessionConnectionTarget &outTarget, std::string &outError) const;
};

class RealmsService {
public:
    explicit RealmsService(MinecraftAuthentication &authentication);

    bool requestRealms(std::vector<RealmDescription> &outRealms, std::string &outError);

    bool requestAddress(long long realmId, unsigned int timeoutMs, const std::atomic<bool> *cancel,
                        RealmAddress &outAddress, std::string &outError);

private:
    bool _get(const std::string &path, int &outStatus, std::string &outBody, std::string &outError);

    MinecraftAuthentication &mAuthentication;
};
