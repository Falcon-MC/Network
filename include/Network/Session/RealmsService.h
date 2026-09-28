#pragma once

#include "Network/Session/SessionConnectionTarget.h"

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

class MinecraftAuthentication;

struct RealmPlayer {
    std::string mUuid;
    std::string mName;
    std::string mPermission;
    bool mOperator = false;
    bool mAccepted = false;
    bool mOnline = false;
};

struct RealmDescription {
    long long mId = 0;
    std::string mName;
    std::string mOwner;
    std::string mOwnerUuid;
    std::string mMotd;
    std::string mState;
    std::string mDefaultPermission;
    std::string mWorldType;
    std::string mRemoteSubscriptionId;
    bool mExpired = false;
    bool mExpiredTrial = false;
    bool mGracePeriod = false;
    int mDaysLeft = 0;
    int mMaxPlayers = 0;
    int64_t mClubId = 0;
    std::vector<RealmPlayer> mPlayers;
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

    /**
     * Makes every request give up as soon as the flag is set, instead of
     * waiting for the HTTP call or the retry delay to finish.
     */
    void setCancelFlag(const std::atomic<bool> *cancel) {
        mCancel = cancel;
    }

    bool requestRealms(std::vector<RealmDescription> &outRealms, std::string &outError);

    bool requestRealmByCode(const std::string &code, RealmDescription &outRealm, std::string &outError);

    bool acceptInviteCode(const std::string &code, RealmDescription &outRealm, std::string &outError);

    bool requestOnlinePlayers(long long realmId, std::vector<RealmPlayer> &outPlayers, std::string &outError);

    bool requestAddress(long long realmId, unsigned int timeoutMs, const std::atomic<bool> *cancel,
                        RealmAddress &outAddress, std::string &outError);

    /**
     * The invite code of a realm link, "realm/CODE" or a realms.gg address,
     * with any query removed; empty when the text is not such a link.
     */
    static std::string inviteCode(const std::string &text);

private:
    bool _request(const std::string &method, const std::string &path, int &outStatus, std::string &outBody,
                  std::string &outError);

    bool _cancelled() const;

    bool _wait(int milliseconds) const;

    MinecraftAuthentication &mAuthentication;
    const std::atomic<bool> *mCancel = nullptr;
};
