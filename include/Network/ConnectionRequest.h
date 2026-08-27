#pragma once

#include "Protocol/Types/SerializedSkin.h"

#include <string>

// Parses the two JWT blobs carried by LoginPacket. Signatures are not verified, only the client
// claims that the server needs for identity are extracted.
class ConnectionRequest {
public:
    bool parse(const std::string &authJwt, const std::string &clientJwt);

    const std::string &getDisplayName() const { return mDisplayName; }

    const std::string &getIdentity() const { return mIdentity; }

    const std::string &getXuid() const { return mXuid; }

    const std::string &getDeviceId() const { return mDeviceId; }

    const std::string &getTitleId() const { return mTitleId; }

    int getBuildPlatform() const { return mBuildPlatform; }

    const SerializedSkin &getSkin() const { return mSkin; }

    static std::string decodeBase64Url(const std::string &value);

    static std::string readJwtPayload(const std::string &jwt);

    static std::string findJsonString(const std::string &json, const std::string &key);

    static int findJsonInt(const std::string &json, const std::string &key, int fallback = 0);

    static bool findJsonBool(const std::string &json, const std::string &key, bool fallback = false);

private:
    void parseSkin(const std::string &clientPayload);

    SerializedSkin buildDefaultSkin() const;

    static void normalizeSkin(SerializedSkin &skin);

    std::string mDisplayName;
    std::string mIdentity;
    std::string mXuid;
    std::string mDeviceId;
    std::string mTitleId;
    int mBuildPlatform = -1;
    SerializedSkin mSkin;
};
