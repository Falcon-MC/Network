#include "Network/Session/RealmsService.h"

#include "Core/Json/Json.h"
#include "Network/Auth/MinecraftAuthentication.h"
#include "Network/Http/HttpClient.h"
#include "Network/NetherNet/NetherNetJsonRpcSignaling.h"

#include <cctype>
#include <chrono>
#include <cstdlib>
#include <memory>
#include <thread>

namespace {

    const char *REALMS_BASE_URL = "https://bedrock.frontendlegacy.realms.minecraft-services.net";
    const char *REALMS_RELYING_PARTY = "https://pocket.realms.minecraft.net/";
    const char *REALMS_USER_AGENT = "MCPE/UWP";
    const char *NETWORK_PROTOCOL_DEFAULT = "DEFAULT";
    const char *NETWORK_PROTOCOL_NETHERNET = "NETHERNET";
    const char *NETWORK_PROTOCOL_NETHERNET_JSON_RPC = "NETHERNET_JSONRPC";
    const int RETRY_INTERVAL_MS = 3000;
    const int RETRY_POLL_MS = 50;
    const size_t MAX_ERROR_BODY_PREVIEW = 512;

    std::string normalizeProtocol(const std::string &value) {
        size_t start = 0;
        size_t end = value.size();

        while (start < end && std::isspace((unsigned char) value[start]))
            ++start;

        while (end > start && std::isspace((unsigned char) value[end - 1]))
            --end;

        std::string normalized;
        normalized.reserve(end - start);

        for (size_t index = start; index < end; ++index)
            normalized.push_back((char) std::toupper((unsigned char) value[index]));

        return normalized;
    }

    std::string describeError(int status, const std::string &body) {
        std::string preview = body.substr(0, MAX_ERROR_BODY_PREVIEW);

        if (body.size() > MAX_ERROR_BODY_PREVIEW)
            preview += "...";

        return preview.empty() ? "HTTP Error: " + std::to_string(status)
                               : "HTTP Error: " + std::to_string(status) + ": " + preview;
    }

}

bool RealmAddress::toTarget(SessionConnectionTarget &outTarget, std::string &outError) const {
    const std::string protocol = normalizeProtocol(mNetworkProtocol);

    if (protocol == NETWORK_PROTOCOL_NETHERNET) {
        outTarget.mTransportLayer = TransportLayer::NetherNet;
        outTarget.mSignalingType = NetherNetSignalingType::WebSocket;
        outTarget.mNetworkId = mAddress;
        return true;
    }

    if (protocol == NETWORK_PROTOCOL_NETHERNET_JSON_RPC) {
        if (!nethernet::JsonRpcSignaling::isMessagingID(mAddress)) {
            outError = "realm address is not a player messaging UUID: " + mAddress;
            return false;
        }

        outTarget.mTransportLayer = TransportLayer::NetherNet;
        outTarget.mSignalingType = NetherNetSignalingType::JsonRpc;
        outTarget.mNetworkId = nethernet::JsonRpcSignaling::normalizeMessagingID(mAddress);
        return true;
    }

    if (protocol == NETWORK_PROTOCOL_DEFAULT || protocol.empty()) {
        const size_t colon = mAddress.rfind(':');

        if (colon == std::string::npos || colon == 0 || colon + 1 >= mAddress.size()) {
            outError = "realm address is not host:port: " + mAddress;
            return false;
        }

        const long port = strtol(mAddress.c_str() + colon + 1, nullptr, 10);
        if (port <= 0 || port > 65535) {
            outError = "realm address has an invalid port: " + mAddress;
            return false;
        }

        std::string host = mAddress.substr(0, colon);
        if (host.size() >= 2 && host.front() == '[' && host.back() == ']')
            host = host.substr(1, host.size() - 2);

        outTarget.mTransportLayer = TransportLayer::RakNet;
        outTarget.mHost = host;
        outTarget.mPort = (unsigned short) port;
        return true;
    }

    outError = "unknown realm network protocol: " + mNetworkProtocol;
    return false;
}

RealmsService::RealmsService(MinecraftAuthentication &authentication) : mAuthentication(authentication) {
}

bool RealmsService::_get(const std::string &path, int &outStatus, std::string &outBody, std::string &outError) {
    XboxLiveToken token;
    if (!mAuthentication.getXboxLiveAuthentication().requestToken(REALMS_RELYING_PARTY, token, outError)) {
        outError = "request realms token: " + outError;
        return false;
    }

    HttpClient::Headers headers;
    headers.emplace_back("User-Agent", REALMS_USER_AGENT);
    headers.emplace_back("Client-Version", mAuthentication.getGameVersion());
    headers.emplace_back("Authorization", token.getAuthorizationHeader());

    HttpResponse response;
    if (!HttpClient::get(std::string(REALMS_BASE_URL) + path, headers, response, outError))
        return false;

    outStatus = response.mStatus;
    outBody = std::move(response.mBody);
    return true;
}

bool RealmsService::requestRealms(std::vector<RealmDescription> &outRealms, std::string &outError) {
    outRealms.clear();

    int status = 0;
    std::string body;

    if (!_get("/worlds", status, body, outError))
        return false;

    if (status >= 400) {
        outError = describeError(status, body);
        return false;
    }

    std::unique_ptr<json::Value> root = json::parse(body);
    const json::Value *servers = root != nullptr ? root->get("servers") : nullptr;

    if (servers == nullptr || !servers->isArray())
        return true;

    for (const std::unique_ptr<json::Value> &server: servers->mArray) {
        if (server == nullptr || !server->isObject())
            continue;

        const json::Value *id = server->get("id");
        const json::Value *name = server->get("name");
        const json::Value *owner = server->get("owner");
        const json::Value *state = server->get("state");
        const json::Value *expired = server->get("expired");

        RealmDescription realm;
        realm.mId = id != nullptr ? (long long) id->number() : 0;
        realm.mName = name != nullptr ? name->string() : std::string();
        realm.mOwner = owner != nullptr ? owner->string() : std::string();
        realm.mState = state != nullptr ? state->string() : std::string();
        realm.mExpired = expired != nullptr && expired->boolean();
        outRealms.push_back(std::move(realm));
    }

    return true;
}

bool RealmsService::requestAddress(long long realmId, unsigned int timeoutMs, const std::atomic<bool> *cancel,
                                   RealmAddress &outAddress, std::string &outError) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    const std::string path = "/worlds/" + std::to_string(realmId) + "/join";

    for (;;) {
        int status = 0;
        std::string body;

        if (!_get(path, status, body, outError))
            return false;

        if (status == 503) {
            const auto retryAt = std::chrono::steady_clock::now() + std::chrono::milliseconds(RETRY_INTERVAL_MS);

            while (std::chrono::steady_clock::now() < retryAt) {
                if (cancel != nullptr && cancel->load()) {
                    outError = "realm join cancelled";
                    return false;
                }

                if (std::chrono::steady_clock::now() >= deadline) {
                    outError = "timed out waiting for the realm to start";
                    return false;
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(RETRY_POLL_MS));
            }

            continue;
        }

        if (status == 404) {
            outError = "realm not found";
            return false;
        }

        if (status == 403) {
            outError = "player is not in the realm";
            return false;
        }

        if (status >= 400) {
            outError = describeError(status, body);
            return false;
        }

        std::unique_ptr<json::Value> root = json::parse(body);

        if (root == nullptr || !root->isObject()) {
            outError = "invalid realm address response";
            return false;
        }

        const json::Value *address = root->get("address");
        const json::Value *protocol = root->get("networkProtocol");
        const json::Value *pendingUpdate = root->get("pendingUpdate");

        outAddress.mAddress = address != nullptr ? address->string() : std::string();
        outAddress.mNetworkProtocol = protocol != nullptr ? protocol->string() : std::string();
        outAddress.mPendingUpdate = pendingUpdate != nullptr && pendingUpdate->boolean();
        return true;
    }
}
