#pragma once

#include <string>
#include <utility>
#include <vector>

struct HttpResponse {
    int mStatus = 0;
    std::vector<std::pair<std::string, std::string>> mHeaders;
    std::string mBody;

    std::string getHeader(const std::string &name) const;
};

class HttpClient {
public:
    typedef std::vector<std::pair<std::string, std::string>> Headers;

    static const int DEFAULT_TIMEOUT_MS = 15000;

    static bool request(const std::string &method, const std::string &url, const Headers &headers,
                        const std::string &body, HttpResponse &outResponse, std::string &outError,
                        int timeoutMs = DEFAULT_TIMEOUT_MS);

    static bool get(const std::string &url, const Headers &headers, HttpResponse &outResponse,
                    std::string &outError, int timeoutMs = DEFAULT_TIMEOUT_MS);

    static bool post(const std::string &url, const Headers &headers, const std::string &body,
                     HttpResponse &outResponse, std::string &outError, int timeoutMs = DEFAULT_TIMEOUT_MS);

    static std::string encodeForm(const Headers &fields);

private:
    static bool _parseUrl(const std::string &url, std::string &host, std::string &port, std::string &path);

    static bool _parseResponse(const std::string &raw, HttpResponse &outResponse, std::string &outError);

    static bool _decodeChunked(const std::string &body, std::string &outBody);
};
