#include "Network/NetherNet/NetherNetSignalingServer.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#endif

#include "Core/Debug/BedrockLog.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <cctype>
#include <cstdlib>
#include <cstring>

#ifdef _WIN32
typedef SOCKET FalconSignalingSocket;
#define FALCON_SIGNALING_INVALID_SOCKET INVALID_SOCKET
#define FALCON_SIGNALING_CLOSE_SOCKET ::closesocket
#else
typedef int FalconSignalingSocket;
#define FALCON_SIGNALING_INVALID_SOCKET (-1)
#define FALCON_SIGNALING_CLOSE_SOCKET ::close
#endif

namespace nethernet {

    struct SignalingServer::Stream {
        FalconSignalingSocket mDescriptor;
        SSL *mSsl;
    };

    namespace {

        const size_t MAX_SDP_BODY_SIZE = 1 << 20;
        const size_t MAX_HEADER_SIZE = 16 * 1024;

        typedef SignalingServer::Stream Stream;

        int readStream(const Stream &stream, char *buffer, size_t size) {
            if (stream.mSsl != nullptr)
                return SSL_read(stream.mSsl, buffer, (int) size);

            return recv(stream.mDescriptor, buffer, (int) size, 0);
        }

        void writeAll(const Stream &stream, const std::string &data) {
            size_t sent = 0;

            while (sent < data.size()) {
                int written;

                if (stream.mSsl != nullptr)
                    written = SSL_write(stream.mSsl, data.data() + sent, (int) (data.size() - sent));
                else
                    written = send(stream.mDescriptor, data.data() + sent, (int) (data.size() - sent), 0);

                if (written <= 0)
                    return;

                sent += (size_t) written;
            }
        }

        void writeText(const Stream &descriptor, int statusCode, const std::string &reason,
                       const std::string &text) {
            std::string response = "HTTP/1.1 " + std::to_string(statusCode) + " " + reason + "\r\n";
            response += "Content-Type: text/plain\r\n";
            response += "Content-Length: " + std::to_string(text.size()) + "\r\n";
            response += "Connection: close\r\n\r\n";
            response += text;
            writeAll(descriptor, response);
        }

        void writeSdp(const Stream &descriptor, const std::string &answer) {
            std::string response = "HTTP/1.1 200 OK\r\n";
            response += "Content-Type: application/sdp\r\n";
            response += "Content-Length: " + std::to_string(answer.size()) + "\r\n";
            response += "Connection: close\r\n\r\n";
            response += answer;
            writeAll(descriptor, response);
        }

        size_t findContentLength(const std::string &headers) {
            std::string lowered;
            lowered.reserve(headers.size());

            for (char c: headers)
                lowered.push_back((char) tolower((unsigned char) c));

            const size_t position = lowered.find("content-length:");
            if (position == std::string::npos)
                return 0;

            const size_t end = lowered.find("\r\n", position);
            if (end == std::string::npos)
                return 0;

            const std::string value = headers.substr(position + 15, end - position - 15);
            return (size_t) strtoull(value.c_str(), nullptr, 10);
        }

    }

    SignalingServer::SignalingServer() : mRunning(false), mListener(-1), mSslContext(nullptr) {
    }

    SignalingServer::~SignalingServer() {
        stop();
    }

    void SignalingServer::setCertificate(const std::string &certificatePath, const std::string &privateKeyPath) {
        mCertificatePath = certificatePath;
        mPrivateKeyPath = privateKeyPath;
    }

    bool SignalingServer::_createSslContext() {
        if (mCertificatePath.empty() || mPrivateKeyPath.empty())
            return false;

        SSL_CTX *context = SSL_CTX_new(TLS_server_method());
        if (context == nullptr) {
            LOG_ERROR(LogAreaID::Network, "NetherNet signaling could not allocate a TLS context, "
                                          "falling back to plaintext HTTP");
            return false;
        }

        SSL_CTX_set_min_proto_version(context, TLS1_2_VERSION);

        if (SSL_CTX_use_certificate_chain_file(context, mCertificatePath.c_str()) != 1) {
            LOG_ERROR(LogAreaID::Network, "NetherNet signaling could not read the TLS certificate chain %s, "
                                          "falling back to plaintext HTTP", mCertificatePath.c_str());
            ERR_clear_error();
            SSL_CTX_free(context);
            return false;
        }

        if (SSL_CTX_use_PrivateKey_file(context, mPrivateKeyPath.c_str(), SSL_FILETYPE_PEM) != 1) {
            LOG_ERROR(LogAreaID::Network, "NetherNet signaling could not read the TLS private key %s, "
                                          "falling back to plaintext HTTP", mPrivateKeyPath.c_str());
            ERR_clear_error();
            SSL_CTX_free(context);
            return false;
        }

        if (SSL_CTX_check_private_key(context) != 1) {
            LOG_ERROR(LogAreaID::Network, "The NetherNet TLS private key does not match the certificate, "
                                          "falling back to plaintext HTTP");
            ERR_clear_error();
            SSL_CTX_free(context);
            return false;
        }

        mSslContext = context;
        return true;
    }

    void SignalingServer::_destroySslContext() {
        if (mSslContext == nullptr)
            return;

        SSL_CTX_free(mSslContext);
        mSslContext = nullptr;
    }

    bool SignalingServer::start(const std::string &address, unsigned short port, const OfferHandler &handler) {
        if (mRunning.load())
            return false;

        _createSslContext();

        addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;

        addrinfo *result = nullptr;
        const std::string service = std::to_string(port);

        if (getaddrinfo(address.empty() ? nullptr : address.c_str(), service.c_str(), &hints, &result) != 0 ||
            result == nullptr) {
            LOG_ERROR(LogAreaID::Network, "NetherNet signaling could not resolve %s:%u", address.c_str(),
                      (unsigned) port);
            _destroySslContext();
            return false;
        }

        FalconSignalingSocket descriptor = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
        if (descriptor == FALCON_SIGNALING_INVALID_SOCKET) {
            freeaddrinfo(result);
            LOG_ERROR(LogAreaID::Network, "NetherNet signaling could not create a listening socket");
            _destroySslContext();
            return false;
        }

        int reuse = 1;
        setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, (const char *) &reuse, sizeof(reuse));

        if (bind(descriptor, result->ai_addr, (int) result->ai_addrlen) != 0 || listen(descriptor, 16) != 0) {
            freeaddrinfo(result);
            FALCON_SIGNALING_CLOSE_SOCKET(descriptor);
            LOG_ERROR(LogAreaID::Network, "NetherNet signaling could not bind %s:%u", address.c_str(),
                      (unsigned) port);
            _destroySslContext();
            return false;
        }

        freeaddrinfo(result);

        mHandler = handler;
        mListener = (long long) descriptor;
        mRunning.store(true);
        mThread = std::thread(&SignalingServer::_acceptLoop, this);
        return true;
    }

    void SignalingServer::stop() {
        if (!mRunning.exchange(false))
            return;

        if (mListener >= 0) {
            FALCON_SIGNALING_CLOSE_SOCKET((FalconSignalingSocket) mListener);
            mListener = -1;
        }

        if (mThread.joinable())
            mThread.join();

        _destroySslContext();
    }

    void SignalingServer::_acceptLoop() {
        while (mRunning.load()) {
            const FalconSignalingSocket client = accept((FalconSignalingSocket) mListener, nullptr, nullptr);

            if (client == FALCON_SIGNALING_INVALID_SOCKET) {
                if (!mRunning.load())
                    return;

                continue;
            }

            _handleClient((long long) client);
            FALCON_SIGNALING_CLOSE_SOCKET(client);
        }
    }

    void SignalingServer::_handleClient(long long handle) {
        const FalconSignalingSocket socketDescriptor = (FalconSignalingSocket) handle;

        Stream descriptor;
        descriptor.mDescriptor = socketDescriptor;
        descriptor.mSsl = nullptr;

        if (mSslContext != nullptr) {
            descriptor.mSsl = SSL_new(mSslContext);

            if (descriptor.mSsl == nullptr) {
                LOG_WARN(LogAreaID::Network, "NetherNet signaling could not allocate a TLS session");
                ERR_clear_error();
                return;
            }

            SSL_set_fd(descriptor.mSsl, (int) socketDescriptor);

            if (SSL_accept(descriptor.mSsl) != 1) {
                ERR_clear_error();
                SSL_free(descriptor.mSsl);
                return;
            }
        }

        _serveRequest(descriptor);

        if (descriptor.mSsl != nullptr) {
            SSL_shutdown(descriptor.mSsl);
            SSL_free(descriptor.mSsl);
        }
    }

    void SignalingServer::_serveRequest(const Stream &descriptor) {
        std::string buffer;
        char chunk[4096];
        size_t headerEnd = std::string::npos;

        while (headerEnd == std::string::npos) {
            const int read = readStream(descriptor, chunk, sizeof(chunk));
            if (read <= 0)
                return;

            buffer.append(chunk, (size_t) read);
            headerEnd = buffer.find("\r\n\r\n");

            if (headerEnd == std::string::npos && buffer.size() > MAX_HEADER_SIZE) {
                writeText(descriptor, 431, "Request Header Fields Too Large", "Headers are too large");
                return;
            }
        }

        const std::string headers = buffer.substr(0, headerEnd + 2);
        std::string body = buffer.substr(headerEnd + 4);

        const size_t lineEnd = headers.find("\r\n");
        if (lineEnd == std::string::npos)
            return;

        const std::string requestLine = headers.substr(0, lineEnd);
        const size_t firstSpace = requestLine.find(' ');
        const size_t secondSpace = firstSpace == std::string::npos ? std::string::npos
                                                                  : requestLine.find(' ', firstSpace + 1);

        if (firstSpace == std::string::npos || secondSpace == std::string::npos) {
            writeText(descriptor, 400, "Bad Request", "Malformed request line");
            return;
        }

        const std::string method = requestLine.substr(0, firstSpace);
        std::string path = requestLine.substr(firstSpace + 1, secondSpace - firstSpace - 1);

        const size_t query = path.find('?');
        if (query != std::string::npos)
            path = path.substr(0, query);

        if (method == "GET" && path == "/v1/join") {
            writeText(descriptor, 200, "OK", std::string());
            return;
        }

        if (method != "POST" || path.rfind("/v1/join/", 0) != 0) {
            writeText(descriptor, 404, "Not Found", "Expected /v1/join/{networkId}");
            return;
        }

        const std::string networkID = path.substr(9);
        if (networkID.empty()) {
            writeText(descriptor, 400, "Bad Request", "Expected /v1/join/{networkId}");
            return;
        }

        for (char c: networkID) {
            if (c < '0' || c > '9') {
                writeText(descriptor, 400, "Bad Request", "Network ID must be uint64");
                return;
            }
        }

        const size_t contentLength = findContentLength(headers);
        if (contentLength > MAX_SDP_BODY_SIZE) {
            writeText(descriptor, 413, "Request Entity Too Large", "SDP offer is too large");
            return;
        }

        while (body.size() < contentLength) {
            const int read = readStream(descriptor, chunk, sizeof(chunk));
            if (read <= 0)
                break;

            body.append(chunk, (size_t) read);

            if (body.size() > MAX_SDP_BODY_SIZE) {
                writeText(descriptor, 413, "Request Entity Too Large", "SDP offer is too large");
                return;
            }
        }

        if (body.size() > contentLength)
            body.resize(contentLength);

        if (body.empty()) {
            writeText(descriptor, 400, "Bad Request", "Missing SDP offer in request body");
            return;
        }

        std::string answer;
        int errorCode = 0;

        if (mHandler == nullptr || !mHandler(networkID, body, answer, errorCode)) {
            if (errorCode != 0) {
                writeText(descriptor, 400, "Bad Request",
                          "Negotiation failed with error code: " + std::to_string(errorCode));
                return;
            }

            writeText(descriptor, 503, "Service Unavailable", "Service unavailable");
            return;
        }

        writeSdp(descriptor, answer);
    }
}
