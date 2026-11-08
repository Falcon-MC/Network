#include "Network/NetherNet/NetherNetSignalingServer.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#endif

#include "Core/Debug/BedrockLog.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <cctype>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <mutex>
#include <cstdlib>
#include <cstring>
#include <thread>

#ifdef _WIN32
typedef SOCKET FalconSignalingSocket;
#define FALCON_SIGNALING_INVALID_SOCKET INVALID_SOCKET
#define FALCON_SIGNALING_CLOSE_SOCKET ::closesocket
#define FALCON_SIGNALING_SHUTDOWN_BOTH SD_BOTH
#define FALCON_SIGNALING_SHUTDOWN_WRITE SD_SEND
#else
typedef int FalconSignalingSocket;
#define FALCON_SIGNALING_INVALID_SOCKET (-1)
#define FALCON_SIGNALING_CLOSE_SOCKET ::close
#define FALCON_SIGNALING_SHUTDOWN_BOTH SHUT_RDWR
#define FALCON_SIGNALING_SHUTDOWN_WRITE SHUT_WR
#endif

namespace nethernet {

    struct SignalingServer::Stream {
        FalconSignalingSocket mDescriptor;
        SSL *mSsl;
        // handshake, headers and body share it: a request arrives whole within it or not at all
        std::chrono::steady_clock::time_point mDeadline;
    };

    namespace {

        const size_t MAX_SDP_BODY_SIZE = 1 << 20;
        const size_t MAX_HEADER_SIZE = 16 * 1024;
        // the game's own probe gives up after 3 s: sub_143A92EB0
        const int REQUEST_DEADLINE_MS = 5000;
        // the answer comes after the negotiation, it gets its own budget
        const int WRITE_DEADLINE_MS = 5000;
        const int DRAIN_TIMEOUT_MS = 12000;
        const int DRAIN_POLL_MS = 20;
        // a join burst outlasts the cap by one negotiation round: wait that long before answering busy
        const int SLOT_WAIT_MS = 1500;
        const unsigned char TLS_HANDSHAKE_RECORD = 0x16;

        typedef SignalingServer::Stream Stream;
        typedef std::chrono::steady_clock Clock;

        bool setNonBlocking(FalconSignalingSocket descriptor) {
#ifdef _WIN32
            u_long mode = 1;
            return ioctlsocket(descriptor, FIONBIO, &mode) == 0;
#else
            const int flags = fcntl(descriptor, F_GETFL, 0);
            return flags >= 0 && fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
        }

        bool wouldBlock() {
#ifdef _WIN32
            return WSAGetLastError() == WSAEWOULDBLOCK;
#else
            return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
#endif
        }

        // false once the deadline passed or the socket failed
        bool waitFor(FalconSignalingSocket descriptor, bool writable, Clock::time_point deadline) {
            const long long remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - Clock::now()).count();
            if (remaining <= 0)
                return false;

#ifdef _WIN32
            WSAPOLLFD entry;
            entry.fd = descriptor;
            entry.events = writable ? POLLWRNORM : POLLRDNORM;
            entry.revents = 0;
            const int ready = WSAPoll(&entry, 1, (INT) remaining);
#else
            pollfd entry;
            entry.fd = descriptor;
            entry.events = writable ? POLLOUT : POLLIN;
            entry.revents = 0;
            const int ready = poll(&entry, 1, (int) remaining);
#endif
            return ready > 0;
        }

        // retries the TLS or socket call while it would block, within the deadline
        bool waitForTls(const Stream &stream, int result, Clock::time_point deadline) {
            switch (SSL_get_error(stream.mSsl, result)) {
                case SSL_ERROR_WANT_READ:
                    return waitFor(stream.mDescriptor, false, deadline);
                case SSL_ERROR_WANT_WRITE:
                    return waitFor(stream.mDescriptor, true, deadline);
                default:
                    return false;
            }
        }

        int readStream(const Stream &stream, char *buffer, size_t size) {
            for (;;) {
                if (stream.mSsl != nullptr) {
                    const int read = SSL_read(stream.mSsl, buffer, (int) size);
                    if (read > 0)
                        return read;
                    if (!waitForTls(stream, read, stream.mDeadline))
                        return -1;
                    continue;
                }

                const int read = (int) recv(stream.mDescriptor, buffer, (int) size, 0);
                if (read >= 0)
                    return read;
                if (!wouldBlock() || !waitFor(stream.mDescriptor, false, stream.mDeadline))
                    return -1;
            }
        }

        bool acceptTls(const Stream &stream) {
            for (;;) {
                const int result = SSL_accept(stream.mSsl);
                if (result == 1)
                    return true;
                if (!waitForTls(stream, result, stream.mDeadline))
                    return false;
            }
        }

        void writeAll(const Stream &stream, const std::string &data) {
            const Clock::time_point deadline = Clock::now() + std::chrono::milliseconds(WRITE_DEADLINE_MS);
            size_t sent = 0;

            while (sent < data.size()) {
                if (stream.mSsl != nullptr) {
                    const int written = SSL_write(stream.mSsl, data.data() + sent, (int) (data.size() - sent));
                    if (written > 0) {
                        sent += (size_t) written;
                        continue;
                    }
                    if (!waitForTls(stream, written, deadline))
                        return;
                    continue;
                }

                const int written = (int) send(stream.mDescriptor, data.data() + sent, (int) (data.size() - sent),
                                               0);
                if (written > 0) {
                    sent += (size_t) written;
                    continue;
                }
                if (written < 0 && wouldBlock() && waitFor(stream.mDescriptor, true, deadline))
                    continue;
                return;
            }
        }

        // a peer that closed while we answer must cost its socket, never the process
        void ignoreBrokenPipes() {
#ifndef _WIN32
            static std::once_flag once;
            std::call_once(once, []() {
                std::signal(SIGPIPE, SIG_IGN);
            });
#endif
        }

        std::string peerAddress(const sockaddr_storage &address) {
            char text[INET6_ADDRSTRLEN] = {0};
            if (address.ss_family == AF_INET)
                inet_ntop(AF_INET, &((const sockaddr_in *) &address)->sin_addr, text, sizeof(text));
            else if (address.ss_family == AF_INET6)
                inet_ntop(AF_INET6, &((const sockaddr_in6 *) &address)->sin6_addr, text, sizeof(text));
            return text;
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

        void writeJson(const Stream &descriptor, const std::string &json, bool includeBody) {
            std::string response = "HTTP/1.1 200 OK\r\n";
            response += "Content-Type: application/json\r\n";
            response += "Content-Length: " + std::to_string(json.size()) + "\r\n";
            response += "Connection: close\r\n\r\n";
            if (includeBody)
                response += json;
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

    SignalingServer::SignalingServer() : mRunning(false), mListener(-1), mSslContext(nullptr), mBoundPort(0) {
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

        ignoreBrokenPipes();
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

        if (bind(descriptor, result->ai_addr, (int) result->ai_addrlen) != 0 || listen(descriptor, LISTEN_BACKLOG) != 0) {
            freeaddrinfo(result);
            FALCON_SIGNALING_CLOSE_SOCKET(descriptor);
            LOG_ERROR(LogAreaID::Network, "NetherNet signaling could not bind %s:%u", address.c_str(),
                      (unsigned) port);
            _destroySslContext();
            return false;
        }

        freeaddrinfo(result);

        // Port 0 asks the system for a free port, so read back the one it picked.
        sockaddr_in bound;
        socklen_t boundLength = sizeof(bound);
        if (getsockname(descriptor, (sockaddr *) &bound, &boundLength) == 0)
            mBoundPort = ntohs(bound.sin_port);
        else
            mBoundPort = port;

        mHandler = handler;
        mListener = (long long) descriptor;
        mRunning.store(true);
        mThread = std::thread(&SignalingServer::_acceptLoop, this);
        return true;
    }

    void SignalingServer::stop() {
        if (!mRunning.exchange(false))
            return;

        {
            std::lock_guard<std::mutex> lock(mSlotMutex);
        }
        mSlotFreed.notify_all();

        if (mListener >= 0) {
            ::shutdown((FalconSignalingSocket) mListener, FALCON_SIGNALING_SHUTDOWN_BOTH);
            FALCON_SIGNALING_CLOSE_SOCKET((FalconSignalingSocket) mListener);
            mListener = -1;
        }

        mBoundPort = 0;

        if (mThread.joinable())
            mThread.join();

        // the detached client threads use the SSL context, so wait for them to drain before it is destroyed.
        // each is bounded by the request and write deadlines, so this cannot wait indefinitely.
        for (int waited = 0; waited < DRAIN_TIMEOUT_MS; waited += DRAIN_POLL_MS) {
            {
                std::lock_guard<std::mutex> lock(mSlotMutex);
                if (mActiveClients.load() == 0)
                    break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(DRAIN_POLL_MS));
        }

        _destroySslContext();
    }

    void SignalingServer::_acceptLoop() {
        while (mRunning.load()) {
            sockaddr_storage peer;
            socklen_t peerLength = sizeof(peer);
            memset(&peer, 0, sizeof(peer));
            const FalconSignalingSocket client = accept((FalconSignalingSocket) mListener, (sockaddr *) &peer,
                                                        &peerLength);

            if (client == FALCON_SIGNALING_INVALID_SOCKET) {
                if (!mRunning.load())
                    return;

                continue;
            }

            // one stalled client must not block the others, so each is served on its own detached thread. a cap
            // keeps a flood of slow clients from spawning unbounded threads; past it the connection is refused.
            const std::string address = peerAddress(peer);
            if (!_claimAddress(address)) {
                _rejectBusy((long long) client);
                continue;
            }

            if (!_waitForSlot()) {
                _releaseAddress(address);
                _rejectBusy((long long) client);
                continue;
            }

            std::thread([this, client, address]() {
                _handleClient((long long) client);
                FALCON_SIGNALING_CLOSE_SOCKET(client);
                _releaseSlot(address);
            }).detach();
        }
    }

    // takes a slot; later connections wait in the listen backlog meanwhile
    bool SignalingServer::_waitForSlot() {
        std::unique_lock<std::mutex> lock(mSlotMutex);
        const bool freed = mSlotFreed.wait_for(lock, std::chrono::milliseconds(SLOT_WAIT_MS), [this]() {
            return mActiveClients.load() < MAX_CONCURRENT_CLIENTS || !mRunning.load();
        });
        if (!freed || !mRunning.load())
            return false;

        mActiveClients.fetch_add(1);
        return true;
    }

    // counted apart from the global slots: one address cannot take the room every other player needs
    bool SignalingServer::_claimAddress(const std::string &address) {
        std::lock_guard<std::mutex> lock(mSlotMutex);
        int &count = mClientsPerAddress[address];
        if (count >= MAX_CLIENTS_PER_ADDRESS)
            return false;

        ++count;
        return true;
    }

    void SignalingServer::_releaseAddress(const std::string &address) {
        std::lock_guard<std::mutex> lock(mSlotMutex);
        _dropAddress(address);
    }

    // under mSlotMutex
    void SignalingServer::_dropAddress(const std::string &address) {
        const auto it = mClientsPerAddress.find(address);
        if (it != mClientsPerAddress.end() && --it->second <= 0)
            mClientsPerAddress.erase(it);
    }

    // notified under the lock: stop() may destroy the server as soon as the count reads zero
    void SignalingServer::_releaseSlot(const std::string &address) {
        std::lock_guard<std::mutex> lock(mSlotMutex);
        _dropAddress(address);
        mActiveClients.fetch_sub(1);
        mSlotFreed.notify_one();
    }

    // a busy answer instead of a dropped socket: clients retry a 503, a reset reads as a failed join
    void SignalingServer::_rejectBusy(long long handle) {
        const FalconSignalingSocket socketDescriptor = (FalconSignalingSocket) handle;

        // drain what already arrived: closing with unread bytes sends a reset that hides the answer
        char discard[4096];
#ifdef _WIN32
        u_long nonBlocking = 1;
        ioctlsocket(socketDescriptor, FIONBIO, &nonBlocking);
        while (recv(socketDescriptor, discard, (int) sizeof(discard), 0) > 0) {
        }
        nonBlocking = 0;
        ioctlsocket(socketDescriptor, FIONBIO, &nonBlocking);
#else
        while (recv(socketDescriptor, discard, sizeof(discard), MSG_DONTWAIT) > 0) {
        }
#endif

        Stream descriptor;
        descriptor.mDescriptor = socketDescriptor;
        descriptor.mSsl = nullptr;
        descriptor.mDeadline = Clock::now();
        writeText(descriptor, 503, "Service Unavailable", "Too many pending joins, retry");
        shutdown(socketDescriptor, FALCON_SIGNALING_SHUTDOWN_WRITE);
        FALCON_SIGNALING_CLOSE_SOCKET(socketDescriptor);
    }

    void SignalingServer::_handleClient(long long handle) {
        const FalconSignalingSocket socketDescriptor = (FalconSignalingSocket) handle;

        Stream descriptor;
        descriptor.mDescriptor = socketDescriptor;
        descriptor.mSsl = nullptr;
        // every read below polls against it: a request trickling in still ends here
        descriptor.mDeadline = Clock::now() + std::chrono::milliseconds(REQUEST_DEADLINE_MS);

        if (!setNonBlocking(socketDescriptor))
            return;
#ifdef SO_NOSIGPIPE
        int noSignal = 1;
        setsockopt(socketDescriptor, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, sizeof(noSignal));
#endif

        // The client opens with a TLS handshake and only retries in plaintext once that is refused, so
        // the first byte tells the two apart. Without a certificate the handshake is closed right away.
        char first = 0;
        for (;;) {
            const int peeked = (int) recv(socketDescriptor, &first, 1, MSG_PEEK);
            if (peeked == 1)
                break;
            if (peeked == 0 || !wouldBlock() || !waitFor(socketDescriptor, false, descriptor.mDeadline))
                return;
        }

        const bool tls = (unsigned char) first == TLS_HANDSHAKE_RECORD;
        if (tls && mSslContext == nullptr)
            return;

        if (tls) {
            descriptor.mSsl = SSL_new(mSslContext);

            if (descriptor.mSsl == nullptr) {
                LOG_WARN(LogAreaID::Network, "NetherNet signaling could not allocate a TLS session");
                ERR_clear_error();
                return;
            }

            SSL_set_fd(descriptor.mSsl, (int) socketDescriptor);

            if (!acceptTls(descriptor)) {
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

        if (path.size() > 1 && path.back() == '/')
            path.pop_back();

        // HEAD probes get the status headers without the body.
        if ((method == "GET" || method == "HEAD") && path == "/v1/join") {
            if (mStatusProvider)
                writeJson(descriptor, mStatusProvider(), method == "GET");
            else
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
