#pragma once

#include <atomic>
#include <functional>
#include <string>
#include <thread>
#include <mutex>
#include <vector>

typedef struct ssl_ctx_st SSL_CTX;

namespace nethernet {
    class SignalingServer {
    public:
        struct Stream;

        typedef std::function<bool(const std::string &networkID, const std::string &offer, std::string &answer,
                                   int &errorCode)> OfferHandler;

        typedef std::function<std::string()> StatusProvider;

        SignalingServer();

        ~SignalingServer();

        bool start(const std::string &address, unsigned short port, const OfferHandler &handler);

        void stop();

        bool isRunning() const { return mRunning.load(); }

        bool isSecure() const { return mSslContext != nullptr; }

        unsigned short getBoundPort() const { return mBoundPort; }

        void setCertificate(const std::string &certificatePath, const std::string &privateKeyPath);

        void setStatusProvider(const StatusProvider &provider) {
            mStatusProvider = provider;
        }

    private:
        bool _createSslContext();

        void _destroySslContext();

        static const int MAX_CONCURRENT_CLIENTS = 64;

        // a burst of joins queues in the kernel instead of being refused
        static const int LISTEN_BACKLOG = 128;

        void _acceptLoop();

        void _rejectBusy(long long descriptor);

        void _handleClient(long long descriptor);

        void _serveRequest(const Stream &stream);

        OfferHandler mHandler;
        StatusProvider mStatusProvider;
        std::thread mThread;
        // one detached thread per client so a slow or stalled client cannot hold back everyone else's negotiation
        std::atomic<int> mActiveClients{0};
        std::atomic<bool> mRunning;
        long long mListener;
        std::string mCertificatePath;
        std::string mPrivateKeyPath;
        SSL_CTX *mSslContext;
        unsigned short mBoundPort;
    };
}
