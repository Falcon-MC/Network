#pragma once

#include <atomic>
#include <functional>
#include <string>
#include <thread>

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

        void setCertificate(const std::string &certificatePath, const std::string &privateKeyPath);

        void setStatusProvider(const StatusProvider &provider) {
            mStatusProvider = provider;
        }

    private:
        bool _createSslContext();

        void _destroySslContext();

        void _acceptLoop();

        void _handleClient(long long descriptor);

        void _serveRequest(const Stream &stream);

        OfferHandler mHandler;
        StatusProvider mStatusProvider;
        std::thread mThread;
        std::atomic<bool> mRunning;
        long long mListener;
        std::string mCertificatePath;
        std::string mPrivateKeyPath;
        SSL_CTX *mSslContext;
    };
}
