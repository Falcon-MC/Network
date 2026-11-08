#include "Network/Acme/AcmeCrypto.h"

#include "Network/Crypto/Base64.h"
#include "Network/JsonText.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <cctype>
#include <ctime>
#include <vector>

namespace acme {

    namespace {

        const int P256_COORDINATE_SIZE = 32;
        // uncompressed point at the end of a P-256 SubjectPublicKeyInfo: 0x04 || x || y
        const size_t P256_POINT_SIZE = 1 + 2 * P256_COORDINATE_SIZE;
        const char *const ACME_IDENTIFIER_OID = "1.3.6.1.5.5.7.1.31";
        const int64_t THIRTY_DAYS = 30LL * 24 * 3600;
        const long CHALLENGE_VALIDITY_SECONDS = 7L * 24 * 3600;

        std::string bioText(BIO *bio) {
            char *data = nullptr;
            const long length = BIO_get_mem_data(bio, &data);
            return length > 0 ? std::string(data, (size_t) length) : std::string();
        }

        // RFC 8555 identifiers: letters, digits, hyphens and dots, no wildcard
        bool isDomain(const std::string &domain) {
            if (domain.empty() || domain.size() > 253 || domain.front() == '.' || domain.back() == '.')
                return false;

            for (char character: domain) {
                const unsigned char byte = (unsigned char) character;
                if (!std::isalnum(byte) && byte != '-' && byte != '.')
                    return false;
            }

            return true;
        }

        bool addSubjectName(X509_NAME *name, const std::string &domain) {
            return X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *) domain.c_str(), -1,
                                              -1, 0) == 1;
        }

        X509_EXTENSION *subjectAltName(const std::string &domain) {
            const std::string value = "DNS:" + domain;
            return X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name, value.c_str());
        }

        X509 *readFirstCertificate(const std::string &chainPem) {
            BIO *bio = BIO_new_mem_buf(chainPem.data(), (int) chainPem.size());
            if (bio == nullptr)
                return nullptr;

            X509 *certificate = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
            return certificate;
        }

        bool toUnixTime(const ASN1_TIME *time, int64_t &outSeconds) {
            ASN1_TIME *epoch = ASN1_TIME_set(nullptr, 0);
            int days = 0;
            int seconds = 0;
            const bool converted = epoch != nullptr && ASN1_TIME_diff(&days, &seconds, epoch, time) == 1;
            ASN1_TIME_free(epoch);
            if (converted)
                outSeconds = (int64_t) days * 86400 + seconds;
            return converted;
        }
    }

    EcKey::EcKey(evp_pkey_st *key) : mKey(key) {
    }

    EcKey::~EcKey() {
        EVP_PKEY_free(mKey);
    }

    std::shared_ptr<EcKey> EcKey::generate() {
        EVP_PKEY *key = nullptr;
        EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
        const bool generated = context != nullptr && EVP_PKEY_keygen_init(context) == 1
                               && EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context, NID_X9_62_prime256v1) == 1
                               && EVP_PKEY_keygen(context, &key) == 1;
        EVP_PKEY_CTX_free(context);

        if (!generated) {
            EVP_PKEY_free(key);
            return nullptr;
        }

        return std::shared_ptr<EcKey>(new EcKey(key));
    }

    std::shared_ptr<EcKey> EcKey::fromPem(const std::string &pem) {
        BIO *bio = BIO_new_mem_buf(pem.data(), (int) pem.size());
        if (bio == nullptr)
            return nullptr;

        EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (key == nullptr || EVP_PKEY_base_id(key) != EVP_PKEY_EC || EVP_PKEY_bits(key) != 256) {
            EVP_PKEY_free(key);
            return nullptr;
        }

        return std::shared_ptr<EcKey>(new EcKey(key));
    }

    std::string EcKey::toPem() const {
        BIO *bio = BIO_new(BIO_s_mem());
        if (bio == nullptr)
            return std::string();

        std::string pem;
        if (PEM_write_bio_PrivateKey(bio, mKey, nullptr, nullptr, 0, nullptr, nullptr) == 1)
            pem = bioText(bio);
        BIO_free(bio);
        return pem;
    }

    std::string EcKey::jwk() const {
        const int length = i2d_PUBKEY(mKey, nullptr);
        if (length <= (int) P256_POINT_SIZE)
            return std::string();

        std::vector<unsigned char> der((size_t) length);
        unsigned char *cursor = der.data();
        if (i2d_PUBKEY(mKey, &cursor) != length)
            return std::string();

        const unsigned char *point = der.data() + der.size() - P256_POINT_SIZE;
        if (point[0] != 0x04)
            return std::string();

        const std::string x((const char *) point + 1, P256_COORDINATE_SIZE);
        const std::string y((const char *) point + 1 + P256_COORDINATE_SIZE, P256_COORDINATE_SIZE);
        return "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" + Base64::encodeUrl(x) + "\",\"y\":\""
               + Base64::encodeUrl(y) + "\"}";
    }

    std::string EcKey::thumbprint() const {
        const std::string key = jwk();
        return key.empty() ? std::string() : Base64::encodeUrl(sha256(key));
    }

    std::string EcKey::signEs256(const std::string &data) const {
        EVP_MD_CTX *context = EVP_MD_CTX_new();
        if (context == nullptr)
            return std::string();

        size_t length = 0;
        std::vector<unsigned char> der;
        bool signedData = EVP_DigestSignInit(context, nullptr, EVP_sha256(), nullptr, mKey) == 1
                          && EVP_DigestSign(context, nullptr, &length, (const unsigned char *) data.data(),
                                            data.size()) == 1;
        if (signedData) {
            der.resize(length);
            signedData = EVP_DigestSign(context, der.data(), &length, (const unsigned char *) data.data(),
                                        data.size()) == 1;
        }
        EVP_MD_CTX_free(context);

        if (!signedData)
            return std::string();

        // JWS wants the fixed-size r || s, OpenSSL emits DER
        const unsigned char *cursor = der.data();
        ECDSA_SIG *signature = d2i_ECDSA_SIG(nullptr, &cursor, (long) length);
        if (signature == nullptr)
            return std::string();

        const BIGNUM *r = nullptr;
        const BIGNUM *s = nullptr;
        ECDSA_SIG_get0(signature, &r, &s);

        std::string raw(2 * P256_COORDINATE_SIZE, '\0');
        const bool converted = BN_bn2binpad(r, (unsigned char *) &raw[0], P256_COORDINATE_SIZE) == P256_COORDINATE_SIZE
                               && BN_bn2binpad(s, (unsigned char *) &raw[P256_COORDINATE_SIZE],
                                               P256_COORDINATE_SIZE) == P256_COORDINATE_SIZE;
        ECDSA_SIG_free(signature);
        return converted ? raw : std::string();
    }

    bool EcKey::verifyEs256(const std::string &data, const std::string &signature) const {
        if (signature.size() != 2 * P256_COORDINATE_SIZE)
            return false;

        BIGNUM *r = BN_bin2bn((const unsigned char *) signature.data(), P256_COORDINATE_SIZE, nullptr);
        BIGNUM *s = BN_bin2bn((const unsigned char *) signature.data() + P256_COORDINATE_SIZE, P256_COORDINATE_SIZE,
                              nullptr);
        ECDSA_SIG *ecdsa = ECDSA_SIG_new();
        if (r == nullptr || s == nullptr || ecdsa == nullptr || ECDSA_SIG_set0(ecdsa, r, s) != 1) {
            BN_free(r);
            BN_free(s);
            ECDSA_SIG_free(ecdsa);
            return false;
        }

        const int length = i2d_ECDSA_SIG(ecdsa, nullptr);
        std::vector<unsigned char> der(length > 0 ? (size_t) length : 0);
        unsigned char *cursor = der.data();
        const bool encoded = length > 0 && i2d_ECDSA_SIG(ecdsa, &cursor) == length;
        ECDSA_SIG_free(ecdsa);
        if (!encoded)
            return false;

        EVP_MD_CTX *context = EVP_MD_CTX_new();
        const bool verified = context != nullptr
                              && EVP_DigestVerifyInit(context, nullptr, EVP_sha256(), nullptr, mKey) == 1
                              && EVP_DigestVerify(context, der.data(), der.size(), (const unsigned char *) data.data(),
                                                  data.size()) == 1;
        EVP_MD_CTX_free(context);
        return verified;
    }

    std::string sha256(const std::string &data) {
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int length = 0;
        if (EVP_Digest(data.data(), data.size(), digest, &length, EVP_sha256(), nullptr) != 1)
            return std::string();
        return std::string((const char *) digest, length);
    }

    std::string signJws(const EcKey &key, const std::string &url, const std::string &nonce, const std::string &kid,
                        const std::string &payload) {
        std::string header = "{\"alg\":\"ES256\",";
        if (kid.empty())
            header += "\"jwk\":" + key.jwk() + ",";
        else
            header += "\"kid\":" + JsonText::quote(kid) + ",";
        header += "\"nonce\":" + JsonText::quote(nonce) + ",\"url\":" + JsonText::quote(url) + "}";

        // POST-as-GET signs an empty payload, not "{}"
        const std::string protectedPart = Base64::encodeUrl(header);
        const std::string payloadPart = Base64::encodeUrl(payload);
        const std::string signature = key.signEs256(protectedPart + "." + payloadPart);
        if (signature.empty())
            return std::string();

        return "{\"protected\":\"" + protectedPart + "\",\"payload\":\"" + payloadPart + "\",\"signature\":\""
               + Base64::encodeUrl(signature) + "\"}";
    }

    std::string keyAuthorization(const std::string &token, const EcKey &accountKey) {
        return token + "." + accountKey.thumbprint();
    }

    std::string createCsr(const EcKey &certificateKey, const std::string &domain) {
        if (!isDomain(domain))
            return std::string();

        X509_REQ *request = X509_REQ_new();
        STACK_OF(X509_EXTENSION) *extensions = sk_X509_EXTENSION_new_null();
        X509_EXTENSION *names = subjectAltName(domain);
        std::string der;

        const bool built = request != nullptr && extensions != nullptr && names != nullptr
                           && X509_REQ_set_version(request, 0) == 1
                           && addSubjectName(X509_REQ_get_subject_name(request), domain)
                           && X509_REQ_set_pubkey(request, certificateKey.get()) == 1
                           && sk_X509_EXTENSION_push(extensions, names) > 0;
        if (built)
            names = nullptr;

        if (built && X509_REQ_add_extensions(request, extensions) == 1
            && X509_REQ_sign(request, certificateKey.get(), EVP_sha256()) > 0) {
            const int length = i2d_X509_REQ(request, nullptr);
            if (length > 0) {
                der.resize((size_t) length);
                unsigned char *cursor = (unsigned char *) &der[0];
                if (i2d_X509_REQ(request, &cursor) != length)
                    der.clear();
            }
        }

        X509_EXTENSION_free(names);
        sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
        X509_REQ_free(request);
        return der;
    }

    bool createTlsAlpnCertificate(const std::string &domain, const std::string &keyAuthorization,
                                  std::string &outCertificatePem, std::string &outKeyPem) {
        if (!isDomain(domain))
            return false;

        const std::shared_ptr<EcKey> key = EcKey::generate();
        if (key == nullptr)
            return false;

        // extnValue holds the DER of an OCTET STRING with the 32-byte digest
        const std::string digest = sha256(keyAuthorization);
        std::string identifier;
        identifier.push_back((char) 0x04);
        identifier.push_back((char) digest.size());
        identifier += digest;

        X509 *certificate = X509_new();
        ASN1_OBJECT *oid = OBJ_txt2obj(ACME_IDENTIFIER_OID, 1);
        ASN1_OCTET_STRING *value = ASN1_OCTET_STRING_new();
        X509_EXTENSION *acmeIdentifier = nullptr;
        X509_EXTENSION *names = subjectAltName(domain);
        unsigned char serial[16];
        BIGNUM *serialNumber = nullptr;

        bool built = certificate != nullptr && oid != nullptr && value != nullptr && names != nullptr
                     && RAND_bytes(serial, sizeof(serial)) == 1
                     && ASN1_OCTET_STRING_set(value, (const unsigned char *) identifier.data(),
                                              (int) identifier.size()) == 1;
        if (built) {
            serial[0] &= 0x7f;
            serialNumber = BN_bin2bn(serial, sizeof(serial), nullptr);
            acmeIdentifier = X509_EXTENSION_create_by_OBJ(nullptr, oid, 1, value);
            built = serialNumber != nullptr && acmeIdentifier != nullptr
                    && X509_set_version(certificate, 2) == 1
                    && BN_to_ASN1_INTEGER(serialNumber, X509_get_serialNumber(certificate)) != nullptr
                    && X509_gmtime_adj(X509_getm_notBefore(certificate), 0) != nullptr
                    && X509_gmtime_adj(X509_getm_notAfter(certificate), CHALLENGE_VALIDITY_SECONDS) != nullptr
                    && addSubjectName(X509_get_subject_name(certificate), domain)
                    && X509_set_issuer_name(certificate, X509_get_subject_name(certificate)) == 1
                    && X509_set_pubkey(certificate, key->get()) == 1
                    && X509_add_ext(certificate, names, -1) == 1
                    && X509_add_ext(certificate, acmeIdentifier, -1) == 1
                    && X509_sign(certificate, key->get(), EVP_sha256()) > 0;
        }

        if (built) {
            BIO *bio = BIO_new(BIO_s_mem());
            built = bio != nullptr && PEM_write_bio_X509(bio, certificate) == 1;
            if (built)
                outCertificatePem = bioText(bio);
            BIO_free(bio);
            outKeyPem = key->toPem();
            built = built && !outKeyPem.empty();
        }

        BN_free(serialNumber);
        X509_EXTENSION_free(acmeIdentifier);
        X509_EXTENSION_free(names);
        ASN1_OCTET_STRING_free(value);
        ASN1_OBJECT_free(oid);
        X509_free(certificate);
        return built;
    }

    bool readValidity(const std::string &chainPem, int64_t &outNotBefore, int64_t &outNotAfter) {
        X509 *certificate = readFirstCertificate(chainPem);
        if (certificate == nullptr)
            return false;

        const bool read = toUnixTime(X509_get0_notBefore(certificate), outNotBefore)
                          && toUnixTime(X509_get0_notAfter(certificate), outNotAfter);
        X509_free(certificate);
        return read;
    }

    bool certificateCovers(const std::string &chainPem, const std::string &domain) {
        X509 *certificate = readFirstCertificate(chainPem);
        if (certificate == nullptr)
            return false;

        const bool covers = X509_check_host(certificate, domain.c_str(), domain.size(), 0, nullptr) == 1;
        X509_free(certificate);
        return covers;
    }

    int64_t renewalTime(int64_t notBefore, int64_t notAfter) {
        const int64_t lifetime = std::max<int64_t>(notAfter - notBefore, 0);
        return notAfter - std::min(THIRTY_DAYS, lifetime / 3);
    }

}
