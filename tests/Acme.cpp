#include "Network/Acme/AcmeChallengeStore.h"
#include "Network/Acme/AcmeClient.h"
#include "Network/Acme/AcmeCrypto.h"
#include "Network/Acme/AcmeManager.h"
#include "Network/Crypto/Base64.h"

#include "Core/Json/Json.h"

#include <openssl/bio.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

namespace {
    // fixed key: expected values computed outside with openssl and python hashlib
    const char *const ACCOUNT_KEY_PEM =
            "-----BEGIN PRIVATE KEY-----\n"
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg4tPmwObIcRWkJYBD\n"
            "ZtQT8mFl8WryHqm+9e+14ewculyhRANCAARBM8Xgfpq/wMaov90E44I5kvaVxvJc\n"
            "J4v199CNZN4EcYQvgKbANzte/kneB01VEsuq2ZYnhXHPhSgCFKQnQJ6h\n"
            "-----END PRIVATE KEY-----\n";
    const char *const ACCOUNT_JWK = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"QTPF4H6av8DGqL_dBOOCOZL2lcbyXCeL9ffQjWTeBHE\","
                                    "\"y\":\"hC-ApsA3O17-Sd4HTVUSy6rZlieFcc-FKAIUpCdAnqE\"}";
    const char *const ACCOUNT_THUMBPRINT = "I5XC7ZkHB9d6DjYamT7-CD_AEIYsl9DMtpHfr5E98ps";
    const char *const TOKEN = "tok-en_1";
    const char *const KEY_AUTHORIZATION_SHA256 = "08e48f98ac4452d1e189ab0ad7b0cb1b5dd1bdd95099dff23df64f29f804b879";
    const char *const DOMAIN = "play.example.org";

    void require(bool condition, const std::string &message) {
        if (!condition)
            throw std::runtime_error(message);
    }

    std::string hex(const std::string &bytes) {
        static const char DIGITS[] = "0123456789abcdef";
        std::string out;
        for (char byte: bytes) {
            out.push_back(DIGITS[((unsigned char) byte) >> 4]);
            out.push_back(DIGITS[((unsigned char) byte) & 0x0f]);
        }
        return out;
    }

    std::shared_ptr<acme::EcKey> accountKey() {
        std::shared_ptr<acme::EcKey> key = acme::EcKey::fromPem(ACCOUNT_KEY_PEM);
        require(key != nullptr, "the fixed account key did not load");
        return key;
    }

    std::unique_ptr<json::Value> decodeJsonPart(const std::string &part) {
        std::string text;
        require(Base64::decodeUrl(part, text), "a JWS part is not base64url");
        json::Parser parser(text);
        return parser.parse();
    }

    void thumbprintMatchesRfc7638() {
        const std::shared_ptr<acme::EcKey> key = accountKey();
        require(key->jwk() == ACCOUNT_JWK, "the JWK differs: " + key->jwk());
        require(key->thumbprint() == ACCOUNT_THUMBPRINT, "the thumbprint differs: " + key->thumbprint());
        require(acme::keyAuthorization(TOKEN, *key) == std::string(TOKEN) + "." + ACCOUNT_THUMBPRINT,
                "the key authorization differs");

        const std::shared_ptr<acme::EcKey> reloaded = acme::EcKey::fromPem(key->toPem());
        require(reloaded != nullptr && reloaded->thumbprint() == ACCOUNT_THUMBPRINT, "the key did not round trip");
    }

    void jwsIsSignedAndShaped() {
        const std::shared_ptr<acme::EcKey> key = accountKey();
        const std::string url = "https://ca.test/acme/new-account";

        const std::string withJwk = acme::signJws(*key, url, "nonce-1", std::string(), "{\"a\":1}");
        json::Parser outerParser(withJwk);
        const std::unique_ptr<json::Value> outer = outerParser.parse();
        require(outer != nullptr && outer->isObject(), "the JWS is not a JSON object");

        const std::string protectedPart = outer->get("protected")->string();
        const std::string payloadPart = outer->get("payload")->string();
        const std::string signaturePart = outer->get("signature")->string();
        require(protectedPart.find('=') == std::string::npos && signaturePart.find('=') == std::string::npos,
                "base64url padding leaked into the JWS");

        const std::unique_ptr<json::Value> header = decodeJsonPart(protectedPart);
        require(header != nullptr && header->get("alg")->string() == "ES256", "alg is not ES256");
        require(header->get("nonce")->string() == "nonce-1" && header->get("url")->string() == url,
                "nonce or url is missing");
        require(header->get("jwk") != nullptr && header->get("kid") == nullptr, "new-account must carry jwk");

        std::string signature;
        require(Base64::decodeUrl(signaturePart, signature) && signature.size() == 64, "ES256 wants 64 bytes");
        require(key->verifyEs256(protectedPart + "." + payloadPart, signature), "the JWS signature is wrong");
        require(!key->verifyEs256(protectedPart + "." + payloadPart + "x", signature), "a tampered JWS verified");

        const std::string withKid = acme::signJws(*key, url, "nonce-2", "https://ca.test/acct/7", std::string());
        json::Parser kidParser(withKid);
        const std::unique_ptr<json::Value> kidOuter = kidParser.parse();
        require(kidOuter != nullptr && kidOuter->get("payload")->string().empty(), "POST-as-GET payload not empty");
        const std::unique_ptr<json::Value> kidHeader = decodeJsonPart(kidOuter->get("protected")->string());
        require(kidHeader->get("kid")->string() == "https://ca.test/acct/7" && kidHeader->get("jwk") == nullptr,
                "an account request must carry kid only");
    }

    void csrNamesTheDomain() {
        const std::shared_ptr<acme::EcKey> key = acme::EcKey::generate();
        const std::string der = acme::createCsr(*key, DOMAIN);
        require(!der.empty(), "no CSR");

        const unsigned char *cursor = (const unsigned char *) der.data();
        X509_REQ *request = d2i_X509_REQ(nullptr, &cursor, (long) der.size());
        require(request != nullptr, "the CSR does not parse");

        EVP_PKEY *publicKey = X509_REQ_get_pubkey(request);
        require(X509_REQ_verify(request, publicKey) == 1, "the CSR self signature is wrong");
        EVP_PKEY_free(publicKey);

        STACK_OF(X509_EXTENSION) *extensions = X509_REQ_get_extensions(request);
        bool named = false;
        for (int index = 0; extensions != nullptr && index < sk_X509_EXTENSION_num(extensions); ++index) {
            X509_EXTENSION *extension = sk_X509_EXTENSION_value(extensions, index);
            if (OBJ_obj2nid(X509_EXTENSION_get_object(extension)) != NID_subject_alt_name)
                continue;
            GENERAL_NAMES *names = (GENERAL_NAMES *) X509V3_EXT_d2i(extension);
            for (int name = 0; names != nullptr && name < sk_GENERAL_NAME_num(names); ++name) {
                GENERAL_NAME *entry = sk_GENERAL_NAME_value(names, name);
                if (entry->type == GEN_DNS
                    && std::string((const char *) ASN1_STRING_get0_data(entry->d.dNSName),
                                   (size_t) ASN1_STRING_length(entry->d.dNSName)) == DOMAIN)
                    named = true;
            }
            GENERAL_NAMES_free(names);
        }
        sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
        X509_REQ_free(request);
        require(named, "the CSR lacks the domain SAN");

        require(acme::createCsr(*key, "a,DNS:evil.test").empty(), "a SAN injection was accepted");
        require(acme::createCsr(*key, "*.example.org").empty(), "a wildcard was accepted");
    }

    void tlsAlpnCertificateCarriesTheDigest() {
        const std::shared_ptr<acme::EcKey> key = accountKey();
        const std::string keyAuthorization = acme::keyAuthorization(TOKEN, *key);
        require(hex(acme::sha256(keyAuthorization)) == KEY_AUTHORIZATION_SHA256, "the key authorization hash differs");

        std::string certificatePem;
        std::string keyPem;
        require(acme::createTlsAlpnCertificate(DOMAIN, keyAuthorization, certificatePem, keyPem),
                "no tls-alpn-01 certificate");
        require(acme::certificateCovers(certificatePem, DOMAIN), "the challenge certificate misses the domain");
        require(acme::EcKey::fromPem(keyPem) != nullptr, "the challenge key does not load");

        BIO *bio = BIO_new_mem_buf(certificatePem.data(), (int) certificatePem.size());
        X509 *certificate = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        require(certificate != nullptr, "the challenge certificate does not parse");

        ASN1_OBJECT *oid = OBJ_txt2obj("1.3.6.1.5.5.7.1.31", 1);
        const int index = X509_get_ext_by_OBJ(certificate, oid, -1);
        ASN1_OBJECT_free(oid);
        require(index >= 0, "the acmeIdentifier extension is missing");

        X509_EXTENSION *extension = X509_get_ext(certificate, index);
        require(X509_EXTENSION_get_critical(extension) == 1, "acmeIdentifier must be critical");
        const ASN1_OCTET_STRING *data = X509_EXTENSION_get_data(extension);
        const std::string value((const char *) ASN1_STRING_get0_data(data), (size_t) ASN1_STRING_length(data));
        require(value.size() == 34 && (unsigned char) value[0] == 0x04 && value[1] == 32,
                "acmeIdentifier is not a DER OCTET STRING of 32 bytes");
        require(hex(value.substr(2)) == KEY_AUTHORIZATION_SHA256, "acmeIdentifier holds the wrong digest");
        X509_free(certificate);
    }

    void renewsAThirdBeforeExpiryAtMostThirtyDays() {
        const int64_t day = 24 * 3600;
        require(acme::renewalTime(0, 90 * day) == 60 * day, "a 90-day certificate must renew 30 days ahead");
        require(acme::renewalTime(0, 6 * day) == 4 * day, "a 6-day certificate must renew 2 days ahead");
        require(acme::renewalTime(0, 45 * day) == 30 * day, "a 45-day certificate must renew 15 days ahead");

        std::string certificatePem;
        std::string keyPem;
        require(acme::createTlsAlpnCertificate(DOMAIN, "x.y", certificatePem, keyPem), "no certificate");
        int64_t notBefore = 0;
        int64_t notAfter = 0;
        require(acme::readValidity(certificatePem, notBefore, notAfter) && notAfter - notBefore >= 7 * day - 1
                && notAfter - notBefore <= 7 * day + 1,
                "the validity did not read back");
    }

    void retriesBackOffAndRespectRateLimits() {
        require(acme::Manager::retryDelay(1, false, 0) == 600, "the first retry is not 10 minutes");
        require(acme::Manager::retryDelay(2, false, 0) == 1200, "retries do not double");
        require(acme::Manager::retryDelay(20, false, 0) == 24 * 3600, "retries are not capped at a day");
        require(acme::Manager::retryDelay(1, false, 5000) == 5000, "Retry-After was ignored");
        require(acme::Manager::retryDelay(1, true, 0) == 3600, "a rate limit retried within the hour");
        require(acme::Manager::retryDelay(1, true, 7200) == 7200, "a rate limit Retry-After was ignored");
    }

    void challengeStoreIgnoresNameCase() {
        acme::ChallengeStore store;
        store.putTlsAlpn("Play.Example.ORG", "cert", "key");
        std::string certificate;
        std::string key;
        require(store.findTlsAlpn(DOMAIN, certificate, key) && certificate == "cert", "SNI lookup is case sensitive");
        store.removeTlsAlpn(DOMAIN);
        require(!store.findTlsAlpn(DOMAIN, certificate, key), "the answer outlived its removal");

        store.putHttp(TOKEN, "auth");
        std::string answer;
        require(store.findHttp(TOKEN, answer) && answer == "auth", "the http-01 answer is missing");
        require(!store.findHttp("other", answer), "an unknown token was answered");
        store.removeHttp(TOKEN);
        require(store.empty(), "the store kept an answer");

        acme::ChallengeType type;
        require(acme::parseChallengeType("tls-alpn-01", type) && type == acme::ChallengeType::TlsAlpn01
                && acme::parseChallengeType("http-01", type) && type == acme::ChallengeType::Http01
                && !acme::parseChallengeType("dns-01", type), "challenge names do not parse");
    }
}

int main() {
    try {
        thumbprintMatchesRfc7638();
        jwsIsSignedAndShaped();
        csrNamesTheDomain();
        tlsAlpnCertificateCarriesTheDigest();
        renewsAThirdBeforeExpiryAtMostThirtyDays();
        retriesBackOffAndRespectRateLimits();
        challengeStoreIgnoresNameCase();
    } catch (const std::exception &error) {
        std::cout << "FAIL: " << error.what() << std::endl;
        return 1;
    }

    std::cout << "PASS: acme" << std::endl;
    return 0;
}
