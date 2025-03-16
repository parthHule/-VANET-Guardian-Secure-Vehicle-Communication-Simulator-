#ifndef VANET_CRYPTO_MODULE_H
#define VANET_CRYPTO_MODULE_H

#include <string>
#include <vector>
#include <memory>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>

namespace vanet {
namespace crypto {

enum class HashAlgorithm {
    SHA256,
    MD5,
    SHA1,
    BLAKE2B,
    SHA3_256
};

enum class SignatureAlgorithm {
    RSA_PSS,
    ECDSA
};

struct Certificate {
    std::string subject;
    std::string issuer;
    std::vector<uint8_t> publicKey;
    std::vector<uint8_t> signature;
    time_t validFrom;
    time_t validUntil;
};

class CryptoModule {
public:
    CryptoModule();
    ~CryptoModule();

    // Key management
    bool generateKeyPair(SignatureAlgorithm algo = SignatureAlgorithm::ECDSA);
    bool loadPrivateKey(const std::string& keyPath);
    bool loadPublicKey(const std::string& keyPath);
    bool loadCertificate(const std::string& certPath);

    // Hashing functions
    std::vector<uint8_t> hashMessage(const std::vector<uint8_t>& message, HashAlgorithm algo = HashAlgorithm::SHA256);
    
    // Digital signatures
    std::vector<uint8_t> signMessage(const std::vector<uint8_t>& message);
    bool verifySignature(const std::vector<uint8_t>& message, 
                        const std::vector<uint8_t>& signature,
                        const std::vector<uint8_t>& publicKey);

    // Certificate operations
    bool verifyCertificate(const Certificate& cert);
    bool isCertificateExpired(const Certificate& cert) const;
    
    // Secure message packaging
    struct SecureMessage {
        std::vector<uint8_t> payload;
        std::vector<uint8_t> signature;
        uint64_t timestamp;
        uint32_t sequenceNumber;
        std::vector<uint8_t> senderCert;
    };

    SecureMessage createSecureMessage(const std::vector<uint8_t>& payload);
    bool verifySecureMessage(const SecureMessage& message);

    // Replay attack prevention
    bool isReplayMessage(const SecureMessage& message);
    void updateMessageHistory(const SecureMessage& message);

private:
    // OpenSSL context and key storage
    EVP_PKEY* privateKey;
    EVP_PKEY* publicKey;
    X509* certificate;

    // Message history for replay prevention
    struct MessageHistory {
        uint64_t timestamp;
        uint32_t sequenceNumber;
        std::vector<uint8_t> messageHash;
    };
    std::vector<MessageHistory> messageHistory;

    // Helper functions
    void initializeOpenSSL();
    void cleanupOpenSSL();
    bool isValidTimestamp(uint64_t timestamp) const;
    void pruneMessageHistory();
};

} // namespace crypto
} // namespace vanet

#endif // VANET_CRYPTO_MODULE_H 