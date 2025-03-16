#include "crypto-module.h"
#include <chrono>
#include <algorithm>
#include <stdexcept>
#include <cstring>

namespace vanet {
namespace crypto {

// Constants for security parameters
constexpr size_t MAX_MESSAGE_HISTORY = 1000;  // Maximum number of messages to store for replay prevention
constexpr uint64_t MESSAGE_TIMEOUT = 5000;    // Message timeout in milliseconds
constexpr size_t MIN_KEY_SIZE = 2048;         // Minimum RSA key size in bits
constexpr size_t MAX_CERT_CHAIN = 5;          // Maximum depth of certificate chain

CryptoModule::CryptoModule() : privateKey(nullptr), publicKey(nullptr), certificate(nullptr) {
    initializeOpenSSL();
}

CryptoModule::~CryptoModule() {
    cleanupOpenSSL();
}

void CryptoModule::initializeOpenSSL() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

void CryptoModule::cleanupOpenSSL() {
    if (privateKey) EVP_PKEY_free(privateKey);
    if (publicKey) EVP_PKEY_free(publicKey);
    if (certificate) X509_free(certificate);
    EVP_cleanup();
    ERR_free_strings();
}

bool CryptoModule::generateKeyPair(SignatureAlgorithm algo) {
    EVP_PKEY_CTX* ctx = nullptr;
    
    if (algo == SignatureAlgorithm::RSA_PSS) {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!ctx) return false;
        
        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, MIN_KEY_SIZE) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
    } else { // ECDSA
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
        if (!ctx) return false;
        
        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp256k1) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
    }
    
    EVP_PKEY* key = nullptr;
    if (EVP_PKEY_keygen(ctx, &key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    
    if (privateKey) EVP_PKEY_free(privateKey);
    privateKey = key;
    EVP_PKEY_CTX_free(ctx);
    return true;
}

std::vector<uint8_t> CryptoModule::hashMessage(const std::vector<uint8_t>& message, HashAlgorithm algo) {
    const EVP_MD* md;
    switch (algo) {
        case HashAlgorithm::SHA256:
            md = EVP_sha256();
            break;
        case HashAlgorithm::MD5:
            md = EVP_md5();
            break;
        case HashAlgorithm::SHA1:
            md = EVP_sha1();
            break;
        case HashAlgorithm::BLAKE2B:
            md = EVP_blake2b512();
            break;
        case HashAlgorithm::SHA3_256:
            md = EVP_sha3_256();
            break;
        default:
            throw std::invalid_argument("Unsupported hash algorithm");
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    std::vector<uint8_t> hash(EVP_MAX_MD_SIZE);
    unsigned int hashLen;

    EVP_DigestInit_ex(mdctx, md, nullptr);
    EVP_DigestUpdate(mdctx, message.data(), message.size());
    EVP_DigestFinal_ex(mdctx, hash.data(), &hashLen);
    EVP_MD_CTX_free(mdctx);

    hash.resize(hashLen);
    return hash;
}

std::vector<uint8_t> CryptoModule::signMessage(const std::vector<uint8_t>& message) {
    if (!privateKey) {
        throw std::runtime_error("Private key not loaded");
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create signature context");
    }

    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, privateKey) <= 0) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize signature");
    }

    size_t sigLen;
    if (EVP_DigestSignUpdate(ctx, message.data(), message.size()) <= 0 ||
        EVP_DigestSignFinal(ctx, nullptr, &sigLen) <= 0) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to calculate signature length");
    }

    std::vector<uint8_t> signature(sigLen);
    if (EVP_DigestSignFinal(ctx, signature.data(), &sigLen) <= 0) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to create signature");
    }

    EVP_MD_CTX_free(ctx);
    signature.resize(sigLen);
    return signature;
}

bool CryptoModule::verifySignature(const std::vector<uint8_t>& message,
                                 const std::vector<uint8_t>& signature,
                                 const std::vector<uint8_t>& publicKey) {
    EVP_PKEY* key = nullptr;
    const unsigned char* pubKeyData = publicKey.data();
    key = d2i_PUBKEY(nullptr, &pubKeyData, publicKey.size());
    
    if (!key) {
        return false;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool result = false;

    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, key) > 0 &&
        EVP_DigestVerifyUpdate(ctx, message.data(), message.size()) > 0 &&
        EVP_DigestVerifyFinal(ctx, signature.data(), signature.size()) > 0) {
        result = true;
    }

    EVP_PKEY_free(key);
    EVP_MD_CTX_free(ctx);
    return result;
}

CryptoModule::SecureMessage CryptoModule::createSecureMessage(const std::vector<uint8_t>& payload) {
    SecureMessage msg;
    msg.payload = payload;
    msg.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    
    static uint32_t sequence = 0;
    msg.sequenceNumber = ++sequence;
    
    // Create signature over payload + timestamp + sequence number
    std::vector<uint8_t> toSign = payload;
    toSign.insert(toSign.end(), 
                 reinterpret_cast<uint8_t*>(&msg.timestamp),
                 reinterpret_cast<uint8_t*>(&msg.timestamp) + sizeof(msg.timestamp));
    toSign.insert(toSign.end(),
                 reinterpret_cast<uint8_t*>(&msg.sequenceNumber),
                 reinterpret_cast<uint8_t*>(&msg.sequenceNumber) + sizeof(msg.sequenceNumber));
    
    msg.signature = signMessage(toSign);
    
    // Add certificate if available
    if (certificate) {
        unsigned char* certBuf = nullptr;
        int certLen = i2d_X509(certificate, &certBuf);
        if (certLen > 0) {
            msg.senderCert.assign(certBuf, certBuf + certLen);
            OPENSSL_free(certBuf);
        }
    }
    
    return msg;
}

bool CryptoModule::verifySecureMessage(const SecureMessage& message) {
    // Check timestamp
    if (!isValidTimestamp(message.timestamp)) {
        return false;
    }
    
    // Check for replay
    if (isReplayMessage(message)) {
        return false;
    }
    
    // Verify certificate if present
    if (!message.senderCert.empty()) {
        const unsigned char* certData = message.senderCert.data();
        X509* cert = d2i_X509(nullptr, &certData, message.senderCert.size());
        if (!cert || !verifyCertificate(Certificate{/*...*/})) {
            X509_free(cert);
            return false;
        }
        X509_free(cert);
    }
    
    // Verify signature
    std::vector<uint8_t> toVerify = message.payload;
    toVerify.insert(toVerify.end(),
                   reinterpret_cast<const uint8_t*>(&message.timestamp),
                   reinterpret_cast<const uint8_t*>(&message.timestamp) + sizeof(message.timestamp));
    toVerify.insert(toVerify.end(),
                   reinterpret_cast<const uint8_t*>(&message.sequenceNumber),
                   reinterpret_cast<const uint8_t*>(&message.sequenceNumber) + sizeof(message.sequenceNumber));
    
    return verifySignature(toVerify, message.signature, message.senderCert);
}

bool CryptoModule::isReplayMessage(const SecureMessage& message) {
    auto it = std::find_if(messageHistory.begin(), messageHistory.end(),
        [&message](const MessageHistory& history) {
            return history.timestamp == message.timestamp &&
                   history.sequenceNumber == message.sequenceNumber;
        });
    return it != messageHistory.end();
}

void CryptoModule::updateMessageHistory(const SecureMessage& message) {
    MessageHistory history;
    history.timestamp = message.timestamp;
    history.sequenceNumber = message.sequenceNumber;
    history.messageHash = hashMessage(message.payload);
    
    messageHistory.push_back(history);
    
    // Prune old messages if necessary
    if (messageHistory.size() > MAX_MESSAGE_HISTORY) {
        pruneMessageHistory();
    }
}

void CryptoModule::pruneMessageHistory() {
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    
    messageHistory.erase(
        std::remove_if(messageHistory.begin(), messageHistory.end(),
            [now](const MessageHistory& history) {
                return (now - history.timestamp) > MESSAGE_TIMEOUT;
            }),
        messageHistory.end()
    );
}

bool CryptoModule::isValidTimestamp(uint64_t timestamp) const {
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    
    return (now - timestamp) <= MESSAGE_TIMEOUT;
}

} // namespace crypto
} // namespace vanet 