
#ifndef ENCRYPTION_HPP
#define ENCRYPTION_HPP

#include "Helper.hpp"
#include <cstdio>
#include <stdexcept>
#include <vector>
#include <optional>
#include <iostream>
#include <array>
#include <sodium.h>

// Single Header file that can be used to add encryption to a lossy unidirectional link

// For developing or when encryption is not important, you can use this default seed to
// create deterministic rx and tx keys
static const std::array<unsigned char,crypto_box_SEEDBYTES> DEFAULT_ENCRYPTION_SEED={0};
// use this one if you are worried about CPU usage when using encryption
//#define DO_NOT_ENCRYPT_DATA_BUT_PROVIDE_BACKWARDS_COMPABILITY

class Encryptor {
public:
    // enable a default deterministic encryption key by using std::nullopt
    // else, pass path to file with encryption keys
    explicit Encryptor(std::optional<std::string> keypair) {
        if(keypair==std::nullopt){
            // use default encryption keys
            crypto_box_seed_keypair(rx_publickey.data(),tx_secretkey.data(),DEFAULT_ENCRYPTION_SEED.data());
            std::cout<<"Using default keys\n";
        }else{
            FILE *fp;
            if ((fp = fopen(keypair->c_str(), "r")) == nullptr) {
                throw std::runtime_error(StringFormat::convert("Unable to open %s: %s", keypair->c_str(), strerror(errno)));
            }
            if (fread(tx_secretkey.data(), crypto_box_SECRETKEYBYTES, 1, fp) != 1) {
                fclose(fp);
                throw std::runtime_error(StringFormat::convert("Unable to read tx secret key: %s", strerror(errno)));
            }
            if (fread(rx_publickey.data(), crypto_box_PUBLICKEYBYTES, 1, fp) != 1) {
                fclose(fp);
                throw std::runtime_error(StringFormat::convert("Unable to read rx public key: %s", strerror(errno)));
            }
            fclose(fp);
        }
    }
    // Don't forget to send the session key after creating a new one
    void makeNewSessionKey(std::array<uint8_t,crypto_box_NONCEBYTES>& sessionKeyNonce,std::array<uint8_t,crypto_aead_chacha20poly1305_KEYBYTES + crypto_box_MACBYTES>& sessionKeyData){
        randombytes_buf(session_key.data(), sizeof(session_key));
        randombytes_buf(sessionKeyNonce.data(), sizeof(sessionKeyNonce));
        if (crypto_box_easy(sessionKeyData.data(), session_key.data(), sizeof(session_key),
                            sessionKeyNonce.data(), rx_publickey.data(), tx_secretkey.data()) != 0) {
            throw std::runtime_error("Unable to make session key!");
        }
    }
    // Encrypt the payload using a public nonce. (aka sequence number)
    // The nonce is not included in the raw encrypted payload, but used for the checksum stuff
    std::vector<uint8_t> encryptPacket(const uint64_t nonce,const uint8_t* payload,std::size_t payloadSize){
#ifdef DO_NOT_ENCRYPT_DATA_BUT_PROVIDE_BACKWARDS_COMPABILITY
        return std::vector<uint8_t>(payload,payload+payloadSize);
#else
        std::vector<uint8_t> encryptedData=std::vector<uint8_t>(payloadSize+ crypto_aead_chacha20poly1305_ABYTES);
        long long unsigned int ciphertext_len;
        crypto_aead_chacha20poly1305_encrypt(encryptedData.data(), &ciphertext_len,
                                             payload, payloadSize,
                                             (uint8_t *)&nonce, sizeof(uint64_t),
                                             nullptr,
                                             (uint8_t *) (&nonce), session_key.data());
        // we allocate the right size in the beginning, but check if ciphertext_len is actually matching what we calculated
        // (the documentation says 'write up to n bytes' but they probably mean (write exactly n bytes unless an error occurs)
        assert(encryptedData.size()==ciphertext_len);
        return encryptedData;
#endif
    }
private:
    // tx->rx keypair
    std::array<uint8_t, crypto_box_SECRETKEYBYTES> tx_secretkey{};
    std::array<uint8_t, crypto_box_PUBLICKEYBYTES> rx_publickey{};
    std::array<uint8_t, crypto_aead_chacha20poly1305_KEYBYTES> session_key{};
public:
    // re-send this packet each time a new session key is created
};

class Decryptor {
public:
    // enable a default deterministic encryption key by using std::nullopt
    // else, pass path to file with encryption keys
    explicit Decryptor(std::optional<std::string> keypair) {
        if(keypair==std::nullopt){
            crypto_box_seed_keypair(tx_publickey.data(),rx_secretkey.data(),DEFAULT_ENCRYPTION_SEED.data());
            std::cout<<"Using default keys\n";
        }else{
            FILE *fp;
            if ((fp = fopen(keypair->c_str(), "r")) == nullptr) {
                throw std::runtime_error(StringFormat::convert("Unable to open %s: %s", keypair->c_str(), strerror(errno)));
            }
            if (fread(rx_secretkey.data(), crypto_box_SECRETKEYBYTES, 1, fp) != 1) {
                fclose(fp);
                throw std::runtime_error(StringFormat::convert("Unable to read rx secret key: %s", strerror(errno)));
            }
            if (fread(tx_publickey.data(), crypto_box_PUBLICKEYBYTES, 1, fp) != 1) {
                fclose(fp);
                throw std::runtime_error(StringFormat::convert("Unable to read tx public key: %s", strerror(errno)));
            }
            fclose(fp);
        }
        memset(session_key.data(), '\0', sizeof(session_key));
    }
public:
    std::array<uint8_t, crypto_box_SECRETKEYBYTES> rx_secretkey{};
public:
    std::array<uint8_t, crypto_box_PUBLICKEYBYTES> tx_publickey{};
    std::array<uint8_t, crypto_aead_chacha20poly1305_KEYBYTES> session_key{};
public:
    // return true if a new session was detected (The same session key can be sent multiple times by the tx)
    bool onNewPacketSessionKeyData(std::array<uint8_t,crypto_box_NONCEBYTES>& sessionKeyNonce,std::array<uint8_t,crypto_aead_chacha20poly1305_KEYBYTES + crypto_box_MACBYTES>& sessionKeyData) {
        std::array<uint8_t, sizeof(session_key)> new_session_key{};
        if (crypto_box_open_easy(new_session_key.data(),
                                 sessionKeyData.data(), sessionKeyData.size(),
                                 sessionKeyNonce.data(),
                                 tx_publickey.data(), rx_secretkey.data()) != 0) {
            // this basically should just never happen, and is an error
            std::cerr<<"unable to decrypt session key\n";
            return false;
        }
        if (memcmp(session_key.data(), new_session_key.data(), sizeof(session_key)) != 0) {
            // this is NOT an error, the same session key is sent multiple times !
            std::cout<<"New session detected\n";
            session_key = new_session_key;
            return true;
        }
        return false;
    }

    // returns decrypted data on success
    std::optional<std::vector<uint8_t>> decryptPacket(const uint64_t nonce,const uint8_t* encryptedPayload,std::size_t encryptedPayloadSize) {
#ifdef DO_NOT_ENCRYPT_DATA_BUT_PROVIDE_BACKWARDS_COMPABILITY
        return std::vector<uint8_t>(encryptedPayload,encryptedPayload+encryptedPayloadSize);
#else
        std::vector<uint8_t> decrypted;
        decrypted.resize(encryptedPayloadSize-crypto_aead_chacha20poly1305_ABYTES);

        long long unsigned int decrypted_len;
        const unsigned long long int cLen=encryptedPayloadSize;

        if (crypto_aead_chacha20poly1305_decrypt(decrypted.data(), &decrypted_len,
                                                 nullptr,
                                                 encryptedPayload,cLen,
                                                 (uint8_t*)&nonce,sizeof(uint64_t),
                                                 (uint8_t *) (&nonce), session_key.data()) != 0) {
            return std::nullopt;
        }
        assert(decrypted.size()==decrypted_len);
        return decrypted;
#endif
    }
};

#endif //ENCRYPTION_HPP