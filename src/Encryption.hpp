
#ifndef ENCRYPTION_HPP
#define ENCRYPTION_HPP

#include "wifibroadcast.hpp"
#include <stdio.h>
#include <stdexcept>
#include <vector>
#include <optional>
#include <iostream>

// For developing or when encryption is not important, you can use this default seed to
// create deterministic rx and tx keys
static const std::array<unsigned char,crypto_box_SEEDBYTES> DEFAULT_ENCRYPTION_SEED={0};
// enable a default deterministic encryption key by using this flag
#define CREATE_DEFAULT_ENCRYPTION_KEYS


class Encryptor {
public:
    explicit Encryptor(const std::string &keypair) {
#ifdef CREATE_DEFAULT_ENCRYPTION_KEYS
        crypto_box_seed_keypair(rx_publickey.data(),tx_secretkey.data(),DEFAULT_ENCRYPTION_SEED.data());
        std::cout<<"Using default keys\n";
        //for(int i=0;i<crypto_box_SEEDBYTES;i++) {
        //    std::cout<<"Seed "<<i<<":"<<((int)DEFAULT_ENCRYPTION_SEED_TX[i])<<"\n";
        //}
#else
        FILE *fp;
        if ((fp = fopen(keypair.c_str(), "r")) == NULL) {
            throw std::runtime_error(string_format("Unable to open %s: %s", keypair.c_str(), strerror(errno)));
        }
        if (fread(tx_secretkey.data(), crypto_box_SECRETKEYBYTES, 1, fp) != 1) {
            fclose(fp);
            throw std::runtime_error(string_format("Unable to read tx secret key: %s", strerror(errno)));
        }
        if (fread(rx_publickey.data(), crypto_box_PUBLICKEYBYTES, 1, fp) != 1) {
            fclose(fp);
            throw std::runtime_error(string_format("Unable to read rx public key: %s", strerror(errno)));
        }
        fclose(fp);
#endif
    }
    // Don't forget to send the session key after creating a new one
    void makeSessionKey() {
        randombytes_buf(session_key.data(), sizeof(session_key));
        session_key_packet.packet_type = WFB_PACKET_KEY;
        randombytes_buf(session_key_packet.session_key_nonce, sizeof(session_key_packet.session_key_nonce));
        if (crypto_box_easy(session_key_packet.session_key_data, session_key.data(), sizeof(session_key),
                            session_key_packet.session_key_nonce, rx_publickey.data(), tx_secretkey.data()) != 0) {
            throw std::runtime_error("Unable to make session key!");
        }
    }
    // create a wfb packet by copying the header and
    // then putting the encrypted data right behind
    // the wblock_hdr_t is needed for calling the encryption method since it contains the 'nonce' for the message
    std::vector<uint8_t>
    makeEncryptedPacket(const wblock_hdr_t& wblockHdr,const uint8_t* payload,std::size_t payloadSize) {
        std::vector<uint8_t> ret;
        ret.resize(sizeof(wblock_hdr_t)+payloadSize+ crypto_aead_chacha20poly1305_ABYTES);
        // copy the wblockHdr data (this part is not encrypted)
        memcpy(ret.data(),(uint8_t*)&wblockHdr,sizeof(wblock_hdr_t));
        // pointer to where the encrypted data begins
        uint8_t* cyphertext=&ret[sizeof(wblock_hdr_t)];
        long long unsigned int ciphertext_len;

        crypto_aead_chacha20poly1305_encrypt(cyphertext, &ciphertext_len,
                                             payload, payloadSize,
                                             (uint8_t *) &wblockHdr, sizeof(wblock_hdr_t),
                                             nullptr,
                                             (uint8_t *) (&(wblockHdr.nonce)), session_key.data());
        // we allocate the right size in the beginning, but check if ciphertext_len is actually matching what we calculated
        // (the documentation says 'write up to n bytes' but they probably mean (write n bytes if everything goes well)
        assert(ret.size()==sizeof(wblock_hdr_t)+ciphertext_len);
        //ret.resize(sizeof(wblock_hdr_t)+ciphertext_len);
        return ret;
    }
    std::vector<uint8_t> makeEncryptedPacket(const XBlock& xBlock) {
        return makeEncryptedPacket(xBlock.header,xBlock.payload,xBlock.payloadSize);
    }
private:
    // tx->rx keypair
    std::array<uint8_t, crypto_box_SECRETKEYBYTES> tx_secretkey{};
    std::array<uint8_t, crypto_box_PUBLICKEYBYTES> rx_publickey{};
    std::array<uint8_t, crypto_aead_chacha20poly1305_KEYBYTES> session_key{};
public:
    // re-send this packet each time a new session key is created
    wsession_key_t session_key_packet;
};

class Decryptor {
public:
    explicit Decryptor(const std::string &keypair) {
#ifdef CREATE_DEFAULT_ENCRYPTION_KEYS
        crypto_box_seed_keypair(tx_publickey.data(),rx_secretkey.data(),DEFAULT_ENCRYPTION_SEED.data());
        std::cout<<"Using default keys\n";
#else
        FILE *fp;
        if ((fp = fopen(keypair.c_str(), "r")) == NULL) {
            throw std::runtime_error(string_format("Unable to open %s: %s", keypair.c_str(), strerror(errno)));
        }
        if (fread(rx_secretkey.data(), crypto_box_SECRETKEYBYTES, 1, fp) != 1) {
            fclose(fp);
            throw std::runtime_error(string_format("Unable to read rx secret key: %s", strerror(errno)));
        }
        if (fread(tx_publickey.data(), crypto_box_PUBLICKEYBYTES, 1, fp) != 1) {
            fclose(fp);
            throw std::runtime_error(string_format("Unable to read tx public key: %s", strerror(errno)));
        }
        fclose(fp);
#endif
        memset(session_key.data(), '\0', sizeof(session_key));
    }

public:
    std::array<uint8_t, crypto_box_SECRETKEYBYTES> rx_secretkey{};
public:
    std::array<uint8_t, crypto_box_PUBLICKEYBYTES> tx_publickey{};
    std::array<uint8_t, crypto_aead_chacha20poly1305_KEYBYTES> session_key{};
public:
    // return true on success
    /*bool onNewPacketWfbKey(const XBlock& xBlock) {

    }*/
    bool onNewPacketWfbKey(const uint8_t *buf) {
        std::array<uint8_t, sizeof(session_key)> new_session_key{};
        if (crypto_box_open_easy(new_session_key.data(),
                                 ((wsession_key_t *) buf)->session_key_data, sizeof(wsession_key_t::session_key_data),
                                 ((wsession_key_t *) buf)->session_key_nonce,
                                 tx_publickey.data(), rx_secretkey.data()) != 0) {
            fprintf(stderr, "unable to decrypt session key\n");
            return false;
        }
        if (memcmp(session_key.data(), new_session_key.data(), sizeof(session_key)) != 0) {
            fprintf(stderr, "New session detected\n");
            session_key = new_session_key;
            return true;
        }
        return false;
    }

    // returns decrypted data on success
    std::optional<std::vector<uint8_t>> decryptPacket(const wblock_hdr_t& wblockHdr,const uint8_t* payload,std::size_t payloadSize) {
        std::vector<uint8_t> decrypted;
        decrypted.resize(payloadSize-crypto_aead_chacha20poly1305_ABYTES);

        long long unsigned int decrypted_len;

        if (crypto_aead_chacha20poly1305_decrypt(decrypted.data(), &decrypted_len,
                                                 nullptr,
                                                 payload,payloadSize,
                                                 (uint8_t*)&wblockHdr,sizeof(wblock_hdr_t),
                                                 (uint8_t *) (&(wblockHdr.nonce)), session_key.data()) != 0) {
            return std::nullopt;
        }
        assert(decrypted.size()==decrypted_len);
        return decrypted;
    }
};

#endif //ENCRYPTION_HPP