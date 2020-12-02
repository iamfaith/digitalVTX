
#ifndef ENCRYPTION_HPP
#define ENCRYPTION_HPP

#include "wifibroadcast.hpp"
#include <stdio.h>
#include <stdexcept>
#include <vector>
#include <optional>

class Encryptor{
public:
    explicit Encryptor(const std::string& keypair){
        FILE *fp;
        if((fp = fopen(keypair.c_str(), "r")) == NULL){
            throw std::runtime_error(string_format("Unable to open %s: %s", keypair.c_str(), strerror(errno)));
        }
        if (fread(tx_secretkey.data(), crypto_box_SECRETKEYBYTES, 1, fp) != 1){
            fclose(fp);
            throw std::runtime_error(string_format("Unable to read tx secret key: %s", strerror(errno)));
        }
        if (fread(rx_publickey.data(), crypto_box_PUBLICKEYBYTES, 1, fp) != 1){
            fclose(fp);
            throw std::runtime_error(string_format("Unable to read rx public key: %s", strerror(errno)));
        }
        fclose(fp);
    }
    void makeSessionKey(){
        randombytes_buf(session_key.data(), sizeof(session_key));
        session_key_packet.packet_type = WFB_PACKET_KEY;
        randombytes_buf(session_key_packet.session_key_nonce, sizeof(session_key_packet.session_key_nonce));
        if (crypto_box_easy(session_key_packet.session_key_data, session_key.data(), sizeof(session_key),
                            session_key_packet.session_key_nonce, rx_publickey.data(), tx_secretkey.data()) != 0){
            throw std::runtime_error("Unable to make session key!");
        }
    }
    //TODO fixme this is still really messy (what about all the params ?!)
    std::vector<uint8_t> makeEncryptedPacket(uint64_t block_idx,uint8_t fragment_idx,uint8_t** block,std::size_t packet_size){
        uint8_t ciphertext[MAX_FORWARDER_PACKET_SIZE];
        wblock_hdr_t *block_hdr = (wblock_hdr_t*)ciphertext;
        long long unsigned int ciphertext_len;

        assert(packet_size <= MAX_FEC_PAYLOAD);

        block_hdr->packet_type = WFB_PACKET_DATA;
        block_hdr->nonce = htobe64(((block_idx & BLOCK_IDX_MASK) << 8) + fragment_idx);

        // encrypted payload
        // TODO I think the encrypted payload begins after the wblock_hdr_t but I still don't really understand everything
        crypto_aead_chacha20poly1305_encrypt(ciphertext + sizeof(wblock_hdr_t), &ciphertext_len,
                                             block[fragment_idx], packet_size,
                                             (uint8_t*)block_hdr, sizeof(wblock_hdr_t),
                                             NULL, (uint8_t*)(&(block_hdr->nonce)), session_key.data());
        //TODO fixme use std::vector with proper size originally
        return std::vector<uint8_t>(ciphertext,ciphertext+(sizeof(wblock_hdr_t) + ciphertext_len));
    }
private:
    // tx->rx keypair
    std::array<uint8_t,crypto_box_SECRETKEYBYTES> tx_secretkey;
    std::array<uint8_t,crypto_box_PUBLICKEYBYTES> rx_publickey;
    std::array<uint8_t,crypto_aead_chacha20poly1305_KEYBYTES> session_key;
public:
    wsession_key_t session_key_packet;
};

class Decryptor{
public:
    explicit Decryptor(const std::string& keypair){
        FILE *fp;
        if((fp = fopen(keypair.c_str(), "r")) == NULL){
            throw std::runtime_error(string_format("Unable to open %s: %s", keypair.c_str(), strerror(errno)));
        }
        if (fread(rx_secretkey.data(), crypto_box_SECRETKEYBYTES, 1, fp) != 1){
            fclose(fp);
            throw std::runtime_error(string_format("Unable to read rx secret key: %s", strerror(errno)));
        }
        if (fread(tx_publickey.data(), crypto_box_PUBLICKEYBYTES, 1, fp) != 1){
            fclose(fp);
            throw std::runtime_error(string_format("Unable to read tx public key: %s", strerror(errno)));
        }
        fclose(fp);
        memset(session_key.data(), '\0', sizeof(session_key));
    }

public:
    std::array<uint8_t,crypto_box_SECRETKEYBYTES> rx_secretkey;
public:
    std::array<uint8_t,crypto_box_PUBLICKEYBYTES> tx_publickey;
    std::array<uint8_t,crypto_aead_chacha20poly1305_KEYBYTES> session_key;
public:
    // TODO what the heck does this exactly ?
    // return true on success
    bool onNewPacketWfbKey(const uint8_t* buf){
        std::array<uint8_t,sizeof(session_key)> new_session_key{};
        if(crypto_box_open_easy(new_session_key.data(),
                                ((wsession_key_t*)buf)->session_key_data, sizeof(wsession_key_t::session_key_data),
                                ((wsession_key_t*)buf)->session_key_nonce,
                                tx_publickey.data(), rx_secretkey.data()) != 0){
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
    // returns true on success
    bool decryptPacket(const uint8_t* buf, size_t size,std::vector<uint8_t>& decryptedData){
        uint8_t decrypted[MAX_FEC_PAYLOAD];
        long long unsigned int decrypted_len;
        auto *block_hdr = (wblock_hdr_t*)buf;

        if (crypto_aead_chacha20poly1305_decrypt(decrypted, &decrypted_len,NULL,
                                                 buf + sizeof(wblock_hdr_t), size - sizeof(wblock_hdr_t),buf,
                                                 sizeof(wblock_hdr_t),
                                                 (uint8_t*)(&(block_hdr->nonce)), session_key.data()) != 0){
            return false;
        }
        decryptedData.resize(decrypted_len),
        memcpy(decryptedData.data(),decrypted,decrypted_len);
        return true;
    }
};

#endif //ENCRYPTION_HPP