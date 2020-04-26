// Copyright (c) 2020 Yineng Zhang <me@zhyncs.com>

#include "crypto.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/md5.h>
#include <openssl/rand.h>

#include <functional>
#include <string>

#include "log.h"
#include "util.h"

#define ENC_UNCHANGED -1
#define ENC_DECRYPTION 0
#define ENC_ENCRYPTION 1

#define AES_128_GCM_KEY_SIZE 16
#define AES_128_GCM_SALT_SIZE 16
#define AES_128_GCM_NONCE_SIZE 12
#define AES_128_GCM_TAG_SIZE 16

#define AEAD_CHUNK_SIZE_LEN 2
#define AEAD_CHUNK_SIZE_MASK 0x3FFF

class AEADCipher {
 public:
  AEADCipher(const std::vector<unsigned char>& key, const std::vector<unsigned char>& salt, int op);
  AEADCipher(const AEADCipher&) = delete;
  AEADCipher& operator=(const AEADCipher&) = delete;
  ~AEADCipher() { destroy(); }

  bool encrypt(const unsigned char* in, int in_len, std::vector<unsigned char>* out) {
    return ae_encrypt(in, in_len, out);
  }
  bool decrypt(const unsigned char* in, int in_len, std::vector<unsigned char>* out) {
    return ae_decrypt(in, in_len, out);
  }

 private:
  EVP_CIPHER_CTX* ctx_ = nullptr;
  std::vector<unsigned char> nonce_;
  std::vector<unsigned char> sub_key_;

  unsigned int chunk_payload_len_ = 0;
  unsigned int chunk_data_pos_ = 0;
  std::vector<unsigned char> chunk_data_;

  void nonce_increment();
  bool ae_encrypt(const unsigned char* in, int in_len, std::vector<unsigned char>* out);
  bool ae_decrypt(const unsigned char* in, int in_len, std::vector<unsigned char>* out);

  bool aead_encrypt(const unsigned char* in, int in_len, std::vector<unsigned char>* out);
  bool aead_decrypt(const unsigned char* in, int in_len, std::vector<unsigned char>* out);

  void destroy();

  bool encrypt_chunk(const unsigned char* in, int in_len, std::vector<unsigned char>* out);
  bool decrypt_chunk_size();
  bool decrypt_chunk_payload(std::vector<unsigned char>* out);
  bool is_chunk_data_available();

  static void sodium_increment(unsigned char* nonce, int nonce_len);
};

static std::shared_ptr<AEADCipher> get_cipher(const std::vector<unsigned char>& key,
                                              const std::vector<unsigned char>& iv, int op) {
  return std::make_shared<AEADCipher>(key, iv, op);
}

bool Crypto::bytes_to_key(const char* password, std::vector<unsigned char>* key) {
  std::vector<unsigned char> local_key(AES_128_GCM_KEY_SIZE);
  if (!EVP_BytesToKey(EVP_aes_128_gcm(), EVP_md5(), nullptr,
                      reinterpret_cast<const unsigned char*>(password),
                      static_cast<int>(strlen(password)), 1, local_key.data(), nullptr)) {
    EvpERR("Fail to EVP_BytesToKey");
    return false;
  }
  key->swap(local_key);
  return true;
}

bool Crypto::gen_salt(std::vector<unsigned char>* salt) {
  std::vector<unsigned char> local_salt(AES_128_GCM_SALT_SIZE);
  if (!RAND_bytes(local_salt.data(), static_cast<int>(local_salt.size()))) {
    EvpERR("Fail to RAND_bytes");
    return false;
  }
  salt->swap(local_salt);
  return true;
}

Crypto::Crypto(const std::string& password) {
  bytes_to_key(password.c_str(), &key_);
  gen_salt(&encipher_salt_);
  encipher_ = get_cipher(key_, encipher_salt_, ENC_ENCRYPTION);
}

bool Crypto::encrypt(const unsigned char* in, int in_len, std::vector<unsigned char>* out) {
  if (in_len == 0) {
    out->clear();
    return true;
  }

  if (salt_sent_) {
    encipher_->encrypt(in, in_len, out);
  } else {
    salt_sent_ = true;
    *out = encipher_salt_;
    encipher_->encrypt(in, in_len, out);
  }
  return true;
}

bool Crypto::decrypt(const unsigned char* in, int in_len, std::vector<unsigned char>* out) {
  if (in_len == 0) {
    out->clear();
    return true;
  }

  auto data_len = in_len;
  if (!decipher_) {
    std::copy(in, in + AES_128_GCM_SALT_SIZE, std::back_inserter(decipher_salt_));
    decipher_ = get_cipher(key_, decipher_salt_, ENC_DECRYPTION);

    data_len -= AES_128_GCM_SALT_SIZE;
    if (!data_len) {
      out->clear();
      return true;
    }
    in += AES_128_GCM_SALT_SIZE;
  }
  decipher_->decrypt(in, data_len, out);
  return true;
}

const std::vector<unsigned char> info = {'s', 's', '-', 's', 'u', 'b', 'k', 'e', 'y'};

bool hkdf_sha1(std::vector<unsigned char>* key, std::vector<unsigned char>* salt,
               std::vector<unsigned char>* sub_key) {
  std::unique_ptr<EVP_PKEY_CTX, std::function<void(EVP_PKEY_CTX*)>> pctx = {
      EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), [](EVP_PKEY_CTX* ptr) {
        if (ptr) {
          EVP_PKEY_CTX_free(ptr);
        }
      }};
  if (!pctx) {
    EvpERR("Fail to EVP_PKEY_CTX_new_id");
    return false;
  }
  if (!EVP_PKEY_derive_init(pctx.get())) {
    EvpERR("Fail to EVP_PKEY_derive_init");
    return false;
  }
  if (!EVP_PKEY_CTX_hkdf_mode(pctx.get(), EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND)) {
    EvpERR("Fail to EVP_PKEY_CTX_hkdf_mode");
    return false;
  }
  if (!EVP_PKEY_CTX_set_hkdf_md(pctx.get(), EVP_sha1())) {
    EvpERR("Fail to EVP_PKEY_CTX_set_hkdf_md EVP_sha1");
    return false;
  }
  if (!EVP_PKEY_CTX_set1_hkdf_salt(pctx.get(), salt->data(), static_cast<int>(salt->size()))) {
    EvpERR("Fail to EVP_PKEY_CTX_set1_hkdf_salt");
    return false;
  }
  if (!EVP_PKEY_CTX_set1_hkdf_key(pctx.get(), key->data(), static_cast<int>(key->size()))) {
    EvpERR("Fail to EVP_PKEY_CTX_set1_hkdf_key");
    return false;
  }
  if (!EVP_PKEY_CTX_add1_hkdf_info(pctx.get(), info.data(), static_cast<int>(info.size()))) {
    EvpERR("Fail to EVP_PKEY_CTX_add1_hkdf_info");
    return false;
  }
  std::vector<unsigned char> local_sub_key(AES_128_GCM_KEY_SIZE);
  size_t len = AES_128_GCM_KEY_SIZE;
  if (!EVP_PKEY_derive(pctx.get(), local_sub_key.data(), &len)) {
    EvpERR("Fail to EVP_PKEY_derive");
    return false;
  }
  sub_key->swap(local_sub_key);
  return true;
}

void AEADCipher::sodium_increment(unsigned char* nonce, int nonce_len) {
  uint_fast16_t c = 1U;
  for (size_t i = 0U; i < nonce_len; ++i) {
    c += static_cast<uint_fast16_t>(nonce[i]);
    nonce[i] = static_cast<unsigned char>(c);
    c >>= 8;
  }
}

void AEADCipher::nonce_increment() { sodium_increment(nonce_.data(), AES_128_GCM_NONCE_SIZE); }

bool AEADCipher::encrypt_chunk(const unsigned char* in, int in_len,
                               std::vector<unsigned char>* out) {
  uint16_t net_order_plen = htons(in_len & AEAD_CHUNK_SIZE_MASK);
  size_t out_size = out->size();

  aead_encrypt((unsigned char*)&net_order_plen, sizeof(net_order_plen), out);
  if (out->size() - out_size != AEAD_CHUNK_SIZE_LEN + AES_128_GCM_TAG_SIZE) {
    return false;
  }

  out_size = out->size();
  aead_encrypt(in, in_len, out);

  if (out->size() - out_size != in_len + AES_128_GCM_TAG_SIZE) {
    return false;
  }

  return true;
}

bool AEADCipher::ae_encrypt(const unsigned char* in, int in_len, std::vector<unsigned char>* out) {
  if (in_len <= AEAD_CHUNK_SIZE_MASK) {
    return encrypt_chunk(in, in_len, out);
  }

  int plen = in_len;
  while (plen > 0) {
    int mlen = plen < AEAD_CHUNK_SIZE_MASK ? plen : AEAD_CHUNK_SIZE_MASK;
    encrypt_chunk(in, mlen, out);
    in += mlen;
    plen -= mlen;
  }
  return true;
}

bool AEADCipher::decrypt_chunk_size() {
  int hlen = AEAD_CHUNK_SIZE_LEN + AES_128_GCM_TAG_SIZE;
  std::vector<unsigned char> plen_out;
  aead_decrypt(&chunk_data_[chunk_data_pos_], hlen, &plen_out);

  auto* plen = reinterpret_cast<uint16_t*>(plen_out.data());
  uint16_t host_order_plen = ntohs(*plen);

  if ((host_order_plen & AEAD_CHUNK_SIZE_MASK) != host_order_plen || host_order_plen <= 0) {
    return false;
  }

  chunk_payload_len_ = host_order_plen;
  chunk_data_pos_ += static_cast<unsigned int>(hlen);

  return true;
}

bool AEADCipher::decrypt_chunk_payload(std::vector<unsigned char>* out) {
  size_t out_size = out->size();
  aead_decrypt(&chunk_data_[chunk_data_pos_],
               static_cast<int>(chunk_payload_len_ + AES_128_GCM_TAG_SIZE), out);
  if (out->size() - out_size != chunk_payload_len_) {
    return false;
  }
  chunk_data_pos_ += chunk_payload_len_ + AES_128_GCM_TAG_SIZE;
  chunk_payload_len_ = 0;

  return true;
}

bool AEADCipher::is_chunk_data_available() {
  auto tag_size = AEAD_CHUNK_SIZE_LEN + AES_128_GCM_TAG_SIZE;
  auto data_size = chunk_payload_len_ + AES_128_GCM_TAG_SIZE;
  if ((chunk_payload_len_ == 0) && (chunk_data_.size() - chunk_data_pos_ >= tag_size)) {
    return true;
  }
  if ((chunk_payload_len_ > 0) && (chunk_data_.size() - chunk_data_pos_ >= data_size)) {
    return true;
  }
  return false;
}

bool AEADCipher::ae_decrypt(const unsigned char* in, int in_len, std::vector<unsigned char>* out) {
  std::copy(in, in + in_len, std::back_inserter(chunk_data_));
  while (is_chunk_data_available()) {
    if (chunk_payload_len_ == 0) {
      decrypt_chunk_size();
      continue;
    }
    if (chunk_payload_len_ > 0) {
      decrypt_chunk_payload(out);
    }
  }
  std::copy(chunk_data_.begin() + chunk_data_pos_, chunk_data_.end(), chunk_data_.begin());
  chunk_data_.resize(chunk_data_.size() - chunk_data_pos_);
  chunk_data_pos_ = 0;
  return true;
}

static int out_len = 0;

void AEADCipher::destroy() {
  if (ctx_) {
    EVP_CIPHER_CTX_free(ctx_);
    ctx_ = nullptr;
  }
}

AEADCipher::AEADCipher(const std::vector<unsigned char>& key,
                       const std::vector<unsigned char>& salt, int op) {
  ctx_ = EVP_CIPHER_CTX_new();
  if (!ctx_) {
    EvpERR("Fail to EVP_CIPHER_CTX_new");
  }

  nonce_.resize(AES_128_GCM_NONCE_SIZE, 0);
  hkdf_sha1(const_cast<std::vector<unsigned char>*>(&key),
            const_cast<std::vector<unsigned char>*>(&salt), &sub_key_);

  if (!EVP_CipherInit_ex(ctx_, EVP_aes_128_gcm(), nullptr, sub_key_.data(), nullptr, op)) {
    EvpERR("Fail to EVP_CipherInit_ex");
  }

  if (!EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_AEAD_SET_IVLEN, AES_128_GCM_NONCE_SIZE, nullptr)) {
    EvpERR("Fail to EVP_CIPHER_CTX_ctrl");
  }

  if (!EVP_CipherInit_ex(ctx_, nullptr, nullptr, nullptr, nonce_.data(), ENC_UNCHANGED)) {
    EvpERR("Fail to EVP_CipherInit_ex");
  }
}

bool AEADCipher::aead_encrypt(const unsigned char* in, int in_len,
                              std::vector<unsigned char>* out) {
  size_t out_size = out->size();
  out->resize(out_size + in_len);
  if (!EVP_CipherUpdate(ctx_, out->data() + out_size, &out_len, in, in_len)) {
    return false;
  }

  if (!EVP_CipherFinal_ex(ctx_, out->data() + out->size(), &out_len)) {
    EvpERR("Fail to finalize cipher");
    return false;
  }

  size_t tag_size = out->size();
  out->resize(tag_size + AES_128_GCM_TAG_SIZE);
  if (!EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_AEAD_GET_TAG, AES_128_GCM_TAG_SIZE,
                           out->data() + tag_size)) {
    return false;
  }

  nonce_increment();
  if (!EVP_CipherInit_ex(ctx_, nullptr, nullptr, nullptr, nonce_.data(), ENC_UNCHANGED)) {
    return false;
  }

  return true;
}

bool AEADCipher::aead_decrypt(const unsigned char* in, int in_len,
                              std::vector<unsigned char>* out) {
  if (in_len < AES_128_GCM_TAG_SIZE) {
    return false;
  }

  if (!EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_AEAD_SET_TAG, AES_128_GCM_TAG_SIZE,
                           const_cast<unsigned char*>(in + (in_len - AES_128_GCM_TAG_SIZE)))) {
    return false;
  }

  size_t out_size = out->size();

  out->resize(out_size + in_len - AES_128_GCM_TAG_SIZE);
  if (!EVP_CipherUpdate(ctx_, out->data() + out_size, &out_len, in,
                        in_len - AES_128_GCM_TAG_SIZE)) {
    return false;
  }

  if (!EVP_CipherFinal_ex(ctx_, out->data() + out->size(), &out_len)) {
    EvpERR("Fail to finalize cipher");
    return false;
  }

  nonce_increment();
  if (!EVP_CipherInit_ex(ctx_, nullptr, nullptr, nullptr, nonce_.data(), ENC_UNCHANGED)) {
    return false;
  }

  return true;
}
