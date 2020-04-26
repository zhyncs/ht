// Copyright (c) 2020 Yineng Zhang <me@zhyncs.com>

#pragma once

#include <memory>
#include <string>
#include <vector>

class AEADCipher;

class Crypto {
 public:
  explicit Crypto(const std::string& password = "831143");
  Crypto(const Crypto&) = delete;
  Crypto& operator=(const Crypto&) = delete;
  ~Crypto() = default;

  bool encrypt(const unsigned char* in, int in_len, std::vector<unsigned char>* out);
  bool decrypt(const unsigned char* in, int in_len, std::vector<unsigned char>* out);

 private:
  bool salt_sent_ = false;
  std::vector<unsigned char> key_;

  std::shared_ptr<AEADCipher> encipher_;
  std::vector<unsigned char> encipher_salt_;

  std::shared_ptr<AEADCipher> decipher_;
  std::vector<unsigned char> decipher_salt_;

  static bool bytes_to_key(const char* password, std::vector<unsigned char>* key);
  static bool gen_salt(std::vector<unsigned char>* salt);
};
