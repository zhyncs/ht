// Copyright (c) 2020 Yineng Zhang <me@zhyncs.com>

#pragma once

#include <netinet/in.h>
#include <strings.h>
#include <sys/un.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

class Socket {
 public:
  Socket();
  Socket(int domain, int type, int protocol);
  Socket& operator=(const Socket& rhs);
  Socket(Socket&& rhs) noexcept;
  Socket& operator=(Socket&& rhs) noexcept;
  ~Socket();

  bool operator==(const Socket& rhs) const;
  bool operator!=(const Socket& rhs) const;
  explicit operator bool() const;
  int get_sock_fd() const;
  Socket accept() const;
  bool bind(const std::string& addr, uint16_t port);
  bool connect(const std::string& addr, uint16_t port);
  std::pair<std::string, uint16_t> getpeername() const;
  bool listen() const;
  ssize_t read(std::vector<unsigned char>* buffer, size_t max_len) const;
  bool setsockopt(int level, int optname, int option_value) const;
  bool set_sock_blocking(bool is_block) const;
  ssize_t write(const std::vector<unsigned char>& buffer) const;
  ssize_t recvfrom(std::vector<unsigned char>* buffer, size_t len,
                   std::pair<std::string, uint16_t>* addr_info, int flags = 0) const;
  ssize_t sendto(const std::vector<unsigned char>& buffer,
                 const std::pair<std::string, uint16_t>& addr_info, int flags = 0) const;

 private:
  int domain_;
  size_t* ref_count_ = nullptr;
  int sock_fd_ = -1;
  struct sockaddr_in* addr_in_ = nullptr;

  void destroy();

  ssize_t read(unsigned char* buffer, size_t max_len) const;
  bool listen(int backlog, int* error_code) const noexcept;
  bool set_sock_blocking(bool is_block, int* error_code) const noexcept;
  bool setsockopt(int level, int optname, int option_value, int* error_code) const noexcept;
  ssize_t write(const unsigned char* buffer, size_t len) const;
  ssize_t recvfrom(unsigned char* buffer, size_t len, std::pair<std::string, uint16_t>* addr_info,
                   int flags = 0) const;
  ssize_t sendto(const unsigned char* buffer, size_t len,
                 const std::pair<std::string, uint16_t>& addr_info, int flags = 0) const;
};
