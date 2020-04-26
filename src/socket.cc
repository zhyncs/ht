// Copyright (c) 2020 Yineng Zhang <me@zhyncs.com>

#include "socket.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>

#include "log.h"

Socket::Socket() : domain_(-1), ref_count_(nullptr), sock_fd_(-1) {
  memset(&addr_in_, 0, sizeof(addr_in_));
}

Socket::Socket(int domain, int type, int protocol)
    : domain_(domain), ref_count_(nullptr), sock_fd_(-1) {
  memset(&addr_in_, 0, sizeof(addr_in_));
  ref_count_ = new size_t(1);

  sock_fd_ = socket(domain, type, protocol);
  if (sock_fd_ < 0) {
    SysERR("Fail to create socket");
  }
}

Socket& Socket::operator=(const Socket& rhs) {
  if (rhs.ref_count_)
    ++*rhs.ref_count_;

  destroy();
  domain_ = rhs.domain_;
  ref_count_ = rhs.ref_count_;
  sock_fd_ = rhs.sock_fd_;
  addr_in_ = rhs.addr_in_;

  return *this;
}

Socket::Socket(Socket&& rhs) noexcept
    : domain_(rhs.domain_),
      ref_count_(rhs.ref_count_),
      sock_fd_(rhs.sock_fd_),
      addr_in_(rhs.addr_in_) {
  rhs.ref_count_ = nullptr;
  rhs.addr_in_ = nullptr;
  rhs.sock_fd_ = -1;
}

Socket& Socket::operator=(Socket&& rhs) noexcept {
  if (this != &rhs) {
    destroy();

    domain_ = rhs.domain_;
    ref_count_ = rhs.ref_count_;
    sock_fd_ = rhs.sock_fd_;
    addr_in_ = rhs.addr_in_;

    rhs.ref_count_ = nullptr;
    rhs.addr_in_ = nullptr;
    rhs.sock_fd_ = -1;
  }

  return *this;
}

Socket::~Socket() { destroy(); }

bool Socket::operator==(const Socket& rhs) const {
  return sock_fd_ != -1 && rhs.sock_fd_ != -1 && sock_fd_ == rhs.sock_fd_;
}

bool Socket::operator!=(const Socket& rhs) const { return !(*this == rhs); }

Socket::operator bool() const { return sock_fd_ != -1; }

int Socket::get_sock_fd() const { return sock_fd_; }

void Socket::destroy() {
  if (ref_count_ && --*ref_count_ == 0) {
    delete ref_count_;
    ref_count_ = nullptr;
    if (domain_ == AF_INET && addr_in_)
      delete addr_in_;

    addr_in_ = nullptr;
    close(sock_fd_);
  }
}

Socket Socket::accept() const {
  Socket conn_sock;
  conn_sock.ref_count_ = new size_t(1);
  int conn_fd = -1;

  if (domain_ == AF_INET) {
    socklen_t length = sizeof(struct sockaddr_in);
    conn_sock.addr_in_ = new (struct sockaddr_in);
    memset(conn_sock.addr_in_, 0, sizeof(struct sockaddr_in));
    conn_fd = ::accept(sock_fd_, (struct sockaddr*)conn_sock.addr_in_, &length);
  }

  if (conn_fd < 0) {
    SysERR("Fail to accept a conn_fd");
  }

  conn_sock.domain_ = domain_;
  conn_sock.sock_fd_ = conn_fd;

  return conn_sock;
}

bool Socket::bind(const std::string& addr, uint16_t port) {
  int flag = -1;

  if (domain_ == AF_INET) {
    auto addr_ptr = addr_in_;
    addr_in_ = new (struct sockaddr_in);
    memset(addr_in_, 0, sizeof(struct sockaddr_in));
    addr_in_->sin_family = AF_INET;
    addr_in_->sin_port = htons(port);
    inet_pton(AF_INET, addr.c_str(), &addr_in_->sin_addr);
    flag = ::bind(sock_fd_, (struct sockaddr*)addr_in_, sizeof(struct sockaddr_in));
    delete addr_ptr;
  }

  if (flag != 0) {
    return false;
  }

  return true;
}

bool Socket::connect(const std::string& addr, uint16_t port) {
  int flag = -1;

  if (domain_ == AF_INET) {
    auto old_addr_ptr = addr_in_;
    addr_in_ = new (struct sockaddr_in);
    memset(addr_in_, 0, sizeof(struct sockaddr_in));
    addr_in_->sin_family = AF_INET;
    addr_in_->sin_port = htons(port);
    inet_pton(AF_INET, addr.c_str(), &addr_in_->sin_addr);
    flag = ::connect(sock_fd_, (struct sockaddr*)addr_in_, sizeof(struct sockaddr_in));
    delete old_addr_ptr;
  }

  if (flag != 0) {
    return false;
  }

  return true;
}

std::pair<std::string, uint16_t> Socket::getpeername() const {
  std::pair<std::string, uint16_t> addr;
  if (domain_ == AF_INET && addr_in_) {
    addr.first.resize(INET_ADDRSTRLEN, 0);
    inet_ntop(AF_INET, &addr_in_->sin_addr, const_cast<char*>(addr.first.data()), INET_ADDRSTRLEN);
    addr.second = ntohs(addr_in_->sin_port);
  }
  auto it = std::find(addr.first.begin(), addr.first.end(), 0);
  addr.first.resize(std::distance(addr.first.begin(), it));
  return addr;
}

bool Socket::listen() const {
  if (!listen(SOMAXCONN, nullptr)) {
    return false;
  }
  return true;
}

ssize_t Socket::read(std::vector<unsigned char>* buffer, size_t max_len) const {
  buffer->resize(max_len);
  return read(buffer->data(), max_len);
}

bool Socket::setsockopt(int level, int optname, int option_value) const {
  if (!setsockopt(level, optname, option_value, nullptr)) {
    return false;
  }
  return true;
}

bool Socket::set_sock_blocking(bool is_block) const {
  if (!set_sock_blocking(is_block, nullptr)) {
    return false;
  }
  return true;
}

ssize_t Socket::write(const std::vector<unsigned char>& buffer) const {
  return write(buffer.data(), buffer.size());
}

ssize_t Socket::recvfrom(std::vector<unsigned char>* buffer, const size_t len,
                         std::pair<std::string, uint16_t>* addr_info, int flags) const {
  buffer->resize(len);
  return recvfrom(buffer->data(), len, addr_info, flags);
}

ssize_t Socket::sendto(const std::vector<unsigned char>& buffer,
                       const std::pair<std::string, uint16_t>& addr_info, int flags) const {
  return sendto(buffer.data(), buffer.size(), addr_info, flags);
}

bool Socket::listen(int backlog, int* error_code) const noexcept {
  int flag = ::listen(sock_fd_, backlog);

  if (error_code)
    *error_code = errno;

  return flag == 0;
}

ssize_t Socket::read(unsigned char* buffer, size_t max_len) const {
  int len = ::read(sock_fd_, buffer, max_len);

  if (len < 0) {
    return false;
  }

  return len;
}

bool Socket::setsockopt(const int level, const int optname, const int option_value,
                        int* error_code) const noexcept {
  int flag = ::setsockopt(sock_fd_, level, optname, &option_value, sizeof(int));
  if (error_code)
    *error_code = errno;

  return flag == 0;
}

bool Socket::set_sock_blocking(const bool is_block, int* error_code) const noexcept {
  int flag = ::fcntl(sock_fd_, F_GETFL, 0);

  if (flag < 0) {
    if (error_code) {
      *error_code = errno;
    }
    return false;
  }

  if (is_block) {
    flag &= ~O_NONBLOCK;
  } else {
    flag |= O_NONBLOCK;
  }

  if (error_code) {
    *error_code = errno;
  }

  if (::fcntl(sock_fd_, F_SETFL, flag) < 0) {
    SysERR("Fail to fcntl sock_fd=%d", sock_fd_);
    return false;
  }

  return true;
}

ssize_t Socket::write(const unsigned char* buffer, size_t len) const {
  int length = ::write(sock_fd_, buffer, len);

  if (length < 0) {
    return -1;
  }

  return length;
}

ssize_t Socket::recvfrom(unsigned char* buffer, size_t len,
                         std::pair<std::string, uint16_t>* addr_info, int flags) const {
  socklen_t addr_len = sizeof(struct sockaddr_un);
  std::vector<unsigned char> addr(addr_len, 0);

  auto ret = ::recvfrom(sock_fd_, buffer, len, flags,
                        reinterpret_cast<struct sockaddr*>(addr.data()), &addr_len);
  if (ret < 0) {
    return -1;
  }

  if (domain_ == AF_INET && addr_len == sizeof(struct sockaddr_in)) {
    auto addr_in = reinterpret_cast<struct sockaddr_in*>(addr.data());
    addr_info->first.resize(INET_ADDRSTRLEN, 0);
    if (!inet_ntop(AF_INET, &addr_in->sin_addr, const_cast<char*>(addr_info->first.data()),
                   INET_ADDRSTRLEN)) {
      return -1;
    }

    addr_info->second = ntohs(addr_in->sin_port);
  } else {
    return -1;
  }

  auto it = std::find(addr_info->first.begin(), addr_info->first.end(), 0);
  addr_info->first.resize(std::distance(addr_info->first.begin(), it));

  return ret;
}

ssize_t Socket::sendto(const unsigned char* buffer, size_t len,
                       const std::pair<std::string, uint16_t>& addr_info, int flags) const {
  int ret = -1;
  if (domain_ == AF_INET) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(addr_info.second);
    if (!inet_pton(AF_INET, addr_info.first.c_str(), &addr.sin_addr)) {
      return -1;
    }

    ret =
        ::sendto(sock_fd_, buffer, len, flags, (struct sockaddr*)&addr, sizeof(struct sockaddr_in));
  }

  if (ret < 0) {
    return -1;
  }

  return ret;
}
