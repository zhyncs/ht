// Copyright (c) 2020 Yineng Zhang <me@zhyncs.com>

#include "tcp_relay.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <ctime>
#include <tuple>
#include <utility>
#include <vector>

#include "log.h"
#include "util.h"

#define TIMEOUTS_CLEAN_SIZE 512

#define STAGE_INIT 0
#define STAGE_DNS 1
#define STAGE_CONNECTING 2
#define STAGE_STREAM 3
#define STAGE_DESTROYED -1

#define STREAM_UP 0
#define STREAM_DOWN 1

#define WAIT_READ 1
#define WAIT_WRITE 2
#define WAIT_READ_WRITE (WAIT_READ | WAIT_WRITE)

#define BUF_SIZE (32 * 1024)

#define TIMEOUT 3600
#define TIMEOUT_PRECISION 10

#define ATYP_IPv4 0x01
#define ATYP_HOST 0x03
#define ATYP_MASK 0xF

#define SERVER_PORT 443

class TCPRelayHandler : public DNSResolveHandler {
 public:
  TCPRelayHandler(TCPRelay* server, const Socket& local_sock, const std::string& password);
  TCPRelayHandler(const TCPRelayHandler& handler) = delete;
  TCPRelayHandler& operator=(const TCPRelayHandler& handler) = delete;
  ~TCPRelayHandler() override;

  time_t last_activity = 0;
  std::pair<std::string, uint16_t> client_address_;
  std::pair<std::string, uint16_t> remote_address_;

  bool handle_dns_resolved(const std::string& hostname, const std::string& ip,
                           const std::string& error) override;
  bool handle_event(int fd, unsigned int events);
  std::pair<int, int> get_sockets() const;

 private:
  TCPRelay* server_ = nullptr;
  Crypto crypto_;
  Socket local_sock_;
  Socket remote_sock_;
  int stage_ = STAGE_INIT;
  std::vector<unsigned char> data_to_write_to_local_;
  std::vector<unsigned char> data_to_write_to_remote_;
  int upstream_status_ = 1;
  int downstream_status_ = 0;

  void update_stream(int stream, int status);
  bool write_to_sock(const std::vector<unsigned char>& data, const Socket& sock);
  bool handle_stage_addr(const std::vector<unsigned char>& data);
  Socket create_remote_sock();
  bool on_local_read();
  bool on_remote_read();
  bool on_local_write();
  bool on_remote_write();
  void destroy();

  static std::tuple<unsigned char, std::string, uint16_t, size_t> parse_header(
      const std::vector<unsigned char>& data);
};

TCPRelayHandler::TCPRelayHandler(TCPRelay* server, const Socket& local_sock,
                                 const std::string& password)
    : crypto_(password.c_str()) {
  server_ = server;
  local_sock_ = local_sock;
  client_address_ = local_sock.getpeername();
  local_sock_.set_sock_blocking(false);
  local_sock_.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1);
  server->event_loop_->add(local_sock.get_sock_fd(), EPOLLIN | EPOLLRDHUP, server);
  server->update_activity(this);
}

TCPRelayHandler::~TCPRelayHandler() { destroy(); }

std::pair<int, int> TCPRelayHandler::get_sockets() const {
  return std::make_pair(local_sock_.get_sock_fd(), remote_sock_.get_sock_fd());
}

void TCPRelayHandler::update_stream(int stream, int status) {
  bool dirty = false;
  if (stream == STREAM_DOWN) {
    if (downstream_status_ != status) {
      downstream_status_ = status;
      dirty = true;
    }
  } else if (stream == STREAM_UP) {
    if (upstream_status_ != status) {
      upstream_status_ = status;
      dirty = true;
    }
  }
  if (!dirty)
    return;

  if (local_sock_) {
    unsigned int event = EPOLLERR | EPOLLRDHUP;

    if (downstream_status_ & WAIT_WRITE)
      event |= EPOLLOUT;

    if (upstream_status_ & WAIT_READ)
      event |= EPOLLIN;

    server_->event_loop_->mod(local_sock_.get_sock_fd(), event);
  }

  if (remote_sock_) {
    unsigned int event = EPOLLERR | EPOLLRDHUP;

    if (downstream_status_ & WAIT_READ)
      event |= EPOLLIN;

    if (upstream_status_ & WAIT_WRITE)
      event |= EPOLLOUT;

    server_->event_loop_->mod(remote_sock_.get_sock_fd(), event);
  }
}

bool TCPRelayHandler::write_to_sock(const std::vector<unsigned char>& data, const Socket& sock) {
  if (data.empty() || !sock)
    return false;

  bool uncomplete = false;

  auto len = data.size();
  size_t write_len = 0;

  write_len = sock.write(data);
  if (write_len < len) {
    uncomplete = true;
  }
  if (write_len == -1) {
    if (errno == EAGAIN || errno == EINPROGRESS || errno == EWOULDBLOCK) {
      uncomplete = true;
      write_len = 0;
    } else {
      destroy();
      return false;
    }
  }

  if (uncomplete) {
    if (sock == local_sock_) {
      std::copy(data.begin() + write_len, data.end(), std::back_inserter(data_to_write_to_local_));
      update_stream(STREAM_DOWN, WAIT_WRITE);
    } else if (sock == remote_sock_) {
      std::copy(data.begin() + write_len, data.end(), std::back_inserter(data_to_write_to_remote_));
      update_stream(STREAM_UP, WAIT_WRITE);
    } else {
      ERROR("write_to_sock unknown sock_fd=%d", sock.get_sock_fd());
    }
  } else {
    if (sock == local_sock_) {
      update_stream(STREAM_DOWN, WAIT_READ);
    } else if (sock == remote_sock_) {
      update_stream(STREAM_UP, WAIT_READ);
    } else {
      ERROR("write_to_sock unknown sock_fd=%d", sock.get_sock_fd());
    }
  }

  return true;
}

bool TCPRelayHandler::handle_stage_addr(const std::vector<unsigned char>& data) {
  auto header_result = parse_header(data);
  if (std::get<1>(header_result).empty()) {
    return false;
  }

  auto remote_addr = std::get<1>(header_result);
  auto remote_port = std::get<2>(header_result);
  auto header_length = std::get<3>(header_result);

  INFO("Connecting %s:%d from %s:%d", remote_addr.c_str(), remote_port,
       client_address_.first.c_str(), client_address_.second);
  remote_address_ = std::make_pair(remote_addr, remote_port);

  update_stream(STREAM_UP, WAIT_WRITE);
  stage_ = STAGE_DNS;
  std::copy(data.begin() + header_length, data.end(), std::back_inserter(data_to_write_to_remote_));
  server_->dns_resolve_->resolve(remote_addr, this);

  return true;
}

Socket TCPRelayHandler::create_remote_sock() {
  Socket remote_sock = Socket(PF_INET, SOCK_STREAM, 0);
  auto hd = server_->fd_to_handlers_.find(local_sock_.get_sock_fd());
  server_->fd_to_handlers_[remote_sock.get_sock_fd()] = hd->second;
  remote_sock.set_sock_blocking(false);
  remote_sock.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1);
  return remote_sock;
}

bool TCPRelayHandler::handle_dns_resolved(const std::string& hostname, const std::string& ip,
                                          const std::string& error) {
  if (!error.empty()) {
    ERROR("%s when handling connection from %s:%d", error.c_str(), client_address_.first.c_str(),
          client_address_.second);
    destroy();
    return false;
  }
  if (hostname.empty() || ip.empty()) {
    ERROR("hostname empty or ip empty");
    destroy();
    return false;
  }

  INFO("Connected %s(%s):%d from %s:%d", remote_address_.first.c_str(), ip.c_str(),
       remote_address_.second, client_address_.first.c_str(), client_address_.second);

  remote_address_.first = ip;
  remote_sock_ = create_remote_sock();
  server_->event_loop_->add(remote_sock_.get_sock_fd(), EPOLLOUT | EPOLLRDHUP, server_);

  if (!remote_sock_.connect(remote_address_.first, remote_address_.second)) {
    if (errno == EINPROGRESS) {
    } else {
      destroy();
      return false;
    }
  }

  stage_ = STAGE_CONNECTING;
  update_stream(STREAM_UP, WAIT_READ_WRITE);
  update_stream(STREAM_DOWN, WAIT_READ);

  return true;
}

bool TCPRelayHandler::on_local_read() {
  if (!local_sock_)
    return false;

  std::vector<unsigned char> data;
  int buf_size = BUF_SIZE;
  size_t ret_len = 0;

  if ((ret_len = local_sock_.read(&data, buf_size)) == -1) {
    if (errno == ETIMEDOUT || errno == EAGAIN || errno == EWOULDBLOCK) {
      return false;
    } else {
      destroy();
      return false;
    }
  }

  if (ret_len == 0) {
    destroy();
    return false;
  }

  server_->update_activity(this);

  std::vector<unsigned char> decrypt_data;

  if (!crypto_.decrypt(data.data(), ret_len, &decrypt_data)) {
    destroy();
    return false;
  }

  if (decrypt_data.empty()) {
    return false;
  }

  if (stage_ == STAGE_STREAM) {
    write_to_sock(decrypt_data, remote_sock_);
  } else if (stage_ == STAGE_CONNECTING) {
    std::copy(decrypt_data.begin(), decrypt_data.end(),
              std::back_inserter(data_to_write_to_remote_));
  } else if (stage_ == STAGE_INIT) {
    handle_stage_addr(decrypt_data);
  }

  return true;
}

bool TCPRelayHandler::on_remote_read() {
  std::vector<unsigned char> data;
  int buf_size = BUF_SIZE;
  size_t ret_len = 0;

  if ((ret_len = remote_sock_.read(&data, buf_size)) == -1) {
    if (errno == ETIMEDOUT || errno == EAGAIN || errno == EWOULDBLOCK) {
      return false;
    } else {
      destroy();
      return false;
    }
  }

  if (ret_len == 0) {
    destroy();
    return false;
  }

  server_->update_activity(this);

  std::vector<unsigned char> encrypt_data;
  if (!crypto_.encrypt(data.data(), ret_len, &encrypt_data)) {
    destroy();
    return false;
  }
  if (!write_to_sock(encrypt_data, local_sock_)) {
    destroy();
    return false;
  }


  return true;
}

bool TCPRelayHandler::on_local_write() {
  if (!data_to_write_to_local_.empty()) {
    auto data = std::move(data_to_write_to_local_);
    data_to_write_to_local_.clear();
    write_to_sock(data, local_sock_);
  } else {
    update_stream(STREAM_DOWN, WAIT_READ);
  }

  return true;
}

bool TCPRelayHandler::on_remote_write() {
  stage_ = STAGE_STREAM;
  if (!data_to_write_to_remote_.empty()) {
    auto data = std::move(data_to_write_to_remote_);
    data_to_write_to_remote_.clear();
    write_to_sock(data, remote_sock_);
  } else {
    update_stream(STREAM_UP, WAIT_READ);
  }

  return true;
}

bool TCPRelayHandler::handle_event(const int fd, const unsigned int events) {
  if (stage_ == STAGE_DESTROYED) {
    ERROR("Ignore handle_event stage=STAGE_DESTROYED");
    return false;
  }
  if (fd == remote_sock_.get_sock_fd()) {
    if (events & EPOLLERR) {
      INFO("handle_event remote error remote_sock_fd=%d", remote_sock_.get_sock_fd());
      destroy();
      return false;
    }

    if (events & (EPOLLIN | EPOLLHUP)) {
      if (!on_remote_read()) {
        destroy();
        return false;
      }
      if (stage_ == STAGE_DESTROYED)
        return false;
    }

    if (events & EPOLLRDHUP) {
      INFO("Closed by remote");
      destroy();
      return false;
    }

    if (events & EPOLLOUT) {
      if (!on_remote_write()) {
        destroy();
        return false;
      }
    }

  } else if (fd == local_sock_.get_sock_fd()) {
    if (events & EPOLLERR) {
      INFO("handle_event local error local_sock_fd=%d", local_sock_.get_sock_fd());
      destroy();
      return false;
    }

    if (events & (EPOLLIN | EPOLLHUP)) {
      if (!on_local_read()) {
        destroy();
        return false;
      }
      if (stage_ == STAGE_DESTROYED)
        return false;
    }

    if (events & EPOLLRDHUP) {
      INFO("Closed by local");
      destroy();
      return false;
    }

    if (events & EPOLLOUT) {
      if (!on_local_write()) {
        destroy();
        return false;
      }
    }
  } else {
    ERROR("Unknown sock_fd=%d local_sock_fd=%d remote_sock_fd=%d", fd, local_sock_.get_sock_fd(),
          remote_sock_.get_sock_fd());
    server_->event_loop_->del(fd);
    close(fd);
    auto it = server_->fd_to_handlers_.find(fd);
    if (it != server_->fd_to_handlers_.end()) {
      server_->fd_to_handlers_.erase(it);
    }
    destroy();
  }

  return true;
}

void TCPRelayHandler::destroy() {
  if (stage_ == STAGE_DESTROYED) {
    return;
  }

  stage_ = STAGE_DESTROYED;
  server_->dns_resolve_->remove_handler(this);
  server_->remove_handler(this);

  if (!remote_address_.first.empty()) {
    INFO("Destroy %s:%d", remote_address_.first.c_str(), remote_address_.second);
  }
  if (local_sock_) {
    INFO("Destroy local_sock_fd=%d", local_sock_.get_sock_fd());
    if (!server_->event_loop_->del(local_sock_.get_sock_fd())) {
      SysERR("event loop fail to del local_sock_fd=%d", local_sock_.get_sock_fd());
    }

    auto it_local = server_->fd_to_handlers_.find(local_sock_.get_sock_fd());
    if (it_local != server_->fd_to_handlers_.end()) {
      server_->fd_to_handlers_.erase(it_local);
    }
  }
  if (remote_sock_) {
    INFO("Destroy remote_sock_fd=%d", remote_sock_.get_sock_fd());
    if (!server_->event_loop_->del(remote_sock_.get_sock_fd())) {
      SysERR("event loop fail to del remote_sock_fd=%d", remote_sock_.get_sock_fd());
    }

    auto it_remote = server_->fd_to_handlers_.find(remote_sock_.get_sock_fd());
    if (it_remote != server_->fd_to_handlers_.end())
      server_->fd_to_handlers_.erase(it_remote);
  }
}

TCPRelay::TCPRelay(const std::shared_ptr<DNSResolve>& dns_resolver, const char* password) {
  dns_resolve_ = dns_resolver;
  std::string listen_addr = "0.0.0.0";
  server_sock_ = Socket(PF_INET, SOCK_STREAM, 0);
  server_sock_.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1);
  if (!server_sock_.bind(listen_addr, SERVER_PORT)) {
    SysERR("Fail to bind %s:%d", listen_addr.c_str(), SERVER_PORT);
    exit(EXIT_FAILURE);
  }
  server_sock_.set_sock_blocking(false);
  server_sock_.listen();
  password_ = std::string(password);
}

TCPRelay::~TCPRelay() { destroy(); }

void TCPRelay::add_to_loop(const std::shared_ptr<EventLoop>& loop) {
  if (event_loop_) {
    ERROR("Already added to loop");
    return;
  }

  event_loop_ = loop;
  event_loop_->add(server_sock_.get_sock_fd(), EPOLLIN, this);
  event_loop_->add_periodic(this);
}

void TCPRelay::remove_handler(TCPRelayHandler* handler) {
  auto it = handler_to_timeouts_.find(handler);
  if (it != handler_to_timeouts_.end()) {
    timeouts_[it->second] = nullptr;
    handler_to_timeouts_.erase(it);
  }
}

void TCPRelay::handle_periodic() { sweep_timeout(); }

void TCPRelay::update_activity(TCPRelayHandler* handler) {
  auto now = time(nullptr);
  if (now - handler->last_activity < TIMEOUT_PRECISION) {
    return;
  }

  handler->last_activity = now;

  auto it = handler_to_timeouts_.find(handler);
  if (it != handler_to_timeouts_.end()) {
    timeouts_[it->second] = nullptr;
  }

  auto length = timeouts_.size();
  timeouts_.push_back(handler);
  handler_to_timeouts_[handler] = length;
}

void TCPRelay::sweep_timeout() {
  if (!timeouts_.empty()) {
    INFO("Sweep timeouts");
    auto now = time(nullptr);
    auto length = timeouts_.size();
    auto pos = timeout_offset_;
    while (pos < length) {
      auto handler = timeouts_[pos];
      if (handler) {
        if (now - handler->last_activity < TIMEOUT) {
          break;
        } else {
          if (!handler->remote_address_.first.empty()) {
            ERROR("Timeout %s:%d", handler->remote_address_.first.c_str(),
                  handler->remote_address_.second);
          } else {
            ERROR("Timeout");
          }

          auto sockets = handler->get_sockets();

          auto it_local = fd_to_handlers_.find(sockets.first);
          if (it_local != fd_to_handlers_.end())
            fd_to_handlers_.erase(it_local);

          auto it_remote = fd_to_handlers_.find(sockets.second);
          if (it_remote != fd_to_handlers_.end()) {
            fd_to_handlers_.erase(it_remote);
          }

          timeouts_[pos] = nullptr;
          pos += 1;
        }
      } else {
        pos += 1;
      }
    }
    if (pos > TIMEOUTS_CLEAN_SIZE && pos > length >> 1) {
      std::copy(timeouts_.begin() + pos, timeouts_.end(), timeouts_.begin());
      timeouts_.resize(timeouts_.size() - pos);

      for (auto& handler_to_timeout : handler_to_timeouts_) {
        handler_to_timeout.second -= pos;
      }
      pos = 0;
    }

    timeout_offset_ = pos;
  }
}

bool TCPRelay::handle_event(int socket_fd, unsigned int events) {
  if (socket_fd == server_sock_.get_sock_fd()) {
    if (events & EPOLLERR) {
      bool ret = false;
      ret = event_loop_->del(server_sock_.get_sock_fd());
      ret = close(server_sock_.get_sock_fd());
      std::string listen_addr = "0.0.0.0";
      server_sock_ = Socket(PF_INET, SOCK_STREAM, 0);
      ret = server_sock_.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1);
      ret = server_sock_.bind(listen_addr, SERVER_PORT);
      ret = server_sock_.set_sock_blocking(false);
      ret = server_sock_.listen();
      if (!ret) {
        ERROR("Server sock_fd=%d error", socket_fd);
        exit(EXIT_FAILURE);
      }

      return false;
    }

    auto socket = server_sock_.accept();
    auto handler = std::make_shared<TCPRelayHandler>(this, socket, password_);
    fd_to_handlers_[socket.get_sock_fd()] = handler;
    if (!socket || !handler) {
      if (errno == EAGAIN || errno == EINPROGRESS || errno == EWOULDBLOCK) {
        return false;
      } else {
        ERROR("server_sock_fd=%d error", server_sock_.get_sock_fd());
      }
    }


  } else {
    auto it = fd_to_handlers_.find(socket_fd);
    if (it != fd_to_handlers_.end()) {
      it->second->handle_event(socket_fd, events);
    } else {
      ERROR("Poll removed fd=%d", socket_fd);
    }
  }

  return true;
}

void TCPRelay::destroy() {
  if (event_loop_) {
    event_loop_->del_periodic(this);
    event_loop_->del(server_sock_.get_sock_fd());
  }
}

std::tuple<unsigned char, std::string, uint16_t, size_t> TCPRelayHandler::parse_header(
    const std::vector<unsigned char>& data) {
  unsigned char addr_type = data[0];
  std::string dst_addr;
  uint16_t dst_port = 0;
  size_t len = 0;
  if ((addr_type & ATYP_MASK) == ATYP_IPv4) {
    if (data.size() >= 7) {
      struct in_addr addr;
      memset(&addr, 0, sizeof(in_addr));
      addr.s_addr = copy_vec_to_val<unsigned int>(data, 1);
      dst_addr.resize(INET_ADDRSTRLEN, 0);
      if (!inet_ntop(AF_INET, &addr, const_cast<char*>(dst_addr.data()), INET_ADDRSTRLEN)) {
        dst_addr.clear();
      }
      auto it = std::find(dst_addr.begin(), dst_addr.end(), 0);
      dst_addr.resize(static_cast<uint64_t>(std::distance(dst_addr.begin(), it)));
      dst_port = ntohs(copy_vec_to_val<uint16_t>(data, 5));
      len = 7;
    }
  } else if ((addr_type & ATYP_MASK) == ATYP_HOST) {
    if (data.size() >= 5) {
      unsigned int addr_len = data[1];
      if (data.size() >= 4 + addr_len) {
        dst_addr.resize(addr_len);
        std::copy(data.begin() + 2, data.begin() + 2 + addr_len, dst_addr.begin());
        dst_port = ntohs(copy_vec_to_val<uint16_t>(data, 2 + addr_len));
        len = 4 + addr_len;
      }
    }
  }
  return std::make_tuple(addr_type, dst_addr, dst_port, len);
}
