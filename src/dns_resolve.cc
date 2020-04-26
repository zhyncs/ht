// Copyright (c) 2020 Yineng Zhang <me@zhyncs.com>

#include "dns_resolve.h"

#include <arpa/inet.h>

#include <algorithm>
#include <random>
#include <regex>
#include <tuple>
#include <utility>

#include "log.h"
#include "util.h"

#define HEADER_ID_POS 0
#define HEADER_FLAG_POS 2
#define HEADER_QDCOUNT_POS 4
#define HEADER_ANCOUNT_POS 6
#define HEADER_QNAME_POS 12

#define HEADER_SIZE 12
#define QCLASS_SIZE 2
#define QTYPE_QCLASS_SIZE 4

#define HEADER_RD 0x0100
#define HEADER_QDCOUNT 0x0001

#define TYPE_A 1
#define TYPE_CNAME 5
#define CLASS_IN 0x0001

#define LABEL_MASK 0x3FFF
#define LABEL_POINTER 0xC0

#define LOCAL_DNS_ADDR "127.0.0.53"
#define LOCAL_DNS_PORT 53
#define DNS_PKT_LIMIT_SIZE 512

std::string DNSResolve::strip(const std::string& str) {
  size_t start = 0;
  size_t end = 0;
  for (const auto& ch : str) {
    if (ch == '.') {
      ++start;
    } else {
      break;
    }
  }
  for (auto rit = str.crbegin(); rit != str.crend(); ++rit) {
    if (*rit == '.') {
      ++end;
    } else {
      break;
    }
  }
  return str.substr(start, str.size() - start - end);
}

std::vector<std::string> DNSResolve::split(const std::string& str, char separator) {
  std::vector<std::string> res;
  size_t start = 0;
  size_t end = 0;
  while (str.find(separator, start) != std::string::npos) {
    end = str.find(separator, start);
    res.emplace_back(str.substr(start, end - start));
    start = end + 1;
  }
  if (start < str.size()) {
    res.emplace_back(str.substr(start, str.size() - start));
  }
  return res;
}

bool DNSResolve::build_address(const std::string& address, std::vector<unsigned char>* res) {
  auto addr = strip(address);
  auto labels = split(addr, '.');
  for (const auto& label : labels) {
    auto len = label.size();
    if (len > 63) {
      ERROR("label_len=%lu > 63", len);
      return false;
    }
    res->emplace_back(static_cast<unsigned char>(len));
    std::copy(label.cbegin(), label.cend(), std::back_inserter(*res));
  }
  res->emplace_back(0);
  return true;
}

void DNSResolve::copy_val_to_vec(uint16_t val, std::vector<unsigned char>* vec, size_t pos) {
  memcpy(vec->data() + pos, reinterpret_cast<unsigned char*>(&val), sizeof(uint16_t));
}

bool DNSResolve::build_request(const std::string& address, std::vector<unsigned char>* request) {
  std::vector<unsigned char> addr;
  if (!build_address(address, &addr)) {
    ERROR("DNSResolve::build_request fail to build_address, address=%s", address.c_str());
    return false;
  }
  request->resize(HEADER_SIZE + addr.size() + QTYPE_QCLASS_SIZE, 0);
  auto request_id = random_id();
  copy_val_to_vec(request_id, request, HEADER_ID_POS);
  copy_val_to_vec(htons(HEADER_RD), request, HEADER_FLAG_POS);
  copy_val_to_vec(htons(HEADER_QDCOUNT), request, HEADER_QDCOUNT_POS);
  std::copy(addr.cbegin(), addr.cend(), request->begin() + HEADER_QNAME_POS);
  copy_val_to_vec(htons(TYPE_A), request, request->size() - QTYPE_QCLASS_SIZE);
  copy_val_to_vec(htons(CLASS_IN), request, request->size() - QCLASS_SIZE);
  return true;
}

std::pair<size_t, std::string> DNSResolve::parse_name(const std::vector<unsigned char>& data,
                                                      size_t offset) {
  size_t pos = offset;
  std::string labels;
  unsigned char len = data[pos];
  while (len > 0) {
    if ((len & LABEL_POINTER) == LABEL_POINTER) {
      uint16_t pointer = ntohs(copy_vec_to_val<uint16_t>(data, pos));
      pointer &= LABEL_MASK;
      auto ret = parse_name(data, pointer);
      labels.insert(labels.end(), ret.second.cbegin(), ret.second.cend());
      pos += 2;
      return std::make_pair(pos - offset, labels);
    } else {
      labels.insert(std::end(labels), data.cbegin() + pos + 1, data.cbegin() + pos + 1 + len);
      labels.push_back('.');
      pos += len + 1;
    }
    len = data[pos];
  }
  if (!labels.empty()) {
    labels.pop_back();
  }
  return std::make_pair(pos - offset + 1, labels);
}

std::string DNSResolve::parse_ip(const std::vector<unsigned char>& data, uint16_t addr_type,
                                 size_t offset) {
  std::string res;
  if (addr_type == TYPE_A) {
    struct in_addr addr;
    memset(&addr, 0, sizeof(in_addr));
    addr.s_addr = copy_vec_to_val<unsigned int>(data, offset);
    std::string ip_str(INET_ADDRSTRLEN, 0);
    if (!inet_ntop(AF_INET, &addr, const_cast<char*>(ip_str.data()), INET_ADDRSTRLEN)) {
      SysERR("DNSResolve::parse_ip fail to inet_ntop");
      ip_str.clear();
    }
    auto it = std::find(ip_str.begin(), ip_str.end(), 0);
    ip_str.resize(static_cast<size_t>(std::distance(ip_str.begin(), it)));
    return ip_str;
  } else if (addr_type == TYPE_CNAME) {
    return parse_name(data, offset).second;
  } else {
    return res;
  }
}

struct Record {
  size_t len_ = 0;
  std::string hostname_;
  std::string addr_;
  uint16_t type_ = 0;
  uint16_t class_ = 0;
};

void DNSResolve::parse_record(const std::vector<unsigned char>& data, size_t offset, Record* res,
                              bool question) {
  auto len_name = parse_name(data, offset);
  if (!question) {
    res->hostname_ = len_name.second;
    res->type_ = ntohs(copy_vec_to_val<uint16_t>(data, offset + len_name.first));
    res->class_ = ntohs(copy_vec_to_val<uint16_t>(data, offset + len_name.first + 2));
    auto rd_len = ntohs(copy_vec_to_val<uint16_t>(data, offset + len_name.first + 8));
    res->addr_ = parse_ip(data, res->type_, offset + len_name.first + 10);
    res->len_ = len_name.first + 10 + rd_len;
  } else {
    res->len_ = len_name.first + 4;
    res->hostname_ = len_name.second;
  }
}

struct DNSResponse {
  std::string hostname_;
  std::vector<std::tuple<std::string, uint16_t, uint16_t>> answers_;
  explicit operator bool() const { return !hostname_.empty(); }
};

DNSResponse DNSResolve::parse_response(const std::vector<unsigned char>& data) {
  DNSResponse response;
  if (data.size() >= HEADER_SIZE) {
    Record ret;
    size_t offset = HEADER_SIZE;
    for (int i = 0; i < ntohs(copy_vec_to_val<uint16_t>(data, HEADER_QDCOUNT_POS)); ++i) {
      parse_record(data, offset, &ret, true);
      offset += ret.len_;
      if (i == 0) {
        response.hostname_ = ret.hostname_;
      }
    }
    for (int i = 0; i < ntohs(copy_vec_to_val<uint16_t>(data, HEADER_ANCOUNT_POS)); ++i) {
      parse_record(data, offset, &ret, false);
      offset += ret.len_;
      response.answers_.emplace_back(std::make_tuple(ret.addr_, ret.type_, ret.class_));
    }
  }
  return response;
}

bool DNSResolve::is_valid_hostname(const std::string& hostname) {
  if (hostname.size() > 255) {
    ERROR("hostname size=%lu > 255", hostname.size());
    return false;
  }
  std::vector<std::string> labels = split(hostname, '.');
  std::regex pattern("(?!-)[-[:alnum:]]{1,63}$");
  for (const auto& label : labels) {
    if (label.back() == '-') {
      return false;
    }
    if (!std::regex_match(label, pattern)) {
      return false;
    }
  }
  return true;
}

DNSResolve::DNSResolve() : cache_(300) {}

DNSResolve::~DNSResolve() { destroy(); }

bool DNSResolve::add_to_loop(const std::shared_ptr<EventLoop>& loop) {
  if (loop_) {
    return false;
  }
  loop_ = loop;
  sock_ = Socket(AF_INET, SOCK_DGRAM, 0);
  sock_.set_sock_blocking(false);
  loop_->add(sock_.get_sock_fd(), EPOLLIN, this);
  loop_->add_periodic(this);

  return true;
}


void DNSResolve::call_handler(const std::string& hostname, const std::string& ip,
                              const std::string& error) {
  auto hds_it = hostname_to_handlers_.find(hostname);
  if (hds_it != hostname_to_handlers_.end()) {
    for (auto& hd : hds_it->second) {
      auto it = handler_to_hostname_.find(hd);
      if (it != handler_to_hostname_.end()) {
        handler_to_hostname_.erase(it);
      }
      if (!ip.empty() || !error.empty()) {
        hd->handle_dns_resolved(hostname, ip, error);
      } else {
        hd->handle_dns_resolved(hostname, "", "Unknown hostname=" + hostname);
      }
    }
    hostname_to_handlers_.erase(hds_it);
  }
}

void DNSResolve::handle_data(const std::vector<unsigned char>& data) {
  auto response = parse_response(data);
  if (response) {
    auto hostname = response.hostname_;
    std::string ip;
    for (const auto& answer : response.answers_) {
      if (std::get<1>(answer) == TYPE_A && std::get<2>(answer) == CLASS_IN) {
        ip = std::get<0>(answer);
        break;
      }
    }
    if (!ip.empty()) {
      cache_.set(hostname, ip);
      call_handler(hostname, ip);
    }
  }
}

bool DNSResolve::handle_event(int fd, unsigned int event) {
  if (fd != sock_.get_sock_fd()) {
    return false;
  }
  if (event & EPOLLERR) {
    SysERR("DNSResolve::handle_event event EPOLLERR fd=%d", fd);
    Socket new_sock(PF_INET, SOCK_DGRAM, 0);

    if (!new_sock.set_sock_blocking(false)) {
      return false;
      if (errno == EMFILE || errno == ENFILE) {
        exit(EXIT_FAILURE);
      }
    }
    if (!loop_->add(new_sock.get_sock_fd(), EPOLLIN, this)) {
      return false;
      if (errno == EMFILE || errno == ENFILE) {
        exit(EXIT_FAILURE);
      }
    }

    loop_->del(fd);
    sock_ = new_sock;
  } else {
    std::vector<unsigned char> data;
    std::pair<std::string, uint16_t> addr;
    auto ret = sock_.recvfrom(&data, DNS_PKT_LIMIT_SIZE, &addr);
    data.resize(ret);
    handle_data(data);
  }

  return true;
}

void DNSResolve::handle_periodic() { cache_.sweep(); }

void DNSResolve::remove_handler(DNSResolveHandler* handler) {
  auto it = handler_to_hostname_.find(handler);
  if (it != handler_to_hostname_.end()) {
    auto hostname = it->second;
    handler_to_hostname_.erase(it);
    auto iter = hostname_to_handlers_.find(hostname);
    if (iter != hostname_to_handlers_.end()) {
      auto call_back_it = std::find(iter->second.begin(), iter->second.end(), handler);
      if (call_back_it != iter->second.end()) {
        iter->second.erase(call_back_it);
      }
      if (iter->second.empty()) {
        hostname_to_handlers_.erase(iter);
      }
    }
  }
}

bool DNSResolve::send_req(const std::string& hostname) {
  std::vector<unsigned char> req;
  if (!build_request(hostname, &req)) {
    return false;
  }
  if (sock_.sendto(req, std::make_pair(LOCAL_DNS_ADDR, LOCAL_DNS_PORT)) == -1) {
    SysERR("DNSResolve::send_req fail to sendto");
    return false;
  }
  return true;
}

bool DNSResolve::resolve(const std::string& hostname, DNSResolveHandler* handler) {
  if (is_ip(hostname) == AF_INET) {
    handler->handle_dns_resolved(hostname, hostname, "");
  } else if (cache_.contains(hostname)) {
    INFO("Hit cache, hostname=%s", hostname.c_str());
    auto ip = cache_.get(hostname);
    handler->handle_dns_resolved(hostname, ip, "");
  } else {
    if (!is_valid_hostname(hostname)) {
      handler->handle_dns_resolved("", "", "Invalid hostname=" + hostname);
      return false;
    }
    auto it = handler_to_hostname_.find(handler);
    if (it != handler_to_hostname_.end()) {
      ERROR("The handler already called DNSResolve::resolve");
      return false;
    }
    handler_to_hostname_[handler] = hostname;
    auto iter = hostname_to_handlers_.find(hostname);
    if (iter == hostname_to_handlers_.end()) {
      send_req(hostname);
      hostname_to_handlers_[hostname].emplace_back(handler);
    } else {
      iter->second.emplace_back(handler);
      send_req(hostname);
    }
  }

  return true;
}

int DNSResolve::is_ip(const std::string& addr) {
  std::vector<unsigned char> buf(sizeof(struct in_addr));
  if (inet_pton(AF_INET, addr.c_str(), buf.data())) {
    return AF_INET;
  } else {
    return -1;
  }
}

uint16_t DNSResolve::random_id() {
  std::random_device r;
  std::default_random_engine e(r());
  std::uniform_int_distribution<uint16_t> uniform_dist(0, static_cast<uint16_t>(exp2(2 * 8) - 1));
  return uniform_dist(e);
}

void DNSResolve::destroy() {
  if (loop_) {
    loop_->del_periodic(this);
    loop_->del(sock_.get_sock_fd());
  }
}
