// Copyright (c) 2020 Yineng Zhang <me@zhyncs.com>

#pragma once

#include <algorithm>
#include <string>
#include <vector>

template <typename T>
static T copy_vec_to_val(const std::vector<unsigned char>& vec, size_t pos) {
  union {
    T first;
    unsigned char second[sizeof(T)];
  } array;
  memset(&array, 0, sizeof(T));
  std::copy(vec.begin() + pos, vec.begin() + pos + sizeof(T), array.second);
  return array.first;
}
