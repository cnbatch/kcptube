#pragma once
#include "share_defines.hpp"

#ifndef __DATA_OPERATIONS_HPP__
#define __DATA_OPERATIONS_HPP__

std::vector<uint8_t> create_raw_random_data(size_t mtu_size);
std::pair<std::string, size_t> encrypt_data(const std::string &password, encryption_mode mode, uint8_t *data_ptr, int length);
std::vector<uint8_t> encrypt_data(const std::string &password, encryption_mode mode, const void *data_ptr, int length, std::string &error_message);
std::vector<uint8_t> encrypt_data(const std::string &password, encryption_mode mode, std::vector<uint8_t> &&plain_data, std::string &error_message);
std::pair<std::string, size_t> decrypt_data(const std::string &password, encryption_mode mode, uint8_t *data_ptr, int length);
std::vector<uint8_t> decrypt_data(const std::string &password, encryption_mode mode, const void *data_ptr, int length, std::string &error_message);
std::vector<uint8_t> decrypt_data(const std::string &password, encryption_mode mode, std::vector<uint8_t> &&cipher_data, std::string &error_message);
void bitwise_not(uint8_t *input_data, size_t length);
std::pair<std::unique_ptr<uint8_t[]>, size_t> clone_into_pair(const uint8_t *original, size_t data_size);
const std::map<size_t, const uint8_t*> mapped_pair_to_mapped_pointer(const std::map<size_t, std::pair<std::unique_ptr<uint8_t[]>, size_t>> &mapped_container);
std::tuple<std::unique_ptr<uint8_t[]>, size_t, size_t> compact_into_container(const std::vector<std::pair<std::unique_ptr<uint8_t[]>, size_t>> &fec_snd_data_cache);
std::pair<std::map<size_t, std::pair<std::unique_ptr<uint8_t[]>, size_t>>, size_t> compact_into_container(const std::map<uint16_t, std::pair<std::unique_ptr<uint8_t[]>, size_t>> &fec_rcv_data_cache, size_t data_max_count);
std::vector<std::vector<uint8_t>> extract_from_container(const std::vector<std::vector<uint8_t>> &recovered_container);
std::vector<uint8_t> copy_from_container(const std::vector<uint8_t> &recovered_container);
std::pair<uint8_t*, size_t> extract_from_container(const std::vector<uint8_t> &recovered_container);

#endif	// !__DATA_OPERATIONS_HPP__