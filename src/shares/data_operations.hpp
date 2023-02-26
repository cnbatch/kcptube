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
void xor_forward(uint8_t *data, size_t data_size);
void xor_forward(std::vector<uint8_t> &data);
void xor_backward(uint8_t *data, size_t data_size);
void xor_backward(std::vector<uint8_t> &data);
void bitwise_not(uint8_t *input_data, size_t length);

#endif	// !__DATA_OPERATIONS_HPP__