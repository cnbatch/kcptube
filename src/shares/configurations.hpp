#pragma once
#include "share_defines.hpp"

#ifndef _CONFIGURATIONS_HPP_
#define _CONFIGURATIONS_HPP_

std::vector<std::string> parse_running_mode(const std::vector<std::string> &args, user_settings &current_user_settings);
std::vector<std::string> parse_the_rest(const std::vector<std::string> &args, user_settings &current_user_settings);
void parse_custom_input_ip(const std::string &line, user_settings::user_input_address_mapping *mappings_ptr, std::vector<std::string> &error_msg);
std::pair<std::string, std::string> split_address(const std::string &input_address, std::vector<std::string> &error_msg);
void check_settings(user_settings &current_user_settings, std::vector<std::string> &error_msg);
void copy_settings(user_settings &inner, user_settings &outter);
void verify_kcp_settings(user_settings &current_user_settings, std::vector<std::string> &error_msg);
void verify_server_listen_port(user_settings &current_user_settings, std::vector<std::string> &error_msg);
void verify_client_destination(user_settings &current_user_settings, std::vector<std::string> &error_msg);
uint64_t bandwidth_from_string(const std::string &bandwidth, std::vector<std::string> &error_msg);

#endif
