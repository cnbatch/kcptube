#pragma once

#include <string>
#include <asio.hpp>

#ifndef _DNS_HELPER_HPP_
#define _DNS_HELPER_HPP_

namespace dns_helper
{
	struct dnstxt_results_t
	{
		std::string host_address;
		asio::ip::address ip_address;
		asio::ip::port_type port_number;
	};

	dnstxt_results_t dns_split_address(const std::string &input_address, std::vector<std::string> &error_msg);

	void save_ddns_result(const std::string &exe_path, asio::ip::address input_address, asio::ip::port_type port_number);

	std::string query_dns_txt(const std::string &fqdn, std::vector<std::string> &error_msg);
}
#endif