#include <algorithm>
#include <bit>
#include <chrono>
#include <memory>
#include <limits>
#include <random>
#include <thread>
#include "connections.hpp"

using namespace std::chrono;
using namespace std::literals;

void empty_tcp_callback(std::unique_ptr<uint8_t[]> tmp1, size_t tmps, std::shared_ptr<tcp_session> tmp2)
{
}

void empty_udp_server_callback(std::unique_ptr<uint8_t[]> tmp1, size_t tmps, udp::endpoint tmp2, udp_server *tmp3)
{
}

void empty_udp_client_callback(std::unique_ptr<uint8_t[]> tmp1, size_t tmps, udp::endpoint tmp2, asio::ip::port_type tmp3)
{
}

void empty_tcp_disconnect(std::shared_ptr<tcp_session> tmp)
{
}

int empty_kcp_output(const char *, int, void *)
{
	return 0;
}

void empty_kcp_postupdate(void *)
{
}

void empty_task_callback(std::unique_ptr<uint8_t[]> null_data)
{
}


std::unique_ptr<rfc3489::stun_header> send_stun_3489_request(udp_server &sender, const std::string &stun_host, ip_only_options ip_version_only)
{
	auto udp_version = ip_version_only == ip_only_options::ipv4 ? udp::v4() : udp::v6();
	udp::resolver::resolver_base::flags input_flags = udp::resolver::numeric_service | udp::resolver::v4_mapped | udp::resolver::all_matching;
	if (ip_version_only != ip_only_options::not_set)
		input_flags = udp::resolver::numeric_service | udp::resolver::address_configured;

	asio::error_code ec;
	udp::resolver &udp_resolver = sender.get_resolver();
	udp::resolver::results_type remote_addresses = udp_resolver.resolve(udp_version, stun_host, "3478", input_flags, ec);

	if (ec)
		return nullptr;

	std::vector<udp::endpoint> stun_servers;
	auto [stun_servers_ipv4, stun_servers_ipv6] = split_resolved_addresses(remote_addresses);
	if (!stun_servers_ipv4.empty())
		stun_servers.emplace_back(stun_servers_ipv4.front());
	if (!stun_servers_ipv6.empty())
		stun_servers.emplace_back(stun_servers_ipv4.front());

	auto number = generate_random_number<uint64_t>();
	std::unique_ptr<rfc3489::stun_header> header = rfc3489::create_stun_header(number);
	size_t header_size = sizeof(rfc3489::stun_header);
	for (auto &target_endpoint : stun_servers)
	{
		std::vector<uint8_t> data(header_size);
		std::copy_n((uint8_t *)(header.get()), header_size, data.begin());
		sender.async_send_out(std::move(data), target_endpoint);
	}

	return header;
}

std::unique_ptr<rfc8489::stun_header> send_stun_8489_request(udp_server &sender, const std::string &stun_host, ip_only_options ip_version_only)
{
	auto udp_version = ip_version_only == ip_only_options::ipv4 ? udp::v4() : udp::v6();
	udp::resolver::resolver_base::flags input_flags = udp::resolver::numeric_service | udp::resolver::v4_mapped | udp::resolver::all_matching;
	if (ip_version_only != ip_only_options::not_set)
		input_flags = udp::resolver::numeric_service | udp::resolver::address_configured;

	asio::error_code ec;
	udp::resolver &udp_resolver = sender.get_resolver();
	udp::resolver::results_type remote_addresses = udp_resolver.resolve(udp_version, stun_host, "3478", input_flags, ec);

	if (ec)
		return nullptr;

	std::vector<udp::endpoint> stun_servers;
	auto [stun_servers_ipv4, stun_servers_ipv6] = split_resolved_addresses(remote_addresses);
	if (!stun_servers_ipv4.empty())
		stun_servers.emplace_back(stun_servers_ipv4.front());
	if (!stun_servers_ipv6.empty())
		stun_servers.emplace_back(stun_servers_ipv4.front());

	auto number = generate_random_number<uint64_t>();
	std::unique_ptr<rfc8489::stun_header> header = rfc8489::create_stun_header(number);
	size_t header_size = sizeof(rfc8489::stun_header);
	for (auto &target_endpoint : stun_servers)
	{
		std::vector<uint8_t> data(header_size);
		std::copy_n((uint8_t *)header.get(), header_size, data.data());
		sender.async_send_out(std::move(data), target_endpoint);
	}

	return header;
}

void resend_stun_8489_request(udp_server &sender, const std::string &stun_host, rfc8489::stun_header *header, ip_only_options ip_version_only)
{
	auto udp_version = ip_version_only == ip_only_options::ipv4 ? udp::v4() : udp::v6();
	udp::resolver::resolver_base::flags input_flags = udp::resolver::numeric_service | udp::resolver::v4_mapped | udp::resolver::all_matching;
	if (ip_version_only != ip_only_options::not_set)
		input_flags = udp::resolver::numeric_service | udp::resolver::address_configured;

	asio::error_code ec;
	udp::resolver &udp_resolver = sender.get_resolver();
	udp::resolver::results_type remote_addresses = udp_resolver.resolve(udp_version, stun_host, "3478", input_flags, ec);

	if (ec)
		return;

	std::vector<udp::endpoint> stun_servers;
	auto [stun_servers_ipv4, stun_servers_ipv6] = split_resolved_addresses(remote_addresses);
	if (!stun_servers_ipv4.empty())
		stun_servers.emplace_back(stun_servers_ipv4.front());
	if (!stun_servers_ipv6.empty())
		stun_servers.emplace_back(stun_servers_ipv4.front());

	size_t header_size = sizeof(rfc8489::stun_header);
	for (auto &target_endpoint : stun_servers)
	{
		std::vector<uint8_t> data(header_size);
		std::copy_n((uint8_t *)header, header_size, data.data());
		sender.async_send_out(std::move(data), target_endpoint);
	}

	return;
}

uint16_t generate_new_port_number(uint16_t start_port_num, uint16_t end_port_num)
{
	thread_local std::mt19937 mt(std::random_device{}());
	std::uniform_int_distribution<uint16_t> uniform_dist(start_port_num, end_port_num);
	return uniform_dist(mt);
}

uint16_t generate_new_port_number(const std::vector<uint16_t> &port_list)
{
	auto pos = generate_new_port_number(0, (uint16_t)(port_list.size() - 1));
	return port_list[pos];
}

size_t randomly_pick_index(size_t container_size)
{
	thread_local std::mt19937 mt(std::random_device{}());
	if (container_size < 2)
		return 0;
	std::uniform_int_distribution<size_t> uniform_dist(0, container_size - 1);
	return uniform_dist(mt);
}

std::string_view feature_to_string(feature ftr)
{
	std::string_view str;
	switch (ftr)
	{
	case feature::initialise:
		str = "initialise";
		break;
	case feature::failure:
		str = "failure";
		break;
	case feature::disconnect:
		str = "disconnect";
		break;
	case feature::keep_alive:
		str = "keep_alive";
		break;
	case feature::raw_data:
		str = "data";
		break;
	case feature::mux_transfer:
		str = "mux_transfer";
		break;
	case feature::mux_cancel:
		str = "mux_cancel";
		break;
	default:
		break;
	}
	return str;
}

std::string protocol_type_to_string(protocol_type prtcl)
{
	std::string str;
	switch (prtcl)
	{
	case protocol_type::not_care:
		str = "not_care";
		break;
	case protocol_type::tcp:
		str = "tcp";
		break;
	case protocol_type::udp:
		str = "udp";
		break;
	case protocol_type::mux:
		str = "mux";
		break;
	default:
		str = std::to_string(int16_t(prtcl));
		break;
	}
	return str;
}

std::string debug_data_to_string(const uint8_t *data, size_t len)
{
	std::stringstream ss;
	for (int i = 0; i < len; ++i)
	{
		ss << std::setfill('0') << std::setw(2) << std::hex << (0xff & (unsigned short)(data[i])) << " ";
	}
	ss << "\nEND\n" << std::dec;
	return ss.str();
}

void debug_print_data(const uint8_t *data, size_t len)
{
	std::stringstream ss;
	for (int i = 0; i < len; ++i)
	{
		ss << std::setfill('0') << std::setw(2) << std::hex << (0xff & (unsigned short)(data[i])) << " ";
	}
	ss << "\nEND\n" << std::dec;
	std::cout << ss.str();
}

bool empty_mapping_function()
{
	return false;
}

namespace packet
{
	uint64_t htonll(uint64_t value) noexcept
	{
		// Check the endianness
		if constexpr (std::endian::native == std::endian::little)
		{
			const uint32_t high_part = htonl(static_cast<uint32_t>(value >> 32));
			const uint32_t low_part = htonl(static_cast<uint32_t>(value & 0xFFFFFFFFLL));
			uint64_t converted_value = (static_cast<uint64_t>(low_part) << 32) | high_part;
			return converted_value;
		}
		else return value;
	}

	uint64_t ntohll(uint64_t value) noexcept
	{
		if constexpr (std::endian::native == std::endian::little)
		{
			const uint32_t high_part = ntohl(static_cast<uint32_t>(value >> 32));
			const uint32_t low_part = ntohl(static_cast<uint32_t>(value & 0xFFFFFFFFLL));
			uint64_t converted_value = (static_cast<uint64_t>(low_part) << 32) | high_part;
			return converted_value;
		}
		else return value;
	}

	int64_t htonll(int64_t value) noexcept
	{
		return ((int64_t)htonll((uint64_t)value));
	}

	int64_t ntohll(int64_t value) noexcept
	{
		return ((int64_t)ntohll((uint64_t)value));
	}

	uint16_t little_endian_to_host(uint16_t value) noexcept
	{
		if constexpr (std::endian::native == std::endian::big)
			return (value >> 8) | (value << 8);
		else return value;
	}

	uint16_t host_to_little_endian(uint16_t value) noexcept
	{
		return little_endian_to_host(value);
	}

	uint32_t little_endian_to_host(uint32_t value) noexcept
	{
		if constexpr (std::endian::native == std::endian::big)
		{
			const uint16_t high_part = little_endian_to_host(static_cast<uint16_t>(value >> 16));
			const uint16_t low_part = little_endian_to_host(static_cast<uint16_t>(value & 0xFFFF));
			uint32_t converted_value = (static_cast<uint32_t>(low_part) << 16) | high_part;
			return converted_value;
		}
		else return value;
	}

	uint32_t host_to_little_endian(uint32_t value) noexcept
	{
		if constexpr (std::endian::native == std::endian::big)
		{
			const uint16_t high_part = host_to_little_endian(static_cast<uint16_t>(value >> 16));
			const uint16_t low_part = host_to_little_endian(static_cast<uint16_t>(value & 0xFFFF));
			uint32_t converted_value = (static_cast<uint32_t>(low_part) << 16) | high_part;
			return converted_value;
		}
		else return value;
	}

	uint64_t little_endian_to_host(uint64_t value) noexcept
	{
		if constexpr (std::endian::native == std::endian::big)
		{
			const uint32_t high_part = little_endian_to_host(static_cast<uint32_t>(value >> 32));
			const uint32_t low_part = little_endian_to_host(static_cast<uint32_t>(value & 0xFFFFFFFFLL));
			uint64_t converted_value = (static_cast<uint64_t>(low_part) << 32) | high_part;
			return converted_value;
		}
		else return value;
	}

	uint64_t host_to_little_endian(uint64_t value) noexcept
	{
		if constexpr (std::endian::native == std::endian::big)
		{
			const uint32_t high_part = host_to_little_endian(static_cast<uint32_t>(value >> 32));
			const uint32_t low_part = host_to_little_endian(static_cast<uint32_t>(value & 0xFFFFFFFFLL));
			uint64_t converted_value = (static_cast<uint64_t>(low_part) << 32) | high_part;
			return converted_value;
		}
		else return value;
	}

	int16_t little_endian_to_host(int16_t value) noexcept
	{
		return ((int16_t)little_endian_to_host((uint16_t)value));
	}

	int16_t host_to_little_endian(int16_t value) noexcept
	{
		return ((int16_t)host_to_little_endian((uint16_t)value));
	}

	int32_t little_endian_to_host(int32_t value) noexcept
	{
		return ((int32_t)little_endian_to_host((uint32_t)value));
	}

	int32_t host_to_little_endian(int32_t value) noexcept
	{
		return ((int32_t)host_to_little_endian((uint32_t)value));
	}

	int64_t little_endian_to_host(int64_t value) noexcept
	{
		return ((int64_t)little_endian_to_host((uint64_t)value));
	}

	int64_t host_to_little_endian(int64_t value) noexcept
	{
		return ((int64_t)host_to_little_endian((uint64_t)value));
	}

	int64_t right_now()
	{
		auto right_now = system_clock::now();
		return duration_cast<seconds>(right_now.time_since_epoch()).count();
	}

	std::pair<std::unique_ptr<uint8_t[]>, int> create_packet(const uint8_t *input_data, int data_size)
	{
		int64_t timestamp = right_now();
		std::unique_ptr<uint8_t[]> new_buffer = std::make_unique_for_overwrite<uint8_t[]>(data_size + gbv_buffer_expand_size);
		packet_layer *ptr = (packet_layer *)new_buffer.get();
		ptr->timestamp = host_to_little_endian((uint32_t)timestamp);
		uint8_t *data_ptr = ptr->data;
		if (data_size > 0)
			std::copy_n(input_data, data_size, data_ptr);

		int new_size = sizeof(packet_layer) - 1 + data_size;
		return { std::move(new_buffer), new_size };
	}

	std::pair<std::unique_ptr<uint8_t[]>, int> create_fec_data_packet(const uint8_t *input_data, int data_size, uint32_t fec_sn, uint8_t fec_sub_sn)
	{
		int64_t timestamp = right_now();
		std::unique_ptr<uint8_t[]> new_buffer = std::make_unique_for_overwrite<uint8_t[]>(data_size + sizeof(packet_layer_fec) + gbv_buffer_expand_size);
		packet_layer_data *pkt_data_ptr = (packet_layer_data *)new_buffer.get();
		uint8_t *data_ptr = pkt_data_ptr->data;

		pkt_data_ptr->timestamp = host_to_little_endian((uint32_t)timestamp);
		pkt_data_ptr->sn = htonl(fec_sn);
		pkt_data_ptr->sub_sn = fec_sub_sn;
		data_ptr = pkt_data_ptr->data;
		if (data_size > 0)
			std::copy_n(input_data, data_size, data_ptr);

		int new_size = sizeof(packet_layer_data) - 1 + data_size;
		return { std::move(new_buffer), new_size };
	}

	std::pair<std::unique_ptr<uint8_t[]>, int> create_fec_redundant_packet(const uint8_t *input_data, int data_size, uint32_t fec_sn, uint8_t fec_sub_sn, uint32_t kcp_conv)
	{
		int64_t timestamp = right_now();
		std::unique_ptr<uint8_t[]> new_buffer = std::make_unique_for_overwrite<uint8_t[]>(data_size + sizeof(packet_layer_fec) + gbv_buffer_expand_size);
		packet_layer_fec *pkt_fec_ptr = (packet_layer_fec *)new_buffer.get();
		uint8_t *data_ptr = pkt_fec_ptr->data;

		pkt_fec_ptr->timestamp = host_to_little_endian((uint32_t)timestamp);
		pkt_fec_ptr->sn = htonl(fec_sn);
		pkt_fec_ptr->sub_sn = fec_sub_sn;
		pkt_fec_ptr->kcp_conv = htonl(kcp_conv);
		data_ptr = pkt_fec_ptr->data;
		if (data_size > 0)
			std::copy_n(input_data, data_size, data_ptr);

		int new_size = sizeof(packet_layer_fec) - 1 + data_size;
		return { std::move(new_buffer), new_size };
	}

	std::vector<uint8_t> create_inner_packet(feature ftr, protocol_type prtcl, const std::vector<uint8_t> &data)
	{
		auto new_data_size = sizeof(data_layer) - 1 + data.size();

		std::vector<uint8_t> new_data(new_data_size);
		data_layer *ptr = (data_layer *)new_data.data();
		ptr->feature_value = ftr;
		ptr->protocol_value = prtcl;
		uint8_t *data_ptr = ptr->data;
		if (data.size() > 0)
			std::copy(data.begin(), data.end(), data_ptr);

		return new_data;
	}

	std::vector<uint8_t> create_inner_packet(feature ftr, protocol_type prtcl, const uint8_t *input_data, size_t data_size)
	{
		auto new_data_size = sizeof(data_layer) - 1 + data_size;
		std::vector<uint8_t> new_data(new_data_size);
		data_layer *ptr = (data_layer *)new_data.data();
		ptr->feature_value = ftr;
		ptr->protocol_value = prtcl;
		uint8_t *data_ptr = ptr->data;
		if (data_size > 0)
			std::copy_n(input_data, data_size, data_ptr);

		return new_data;
	}

	size_t create_inner_packet(feature ftr, protocol_type prtcl, uint8_t *input_data, size_t data_size)
	{
		size_t new_size = sizeof(data_layer) - 1 + data_size;
		uint8_t new_data[gbv_buffer_size + gbv_buffer_expand_size] = {};

		data_layer *ptr = (data_layer *)new_data;
		ptr->feature_value = ftr;
		ptr->protocol_value = prtcl;

		uint8_t *data_ptr = ptr->data;
		if (data_size > 0)
			std::copy_n(input_data, data_size, data_ptr);

		std::copy_n(new_data, new_size, input_data);

		return new_size;
	}

	std::tuple<uint32_t, uint8_t*, size_t> unpack(uint8_t *data, size_t length)
	{
		packet_layer *ptr = (packet_layer *)data;
		uint32_t timestamp = little_endian_to_host(ptr->timestamp);
		uint8_t *data_ptr = ptr->data;
		size_t data_size = length - (data_ptr - data);
		return { timestamp, data_ptr, data_size };
	}

	std::tuple<packet_layer_data, uint8_t*, size_t> unpack_fec(uint8_t *data, size_t length)
	{
		packet_layer_data packet_header{};
		packet_layer_data *ptr = (packet_layer_data *)data;
		packet_header.timestamp = little_endian_to_host(ptr->timestamp);
		packet_header.sn = ntohl(ptr->sn);
		packet_header.sub_sn = ptr->sub_sn;
		uint8_t *data_ptr = ptr->data;
		size_t data_size = length - (data_ptr - data);
		return { packet_header, data_ptr, data_size };
	}

	std::tuple<packet_layer_fec, uint8_t*, size_t> unpack_fec_redundant(uint8_t *data, size_t length)
	{
		packet_layer_fec packet_header{};
		packet_layer_fec *ptr = (packet_layer_fec *)data;
		packet_header.timestamp = little_endian_to_host(ptr->timestamp);
		packet_header.sn = ntohl(ptr->sn);
		packet_header.sub_sn = ptr->sub_sn;
		packet_header.kcp_conv = ntohl(ptr->kcp_conv);
		uint8_t *data_ptr = ptr->data;
		size_t data_size = length - (data_ptr - data);
		return { packet_header, data_ptr, data_size };
	}

	std::tuple<feature, protocol_type, std::vector<uint8_t>> unpack_inner(const std::vector<uint8_t> &data)
	{
		const data_layer *ptr = (const data_layer *)data.data();
		feature ftr = (feature)ptr->feature_value;
		protocol_type prtcl = (protocol_type)ptr->protocol_value;
		const uint8_t *data_ptr = ptr->data;

		size_t data_size = data.size() - (data_ptr - data.data());

		return { ftr, prtcl, std::vector<uint8_t>(data_ptr, data_ptr + data_size) };
	}

	std::tuple<feature, protocol_type, uint8_t*, size_t> unpack_inner(uint8_t *data, size_t length)
	{
		data_layer *ptr = (data_layer *)data;
		feature ftr = (feature)ptr->feature_value;
		protocol_type prtcl = (protocol_type)ptr->protocol_value;
		uint8_t *data_ptr = ptr->data;
		size_t data_size = length - (data_ptr - data);

		return { ftr, prtcl, data_ptr, data_size };
	}

	const settings_wrapper* get_initialise_details_from_unpacked_data(const std::vector<uint8_t> &data)
	{
		const settings_wrapper *settings = (const settings_wrapper *)data.data();
		return settings;
	}

	const settings_wrapper* get_initialise_details_from_unpacked_data(const uint8_t *data)
	{
		const settings_wrapper *settings = (const settings_wrapper *)data;
		return settings;
	}

	void convert_wrapper_byte_order_ntoh(void *data)
	{
		settings_wrapper *settings = (settings_wrapper *)data;
		settings->uid = ntohl(settings->uid);
		settings->port_start = ntohs(settings->port_start);
		settings->port_end = ntohs(settings->port_end);
		settings->outbound_bandwidth = ntohll(settings->outbound_bandwidth);
		settings->inbound_bandwidth = ntohll(settings->inbound_bandwidth);
		settings->user_input_port = ntohs(settings->user_input_port);
	}

	void convert_wrapper_byte_order_hton(void *data)
	{
		settings_wrapper *settings = (settings_wrapper *)data;
		settings->uid = htonl(settings->uid);
		settings->port_start = htons(settings->port_start);
		settings->port_end = htons(settings->port_end);
		settings->outbound_bandwidth = htonll(settings->outbound_bandwidth);
		settings->inbound_bandwidth = htonll(settings->inbound_bandwidth);
		settings->user_input_port = htons(settings->user_input_port);
	}

	void convert_wrapper_byte_order(const std::vector<uint8_t> &input_data, std::vector<uint8_t> &output_data)
	{
		output_data = input_data;
		convert_wrapper_byte_order_ntoh(output_data.data());
	}

	void convert_wrapper_byte_order(const uint8_t *input_data, uint8_t *output_data, size_t data_size)
	{
		std::copy_n(input_data, data_size, output_data);
		convert_wrapper_byte_order_ntoh(output_data);
	}

	void modify_initialise_details_of_unpacked_data(uint8_t *data, const settings_wrapper &settings)
	{
		settings_wrapper *ptr = (settings_wrapper *)data;
		ptr->port_start = htons(settings.port_start);
		ptr->port_end = htons(settings.port_end);
		ptr->outbound_bandwidth = htonll(settings.outbound_bandwidth);
		ptr->inbound_bandwidth = htonll(settings.inbound_bandwidth);
	}

	std::vector<uint8_t> request_initialise_packet(protocol_type prtcl, uint64_t outbound_bandwidth, uint64_t inbound_bandwidth)
	{
		std::vector<uint8_t> data(sizeof(settings_wrapper));
		settings_wrapper *ptr = (settings_wrapper *)data.data();
		ptr->outbound_bandwidth = htonll(outbound_bandwidth);
		ptr->inbound_bandwidth = htonll(inbound_bandwidth);

		return create_inner_packet(feature::initialise, prtcl, data);
	}

	std::vector<uint8_t> request_initialise_packet(protocol_type prtcl, uint64_t outbound_bandwidth, uint64_t inbound_bandwidth, const std::string &set_address, asio::ip::port_type set_port)
	{
		std::vector<uint8_t> data(sizeof(settings_wrapper) + set_address.size());
		settings_wrapper *ptr = (settings_wrapper *)data.data();
		ptr->outbound_bandwidth = htonll(outbound_bandwidth);
		ptr->inbound_bandwidth = htonll(inbound_bandwidth);
		ptr->user_input_port = htons(set_port);
		char *str_ptr = ptr->user_input_ip;
		std::copy(set_address.begin(), set_address.end(), str_ptr);

		return create_inner_packet(feature::initialise, prtcl, data);
	}

	std::vector<uint8_t> response_initialise_packet(protocol_type prtcl, settings_wrapper settings)
	{
		convert_wrapper_byte_order_hton(&settings);
		const uint8_t *data_ptr = (uint8_t *)&settings;
		return create_inner_packet(feature::initialise, prtcl, data_ptr, sizeof settings);
	}

	std::vector<uint8_t> create_test_connection_packet()
	{
		return create_keep_alive_packet(protocol_type::not_care);
	}

	std::vector<uint8_t> inform_disconnect_packet(protocol_type prtcl)
	{
		return create_inner_packet(feature::disconnect, prtcl, std::vector<uint8_t>(empty_data_size));
	}

	std::vector<uint8_t> inform_error_packet(protocol_type prtcl, const std::string &error_msg)
	{
		std::vector<uint8_t> message(error_msg.size() + 1);
		std::copy(error_msg.begin(), error_msg.end(), message.begin());
		return create_inner_packet(feature::failure, prtcl, message);
	}

	std::vector<uint8_t> create_data_packet(protocol_type prtcl, const std::vector<uint8_t> &custom_data)
	{
		return create_inner_packet(feature::raw_data, prtcl, custom_data);
	}

	size_t create_data_packet(protocol_type prtcl, uint8_t *custom_data, size_t length)
	{
		return create_inner_packet(feature::raw_data, prtcl, custom_data, length);
	}

	std::vector<uint8_t> create_keep_alive_packet(protocol_type prtcl)
	{
		return create_inner_packet(feature::keep_alive, prtcl, std::vector<uint8_t>(empty_data_size));
	}

	std::vector<uint8_t> create_keep_alive_response_packet(protocol_type prtcl)
	{
		return create_inner_packet(feature::keep_alive_response, prtcl, std::vector<uint8_t>(empty_data_size));
	}

	std::vector<uint8_t> create_mux_data_packet(protocol_type prtcl, uint32_t connection_id, const std::vector<uint8_t> &custom_data)
	{
		const auto new_data_size = sizeof(data_layer) - 1 + sizeof(mux_data_wrapper) - 1 + custom_data.size();
		std::vector<uint8_t> new_data(new_data_size);

		data_layer *ptr = (data_layer *)new_data.data();
		ptr->feature_value = feature::mux_transfer;
		ptr->protocol_value = prtcl;

		mux_data_wrapper *mux_data_ptr = (mux_data_wrapper *)ptr->data;
		mux_data_ptr->connection_id = htonl(connection_id);
		uint8_t *data_ptr = mux_data_ptr->data;
		if (custom_data.size() > 0)
			std::copy(custom_data.cbegin(), custom_data.cend(), data_ptr);

		return new_data;
	}

	size_t create_mux_data_packet(protocol_type prtcl, uint32_t connection_id, uint8_t *input_data, size_t data_size)
	{
		const auto new_size = sizeof(data_layer) - 1 + sizeof(mux_data_wrapper) - 1 + data_size;
		uint8_t new_data[gbv_buffer_size + gbv_buffer_expand_size] = {};

		data_layer *ptr = (data_layer *)new_data;
		ptr->feature_value = feature::mux_transfer;
		ptr->protocol_value = prtcl;

		mux_data_wrapper *mux_data_ptr = (mux_data_wrapper *)ptr->data;
		mux_data_ptr->connection_id = htonl(connection_id);
		uint8_t *data_ptr = mux_data_ptr->data;
		if (data_size > 0)
			std::copy_n(input_data, data_size, data_ptr);

		std::copy_n(new_data, new_size, input_data);
		return new_size;
	}

	std::vector<uint8_t> mux_tell_server_connect_address(protocol_type prtcl, uint32_t connection_id, const std::string &connect_address, asio::ip::port_type connect_port)
	{
		const auto new_size = sizeof(data_layer) - 1 + sizeof(pre_connect_custom_address) + connect_address.size();
		std::vector<uint8_t> new_data(new_size);

		data_layer *ptr = (data_layer *)new_data.data();
		ptr->feature_value = feature::pre_connect_custom_address;
		ptr->protocol_value = prtcl;

		pre_connect_custom_address *mux_ptr = (pre_connect_custom_address *)ptr->data;
		mux_ptr->connection_id = htonl(connection_id);
		mux_ptr->user_input_port = htons(connect_port);
		char *ip_str = mux_ptr->user_input_ip;
		if (!connect_address.empty())
			std::copy(connect_address.begin(), connect_address.end(), ip_str);

		return new_data;
	}

	std::tuple<uint32_t, uint8_t*, size_t> extract_mux_data_from_unpacked_data(uint8_t *data, size_t length)
	{
		mux_data_wrapper *ptr = (mux_data_wrapper *)data;
		uint32_t connection_id = ntohl(ptr->connection_id);
		uint8_t *data_ptr = ptr->data;
		size_t data_size = length - (data_ptr - data);

		return { connection_id, data_ptr, data_size };
	}

	std::tuple<uint32_t, uint16_t, std::string> extract_mux_pre_connect_from_unpacked_data(uint8_t * data, size_t length)
	{
		pre_connect_custom_address *ptr = (pre_connect_custom_address *)data;
		uint32_t connection_id = ntohl(ptr->connection_id);
		uint16_t user_input_port = ntohs(ptr->user_input_port);
		char *str = ptr->user_input_ip;
		std::string user_input_ip = str;

		return { connection_id, user_input_port, user_input_ip };
	}

	std::vector<uint8_t> inform_mux_cancel_packet(protocol_type prtcl, uint32_t connection_id)
	{
		const auto new_data_size = sizeof(data_layer) - 1 + sizeof(mux_data_wrapper);
		std::vector<uint8_t> new_data(new_data_size);

		data_layer *ptr = (data_layer *)new_data.data();
		ptr->feature_value = feature::mux_cancel;
		ptr->protocol_value = prtcl;

		mux_data_wrapper *mux_data_ptr = (mux_data_wrapper *)ptr->data;
		mux_data_ptr->connection_id = htonl(connection_id);
		return new_data;
	}

	uint32_t extract_mux_cancel_from_unpacked_data(uint8_t *data, size_t length)
	{
		mux_data_wrapper *ptr = (mux_data_wrapper *)data;
		uint32_t connection_id = ntohl(ptr->connection_id);
		return connection_id;
	}

	std::string get_error_message_from_unpacked_data(const std::vector<uint8_t> &data)
	{
		return std::string((const char *)data.data(), data.size());
	}

	std::string get_error_message_from_unpacked_data(uint8_t *data, size_t length)
	{
		return std::string((const char *)data, length);
	}
}	// namespace packet




void tcp_session::start()
{
	async_read_data();
}

void tcp_session::session_is_ending(bool set_ending)
{
	session_ending.store(set_ending);
}

bool tcp_session::session_is_ending()
{
	return session_ending.load();
}

void tcp_session::pause(bool set_as_pause)
{
	bool expect = set_as_pause;
	if (paused.compare_exchange_strong(expect, set_as_pause))
		return;
	paused.store(set_as_pause);
	async_read_data();
}

void tcp_session::stop()
{
	bool expect = true;
	if (stopped.compare_exchange_strong(expect, true))
		return;
	stopped.store(true);
	if (is_open())
		disconnect();
}

bool tcp_session::is_pause() const
{
	return paused.load();
}

bool tcp_session::is_stop() const
{
	return stopped.load();
}

bool tcp_session::is_open() const
{
	return connection_socket.is_open();
}

void tcp_session::disconnect()
{
	asio::error_code ec;
	connection_socket.shutdown(asio::socket_base::shutdown_both, ec);
}

void tcp_session::async_read_data()
{
	if (paused.load() || stopped.load())
		return;

	std::unique_ptr<uint8_t[]> buffer_cache = std::make_unique_for_overwrite<uint8_t[]>(gbv_buffer_size);
	auto asio_buffer = asio::buffer(buffer_cache.get(), gbv_buffer_size);
	asio::async_read(connection_socket, asio_buffer, asio::transfer_at_least(1),
		[data = std::move(buffer_cache), this, sptr = shared_from_this()](const asio::error_code &error, std::size_t bytes_transferred) mutable
		{
			after_read_completed(std::move(data), error, bytes_transferred);
		});
}

size_t tcp_session::send_data(const std::vector<uint8_t> &buffer_data)
{
	if (stopped.load() || buffer_data.empty())
		return 0;

	size_t sent_size = connection_socket.send(asio::buffer(buffer_data));
	last_send_time.store(packet::right_now());
	return sent_size;
}

size_t tcp_session::send_data(const uint8_t *buffer_data, size_t size_in_bytes)
{
	if (stopped.load() || buffer_data == nullptr || size_in_bytes == 0)
		return 0;

	size_t sent_size = connection_socket.send(asio::buffer(buffer_data, size_in_bytes));
	last_send_time.store(packet::right_now());
	return sent_size;
}

size_t tcp_session::send_data(const uint8_t *buffer_data, size_t size_in_bytes, asio::error_code &ec)
{
	if (stopped.load() || buffer_data == nullptr || size_in_bytes == 0)
		return 0;

	size_t sent_size = connection_socket.send(asio::buffer(buffer_data, size_in_bytes), 0, ec);
	last_send_time.store(packet::right_now());
	return sent_size;
}

void tcp_session::async_send_data(std::unique_ptr<std::vector<uint8_t>> data)
{
	if (stopped.load() || data == nullptr || data->empty())
		return;

	auto asio_buffer = asio::buffer(*data);
	asio::async_write(connection_socket, asio_buffer,
		[this, data_ = std::move(data), sptr = shared_from_this()](const asio::error_code& error, size_t bytes_transferred)
		{
			after_write_completed(error, bytes_transferred);
		});
}

void tcp_session::async_send_data(std::vector<uint8_t> &&data)
{
	if (stopped.load() || data.empty())
		return;

	auto asio_buffer = asio::buffer(data);
	asio::async_write(connection_socket, asio_buffer,
		[this, data_ = std::move(data), sptr = shared_from_this()](const asio::error_code &error, size_t bytes_transferred)
		{ after_write_completed(error, bytes_transferred); });
}

void tcp_session::async_send_data(std::unique_ptr<uint8_t[]> buffer_data, size_t size_in_bytes)
{
	if (stopped.load() || buffer_data == nullptr || size_in_bytes == 0)
		return;

	auto asio_buffer = asio::buffer(buffer_data.get(), size_in_bytes);
	asio::async_write(connection_socket, asio_buffer,
		[this, buffer_ptr = std::move(buffer_data), sptr = shared_from_this()](const asio::error_code &error, size_t bytes_transferred)
		{ after_write_completed(error, bytes_transferred); });
}

void tcp_session::async_send_data(std::unique_ptr<uint8_t[]> buffer_data, uint8_t *start_pos, size_t size_in_bytes)
{
	if (stopped.load() || buffer_data == nullptr || start_pos == nullptr || size_in_bytes == 0)
		return;

	asio::async_write(connection_socket, asio::buffer(start_pos, size_in_bytes),
		[this, buffer_ptr = std::move(buffer_data), sptr = shared_from_this()](const asio::error_code &error, size_t bytes_transferred)
		{ after_write_completed(error, bytes_transferred); });
}

void tcp_session::async_send_data(const uint8_t *buffer_data, size_t size_in_bytes)
{
	if (stopped.load() || buffer_data == nullptr || size_in_bytes == 0)
		return;

	asio::async_write(connection_socket, asio::buffer(buffer_data, size_in_bytes),
		std::bind(&tcp_session::after_write_completed, shared_from_this(),
			std::placeholders::_1, std::placeholders::_2));
}

void tcp_session::when_disconnect(std::function<void(std::shared_ptr<tcp_session>)> callback_before_disconnect)
{
	callback_for_disconnect = callback_before_disconnect;
}

bool tcp_session::replace_callback(tcp_callback_t callback_func)
{
	if (session_ending.load() || stopped.load())
		return false;

	callback = callback_func;
	return true;
}

tcp::socket& tcp_session::socket()
{
	return connection_socket;
}

int64_t tcp_session::time_gap_of_receive()
{
	return calculate_difference(packet::right_now(), last_receive_time.load());
}

int64_t tcp_session::time_gap_of_send()
{
	return calculate_difference(packet::right_now(), last_send_time.load());
}

void tcp_session::after_write_completed(const asio::error_code &error, size_t bytes_transferred)
{
	if (error && stopped.load())
		return;

	last_send_time.store(packet::right_now());
}

void tcp_session::after_read_completed(std::unique_ptr<uint8_t[]> buffer_cache, const asio::error_code &error, size_t bytes_transferred)
{
	if (session_ending.load())
		return;

	if (error)
	{
		transfer_data_to_next_function(std::move(buffer_cache), bytes_transferred);
		if (stopped.load())
		{
			if (connection_socket.is_open())
			{
				asio::error_code ec;
				connection_socket.close(ec);
			}
			return;
		}

		try
		{
			if (!session_ending.load())
			{
				callback_for_disconnect(shared_from_this());
				callback_for_disconnect = empty_tcp_disconnect;
			}
		}
		catch (...) {}

		if (connection_socket.is_open())
			this->disconnect();
		return;
	}

	last_receive_time.store(packet::right_now());

	transfer_data_to_next_function(std::move(buffer_cache), bytes_transferred);
	async_read_data();
}

void tcp_session::transfer_data_to_next_function(std::unique_ptr<uint8_t[]> buffer_cache, size_t bytes_transferred)
{
	if (buffer_cache == nullptr || bytes_transferred == 0)
		return;

	if (gbv_buffer_size - bytes_transferred < gbv_buffer_expand_size)
	{
		std::unique_ptr<uint8_t[]> new_buffer = std::make_unique_for_overwrite<uint8_t[]>(gbv_buffer_size + gbv_buffer_expand_size);
		std::copy_n(buffer_cache.get(), bytes_transferred, new_buffer.get());
		buffer_cache.swap(new_buffer);
	}

	switch (task_type_running)
	{
	case task_type::sequence:
	{
		size_t pointer_to_number = (size_t)this;
		push_task_seq(pointer_to_number, [this, bytes_transferred, self_shared = shared_from_this()](std::unique_ptr<uint8_t[]> data) mutable
			{ callback(std::move(data), bytes_transferred, self_shared); },
			std::move(buffer_cache));
		break;
	}
	case task_type::direct:
	{
		push_task([this, bytes_transferred, self_shared = shared_from_this()](std::unique_ptr<uint8_t[]> data) mutable
			{ callback(std::move(data), bytes_transferred, self_shared); },
			std::move(buffer_cache));
		break;
	}
	case task_type::in_place:
		callback(std::move(buffer_cache), bytes_transferred, shared_from_this());
		break;
	default:
		break;
	}
}



void tcp_server::acceptor_initialise(const tcp::endpoint &ep)
{
	asio::ip::v6_only v6_option(ip_version_only == ip_only_options::ipv6);
	asio::socket_base::keep_alive keep_alive_option(true);
	tcp_acceptor.open(ep.protocol());
	if (ep.address().is_v6())
		tcp_acceptor.set_option(v6_option);
	tcp_acceptor.set_option(keep_alive_option);
	tcp_acceptor.set_option(tcp::no_delay(true));

#if __FreeBSD__
	if (fib_ingress >= 0)
	{
		asio::detail::socket_option::integer<ASIO_OS_DEF(SOL_SOCKET), SO_SETFIB> fib_option(fib_ingress);
		tcp_acceptor.set_option(fib_option);
	}
#endif

	tcp_acceptor.bind(ep);
	tcp_acceptor.listen(tcp_acceptor.max_connections);
}

void tcp_server::start_accept()
{
	std::shared_ptr<tcp_session> new_connection;
	switch (task_type_running)
	{
	case task_type::sequence:
	{
		new_connection = std::make_shared<tcp_session>(internal_io_context, push_task_seq, session_callback);
		break;
	}
	case task_type::direct:
	{
		new_connection = std::make_shared<tcp_session>(internal_io_context, push_task, session_callback);
		break;
	}
	case task_type::in_place:
		new_connection = std::make_shared<tcp_session>(internal_io_context, session_callback);
		break;
	default:
		return;
		break;
	}

	tcp_acceptor.async_accept(new_connection->socket(),
		[this, new_connection](const asio::error_code &error_code)
		{
			handle_accept(new_connection, error_code);
		});
}

void tcp_server::handle_accept(std::shared_ptr<tcp_session> new_connection, const asio::error_code &error_code)
{
	if (error_code)
	{
		if (!tcp_acceptor.is_open())
			return;
	}

	start_accept();
	acceptor_callback(new_connection);
}



std::shared_ptr<tcp_session> tcp_client::connect(asio::error_code &ec)
{
	std::shared_ptr<tcp_session> new_connection;
	switch (task_type_running)
	{
	case task_type::sequence:
		new_connection = std::make_shared<tcp_session>(internal_io_context, push_task_seq, session_callback);
		break;
	case task_type::direct:
		new_connection = std::make_shared<tcp_session>(internal_io_context, push_task, session_callback);
		break;
	case task_type::in_place:
		new_connection = std::make_shared<tcp_session>(internal_io_context, session_callback);
		break;
	default:
		return new_connection;
		break;
	}

	tcp::socket &current_socket = new_connection->socket();
	for (auto &endpoint_entry : remote_endpoints)
	{
		current_socket.open(endpoint_entry.endpoint().protocol());
		current_socket.set_option(asio::socket_base::keep_alive(true));
		current_socket.set_option(tcp::no_delay(true));
		if (endpoint_entry.endpoint().protocol() == tcp::v6())
			current_socket.set_option(asio::ip::v6_only(false));

#if __FreeBSD__
		if (fib_egress >= 0)
		{
			asio::detail::socket_option::integer<ASIO_OS_DEF(SOL_SOCKET), SO_SETFIB> fib_option(fib_egress);
			current_socket.set_option(fib_option);
		}
#endif

		current_socket.connect(endpoint_entry, ec);
		if (!ec)
			break;
		asio::error_code ec_close;
		current_socket.close(ec_close);
	}
	return new_connection;
}

bool tcp_client::set_remote_hostname(const std::string &remote_address, asio::ip::port_type port_num, asio::error_code &ec)
{
	return set_remote_hostname(remote_address, std::to_string(port_num), ec);
}

bool tcp_client::set_remote_hostname(const std::string &remote_address, const std::string &port_num, asio::error_code &ec)
{
	auto tcp_version = ip_version_only == ip_only_options::ipv4 ? tcp::v4() : tcp::v6();
	tcp::resolver::resolver_base::flags input_flags = tcp::resolver::numeric_service | tcp::resolver::v4_mapped | tcp::resolver::all_matching;
	if (ip_version_only != ip_only_options::not_set)
		input_flags = tcp::resolver::numeric_service | tcp::resolver::address_configured;

	remote_endpoints = resolver.resolve(tcp_version, remote_address, port_num, input_flags, ec);

	return remote_endpoints.size() > 0;
}



void udp_server::continue_receive()
{
	start_receive();
}

void udp_server::async_send_out(std::unique_ptr<std::vector<uint8_t>> data, const udp::endpoint &client_endpoint)
{
	if (data == nullptr)
		return;
	auto asio_buffer = asio::buffer(*data);
	connection_socket.async_send_to(asio_buffer, client_endpoint,
		[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
}

void udp_server::async_send_out(std::unique_ptr<uint8_t[]> data, uint8_t *start_pos, size_t data_size, const udp::endpoint &client_endpoint)
{
	if (data == nullptr)
		return;
	connection_socket.async_send_to(asio::buffer(start_pos, data_size), client_endpoint,
		[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
}

void udp_server::async_send_out(std::unique_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &client_endpoint)
{
	if (data == nullptr)
		return;
	auto asio_buffer = asio::buffer(data.get(), data_size);
	connection_socket.async_send_to(asio_buffer, client_endpoint,
		[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
}

void udp_server::async_send_out(std::vector<uint8_t> &&data, const udp::endpoint &client_endpoint)
{
	auto asio_buffer = asio::buffer(data);
	connection_socket.async_send_to(asio_buffer, client_endpoint,
		[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
}


void udp_server::initialise(const udp::endpoint &ep)
{
	asio::ip::v6_only v6_option(ip_version_only == ip_only_options::ipv6);
	connection_socket.open(ep.protocol());
	if (ep.address().is_v6())
		connection_socket.set_option(v6_option);

#if __FreeBSD__
	if (fib_ingress >= 0)
	{
		asio::detail::socket_option::integer<ASIO_OS_DEF(SOL_SOCKET), SO_SETFIB> fib_option(fib_ingress);
		connection_socket.set_option(fib_option);
	}
#endif

	connection_socket.bind(ep);
}

void udp_server::start_receive()
{
	std::unique_ptr<uint8_t[]> buffer_cache = std::make_unique_for_overwrite<uint8_t[]>(gbv_buffer_size);
	auto asio_buffer = asio::buffer(buffer_cache.get(), gbv_buffer_size);
	connection_socket.async_receive_from(asio_buffer, incoming_endpoint,
		[buffer_ptr = std::move(buffer_cache), this](const asio::error_code &error, std::size_t bytes_transferred) mutable
		{
			handle_receive(std::move(buffer_ptr), error, bytes_transferred);
		});
}

void udp_server::handle_receive(std::unique_ptr<uint8_t[]> buffer_cache, const asio::error_code &error, std::size_t bytes_transferred)
{
	if (error)
	{
		if (error == asio::error::operation_aborted || !connection_socket.is_open())
			return;
	}

	udp::endpoint copy_of_incoming_endpoint = incoming_endpoint;
	start_receive();

	if (buffer_cache == nullptr || bytes_transferred == 0 || task_count.load() > gbv_task_count_limit)
		return;

	if (gbv_buffer_size - bytes_transferred < gbv_buffer_expand_size)
	{
		std::unique_ptr<uint8_t[]> new_buffer = std::make_unique_for_overwrite<uint8_t[]>(gbv_buffer_size + gbv_buffer_expand_size);
		std::copy_n(buffer_cache.get(), bytes_transferred, new_buffer.get());
		buffer_cache.swap(new_buffer);
	}

	switch (task_type_running)
	{
	case task_type::sequence:
		task_count++;
		push_task_seq((size_t)this, [this, bytes_transferred, copy_of_incoming_endpoint](std::unique_ptr<uint8_t[]> data) mutable
			{ callback(std::move(data), bytes_transferred, copy_of_incoming_endpoint, this); task_count--; },
		              std::move(buffer_cache));
		break;
	case task_type::direct:
		task_count++;
		push_task([this, bytes_transferred, copy_of_incoming_endpoint](std::unique_ptr<uint8_t[]> data) mutable
			{ callback(std::move(data), bytes_transferred, copy_of_incoming_endpoint, this); task_count--; },
		          std::move(buffer_cache));
		break;
	case task_type::in_place:
		callback(std::move(buffer_cache), bytes_transferred, copy_of_incoming_endpoint, this);
		break;
	default:
		break;
	}
}




void udp_client::pause(bool set_as_pause)
{
	bool expect = set_as_pause;
	if (paused.compare_exchange_strong(expect, set_as_pause))
		return;
	paused.store(set_as_pause);
	start_receive();
}

void udp_client::stop()
{
	bool expect = true;
	if (stopped.compare_exchange_strong(expect, true))
		return;
	stopped.store(true);
	callback = empty_udp_client_callback;
	this->disconnect();
}

bool udp_client::is_pause() const
{
	return paused.load();
}

bool udp_client::is_stop() const
{
	return stopped.load();
}

udp::resolver::results_type udp_client::get_remote_hostname(const std::string &remote_address, asio::ip::port_type port_num, asio::error_code &ec)
{
	return get_remote_hostname(remote_address, std::to_string(port_num), ec);
}

udp::resolver::results_type udp_client::get_remote_hostname(const std::string &remote_address, const std::string &port_num, asio::error_code &ec)
{
	auto udp_version = ip_version_only == ip_only_options::ipv4 ? udp::v4() : udp::v6();
	udp::resolver::resolver_base::flags input_flags = udp::resolver::numeric_service | udp::resolver::v4_mapped | udp::resolver::all_matching;
	if (ip_version_only != ip_only_options::not_set)
		input_flags = udp::resolver::numeric_service | udp::resolver::address_configured;

	return resolver.resolve(udp_version, remote_address, port_num, input_flags, ec);
}

void udp_client::disconnect()
{
	asio::error_code ec;
	connection_socket.close(ec);
}

void udp_client::async_receive()
{
	if (paused.load() || stopped.load())
		return;
	start_receive();
}

size_t udp_client::send_out(const std::vector<uint8_t> &data, const udp::endpoint &peer_endpoint, asio::error_code &ec)
{
	if (stopped.load() || data.empty())
		return 0;

	size_t sent_size = connection_socket.send_to(asio::buffer(data), peer_endpoint, 0, ec);
	last_send_time.store(packet::right_now());
	return sent_size;
}

size_t udp_client::send_out(const uint8_t *data, size_t size, const udp::endpoint &peer_endpoint, asio::error_code &ec)
{
	if (stopped.load() || data == nullptr || size == 0)
		return 0;

	size_t sent_size = connection_socket.send_to(asio::buffer(data, size), peer_endpoint, 0, ec);
	last_send_time.store(packet::right_now());
	return sent_size;
}

void udp_client::async_send_out(std::unique_ptr<std::vector<uint8_t>> data, const udp::endpoint &peer_endpoint)
{
	if (stopped.load() || data == nullptr || data->empty())
		return;

	auto asio_buffer = asio::buffer(*data);
	connection_socket.async_send_to(asio_buffer, peer_endpoint,
		[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
	last_send_time.store(packet::right_now());
}

void udp_client::async_send_out(std::unique_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &peer_endpoint)
{
	if (stopped.load() || data == nullptr || data_size == 0)
		return;

	auto asio_buffer = asio::buffer(data.get(), data_size);
	connection_socket.async_send_to(asio_buffer, peer_endpoint,
		[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
	last_send_time.store(packet::right_now());
}

void udp_client::async_send_out(std::unique_ptr<uint8_t[]> data, uint8_t *start_pos, size_t data_size, const udp::endpoint &peer_endpoint)
{
	if (stopped.load() || data == nullptr || data_size == 0)
		return;

	connection_socket.async_send_to(asio::buffer(start_pos, data_size), peer_endpoint,
		[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
	last_send_time.store(packet::right_now());
}

void udp_client::async_send_out(std::vector<uint8_t> &&data, const udp::endpoint &peer_endpoint)
{
	if (stopped.load() || data.empty())
		return;

	auto asio_buffer = asio::buffer(data);
	connection_socket.async_send_to(asio_buffer, peer_endpoint,
		[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
	last_send_time.store(packet::right_now());
}

int64_t udp_client::time_gap_of_receive()
{
	return calculate_difference(packet::right_now(), last_receive_time.load());
}

int64_t udp_client::time_gap_of_send()
{
	return calculate_difference(packet::right_now(), last_send_time.load());
}

void udp_client::initialise()
{
	if (ip_version_only == ip_only_options::ipv4)
	{
		connection_socket.open(udp::v4());
	}
	else
	{
		asio::ip::v6_only v6_option(ip_version_only == ip_only_options::ipv6);
		connection_socket.open(udp::v6());
		connection_socket.set_option(v6_option);
	}
#if __FreeBSD__
	if (fib_egress >= 0)
	{
		asio::detail::socket_option::integer<ASIO_OS_DEF(SOL_SOCKET), SO_SETFIB> fib_option(fib_egress);
		connection_socket.set_option(fib_option);
	}
#endif
}

void udp_client::start_receive()
{
	if (paused.load() || stopped.load())
		return;

	std::unique_ptr<uint8_t[]> buffer_cache = std::make_unique_for_overwrite<uint8_t[]>(gbv_buffer_size);
	uint8_t *buffer_cache_ptr = buffer_cache.get();
	auto asio_buffer = asio::buffer(buffer_cache_ptr, gbv_buffer_size);
	if (!connection_socket.is_open())
		return;
	connection_socket.async_receive_from(asio_buffer, incoming_endpoint,
		[buffer_ptr = std::move(buffer_cache), this, sptr = shared_from_this()](const asio::error_code &error, std::size_t bytes_transferred) mutable
		{
			handle_receive(std::move(buffer_ptr), error, bytes_transferred);
		});
}

void udp_client::handle_receive(std::unique_ptr<uint8_t[]> buffer_cache, const asio::error_code &error, std::size_t bytes_transferred)
{
	if (error)
	{
		if (error != asio::error::operation_aborted && !stopped.load() && !paused.load() && connection_socket.is_open())
			start_receive();
		return;
	}

	if (stopped.load() || buffer_cache == nullptr || bytes_transferred == 0)
		return;

	last_receive_time.store(packet::right_now());
	udp::endpoint copy_of_incoming_endpoint = incoming_endpoint;
	asio::error_code ec;

	start_receive();

	if (task_count.load() > gbv_task_count_limit)
		return;

	if (gbv_buffer_size - bytes_transferred < gbv_buffer_expand_size)
	{
		std::unique_ptr<uint8_t[]> new_buffer = std::make_unique_for_overwrite<uint8_t[]>(gbv_buffer_size + gbv_buffer_expand_size);
		std::copy_n(buffer_cache.get(), bytes_transferred, new_buffer.get());
		buffer_cache.swap(new_buffer);
	}

	switch (task_type_running)
	{
	case task_type::sequence:
		task_count++;
		push_task_seq((size_t)this, [this, bytes_transferred, copy_of_incoming_endpoint, sptr = shared_from_this()](std::unique_ptr<uint8_t[]> data) mutable
			{ callback(std::move(data), bytes_transferred, copy_of_incoming_endpoint, 0); task_count--; },
			std::move(buffer_cache));
		break;
	case task_type::direct:
		task_count++;
		push_task([this, bytes_transferred, copy_of_incoming_endpoint, sptr = shared_from_this()](std::unique_ptr<uint8_t[]> data) mutable
			{ callback(std::move(data), bytes_transferred, copy_of_incoming_endpoint, 0); task_count--; },
			std::move(buffer_cache));
		break;
	case task_type::in_place:
		callback(std::move(buffer_cache), bytes_transferred, copy_of_incoming_endpoint, 0);
		break;
	default:
		break;
	}
}
