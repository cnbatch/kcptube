#pragma once

#ifndef __STUN_HPP__
#define __STUN_HPP__

#include <cstdint>
#include <array>
#include <memory>

namespace rfc3489
{
	namespace message_type
	{
		constexpr uint16_t binding_request              = 0x0001;
		constexpr uint16_t binding_response             = 0x0101;
		constexpr uint16_t binding_error_response       = 0x0111;
		constexpr uint16_t shared_secret_request        = 0x0002;
		constexpr uint16_t shared_secret_response       = 0x0102;
		constexpr uint16_t shared_secret_error_response = 0x0112;
	}

	namespace attributes_type
	{
		constexpr uint16_t mapped_address     = 0x0001;
		constexpr uint16_t response_address   = 0x0002;
		constexpr uint16_t change_request     = 0x0003;
		constexpr uint16_t source_address     = 0x0004;
		constexpr uint16_t changed_address    = 0x0005;
		constexpr uint16_t username           = 0x0006;
		constexpr uint16_t password           = 0x0007;
		constexpr uint16_t message_integrity  = 0x0008;
		constexpr uint16_t error_code         = 0x0009;
		constexpr uint16_t unknown_attributes = 0x000a;
		constexpr uint16_t reflected_from     = 0x000b;
	}

#pragma pack (push, 1)
	struct stun_header
	{
		uint16_t message_type;
		uint16_t message_length;
		uint64_t transaction_id_part_1;
		uint64_t transaction_id_part_2;
	};

	struct stun_attributes
	{
		uint16_t attribute_type;
		uint16_t length;
	};

	struct stun_mapped_address_ipv4
	{
		uint8_t ignore;
		uint8_t family;
		uint16_t port;
		uint32_t ip_address;
	};
#pragma pack(pop)

	std::unique_ptr<stun_header> create_stun_header(uint64_t id);
	bool unpack_address_port(const uint8_t *data, const stun_header *current_header, uint32_t &ip_address, uint16_t &port);
}

namespace rfc8489
{
	constexpr uint32_t magic_cookie_value = 0x2112A442;
	constexpr uint16_t magic_cookie_front16 = 0x2112;

	namespace message_type
	{
		constexpr uint16_t class_xor_bitset       = 0b00'00000'1'000'1'0000;
		constexpr uint16_t class_request          = 0b00'00000'0'000'0'0000;
		constexpr uint16_t class_indication       = 0b00'00000'0'000'1'0000;
		constexpr uint16_t class_success_response = 0b00'00000'1'000'0'0000;
		constexpr uint16_t class_error_response   = 0b00'00000'1'000'1'0000;

		constexpr uint16_t binding = 0x001;
	}

	namespace attributes_type
	{
		constexpr uint16_t mapped_address           = 0x0001;
		constexpr uint16_t username                 = 0x0006;
		constexpr uint16_t message_integrity        = 0x0008;
		constexpr uint16_t error_code               = 0x0009;
		constexpr uint16_t unknown_attributes       = 0x000a;
		constexpr uint16_t realm                    = 0x000b;
		constexpr uint16_t nonce                    = 0x000b;
		constexpr uint16_t xor_mapped_address       = 0x0020;
		constexpr uint16_t software                 = 0x8022;
		constexpr uint16_t alternate_server         = 0x8023;
		constexpr uint16_t fingerprint              = 0x8028;
		constexpr uint16_t message_integrity_sha256 = 0x001c;
		constexpr uint16_t password_algorithm       = 0x001d;
		constexpr uint16_t userhash                 = 0x001e;
		constexpr uint16_t password_algorithms      = 0x8002;
		constexpr uint16_t alternate_domain         = 0x8003;
	}

	namespace password_algorithms
	{
		constexpr uint16_t md5     = 0x0001;
		constexpr uint16_t sha_256 = 0x0002;
	}

	namespace ip_family
	{
		constexpr uint8_t ipv4 = 1;
		constexpr uint8_t ipv6 = 2;
	}

#pragma pack (push, 1)
	struct stun_header
	{
		uint16_t message_type;
		uint16_t message_length;
		uint32_t magic_cookie;
		uint32_t transaction_id_part_1;
		uint64_t transaction_id_part_2;
	};

	struct stun_attributes
	{
		uint16_t attribute_type;
		uint16_t length;
	};

	struct stun_mapped_address_ipv4
	{
		uint8_t ignore;
		uint8_t family;
		uint16_t x_port;
		uint32_t x_ip_address;
	};

	struct stun_mapped_address_ipv6
	{
		uint8_t ignore;
		uint8_t family;
		uint16_t x_port;
		uint8_t x_ip_address[16];
	};
#pragma pack(pop)

	std::unique_ptr<stun_header> create_stun_header(uint64_t id);
	bool unpack_address_port(const uint8_t *data, const stun_header *current_header,
	                         uint32_t &ipv4_address, uint16_t &ipv4_port,
	                         std::array<uint8_t, 16> &ipv6_address, uint16_t &ipv6_port);
}

#endif // !__STUN_HPP__

