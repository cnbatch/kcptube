#include <bitset>
#include <limits>
#include <asio.hpp>
#include "stun.hpp"

namespace rfc3489
{
	std::unique_ptr<stun_header> create_stun_header(uint64_t id)
	{
		std::unique_ptr<stun_header> header_data = std::make_unique<stun_header>();
		header_data->message_type = htons(message_type::binding_request);
		header_data->message_length = 0;
		header_data->transaction_id_part_1 = std::numeric_limits<uint64_t>::max();
		header_data->transaction_id_part_2 = id;

		return header_data;
	}

	bool unpack_address_port(const uint8_t *data, uint64_t transaction_id_part_1, uint64_t transaction_id_part_2, uint32_t &ip_address, uint16_t &port)
	{
		const uint8_t *ptr = data;
		const stun_header *header = (const stun_header *)ptr;
		if(ntohs(header->message_type) != message_type::binding_response)
			return false;

		uint16_t attrbutes_size = ntohs(header->message_length);
		if (header->transaction_id_part_1 != transaction_id_part_1 || header->transaction_id_part_2 != transaction_id_part_2)
			return false;

		const stun_attributes *attribute_ptr = (const stun_attributes *)(ptr + sizeof(stun_header));
		const stun_attributes *next_attribute_ptr = attribute_ptr;
		while ((const uint8_t *)next_attribute_ptr < (const uint8_t *)attribute_ptr + attrbutes_size)
		{
			const stun_attributes *current_attribute_ptr = next_attribute_ptr;
			if (ntohs(current_attribute_ptr->attribute_type) == attributes_type::mapped_address)
			{
				const uint8_t *ipaddress_ptr = (const uint8_t *)current_attribute_ptr + sizeof(stun_attributes);
				stun_mapped_address_ipv4 *ipv4 = (stun_mapped_address_ipv4 *)ipaddress_ptr;
				if (ipv4->family == 1)
				{
					ip_address = ntohl(ipv4->ip_address);
					port = ntohs(ipv4->port);
					return true;
				}
			}

			const uint8_t *next_ptr = (const uint8_t *)current_attribute_ptr + sizeof(stun_attributes) + ntohs(current_attribute_ptr->length);
			next_attribute_ptr = (const stun_attributes *)next_ptr;
		}

		return false;
	}
}

namespace rfc8489
{
	std::unique_ptr<stun_header> create_stun_header(uint64_t id)
	{
		std::unique_ptr<stun_header> header_data = std::make_unique<stun_header>();
		header_data->message_type = htons(message_type::class_request | message_type::binding);
		header_data->message_length = 0;
		header_data->magic_cookie = htonl(magic_cookie_value);
		header_data->transaction_id_part_1 = std::numeric_limits<uint32_t>::max();
		header_data->transaction_id_part_2 = id;

		return header_data;
	}

	//bool unpack_address_port(const vla::dynarray<uint8_t> &data, uint32_t transaction_id_part_1, uint64_t transaction_id_part_2,
	//	uint32_t &ipv4_address, uint16_t &ipv4_port, std::array<uint8_t, 16> &ipv6_address, uint16_t &ipv6_port)
	//{
	//	return unpack_address_port(data.data(), transaction_id_part_1, transaction_id_part_2, ipv4_address, ipv4_port, ipv6_address, ipv6_port);
	//}

	bool unpack_address_port(const uint8_t *data, uint32_t transaction_id_part_1, uint64_t transaction_id_part_2, uint32_t & ipv4_address, uint16_t & ipv4_port, std::array<uint8_t, 16>& ipv6_address, uint16_t & ipv6_port)
	{
		bool address_has_found = false;
		const uint8_t *ptr = data;
		const stun_header *header = (const stun_header *)ptr;
		uint16_t message_type = ntohs(header->message_type);

		if ((message_type & message_type::class_xor_bitset) != message_type::class_success_response)
			return false;

		uint16_t attrbutes_size = ntohs(header->message_length);
		if (header->transaction_id_part_1 != transaction_id_part_1 || header->transaction_id_part_2 != transaction_id_part_2)
			return false;

		const stun_attributes *attribute_ptr = (const stun_attributes *)(ptr + sizeof(stun_header));
		const stun_attributes *next_attribute_ptr = attribute_ptr;
		while ((const uint8_t *)next_attribute_ptr < (const uint8_t *)attribute_ptr + attrbutes_size)
		{
			const stun_attributes *current_attribute_ptr = next_attribute_ptr;
			if (ntohs(current_attribute_ptr->attribute_type) == attributes_type::mapped_address)
			{
				const uint8_t *ipaddress_ptr = (const uint8_t *)current_attribute_ptr + sizeof(stun_attributes);
				rfc3489::stun_mapped_address_ipv4 *ipv4 = (rfc3489::stun_mapped_address_ipv4 *)ipaddress_ptr;
				if (ipv4->family == 1)
				{
					ipv4_address = ntohl(ipv4->ip_address);
					ipv4_port = ntohs(ipv4->port);
					address_has_found = true;
				}
			}

			if (ntohs(current_attribute_ptr->attribute_type) == attributes_type::xor_mapped_address)
			{
				const uint8_t *ipaddress_ptr = (const uint8_t *)current_attribute_ptr + sizeof(stun_attributes);
				stun_mapped_address_ipv4 *ipv4 = (stun_mapped_address_ipv4 *)ipaddress_ptr;
				stun_mapped_address_ipv6 *ipv6 = (stun_mapped_address_ipv6 *)ipaddress_ptr;
				if (ipv4->family == ip_family::ipv4)
				{
					ipv4_address = ntohl(ipv4->x_ip_address) ^ magic_cookie_value;
					ipv4_port = ntohs(ipv4->x_port) ^ magic_cookie_front16;
					address_has_found = true;
				}

				if (ipv6->family == ip_family::ipv6)
				{
					std::copy(std::begin(ipv6->x_ip_address), std::end(ipv6->x_ip_address), ipv6_address.begin());
					uint8_t *ptr = ipv6_address.data();
					uint32_t n_cookie = htonl(magic_cookie_value);

					for (uint8_t *u8_ptr = (uint8_t *)&n_cookie;
						u8_ptr < (uint8_t *)&n_cookie + sizeof(n_cookie);
						u8_ptr++, ptr++)
					{
						*ptr ^= *u8_ptr;
					}

					for (uint8_t *u8_ptr = (uint8_t *)&transaction_id_part_1;
						u8_ptr < (uint8_t *)&transaction_id_part_1 + sizeof(transaction_id_part_1);
						u8_ptr++, ptr++)
					{
						*ptr ^= *u8_ptr;
					}

					for (uint8_t *u8_ptr = (uint8_t *)&transaction_id_part_2;
						u8_ptr < (uint8_t *)&transaction_id_part_2 + sizeof(transaction_id_part_2);
						u8_ptr++, ptr++)
					{
						*ptr ^= *u8_ptr;
					}

					ipv6_port = ntohs(ipv6->x_port) ^ magic_cookie_front16;
					address_has_found = true;
				}
			}

			const uint8_t *next_ptr = (const uint8_t *)current_attribute_ptr + sizeof(stun_attributes) + ntohs(current_attribute_ptr->length);
			next_attribute_ptr = (const stun_attributes *)next_ptr;
		}

		return address_has_found;
	}
}
