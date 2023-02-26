#pragma once
#include <cstdint>

#ifndef __SIMPLE_HASHING_HPP__
#define __SIMPLE_HASHING_HPP__

struct simple_hashing
{
	// Longitudinal redundancy check
	static uint8_t xor_u8(const void *data_ptr, size_t length)
	{
		uint8_t tmp = 0;
		const uint8_t *ptr = (const uint8_t *)data_ptr;

		for (const uint8_t *next_ptr = ptr; next_ptr < ptr + length; ++next_ptr)
		{
			tmp ^= *next_ptr;
		}

		return tmp;
	}

	static uint8_t checksum8(const void *data_ptr, size_t length)
	{
		uint32_t tmp = 0;
		const uint8_t *ptr = (const uint8_t *)data_ptr;

		for (const uint8_t *next_ptr = ptr; next_ptr < ptr + length; ++next_ptr)
		{
			tmp += *next_ptr;
		}

		return (uint8_t)tmp;
	}
};

#endif	// !__SIMPLE_HASHING_HPP__