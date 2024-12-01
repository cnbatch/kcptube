#pragma once
#include <cstdint>
#include <array>
#include <memory>
#include <botan/hash.h>

#ifndef __SIMPLE_HASHING_HPP__
#define __SIMPLE_HASHING_HPP__

class simple_hashing
{
private:
	std::unique_ptr<Botan::HashFunction> crc32 = Botan::HashFunction::create("CRC32");

public:
	std::array<uint8_t, 2> checksum16(const void *data_ptr, size_t length)
	{
		std::array<uint8_t, 2> output = {};
		std::array<uint8_t, 4> crc32_output = {};
		crc32->update((const uint8_t*)data_ptr, length);
		crc32->final(crc32_output.data());
		*((uint16_t *)output.data()) = *((uint16_t*)crc32_output.data()) ^ *((uint16_t*)(crc32_output.data() + 2));
		return output;
	}
};

#endif	// !__SIMPLE_HASHING_HPP__