#include <map>
#include "data_operations.hpp"
#include "aead.hpp"
#include "simple_hashing.hpp"

template<typename T>
class encrypt_decrypt
{
private:
	std::map<std::string, T> core;

public:
	std::string encrypt(const std::string &password, const uint8_t *input_plain_data, size_t length, uint8_t *output_cipher, size_t &output_length)
	{
		auto iter = core.find(password);
		if (iter == core.end())
		{
			core.insert({ password, T(password) });
			iter = core.find(password);
		}

		return iter->second.encrypt(input_plain_data, length, output_cipher, output_length);
	}

	template<typename Container>
	Container encrypt(const std::string &password, const Container &cipher_data, std::string &error_message)
	{
		auto iter = core.find(password);
		if (iter == core.end())
		{
			core.insert({ password, T(password) });
			iter = core.find(password);
		}

		return iter->second.encrypt(cipher_data, error_message);
	}

	template<typename Container>
	Container encrypt(const std::string &password, Container &&cipher_data, std::string &error_message)
	{
		auto iter = core.find(password);
		if (iter == core.end())
		{
			core.insert({ password, T(password) });
			iter = core.find(password);
		}

		return iter->second.encrypt(std::move(cipher_data), error_message);
	}

	std::string decrypt(const std::string &password, const uint8_t *input_plain_data, size_t length, uint8_t *output_cipher, size_t &output_length)
	{
		auto iter = core.find(password);
		if (iter == core.end())
		{
			core.insert({ password, T(password) });
			iter = core.find(password);
		}

		return iter->second.decrypt(input_plain_data, length, output_cipher, output_length);
	}

	template<typename Container>
	Container decrypt(const std::string &password, const Container &cipher_data, std::string &error_message)
	{
		auto iter = core.find(password);
		if (iter == core.end())
		{
			core.insert({ password, T(password) });
			iter = core.find(password);
		}

		return iter->second.decrypt(cipher_data, error_message);
	}

	template<typename Container>
	Container decrypt(const std::string &password, Container &&cipher_data, std::string &error_message)
	{
		auto iter = core.find(password);
		if (iter == core.end())
		{
			core.insert({ password, T(password) });
			iter = core.find(password);
		}

		return iter->second.decrypt(std::move(cipher_data), error_message);
	}
};


std::pair<std::string, size_t> encrypt_data(const std::string &password, encryption_mode mode, uint8_t *data_ptr, int length)
{
	size_t cipher_length = 0;
	std::string error_message;
	switch (mode)
	{
	case encryption_mode::aes_gcm:
	{
		thread_local encrypt_decrypt<aes_256_gcm> gcm;
		error_message = gcm.encrypt(password, data_ptr, length, data_ptr, cipher_length);
		break;
	}
	case encryption_mode::aes_ocb:
	{
		thread_local encrypt_decrypt<aes_256_ocb> ocb;
		error_message = ocb.encrypt(password, data_ptr, length, data_ptr, cipher_length);
		break;
	}
	case encryption_mode::chacha20:
	{
		thread_local encrypt_decrypt<chacha20> cc20;
		error_message = cc20.encrypt(password, data_ptr, length, data_ptr, cipher_length);
		break;
	}
	case encryption_mode::xchacha20:
	{
		thread_local encrypt_decrypt<xchacha20> xcc20;
		error_message = xcc20.encrypt(password, data_ptr, length, data_ptr, cipher_length);
		break;
	}
	default:
	{
		cipher_length = length;
		uint8_t first_hash = simple_hashing::xor_u8(data_ptr, length);
		uint8_t second_hash = simple_hashing::checksum8(data_ptr, length);
		data_ptr[cipher_length] = first_hash;
		cipher_length++;
		data_ptr[cipher_length] = second_hash;
		cipher_length++;
		bitwise_not(data_ptr, cipher_length);
		break;
	}
	};

	xor_backward(data_ptr, cipher_length);

	return { std::move(error_message), cipher_length };
}

std::vector<uint8_t> encrypt_data(const std::string &password, encryption_mode mode, const void *data_ptr, int length, std::string &error_message)
{
	size_t cipher_length = length;
	std::vector<uint8_t> cipher_cache(length + 48);

	switch (mode)
	{
	case encryption_mode::aes_gcm:
	{
		thread_local encrypt_decrypt<aes_256_gcm> gcm;
		error_message = gcm.encrypt(password, (const uint8_t *)data_ptr, length, cipher_cache.data(), cipher_length);
		if (error_message.empty() && cipher_length > 0)
			cipher_cache.resize(cipher_length);
		break;
	}
	case encryption_mode::aes_ocb:
	{
		thread_local encrypt_decrypt<aes_256_ocb> ocb;
		error_message = ocb.encrypt(password, (const uint8_t *)data_ptr, length, cipher_cache.data(), cipher_length);
		if (error_message.empty() && cipher_length > 0)
			cipher_cache.resize(cipher_length);
		break;
	}
	case encryption_mode::chacha20:
	{
		thread_local encrypt_decrypt<chacha20> cc20;
		error_message = cc20.encrypt(password, (const uint8_t *)data_ptr, length, cipher_cache.data(), cipher_length);
		if (error_message.empty() && cipher_length > 0)
			cipher_cache.resize(cipher_length);
		break;
	}
	case encryption_mode::xchacha20:
	{
		thread_local encrypt_decrypt<xchacha20> xcc20;
		error_message = xcc20.encrypt(password, (const uint8_t *)data_ptr, length, cipher_cache.data(), cipher_length);
		if (error_message.empty() && cipher_length > 0)
			cipher_cache.resize(cipher_length);
		break;
	}
	default:
	{
		cipher_length = length;
		uint8_t first_hash = simple_hashing::xor_u8(data_ptr, length);
		uint8_t second_hash = simple_hashing::checksum8(data_ptr, length);
		cipher_cache[cipher_length] = ~first_hash;
		cipher_length++;
		cipher_cache[cipher_length] = ~second_hash;
		cipher_length++;
		cipher_cache.resize(cipher_length);
		std::transform((const uint8_t *)data_ptr, (const uint8_t *)data_ptr + length, cipher_cache.begin(), [](auto ch) { return ~ch; });
		break;
	}
	};

	xor_backward(cipher_cache);

	return cipher_cache;
}

std::vector<uint8_t> encrypt_data(const std::string &password, encryption_mode mode, std::vector<uint8_t> &&input_data, std::string &error_message)
{
	switch (mode)
	{
	case encryption_mode::aes_gcm:
	{
		thread_local encrypt_decrypt<aes_256_gcm> gcm;
		input_data = gcm.encrypt(password, std::move(input_data), error_message);
		if (!error_message.empty() || input_data.size() == 0)
			return input_data;
		break;
	}
	case encryption_mode::aes_ocb:
	{
		thread_local encrypt_decrypt<aes_256_ocb> ocb;
		input_data = ocb.encrypt(password, std::move(input_data), error_message);
		if (!error_message.empty() || input_data.size() == 0)
			return input_data;
		break;
	}
	case encryption_mode::chacha20:
	{
		thread_local encrypt_decrypt<chacha20> cc20;
		input_data = cc20.encrypt(password, std::move(input_data), error_message);
		if (!error_message.empty() || input_data.size() == 0)
			return input_data;
		break;
	}
	case encryption_mode::xchacha20:
	{
		thread_local encrypt_decrypt<xchacha20> xcc20;
		input_data = xcc20.encrypt(password, std::move(input_data), error_message);
		if (!error_message.empty() || input_data.size() == 0)
			return input_data;
		break;
	}
	default:
	{
		const size_t cipher_length = input_data.size();
		uint8_t first_hash = simple_hashing::xor_u8(input_data.data(), input_data.size());
		uint8_t second_hash = simple_hashing::checksum8(input_data.data(), input_data.size());

		size_t pos = input_data.size();
		input_data.resize(cipher_length + constant_values::checksum_block_size);
		input_data[pos] = first_hash;
		pos++;
		input_data[pos] = second_hash;
		pos++;
		std::transform(input_data.begin(), input_data.end(), input_data.begin(), [](auto ch) { return ~ch; });
		break;
	}
	};

	xor_backward(input_data);
	return input_data;
}

std::pair<std::string, size_t> decrypt_data(const std::string &password, encryption_mode mode, uint8_t *data_ptr, int length)
{
	xor_forward(data_ptr, length);

	size_t data_length = 0;
	std::string error_message;
	switch (mode)
	{
	case encryption_mode::aes_gcm:
	{
		thread_local encrypt_decrypt<aes_256_gcm> gcm;
		error_message = gcm.decrypt(password, data_ptr, length, data_ptr, data_length);
		break;
	}
	case encryption_mode::aes_ocb:
	{
		thread_local encrypt_decrypt<aes_256_ocb> ocb;
		error_message = ocb.decrypt(password, data_ptr, length, data_ptr, data_length);
		break;
	}
	case encryption_mode::chacha20:
	{
		thread_local encrypt_decrypt<chacha20> cc20;
		error_message = cc20.decrypt(password, data_ptr, length, data_ptr, data_length);
		break;
	}
	case encryption_mode::xchacha20:
	{
		thread_local encrypt_decrypt<xchacha20> xcc20;
		error_message = xcc20.decrypt(password, data_ptr, length, data_ptr, data_length);
		break;
	}
	default:
	{
		bitwise_not(data_ptr, length);
		data_length = length - constant_values::checksum_block_size;
		uint8_t first_hash = simple_hashing::xor_u8(data_ptr, data_length);
		uint8_t second_hash = simple_hashing::checksum8(data_ptr, data_length);

		if (first_hash != data_ptr[data_length] || second_hash != data_ptr[data_length + 1])
			error_message = "checksum incorrect";
		break;
	}
	};

	return { std::move(error_message), data_length };
}

std::vector<uint8_t> decrypt_data(const std::string &password, encryption_mode mode, const void *data_ptr, int length, std::string &error_message)
{
	std::vector<uint8_t> data_cache((const uint8_t *)data_ptr, (const uint8_t *)data_ptr + length);
	xor_forward(data_cache);

	switch (mode)
	{
	case encryption_mode::aes_gcm:
	{
		thread_local encrypt_decrypt<aes_256_gcm> gcm;
		data_cache = gcm.decrypt(password, std::move(data_cache), error_message);
		break;
	}
	case encryption_mode::aes_ocb:
	{
		thread_local encrypt_decrypt<aes_256_ocb> ocb;
		data_cache = ocb.decrypt(password, std::move(data_cache), error_message);
		break;
	}
	case encryption_mode::chacha20:
	{
		thread_local encrypt_decrypt<chacha20> cc20;
		data_cache = cc20.decrypt(password, std::move(data_cache), error_message);
		break;
	}
	case encryption_mode::xchacha20:
	{
		thread_local encrypt_decrypt<xchacha20> xcc20;
		data_cache = xcc20.decrypt(password, std::move(data_cache), error_message);
		break;
	}
	default:
	{
		std::transform(data_cache.begin(), data_cache.end(), data_cache.begin(), [](auto ch) { return ~ch; });
		int data_length = length - constant_values::checksum_block_size;
		uint8_t first_hash = simple_hashing::xor_u8(data_ptr, data_length);
		uint8_t second_hash = simple_hashing::checksum8(data_ptr, data_length);
		if (first_hash != data_cache[data_length] || second_hash != data_cache[data_length + 1])
			error_message = "Checksum incorrect";
		data_cache.resize(data_length);
		break;
	}
	};

	return data_cache;
}

std::vector<uint8_t> decrypt_data(const std::string &password, encryption_mode mode, std::vector<uint8_t> &&input_data, std::string &error_message)
{
	xor_forward(input_data);

	switch (mode)
	{
	case encryption_mode::aes_gcm:
	{
		thread_local encrypt_decrypt<aes_256_gcm> gcm;
		input_data = gcm.decrypt(password, std::move(input_data), error_message);
		if (!error_message.empty() || input_data.size() == 0)
			return input_data;
		break;
	}
	case encryption_mode::aes_ocb:
	{
		thread_local encrypt_decrypt<aes_256_ocb> ocb;
		input_data = ocb.decrypt(password, std::move(input_data), error_message);
		if (!error_message.empty() || input_data.size() == 0)
			return input_data;
		break;
	}
	case encryption_mode::chacha20:
	{
		thread_local encrypt_decrypt<chacha20> cc20;
		input_data = cc20.decrypt(password, std::move(input_data), error_message);
		if (!error_message.empty() || input_data.size() == 0)
			return input_data;
		break;
	}
	case encryption_mode::xchacha20:
	{
		thread_local encrypt_decrypt<xchacha20> xcc20;
		input_data = xcc20.decrypt(password, std::move(input_data), error_message);
		if (!error_message.empty() || input_data.size() == 0)
			return input_data;
		break;
	}
	default:
	{
		std::transform(input_data.begin(), input_data.end(), input_data.begin(), [](auto ch) { return ~ch; });
		size_t data_length = input_data.size() - constant_values::checksum_block_size;
		uint8_t first_hash = simple_hashing::xor_u8(input_data.data(), data_length);
		uint8_t second_hash = simple_hashing::checksum8(input_data.data(), data_length);
		if (first_hash != input_data[data_length] || second_hash != input_data[data_length + 1])
			error_message = "Checksum Incorrect";
		input_data.resize(data_length);
		break;
	}
	};

	return input_data;
}

void xor_forward(uint8_t *data, size_t data_size)
{
	for (auto ptr = data, next = ptr + 1;
		next < data + data_size;
		++ptr, ++next)
	{
		*ptr ^= *next;
	}
}

void xor_forward(std::vector<uint8_t> &data)
{
	for (auto iter = data.begin(), next = iter + 1;
		next != data.end();
		++iter, ++next)
	{
		*iter ^= *next;
	}
}

void xor_backward(uint8_t *data, size_t data_size)
{
	for (auto ptr = data + data_size - 1, next = ptr - 1;
		next >= data;
		--ptr, --next)
	{
		*next ^= *ptr;
	}
}

void xor_backward(std::vector<uint8_t> &data)
{
	for (auto iter = data.rbegin(), next = iter + 1;
		next != data.rend();
		++iter, ++next)
	{
		*next ^= *iter;
	}
}

void bitwise_not(uint8_t *input_data, size_t length)
{
	if (length < sizeof(uint64_t) * 2)
	{
		std::transform(input_data, input_data + length, input_data, [](auto ch) { return ~ch; });
	}
	else
	{
		uint64_t *pos_ptr = (uint64_t *)input_data;
		for (; pos_ptr + 1 < (uint64_t *)(input_data + length); pos_ptr++)
		{
			*pos_ptr = ~(*pos_ptr);
		}

		for (uint8_t *ending_ptr = (uint8_t *)pos_ptr; ending_ptr < input_data + length; ending_ptr++)
		{
			*ending_ptr = ~(*ending_ptr);
		}
	}
}
