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

	std::array<uint8_t, 2> change_iv(const std::string &password)
	{
		auto iter = core.find(password);
		if (iter == core.end())
		{
			core.insert({ password, T(password) });
			iter = core.find(password);
		}
		
		return iter->second.change_iv();
	}

	void change_iv(const std::string &password, std::array<uint8_t, 2> iv_raw)
	{
		auto iter = core.find(password);
		if (iter == core.end())
		{
			core.insert({ password, T(password) });
			iter = core.find(password);
		}
		
		return iter->second.change_iv(iv_raw);
	}
};


std::pair<std::string, size_t> encrypt_data(const std::string &password, encryption_mode mode, uint8_t *data_ptr, int length)
{
	if (length <= 0)
		return { "empty data", 0 };

	size_t cipher_length = 0;
	std::array<uint8_t, 2> iv_raw{};
	std::string error_message;
	switch (mode)
	{
	case encryption_mode::aes_gcm:
	{
		thread_local encrypt_decrypt<aes_256_gcm> gcm;
		iv_raw = gcm.change_iv(password);
		error_message = gcm.encrypt(password, data_ptr, length, data_ptr, cipher_length);
		break;
	}
	case encryption_mode::aes_ocb:
	{
		thread_local encrypt_decrypt<aes_256_ocb> ocb;
		iv_raw = ocb.change_iv(password);
		error_message = ocb.encrypt(password, data_ptr, length, data_ptr, cipher_length);
		break;
	}
	case encryption_mode::chacha20:
	{
		thread_local encrypt_decrypt<chacha20> cc20;
		iv_raw = cc20.change_iv(password);
		error_message = cc20.encrypt(password, data_ptr, length, data_ptr, cipher_length);
		break;
	}
	case encryption_mode::xchacha20:
	{
		thread_local encrypt_decrypt<xchacha20> xcc20;
		iv_raw = xcc20.change_iv(password);
		error_message = xcc20.encrypt(password, data_ptr, length, data_ptr, cipher_length);
		break;
	}
	default:
	{
		cipher_length = length;
		uint8_t first_hash = simple_hashing::xor_u8(data_ptr, length);
		uint8_t second_hash = simple_hashing::checksum8(data_ptr, length);
		iv_raw[0] = ~first_hash;
		iv_raw[1] = ~second_hash;
		bitwise_not(data_ptr, cipher_length);
		break;
	}
	};

	if (cipher_length + constant_values::iv_checksum_block_size > iv_raw.size())
	{
		data_ptr[cipher_length] = iv_raw[0];
		data_ptr[cipher_length + 1] = iv_raw[1];
		cipher_length += constant_values::iv_checksum_block_size;
	}

	return { std::move(error_message), cipher_length };
}

std::vector<uint8_t> encrypt_data(const std::string &password, encryption_mode mode, const void *data_ptr, int length, std::string &error_message)
{
	size_t cipher_length = length;
	std::array<uint8_t, 2> iv_raw{};
	std::vector<uint8_t> cipher_cache(length + constant_values::encryption_block_reserve + constant_values::iv_checksum_block_size);

	switch (mode)
	{
	case encryption_mode::aes_gcm:
	{
		thread_local encrypt_decrypt<aes_256_gcm> gcm;
		iv_raw = gcm.change_iv(password);
		error_message = gcm.encrypt(password, (const uint8_t *)data_ptr, length, cipher_cache.data(), cipher_length);
		if (error_message.empty() && cipher_length > 0)
			cipher_cache.resize(cipher_length + constant_values::iv_checksum_block_size);
		break;
	}
	case encryption_mode::aes_ocb:
	{
		thread_local encrypt_decrypt<aes_256_ocb> ocb;
		iv_raw = ocb.change_iv(password);
		error_message = ocb.encrypt(password, (const uint8_t *)data_ptr, length, cipher_cache.data(), cipher_length);
		if (error_message.empty() && cipher_length > 0)
			cipher_cache.resize(cipher_length + constant_values::iv_checksum_block_size);
		break;
	}
	case encryption_mode::chacha20:
	{
		thread_local encrypt_decrypt<chacha20> cc20;
		iv_raw = cc20.change_iv(password);
		error_message = cc20.encrypt(password, (const uint8_t *)data_ptr, length, cipher_cache.data(), cipher_length);
		if (error_message.empty() && cipher_length > 0)
			cipher_cache.resize(cipher_length + constant_values::iv_checksum_block_size);
		break;
	}
	case encryption_mode::xchacha20:
	{
		thread_local encrypt_decrypt<xchacha20> xcc20;
		iv_raw = xcc20.change_iv(password);
		error_message = xcc20.encrypt(password, (const uint8_t *)data_ptr, length, cipher_cache.data(), cipher_length);
		if (error_message.empty() && cipher_length > 0)
			cipher_cache.resize(cipher_length + constant_values::iv_checksum_block_size);
		break;
	}
	default:
	{
		cipher_length = length;
		uint8_t first_hash = simple_hashing::xor_u8(data_ptr, length);
		uint8_t second_hash = simple_hashing::checksum8(data_ptr, length);
		iv_raw[0] = ~first_hash;
		iv_raw[1] = ~second_hash;
		cipher_cache.resize(cipher_length + constant_values::iv_checksum_block_size);
		std::transform((const uint8_t *)data_ptr, (const uint8_t *)data_ptr + length, cipher_cache.begin(), [](auto ch) { return ~ch; });
		break;
	}
	};

	if (cipher_cache.size() > iv_raw.size())
	{
		cipher_cache[cipher_length] = iv_raw[0];
		cipher_cache[cipher_length + 1] = iv_raw[1];
	}

	return cipher_cache;
}

std::vector<uint8_t> encrypt_data(const std::string &password, encryption_mode mode, std::vector<uint8_t> &&input_data, std::string &error_message)
{
	std::array<uint8_t, 2> iv_raw{};
	switch (mode)
	{
	case encryption_mode::aes_gcm:
	{
		thread_local encrypt_decrypt<aes_256_gcm> gcm;
		iv_raw = gcm.change_iv(password);
		input_data = gcm.encrypt(password, std::move(input_data), error_message);
		if (!error_message.empty() || input_data.size() == 0)
			return input_data;
		break;
	}
	case encryption_mode::aes_ocb:
	{
		thread_local encrypt_decrypt<aes_256_ocb> ocb;
		iv_raw = ocb.change_iv(password);
		input_data = ocb.encrypt(password, std::move(input_data), error_message);
		if (!error_message.empty() || input_data.size() == 0)
			return input_data;
		break;
	}
	case encryption_mode::chacha20:
	{
		thread_local encrypt_decrypt<chacha20> cc20;
		iv_raw = cc20.change_iv(password);
		input_data = cc20.encrypt(password, std::move(input_data), error_message);
		if (!error_message.empty() || input_data.size() == 0)
			return input_data;
		break;
	}
	case encryption_mode::xchacha20:
	{
		thread_local encrypt_decrypt<xchacha20> xcc20;
		iv_raw = xcc20.change_iv(password);
		input_data = xcc20.encrypt(password, std::move(input_data), error_message);
		if (!error_message.empty() || input_data.size() == 0)
			return input_data;
		break;
	}
	default:
	{
		uint8_t first_hash = simple_hashing::xor_u8(input_data.data(), input_data.size());
		uint8_t second_hash = simple_hashing::checksum8(input_data.data(), input_data.size());
		iv_raw[0] = ~first_hash;
		iv_raw[1] = ~second_hash;
		std::transform(input_data.begin(), input_data.end(), input_data.begin(), [](auto ch) { return ~ch; });
		break;
	}
	};

	const size_t cipher_length = input_data.size();
	input_data.resize(cipher_length + constant_values::iv_checksum_block_size);
	input_data[cipher_length] = iv_raw[0];
	input_data[cipher_length + 1] = iv_raw[1];

	return input_data;
}

std::pair<std::string, size_t> decrypt_data(const std::string &password, encryption_mode mode, uint8_t *data_ptr, int length)
{
	if (length <= constant_values::iv_checksum_block_size)
		return { "incorrect data length", 0 };

	size_t data_length = 0;
	int input_length = length - constant_values::iv_checksum_block_size;
	std::array<uint8_t, 2> iv_raw{};
	std::string error_message;

	iv_raw[0] = data_ptr[length - 2];
	iv_raw[1] = data_ptr[length - 1];

	switch (mode)
	{
	case encryption_mode::aes_gcm:
	{
		thread_local encrypt_decrypt<aes_256_gcm> gcm;
		gcm.change_iv(password, iv_raw);
		error_message = gcm.decrypt(password, data_ptr, input_length, data_ptr, data_length);
		break;
	}
	case encryption_mode::aes_ocb:
	{
		thread_local encrypt_decrypt<aes_256_ocb> ocb;
		ocb.change_iv(password, iv_raw);
		error_message = ocb.decrypt(password, data_ptr, input_length, data_ptr, data_length);
		break;
	}
	case encryption_mode::chacha20:
	{
		thread_local encrypt_decrypt<chacha20> cc20;
		cc20.change_iv(password, iv_raw);
		error_message = cc20.decrypt(password, data_ptr, input_length, data_ptr, data_length);
		break;
	}
	case encryption_mode::xchacha20:
	{
		thread_local encrypt_decrypt<xchacha20> xcc20;
		xcc20.change_iv(password, iv_raw);
		error_message = xcc20.decrypt(password, data_ptr, input_length, data_ptr, data_length);
		break;
	}
	default:
	{
		bitwise_not(data_ptr, length);
		data_length = length - constant_values::iv_checksum_block_size;
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
	if (length <= constant_values::iv_checksum_block_size)
	{
		error_message = "Incorrect Data Size.";
		return std::vector<uint8_t>{};
	}

	int data_length = length - constant_values::iv_checksum_block_size;
	std::vector<uint8_t> data_cache((const uint8_t *)data_ptr, (const uint8_t *)data_ptr + data_length);
	std::array<uint8_t, 2> iv_raw{};
	iv_raw[0] = ((const uint8_t *)data_ptr)[length - 2];
	iv_raw[1] = ((const uint8_t *)data_ptr)[length - 1];

	switch (mode)
	{
	case encryption_mode::aes_gcm:
	{
		thread_local encrypt_decrypt<aes_256_gcm> gcm;
		gcm.change_iv(password, iv_raw);
		data_cache = gcm.decrypt(password, std::move(data_cache), error_message);
		break;
	}
	case encryption_mode::aes_ocb:
	{
		thread_local encrypt_decrypt<aes_256_ocb> ocb;
		ocb.change_iv(password, iv_raw);
		data_cache = ocb.decrypt(password, std::move(data_cache), error_message);
		break;
	}
	case encryption_mode::chacha20:
	{
		thread_local encrypt_decrypt<chacha20> cc20;
		cc20.change_iv(password, iv_raw);
		data_cache = cc20.decrypt(password, std::move(data_cache), error_message);
		break;
	}
	case encryption_mode::xchacha20:
	{
		thread_local encrypt_decrypt<xchacha20> xcc20;
		xcc20.change_iv(password, iv_raw);
		data_cache = xcc20.decrypt(password, std::move(data_cache), error_message);
		break;
	}
	default:
	{
		std::transform(data_cache.begin(), data_cache.end(), data_cache.begin(), [](auto ch) { return ~ch; });
		iv_raw[0] = ~iv_raw[0];
		iv_raw[1] = ~iv_raw[1];
		uint8_t first_hash = simple_hashing::xor_u8(data_ptr, data_length);
		uint8_t second_hash = simple_hashing::checksum8(data_ptr, data_length);
		if (first_hash != iv_raw[0] || second_hash != iv_raw[1])
			error_message = "Checksum incorrect";
		data_cache.resize(data_length);
		break;
	}
	};

	return data_cache;
}

std::vector<uint8_t> decrypt_data(const std::string &password, encryption_mode mode, std::vector<uint8_t> &&input_data, std::string &error_message)
{
	if (input_data.size() <= constant_values::iv_checksum_block_size)
	{
		error_message = "Incorrect Data Length.";
		return std::vector<uint8_t>{};
	}

	std::array<uint8_t, 2> iv_raw{};
	iv_raw[0] = input_data[input_data.size() - 2];
	iv_raw[1] = input_data[input_data.size() - 1];
	input_data.resize(input_data.size() - constant_values::iv_checksum_block_size);

	switch (mode)
	{
	case encryption_mode::aes_gcm:
	{
		thread_local encrypt_decrypt<aes_256_gcm> gcm;
		gcm.change_iv(password, iv_raw);
		input_data = gcm.decrypt(password, std::move(input_data), error_message);
		if (!error_message.empty() || input_data.size() == 0)
			return input_data;
		break;
	}
	case encryption_mode::aes_ocb:
	{
		thread_local encrypt_decrypt<aes_256_ocb> ocb;
		ocb.change_iv(password, iv_raw);
		input_data = ocb.decrypt(password, std::move(input_data), error_message);
		if (!error_message.empty() || input_data.size() == 0)
			return input_data;
		break;
	}
	case encryption_mode::chacha20:
	{
		thread_local encrypt_decrypt<chacha20> cc20;
		cc20.change_iv(password, iv_raw);
		input_data = cc20.decrypt(password, std::move(input_data), error_message);
		if (!error_message.empty() || input_data.size() == 0)
			return input_data;
		break;
	}
	case encryption_mode::xchacha20:
	{
		thread_local encrypt_decrypt<xchacha20> xcc20;
		xcc20.change_iv(password, iv_raw);
		input_data = xcc20.decrypt(password, std::move(input_data), error_message);
		if (!error_message.empty() || input_data.size() == 0)
			return input_data;
		break;
	}
	default:
	{
		std::transform(input_data.begin(), input_data.end(), input_data.begin(), [](auto ch) { return ~ch; });
		iv_raw[0] = ~iv_raw[0];
		iv_raw[1] = ~iv_raw[1];
		uint8_t first_hash = simple_hashing::xor_u8(input_data.data(), input_data.size());
		uint8_t second_hash = simple_hashing::checksum8(input_data.data(), input_data.size());
		if (first_hash != iv_raw[0] || second_hash != iv_raw[1])
			error_message = "Checksum Incorrect";
		break;
	}
	};

	return input_data;
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
