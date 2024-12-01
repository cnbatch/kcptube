#include <map>
#include <asio.hpp>
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

void xor_forward(uint8_t *data, size_t data_size);
void xor_forward(std::vector<uint8_t> &data);
void xor_backward(uint8_t *data, size_t data_size);
void xor_backward(std::vector<uint8_t> &data);

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

std::vector<uint8_t> create_empty_data(const std::string &password, encryption_mode mode, size_t mtu_size)
{
	std::vector<uint8_t> temp_array(mtu_size, 0);
	uint8_t* ptr = temp_array.data() + (mtu_size / 2);
	uint64_t* ptr_force_uint64_t = reinterpret_cast<uint64_t*>(ptr);
	*ptr_force_uint64_t = generate_random_number<uint64_t>();
	std::string error_message;
	temp_array = encrypt_data(password, mode, std::move(temp_array), error_message);
	return temp_array;
}

std::pair<std::string, size_t> encrypt_data(const std::string &password, encryption_mode mode, uint8_t *data_ptr, int length)
{
	if (length <= 0)
		return { "empty data", 0 };

	bool no_encryption = false;
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
		thread_local simple_hashing checksum_hash;
		iv_raw = checksum_hash.checksum16(data_ptr, length);
		cipher_length = length;
		no_encryption = true;
		break;
	}
	};

	if (cipher_length + constant_values::iv_checksum_block_size > iv_raw.size())
	{
		*(uint16_t *)(data_ptr + cipher_length) = *(uint16_t *)iv_raw.data();
		cipher_length += constant_values::iv_checksum_block_size;
	}

	if (no_encryption)
		xor_forward(data_ptr, cipher_length);

	return { std::move(error_message), cipher_length };
}

std::vector<uint8_t> encrypt_data(const std::string &password, encryption_mode mode, const void *data_ptr, int length, std::string &error_message)
{
	bool no_encryption = false;
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
		thread_local simple_hashing checksum_hash;
		iv_raw = checksum_hash.checksum16(data_ptr, length);
		cipher_length = length;
		no_encryption = true;
		cipher_cache.resize(cipher_length + constant_values::iv_checksum_block_size);
		std::copy_n((const uint8_t *)data_ptr, length, cipher_cache.begin());
		break;
	}
	};

	if (cipher_cache.size() > iv_raw.size())
	{
		*(uint16_t*)(cipher_cache.data() + cipher_length) = *(uint16_t*)iv_raw.data();
	}

	if (no_encryption)
		xor_forward(cipher_cache);

	return cipher_cache;
}

std::vector<uint8_t> encrypt_data(const std::string &password, encryption_mode mode, std::vector<uint8_t> &&input_data, std::string &error_message)
{
	bool no_encryption = false;
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
		thread_local simple_hashing checksum_hash;
		iv_raw = checksum_hash.checksum16(input_data.data(), input_data.size());
		break;
	}
	};

	const size_t cipher_length = input_data.size();
	input_data.resize(cipher_length + constant_values::iv_checksum_block_size);
	*(uint16_t*)(input_data.data() + cipher_length) = *(uint16_t*)iv_raw.data();

	if (no_encryption)
		xor_forward(input_data);

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
	*(uint16_t*)iv_raw.data() = *(uint16_t*)(data_ptr + input_length);

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
		xor_backward(data_ptr, length);
		*(uint16_t*)iv_raw.data() = *(uint16_t*)(data_ptr + input_length);
		data_length = input_length;
		thread_local simple_hashing checksum_hash;
		std::array<uint8_t, 2> checksum16_value = checksum_hash.checksum16(data_ptr, data_length);

		if (checksum16_value != iv_raw)
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
	*(uint16_t*)iv_raw.data() = *(uint16_t*)(((const uint8_t*)data_ptr) + data_length);

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
		data_cache.resize(length);
		std::copy_n((const uint8_t *)data_ptr, length, data_cache.begin());
		xor_backward(data_cache);
		*(uint16_t*)iv_raw.data() = *(uint16_t*)(data_cache.data() + data_length);
		data_cache.resize(data_length);
		thread_local simple_hashing checksum_hash;
		std::array<uint8_t, 2> checksum16_value = checksum_hash.checksum16(data_cache.data(), data_length);
		if (checksum16_value != iv_raw)
			error_message = "Checksum incorrect";
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

	size_t data_length = input_data.size() - constant_values::iv_checksum_block_size;
	std::array<uint8_t, 2> iv_raw{};
	*(uint16_t*)iv_raw.data() = *(uint16_t*)(input_data.data() + data_length);
	input_data.resize(data_length);

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
		xor_backward(input_data);
		*(uint16_t*)iv_raw.data() = *(uint16_t*)(input_data.data() + data_length);
		thread_local simple_hashing checksum_hash;
		std::array<uint8_t, 2> checksum16_value = checksum_hash.checksum16(input_data.data(), input_data.size());
		if (checksum16_value != iv_raw)
			error_message = "Checksum Incorrect";
		break;
	}
	};

	return input_data;
}

//void bitwise_not(uint8_t *input_data, size_t length)
//{
//	if (length < sizeof(uint64_t) * 2)
//	{
//		std::transform(input_data, input_data + length, input_data, [](auto ch) { return ~ch; });
//	}
//	else
//	{
//		uint64_t *pos_ptr = (uint64_t *)input_data;
//		for (; pos_ptr + 1 < (uint64_t *)(input_data + length); pos_ptr++)
//		{
//			*pos_ptr = ~(*pos_ptr);
//		}
//
//		for (uint8_t *ending_ptr = (uint8_t *)pos_ptr; ending_ptr < input_data + length; ending_ptr++)
//		{
//			*ending_ptr = ~(*ending_ptr);
//		}
//	}
//}

std::pair<std::unique_ptr<uint8_t[]>, size_t> clone_into_pair(const uint8_t *original, size_t data_size)
{
	std::pair<std::unique_ptr<uint8_t[]>, size_t> cloned;
	cloned.first = std::make_unique<uint8_t[]>(data_size);
	cloned.second = data_size;
	std::copy_n(original, data_size, cloned.first.get());
	return cloned;
}

const std::map<size_t, const uint8_t*> mapped_pair_to_mapped_pointer(const std::map<size_t, std::pair<std::unique_ptr<uint8_t[]>, size_t>>& mapped_container)
{
	std::map<size_t, const uint8_t*> results;

	for (auto &[i, data] : mapped_container)
		results.insert({ i, data.first.get() });

	return results;
}

std::tuple<std::unique_ptr<uint8_t[]>, size_t, size_t> compact_into_container(const std::vector<std::pair<std::unique_ptr<uint8_t[]>, size_t>> &fec_snd_data_cache)
{
	size_t align_length = 0;
	for (auto &[data_ptr, data_size] : fec_snd_data_cache)
		align_length = std::max(align_length, data_size);
	align_length += constant_values::fec_container_header;

	size_t total_size = fec_snd_data_cache.size() * align_length;
	std::unique_ptr<uint8_t[]> final_array = std::make_unique<uint8_t[]>(total_size);

	for (uint16_t i = 0; i < fec_snd_data_cache.size(); ++i)
	{
		const uint8_t *original_data_ptr = fec_snd_data_cache[i].first.get();
		uint16_t data_size = (uint16_t)fec_snd_data_cache[i].second;
		fec_container *fec_packet = (fec_container *)(final_array.get() + i * align_length);
		uint8_t *fec_data_ptr = fec_packet->data;
		fec_packet->data_length = htons(data_size);
		std::copy_n(original_data_ptr, data_size, fec_data_ptr);
	}

	return { std::move(final_array), align_length, total_size };
}

std::pair<std::map<size_t, std::pair<std::unique_ptr<uint8_t[]>, size_t>>, size_t>
compact_into_container(const std::map<uint16_t, std::pair<std::unique_ptr<uint8_t[]>, size_t>> &fec_rcv_data_cache, size_t data_max_count)
{
	size_t align_length = 0;
	std::map<size_t, std::pair<std::unique_ptr<uint8_t[]>, size_t>> final_array;
	for (auto &[i, data] : fec_rcv_data_cache)
	{
		size_t data_size = data.second;
		if (i < data_max_count)
			align_length = std::max(align_length, data_size + constant_values::fec_container_header);
		else
			align_length = std::max(align_length, data_size);
	}

	for (auto &[i, data] : fec_rcv_data_cache)
	{
		uint8_t *original_data_ptr = data.first.get();
		uint16_t data_size = (uint16_t)data.second;
		std::unique_ptr<uint8_t[]> cache_piece = std::make_unique<uint8_t[]>(align_length);
		if (i < data_max_count)
		{
			fec_container *fec_packet = (fec_container *)(cache_piece.get());
			uint8_t *data_ptr = fec_packet->data;
			fec_packet->data_length = htons(data_size);
			std::copy_n(original_data_ptr, data_size, data_ptr);
		}
		else
		{
			std::copy_n(original_data_ptr, data_size, cache_piece.get());
		}
		final_array.insert(std::pair{ i, std::pair{std::move(cache_piece), data_size} });
	}

	return { std::move(final_array), align_length };
}

std::vector<std::vector<uint8_t>> extract_from_container(const std::vector<std::vector<uint8_t>> &recovered_container)
{
	std::vector<std::vector<uint8_t>> recovered_data(recovered_container.size());

	for (uint16_t i = 0; i < recovered_container.size(); ++i)
	{
		fec_container *fec_packet = (fec_container *)(recovered_container[i].data());
		uint8_t *data_ptr = fec_packet->data;
		size_t data_length = ntohs(fec_packet->data_length);
		recovered_data[i].resize(data_length);
		std::copy_n(data_ptr, data_length, recovered_data[i].data());
	}

	return recovered_data;
}

std::vector<uint8_t> copy_from_container(const std::vector<uint8_t> &recovered_container)
{
	std::vector<uint8_t> recovered_data;
	fec_container *fec_packet = (fec_container *)(recovered_container.data());
	uint8_t *data_ptr = fec_packet->data;
	size_t data_length = ntohs(fec_packet->data_length);
	recovered_data.resize(data_length);
	std::copy_n(data_ptr, data_length, recovered_data.data());

	return recovered_data;
}

std::pair<uint8_t*, size_t> extract_from_container(const std::vector<uint8_t> &recovered_container)
{
	fec_container *fec_packet = (fec_container *)(recovered_container.data());
	uint8_t *data_ptr = fec_packet->data;
	size_t data_length = ntohs(fec_packet->data_length);

	return { data_ptr, data_length };
}
