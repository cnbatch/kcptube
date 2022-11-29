#include <limits>
#include <stdexcept>
#include <cstdlib>
#include <map>
#include <fstream>
#include "share_defines.hpp"
#include "string_utils.hpp"
#include "aead.hpp"


struct default_values
{
	static const int TIMEOUT = 1800;	// second
	static const int KCP_SEND_WINDOW = 256;
	static const int KCP_RECEIVE_WINDOW = 1024;
	static const int KCP_MTU = 1420;
};

template<typename T>
class encrypt_decrypt
{
private:
	std::map<std::string, T> core;

public:
	std::string encrypt(const std::string &password, const uint8_t *input_plain_data, size_t length, uint8_t *output_cipher, size_t &output_legnth)
	{
		auto iter = core.find(password);
		if (iter == core.end())
		{
			core.insert({ password, T(password) });
			iter = core.find(password);
		}

		return iter->second.encrypt(input_plain_data, length, output_cipher, output_legnth);
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

	std::string decrypt(const std::string &password, const uint8_t *input_plain_data, size_t length, uint8_t *output_cipher, size_t &output_legnth)
	{
		auto iter = core.find(password);
		if (iter == core.end())
		{
			core.insert({ password, T(password) });
			iter = core.find(password);
		}

		return iter->second.decrypt(input_plain_data, length, output_cipher, output_legnth);
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

user_settings parse_from_args(const std::vector<std::string> &args, std::vector<std::string> &error_msg)
{
	using namespace str_utils;

	user_settings current_user_settings;
	error_msg.clear();

	for (const std::string &arg : args)
	{
		auto line = trim_copy(arg);
		if (line.empty() || line[0] == '#')
			continue;
		auto eq = line.find_first_of("=");
		if (eq == std::string::npos) continue;

		std::string name = line.substr(0, eq);
		std::string value = line.substr(eq + 1);
		trim(name);
		trim(value);
		std::string original_value = value;
		to_lower(name);
		to_lower(value);

		if (value.empty())
			continue;

		switch (strhash(name.c_str()))
		{
		case strhash("mode"):
			switch (strhash(value.c_str()))
			{
			case strhash("server"):
				current_user_settings.mode = running_mode::server;
				break;
			case strhash("client"):
				current_user_settings.mode = running_mode::client;
				break;
			default:
				current_user_settings.mode = running_mode::unknow;
				error_msg.emplace_back("invalid mode: " + value);
				break;
			}
			break;

		case strhash("listen_on"):
			current_user_settings.listen_on = original_value;
			break;

		case strhash("listen_port"):
			if (auto pos = value.find("-"); pos == std::string::npos)
			{
				if (auto port_number = std::stoi(value); port_number > 0 && port_number < 65536)
					current_user_settings.listen_port = static_cast<uint16_t>(port_number);
				else
					error_msg.emplace_back("invalid listen_port number: " + value);
			}
			else
			{
				std::string start_port = value.substr(0, pos);
				std::string end_port = value.substr(pos + 1);
				trim(start_port);
				trim(end_port);

				if (start_port.empty() || end_port.empty())
				{
					error_msg.emplace_back("invalid listen_port range: " + value);
					break;
				}

				if (auto port_number = std::stoi(start_port); port_number > 0 && port_number < 65536)
					current_user_settings.listen_port_start = static_cast<uint16_t>(port_number);
				else
					error_msg.emplace_back("invalid listen_port_start number: " + start_port);

				if (auto port_number = std::stoi(end_port); port_number > 0 && port_number < 65536)
					current_user_settings.listen_port_end = static_cast<uint16_t>(port_number);
				else
					error_msg.emplace_back("invalid listen_port_end number: " + end_port);
			}
			break;

		case strhash("dport_refresh"):	// client only
			if (auto time_interval = std::stoi(value); time_interval < dport_refresh_minimal)
				current_user_settings.dynamic_port_refresh = dport_refresh_minimal;
			else if (time_interval >= dport_refresh_minimal && time_interval < 65536)
				current_user_settings.dynamic_port_refresh = static_cast<uint16_t>(time_interval);
			else if (time_interval >= 65536)
				current_user_settings.dynamic_port_refresh = std::numeric_limits<uint16_t>::max();
			break;

		case strhash("destination_port"):
			if (auto pos = value.find("-"); pos == std::string::npos)
			{
				if (auto port_number = std::stoi(value); port_number > 0 && port_number < 65536)
					current_user_settings.destination_port = static_cast<uint16_t>(port_number);
				else
					error_msg.emplace_back("invalid listen_port number: " + value);
			}
			else
			{
				std::string start_port = value.substr(0, pos);
				std::string end_port = value.substr(pos + 1);
				trim(start_port);
				trim(end_port);

				if (start_port.empty() || end_port.empty())
				{
					error_msg.emplace_back("invalid destination_port range: " + value);
					break;
				}

				if (auto port_number = std::stoi(start_port); port_number > 0 && port_number < 65536)
					current_user_settings.destination_port_start = static_cast<uint16_t>(port_number);
				else
					error_msg.emplace_back("invalid destination_port_start number: " + start_port);

				if (auto port_number = std::stoi(end_port); port_number > 0 && port_number < 65536)
					current_user_settings.destination_port_end = static_cast<uint16_t>(port_number);
				else
					error_msg.emplace_back("invalid destination_port_end number: " + end_port);
			}
			break;


		case strhash("destination_address"):
			current_user_settings.destination_address = value;
			break;

		case strhash("encryption_password"):
			current_user_settings.encryption_password = original_value;
			break;

		case strhash("encryption_algorithm"):
			switch (strhash(value.c_str()))
			{
			case strhash("none"):
				current_user_settings.encryption = encryption_mode::none;
				break;
			case strhash("aes-gcm"):
				current_user_settings.encryption = encryption_mode::aes_gcm;
				break;
			case strhash("aes-ocb"):
				current_user_settings.encryption = encryption_mode::aes_ocb;
				break;
			case strhash("chacha20"):
				current_user_settings.encryption = encryption_mode::chacha20;
				break;
			case strhash("xchacha20"):
				current_user_settings.encryption = encryption_mode::xchacha20;
				break;
			default:
				current_user_settings.encryption = encryption_mode::unknow;
				error_msg.emplace_back("encryption_algorithm is incorrect: " + value);
				break;
			}
			break;

		case strhash("kcp"):
			switch (strhash(value.c_str()))
			{
			case strhash("manual"):
				current_user_settings.kcp_setting = kcp_mode::manual;
				break;
			case strhash("largo"):
				current_user_settings.kcp_setting = kcp_mode::largo;
				break;
			case strhash("andante"):
				current_user_settings.kcp_setting = kcp_mode::andante;
				break;
			case strhash("moderato"):
				current_user_settings.kcp_setting = kcp_mode::moderato;
				break;
			case strhash("allegro"):
				current_user_settings.kcp_setting = kcp_mode::allegro;
				break;
			case strhash("presto"):
				current_user_settings.kcp_setting = kcp_mode::presto;
				break;
			case strhash("prestissimo"):
				current_user_settings.kcp_setting = kcp_mode::prestissimo;
				break;
			default:
				current_user_settings.kcp_setting = kcp_mode::unknow;
				error_msg.emplace_back("invalid kcp setting: " + value);
				break;
			}
			break;

		case strhash("timeout"):
			current_user_settings.timeout = std::stoi(value);
			break;

		case strhash("kcp_mtu"):
			current_user_settings.kcp_mtu = std::stoi(value);
			break;

		case strhash("kcp_sndwnd"):
			current_user_settings.kcp_sndwnd = std::stoi(value);
			break;

		case strhash("kcp_rcvwnd"):
			current_user_settings.kcp_rcvwnd = std::stoi(value);
			break;

		case strhash("kcp_nodelay"):
			current_user_settings.kcp_nodelay = std::stoi(value);
			break;

		case strhash("kcp_interval"):
			current_user_settings.kcp_interval = std::stoi(value);
			break;

		case strhash("kcp_resend"):
			current_user_settings.kcp_resend = std::stoi(value);
			break;

		case strhash("kcp_nc"):
		{
			bool yes = value == "yes" || value == "true";
			current_user_settings.kcp_nc = yes;
			break;
		}

		case strhash("stun_server"):
			current_user_settings.stun_server = original_value;
			break;

		case strhash("log_path"):
			current_user_settings.log_directory = original_value;
			break;

		default:
			error_msg.emplace_back("unknow option: " + arg);
		}
	}

	check_settings(current_user_settings, error_msg);

	return current_user_settings;
}

void check_settings(user_settings &current_user_settings, std::vector<std::string> &error_msg)
{
	if (kcp_mode::unknow == current_user_settings.kcp_setting)
		current_user_settings.kcp_setting = kcp_mode::andante;

	switch (current_user_settings.kcp_setting)
	{
	case kcp_mode::manual:
	{
		if (current_user_settings.kcp_nodelay < 0)
			error_msg.emplace_back("kcp_nodelay not set");

		if (current_user_settings.kcp_interval < 0)
			error_msg.emplace_back("kcp_interval not set");

		if (current_user_settings.kcp_resend < 0)
			error_msg.emplace_back("kcp_resend not set");

		if (current_user_settings.kcp_nc < 0)
			error_msg.emplace_back("kcp_nc not set");

		if (current_user_settings.kcp_sndwnd < 0)
			current_user_settings.kcp_sndwnd = default_values::KCP_SEND_WINDOW;

		if (current_user_settings.kcp_rcvwnd < 0)
			current_user_settings.kcp_rcvwnd = default_values::KCP_RECEIVE_WINDOW;

		break;
	}

	case kcp_mode::prestissimo:
	{
		current_user_settings.kcp_nodelay = 1;
		current_user_settings.kcp_interval = 4;
		current_user_settings.kcp_resend = 2;
		current_user_settings.kcp_nc = 1;
		if (current_user_settings.kcp_sndwnd < 0)
			current_user_settings.kcp_sndwnd = default_values::KCP_SEND_WINDOW * 2;
		if (current_user_settings.kcp_rcvwnd < 0)
			current_user_settings.kcp_rcvwnd = default_values::KCP_RECEIVE_WINDOW * 2;
		break;
	}

	case kcp_mode::presto:
	{
		current_user_settings.kcp_nodelay = 1;
		current_user_settings.kcp_interval = 10;
		current_user_settings.kcp_resend = 4;
		current_user_settings.kcp_nc = 1;
		if (current_user_settings.kcp_sndwnd < 0)
			current_user_settings.kcp_sndwnd = default_values::KCP_SEND_WINDOW * 2;
		if (current_user_settings.kcp_rcvwnd < 0)
			current_user_settings.kcp_rcvwnd = default_values::KCP_RECEIVE_WINDOW * 2;
		break;
	}

	case kcp_mode::allegro:
	{
		current_user_settings.kcp_nodelay = 1;
		current_user_settings.kcp_interval = 15;
		current_user_settings.kcp_resend = 3;
		current_user_settings.kcp_nc = 0;
		if (current_user_settings.kcp_sndwnd < 0)
			current_user_settings.kcp_sndwnd = default_values::KCP_SEND_WINDOW * 2;
		if (current_user_settings.kcp_rcvwnd < 0)
			current_user_settings.kcp_rcvwnd = default_values::KCP_RECEIVE_WINDOW * 2;
		break;
	}

	case kcp_mode::moderato:
	{
		current_user_settings.kcp_nodelay = 1;
		current_user_settings.kcp_interval = 20;
		current_user_settings.kcp_resend = 0;
		current_user_settings.kcp_nc = 0;
		if (current_user_settings.kcp_sndwnd < 0)
			current_user_settings.kcp_sndwnd = default_values::KCP_SEND_WINDOW;
		if (current_user_settings.kcp_rcvwnd < 0)
			current_user_settings.kcp_rcvwnd = default_values::KCP_RECEIVE_WINDOW;
		break;
	}

	case kcp_mode::andante:
	{
		current_user_settings.kcp_nodelay = 0;
		current_user_settings.kcp_interval = 30;
		current_user_settings.kcp_resend = 0;
		current_user_settings.kcp_nc = 0;
		if (current_user_settings.kcp_sndwnd < 0)
			current_user_settings.kcp_sndwnd = default_values::KCP_SEND_WINDOW;
		if (current_user_settings.kcp_rcvwnd < 0)
			current_user_settings.kcp_rcvwnd = default_values::KCP_RECEIVE_WINDOW;
		break;
	}

	case kcp_mode::largo:
		[[fallthrough]];
	case kcp_mode::unknow:
		[[fallthrough]];
	default:
	{
		current_user_settings.kcp_nodelay = 0;
		current_user_settings.kcp_interval = 40;
		current_user_settings.kcp_resend = 0;
		current_user_settings.kcp_nc = 0;
		if (current_user_settings.kcp_sndwnd < 0)
			current_user_settings.kcp_sndwnd = default_values::KCP_SEND_WINDOW;
		if (current_user_settings.kcp_rcvwnd < 0)
			current_user_settings.kcp_rcvwnd = default_values::KCP_RECEIVE_WINDOW;
		break;
	}
	}

	if (current_user_settings.kcp_mtu < 0)
		current_user_settings.kcp_mtu = default_values::KCP_MTU;

	if (current_user_settings.timeout < 0)
		current_user_settings.timeout = default_values::TIMEOUT;

	if (current_user_settings.destination_address.empty())
		error_msg.emplace_back("invalid destination_address setting");

	if (encryption_mode::empty != current_user_settings.encryption &&
		encryption_mode::unknow != current_user_settings.encryption &&
		encryption_mode::none != current_user_settings.encryption &&
		current_user_settings.encryption_password.empty())
		error_msg.emplace_back("encryption_password is not set");

	if (running_mode::empty == current_user_settings.mode)
		error_msg.emplace_back("running mode is not set");

	if (running_mode::client == current_user_settings.mode)
	{
		if (0 == current_user_settings.listen_port)
			error_msg.emplace_back("listen_port is not set");

		if (current_user_settings.listen_port_start > 0)
			error_msg.emplace_back("listen_port_start should not be set");

		if (current_user_settings.listen_port_end > 0)
			error_msg.emplace_back("listen_port_end should not be set");

		if (current_user_settings.destination_port == 0 &&
			(current_user_settings.destination_port_start == 0 ||
			current_user_settings.destination_port_end == 0))
		{
			error_msg.emplace_back("destination port setting incorrect");
		}
	}

	if (running_mode::server == current_user_settings.mode)
	{
		bool use_dynamic_ports = current_user_settings.listen_port_start || current_user_settings.listen_port_end;
		if (use_dynamic_ports)
		{
			if (0 == current_user_settings.listen_port_start)
				error_msg.emplace_back("listen_port_start is missing");

			if (0 == current_user_settings.listen_port_end)
				error_msg.emplace_back("listen_port_end is missing");

			if (current_user_settings.listen_port_start > 0 && current_user_settings.listen_port_end > 0)
			{
				if (current_user_settings.listen_port_end == current_user_settings.listen_port_start)
					error_msg.emplace_back("listen_port_start is equal to listen_port_end");

				if (current_user_settings.listen_port_end < current_user_settings.listen_port_start)
					error_msg.emplace_back("listen_port_end is less than listen_port_start");
			}
		}
		else
		{
			if (0 == current_user_settings.listen_port)
				error_msg.emplace_back("listen_port is not set");
		}

		if (0 == current_user_settings.destination_port)
			error_msg.emplace_back("destination_port is not set");

		if (current_user_settings.destination_port_start > 0)
			error_msg.emplace_back("destination_port_start should not be set");

		if (current_user_settings.destination_port_end > 0)
			error_msg.emplace_back("destination_port_end should not be set");
	}

	if (!current_user_settings.stun_server.empty())
	{
		if (0 == current_user_settings.listen_port)
			error_msg.emplace_back("do not specify multiple listen ports when STUN Server is set");
	}

	if (!current_user_settings.log_directory.empty())
	{
		if (std::filesystem::exists(current_user_settings.log_directory))
		{
			if (std::filesystem::is_directory(current_user_settings.log_directory))
				current_user_settings.log_ip_address = current_user_settings.log_directory / "ip_address.log";
			else
				error_msg.emplace_back("Log Path is not directory");
		}
		else
		{
			error_msg.emplace_back("Log Path does not exist");
		}
	}
}

int64_t calculate_difference(int64_t number1, int64_t number2)
{
	return abs(number1 - number2);
}

std::vector<uint8_t> create_raw_random_data(size_t mtu_size)
{
	std::vector<uint8_t> temp_array(mtu_size, 0);
	uint8_t *ptr = temp_array.data() + (mtu_size / 2);
	uint64_t *ptr_force_uint64_t = reinterpret_cast<uint64_t*>(ptr);
	*ptr_force_uint64_t = generate_random_number<uint64_t>();
	return temp_array;
}

std::pair<std::string, size_t> encrypt_data(const std::string& password, encryption_mode mode, uint8_t* data_ptr, int length)
{
	size_t cipher_legnth = 0;
	std::string error_message;
	switch (mode)
	{
	case encryption_mode::aes_gcm:
	{
		thread_local encrypt_decrypt<aes_256_gcm> gcm;
		error_message = gcm.encrypt(password, data_ptr, length, data_ptr, cipher_legnth);
		break;
	}
	case encryption_mode::aes_ocb:
	{
		thread_local encrypt_decrypt<aes_256_ocb> ocb;
		error_message = ocb.encrypt(password, data_ptr, length, data_ptr, cipher_legnth);
		break;
	}
	case encryption_mode::chacha20:
	{
		thread_local encrypt_decrypt<chacha20> cc20;
		error_message = cc20.encrypt(password, data_ptr, length, data_ptr, cipher_legnth);
		break;
	}
	case encryption_mode::xchacha20:
	{
		thread_local encrypt_decrypt<xchacha20> xcc20;
		error_message = xcc20.encrypt(password, data_ptr, length, data_ptr, cipher_legnth);
		break;
	}
	default:
		cipher_legnth = length;
		bitwise_not(data_ptr, length);
		break;
	};

	xor_backward(data_ptr, cipher_legnth);

	return { std::move(error_message), cipher_legnth };
}

std::vector<uint8_t> encrypt_data(const std::string& password, encryption_mode mode, const void* data_ptr, int length, std::string& error_message)
{
	size_t cipher_legnth = length;
	std::vector<uint8_t> cipher_cache(length + 48);

	switch (mode)
	{
	case encryption_mode::aes_gcm:
	{
		thread_local encrypt_decrypt<aes_256_gcm> gcm;
		error_message = gcm.encrypt(password, (const uint8_t*)data_ptr, length, cipher_cache.data(), cipher_legnth);
		if (error_message.empty() && cipher_legnth > 0)
			cipher_cache.resize(cipher_legnth);
		break;
	}
	case encryption_mode::aes_ocb:
	{
		thread_local encrypt_decrypt<aes_256_ocb> ocb;
		error_message = ocb.encrypt(password, (const uint8_t*)data_ptr, length, cipher_cache.data(), cipher_legnth);
		if (error_message.empty() && cipher_legnth > 0)
			cipher_cache.resize(cipher_legnth);
		break;
	}
	case encryption_mode::chacha20:
	{
		thread_local encrypt_decrypt<chacha20> cc20;
		error_message = cc20.encrypt(password, (const uint8_t*)data_ptr, length, cipher_cache.data(), cipher_legnth);
		if (error_message.empty() && cipher_legnth > 0)
			cipher_cache.resize(cipher_legnth);
		break;
	}
	case encryption_mode::xchacha20:
	{
		thread_local encrypt_decrypt<xchacha20> xcc20;
		error_message = xcc20.encrypt(password, (const uint8_t*)data_ptr, length, cipher_cache.data(), cipher_legnth);
		if (error_message.empty() && cipher_legnth > 0)
			cipher_cache.resize(cipher_legnth);
		break;
	}
	default:
		cipher_cache.resize(length);
		std::transform((const uint8_t*)data_ptr, (const uint8_t*)data_ptr + length, cipher_cache.begin(), [](auto ch) { return ~ch; });
		break;
	};

	xor_backward(cipher_cache);

	return cipher_cache;
}

std::vector<uint8_t> encrypt_data(const std::string& password, encryption_mode mode, std::vector<uint8_t>&& input_data, std::string& error_message)
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
		std::transform(input_data.begin(), input_data.end(), input_data.begin(), [](auto ch) { return ~ch; });
		break;
	};

	xor_backward(input_data);
	return input_data;
}

std::pair<std::string, size_t> decrypt_data(const std::string& password, encryption_mode mode, uint8_t* data_ptr, int length)
{
	xor_forward(data_ptr, length);

	size_t data_legnth = 0;
	std::string error_message;
	switch (mode)
	{
	case encryption_mode::aes_gcm:
	{
		thread_local encrypt_decrypt<aes_256_gcm> gcm;
		error_message = gcm.decrypt(password, data_ptr, length, data_ptr, data_legnth);
		break;
	}
	case encryption_mode::aes_ocb:
	{
		thread_local encrypt_decrypt<aes_256_ocb> ocb;
		error_message = ocb.decrypt(password, data_ptr, length, data_ptr, data_legnth);
		break;
	}
	case encryption_mode::chacha20:
	{
		thread_local encrypt_decrypt<chacha20> cc20;
		error_message = cc20.decrypt(password, data_ptr, length, data_ptr, data_legnth);
		break;
	}
	case encryption_mode::xchacha20:
	{
		thread_local encrypt_decrypt<xchacha20> xcc20;
		error_message = xcc20.decrypt(password, data_ptr, length, data_ptr, data_legnth);
		break;
	}
	default:
		data_legnth = length;
		bitwise_not(data_ptr, length);
		break;
	};

	return { std::move(error_message), data_legnth };
}

std::vector<uint8_t> decrypt_data(const std::string& password, encryption_mode mode, const void* data_ptr, int length, std::string& error_message)
{
	std::vector<uint8_t> data_cache((const uint8_t*)data_ptr, (const uint8_t*)data_ptr + length);
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
		std::transform(data_cache.begin(), data_cache.end(), data_cache.begin(), [](auto ch) { return ~ch; });
		break;
	};

	return data_cache;
}

std::vector<uint8_t> decrypt_data(const std::string& password, encryption_mode mode, std::vector<uint8_t>&& input_data, std::string& error_message)
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
		std::transform(input_data.begin(), input_data.end(), input_data.begin(), [](auto ch) { return ~ch; });
		break;
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

void print_message_to_file(const std::string &message, const std::filesystem::path &log_file)
{
	std::ofstream output_file;
	output_file.open(log_file, std::ios::out | std::ios::app);
	output_file << message;
}
