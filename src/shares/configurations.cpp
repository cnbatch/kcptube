#include <algorithm>
#include <climits>
#include <asio.hpp>
#include "configurations.hpp"
#include "string_utils.hpp"

using namespace str_utils;

std::vector<std::string> parse_running_mode(const std::vector<std::string> &args, user_settings &current_user_settings)
{
	std::vector<std::string> error_messages;
	uint16_t count = 0;

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

		try
		{
			switch (strhash(name.c_str()))
			{
			case strhash("mode"):
			{
				switch (strhash(value.c_str()))
				{
				case strhash("server"):
					current_user_settings.mode = running_mode::server;
					break;
				case strhash("client"):
					current_user_settings.mode = running_mode::client;
					break;
				case strhash("relay"):
					current_user_settings.mode = running_mode::relay;
					break;
				default:
					current_user_settings.mode = running_mode::unknow;
					error_messages.emplace_back("invalid mode: " + value);
					break;
				}
				count++;
				break;
			}
			default:
				break;
			}
		}
		catch (const std::exception &ex)
		{
			error_messages.emplace_back("invalid input: '" + arg + "'" + ", " + ex.what());
		}
	}

	if (count == 0)
		error_messages.emplace_back("running mode is not set");

	if (count > 1)
		error_messages.emplace_back("Too many 'mode=' in configuration file.");

	return error_messages;
}

std::vector<std::string> parse_the_rest(const std::vector<std::string> &args, user_settings &current_user_settings)
{
	std::vector<std::string> error_msg;

	user_settings *current_settings = &current_user_settings;
	user_settings::user_input_address_mapping *current_mappings_ptr = nullptr;

	for (const std::string &arg : args)
	{
		auto line = trim_copy(arg);
		if (line.empty() || line[0] == '#')
			continue;
		auto eq = line.find("=");
		std::string name = line.substr(0, eq);
		bool has_point_to = line.find("->") != line.npos;
		trim(name);
		to_lower(name);
		std::string value;
		std::string original_value;
		if (eq == std::string::npos)
		{
			if ((line.front() != '[' || line.back() != ']') && !has_point_to)
			{
				error_msg.emplace_back("unknow option: " + arg);
				continue;
			}
		}
		else
		{
			value = line.substr(eq + 1);
			trim(value);
			original_value = value;
			to_lower(value);

			if (value.empty())
				continue;
		}

		try
		{
			switch (strhash(name.c_str()))
			{
			case strhash("mode"):
				break;

			case strhash("listen_on"):
				if (value == "{}")
					current_settings->ignore_listen_address = true;
				else
					current_settings->listen_on = string_to_address_list(original_value);
				break;

			case strhash("listen_port"):
				if (value == "{}")
				{
					current_settings->ignore_listen_port = true;
					break;
				}
				current_settings->listen_ports = string_to_port_numbers(value, error_msg, "listen");
				break;

			case strhash("dport_refresh"):	// only for client and relay
				if (auto time_interval = std::stoi(value); time_interval >= 0 && time_interval <= SHRT_MAX)
					current_settings->dynamic_port_refresh = static_cast<int16_t>(time_interval);
				else if (time_interval > SHRT_MAX)
					current_settings->dynamic_port_refresh = SHRT_MAX;
				break;

			case strhash("destination_port"):
				if (value == "{}")
				{
					current_settings->ignore_destination_port = true;
					break;
				}
				current_settings->destination_ports = string_to_port_numbers(value, error_msg, "destination");
				break;


			case strhash("destination_address"):
				if (value == "{}")
					current_settings->ignore_destination_address = true;
				else
					current_settings->destination_address_list = string_to_address_list(value);
				break;

			case strhash("destination_dnstxt"):
				current_settings->destination_dnstxt = value;
				break;
			
			case strhash("encryption_password"):
				current_settings->encryption_password = original_value;
				break;

			case strhash("encryption_algorithm"):
				switch (strhash(value.c_str()))
				{
				case strhash("none"):
					current_settings->encryption = encryption_mode::none;
					break;
				case strhash("xor"):
					current_settings->encryption = encryption_mode::plain_xor;
					break;
				case strhash("aes-gcm"):
					current_settings->encryption = encryption_mode::aes_gcm;
					break;
				case strhash("aes-ocb"):
					current_settings->encryption = encryption_mode::aes_ocb;
					break;
				case strhash("chacha20"):
					current_settings->encryption = encryption_mode::chacha20;
					break;
				case strhash("xchacha20"):
					current_settings->encryption = encryption_mode::xchacha20;
					break;
				default:
					current_settings->encryption = encryption_mode::unknow;
					error_msg.emplace_back("encryption_algorithm is incorrect: " + value);
					break;
				}
				break;

			case strhash("kcp"):
				switch (strhash(value.c_str()))
				{
				case strhash("manual"):
					current_settings->kcp_setting = kcp_mode::manual;
					break;
				case strhash("regular1"):
					current_settings->kcp_setting = kcp_mode::regular1;
					break;
				case strhash("regular2"):
					current_settings->kcp_setting = kcp_mode::regular2;
					break;
				case strhash("regular3"):
					current_settings->kcp_setting = kcp_mode::regular3;
					break;
				case strhash("regular4"):
					current_settings->kcp_setting = kcp_mode::regular4;
					break;
				case strhash("regular5"):
					current_settings->kcp_setting = kcp_mode::regular5;
					break;
				case strhash("fast1"):
					current_settings->kcp_setting = kcp_mode::fast1;
					break;
				case strhash("fast2"):
					current_settings->kcp_setting = kcp_mode::fast2;
					break;
				case strhash("fast3"):
					current_settings->kcp_setting = kcp_mode::fast3;
					break;
				case strhash("fast4"):
					current_settings->kcp_setting = kcp_mode::fast4;
					break;
				case strhash("fast5"):
					current_settings->kcp_setting = kcp_mode::fast5;
					break;
				case strhash("fast6"):
					current_settings->kcp_setting = kcp_mode::fast6;
					break;
				default:
					current_settings->kcp_setting = kcp_mode::unknow;
					error_msg.emplace_back("invalid kcp setting: " + value);
					break;
				}
				break;

			case strhash("mtu"):
				current_settings->mtu = std::stoi(value);
				break;

			case strhash("kcp_mtu"):
				current_settings->kcp_mtu = std::stoi(value);
				break;

			case strhash("kcp_nodelay"):
				current_settings->kcp_nodelay = std::stoi(value);
				break;

			case strhash("kcp_interval"):
				current_settings->kcp_interval = std::stoi(value);
				break;

			case strhash("kcp_resend"):
				current_settings->kcp_resend = std::stoi(value);
				break;

			case strhash("kcp_nc"):
			{
				bool yes = value == "yes" || value == "true" || value == "1";
				current_settings->kcp_nc = yes;
				break;
			}

			case strhash("kcp_sndwnd"):
				if (auto wnd = std::stoi(value); wnd >= 0)
					current_settings->kcp_sndwnd = static_cast<uint32_t>(wnd);
				else
					error_msg.emplace_back("invalid kcp_sndwnd value: " + value);
				break;

			case strhash("kcp_rcvwnd"):
				if (auto wnd = std::stoi(value); wnd >= 0)
					current_settings->kcp_rcvwnd = static_cast<uint32_t>(wnd);
				else
					error_msg.emplace_back("invalid kcp_rcvwnd value: " + value);
				break;

			case strhash("udp_timeout"):
				if (auto time_interval = std::stoi(value); time_interval <= 0 || time_interval > USHRT_MAX)
					current_settings->udp_timeout = 0;
				else
					current_settings->udp_timeout = static_cast<uint16_t>(time_interval);
				break;

			case strhash("keep_alive"):
				if (auto time_interval = std::stoi(value); time_interval <= 0)
					current_settings->keep_alive = 0;
				else if (time_interval > 0 && time_interval < USHRT_MAX)
					current_settings->keep_alive = static_cast<uint16_t>(time_interval);
				else
					current_settings->keep_alive = USHRT_MAX;
				break;

			case strhash("mux_tunnels"):
				if (auto time_interval = std::stoi(value); time_interval <= 0)
					current_settings->mux_tunnels = 0;
				else if (time_interval > 0 && time_interval < USHRT_MAX)
					current_settings->mux_tunnels = static_cast<uint16_t>(time_interval);
				else
					current_settings->mux_tunnels = USHRT_MAX;
				break;

			case strhash("stun_server"):
				current_settings->stun_server = original_value;
				break;

			case strhash("update_ipv4"):
				current_settings->update_ipv4_path = original_value;
				break;

			case strhash("update_ipv6"):
				current_settings->update_ipv6_path = original_value;
				break;
			
			case strhash("outbound_bandwidth"):
				current_settings->outbound_bandwidth = bandwidth_from_string(original_value, error_msg);
				break;

			case strhash("inbound_bandwidth"):
				current_settings->inbound_bandwidth = bandwidth_from_string(original_value, error_msg);
				break;

			case strhash("log_path"):
				current_settings->log_directory = original_value;
				break;

			case strhash("ipv4_only"):
			{
				bool yes = value == "yes" || value == "true" || value == "1";
				current_settings->ip_version_only |= ip_only_options::ipv4;
				break;
			}

			case strhash("ipv6_only"):
			{
				bool yes = value == "yes" || value == "true" || value == "1";
				current_settings->ip_version_only = ip_only_options::ipv6;
				break;
			}

			case strhash("blast"):
			{
				bool yes = value == "yes" || value == "true" || value == "1";
				current_settings->blast = yes;
				break;
			}

			case strhash("fec"):
				if (auto pos = value.find(":"); pos == std::string::npos)
				{
					error_msg.emplace_back("invalid fec format: " + value);
				}
				else
				{
					std::string fec_data_part = value.substr(0, pos);
					std::string fec_redundant_part = value.substr(pos + 1);
					trim(fec_data_part);
					trim(fec_redundant_part);

					if (fec_data_part.empty() || fec_redundant_part.empty())
					{
						error_msg.emplace_back("invalid fec setting: " + value);
						break;
					}

					int fec_data_number = std::stoi(fec_data_part);
					int fec_redundant_number = std::stoi(fec_redundant_part);

					if (fec_data_number > 0 && fec_data_number <= UCHAR_MAX)
						current_settings->fec_data = static_cast<uint8_t>(fec_data_number);

					if (fec_redundant_number > 0 && fec_redundant_number <= UCHAR_MAX)
						current_settings->fec_redundant = static_cast<uint8_t>(fec_redundant_number);

					if (int sum = fec_data_number + fec_redundant_number; sum > UCHAR_MAX)
						error_msg.emplace_back("the sum of fec value is too large: " + std::to_string(sum) + " (" + arg + ")");

					if (current_settings->fec_data == 0 || current_settings->fec_redundant == 0)
						current_settings->fec_data = current_settings->fec_redundant = 0;
				}
				break;

			case strhash("fib_ingress"):
			{
				if (int fib_value = std::stoi(value); fib_value <= 0)
					current_settings->fib_ingress = 0;
				else if (fib_value > 0 && fib_value < USHRT_MAX)
					current_settings->fib_ingress = fib_value;
				else
					current_settings->fib_ingress = USHRT_MAX;
				break;
			}

			case strhash("fib_egress"):
			{
				if (int fib_value = std::stoi(value); fib_value <= 0)
					current_settings->fib_egress = 0;
				else if (fib_value > 0 && fib_value < USHRT_MAX)
					current_settings->fib_egress = fib_value;
				else
					current_settings->fib_egress = USHRT_MAX;
				break;
			}

			case strhash("[listener]"):
			{
				if (current_user_settings.mode == running_mode::relay)
				{
					if (current_user_settings.ingress == nullptr)
					{
						current_user_settings.ingress = std::make_shared<user_settings>();
						current_user_settings.ingress->mode = running_mode::relay_ingress;
					}
					current_settings = current_user_settings.ingress.get();
				}
				else
				{
					error_msg.emplace_back("invalid section tag: " + arg);
				}
				break;
			}

			case strhash("[forwarder]"):
			{
				if (current_user_settings.mode == running_mode::relay)
				{
					if (current_user_settings.egress == nullptr)
					{
						current_user_settings.egress = std::make_shared<user_settings>();
						current_user_settings.egress->mode = running_mode::relay_egress;
					}
					current_settings = current_user_settings.egress.get();
				}
				else
				{
					error_msg.emplace_back("invalid section tag: " + arg);
				}
				break;
			}

			case strhash("[custom_input]"):
			{
				if (current_user_settings.mode == running_mode::client)
				{
					if (current_user_settings.user_input_mappings == nullptr)
						current_user_settings.user_input_mappings = std::make_shared<user_settings::user_input_address_mapping>();
					current_mappings_ptr = current_user_settings.user_input_mappings.get();
				}
				else
				{
					error_msg.emplace_back("invalid section tag: " + arg);
				}
				break;
			}

			case strhash("[custom_input_tcp]"):
			{
				if (current_user_settings.mode == running_mode::client)
				{
					if (current_user_settings.user_input_mappings_tcp == nullptr)
						current_user_settings.user_input_mappings_tcp = std::make_shared<user_settings::user_input_address_mapping>();
					current_mappings_ptr = current_user_settings.user_input_mappings_tcp.get();
				}
				else
				{
					error_msg.emplace_back("invalid section tag: " + arg);
				}
				break;
			}

			case strhash("[custom_input_udp]"):
			{
				if (current_user_settings.mode == running_mode::client)
				{
					if (current_user_settings.user_input_mappings_udp == nullptr)
						current_user_settings.user_input_mappings_udp = std::make_shared<user_settings::user_input_address_mapping>();
					current_mappings_ptr = current_user_settings.user_input_mappings_udp.get();
				}
				else
				{
					error_msg.emplace_back("invalid section tag: " + arg);
				}
				break;
			}

			default:
				if (!has_point_to)
					error_msg.emplace_back("unknow option: " + arg);
			}

			if (has_point_to)
			{
				if (current_mappings_ptr != nullptr)
					parse_custom_input_ip(line, current_mappings_ptr, error_msg);
				else
					error_msg.emplace_back("invalid input: '" + arg + "'. Does not belongs to any custom address sections.");
			}

		}
		catch (const std::exception &ex)
		{
			error_msg.emplace_back("invalid input: '" + arg + "'" + ", " + ex.what());
		}
	}

	return error_msg;
}

void parse_custom_input_ip(const std::string &line, user_settings::user_input_address_mapping *mappings_ptr, std::vector<std::string> &error_msg)
{
	auto point_to = line.find("->");
	std::string local_address = line.substr(0, point_to);
	std::string remote_address = line.substr(point_to + 2);
	trim(local_address);
	trim(remote_address);

	std::vector<std::string> error_message_local;
	std::vector<std::string> error_message_remote;
	auto [local_ip, local_port] = split_address(local_address, error_message_local);
	auto [remote_ip, remote_port] = split_address(remote_address, error_message_remote);

	if (!error_message_local.empty() || !error_message_remote.empty() || remote_ip.empty())
	{
		if (!error_message_local.empty())
			error_msg.emplace_back("'" + line + "'" + std::reduce(error_message_local.begin(), error_message_local.end(), std::string(",")));
		if (!error_message_remote.empty())
			error_msg.emplace_back("'" + line + "'" + std::reduce(error_message_remote.begin(), error_message_remote.end(), std::string(",")));
		if (remote_ip.empty())
			error_msg.emplace_back("'" + line + "' Remote Address can't be empty");
		return;
	}

	uint16_t local_port_number = (uint16_t)std::stoi(local_port);
	uint16_t remote_port_number = (uint16_t)std::stoi(remote_port);

	(*mappings_ptr)[std::pair{ local_ip, local_port_number }] = std::pair{ remote_ip, remote_port_number };
}

std::pair<std::string, std::string> split_address(const std::string &input_address, std::vector<std::string> &error_msg)
{
	auto colon = input_address.rfind(':');
	if (colon == input_address.npos)
		return std::pair<std::string, std::string>();

	bool correct_address = false;
	bool correct_port = false;

	std::string address_name = input_address.substr(0, colon);
	std::string input_port = input_address.substr(colon + 1);

	trim(address_name);
	trim(input_port);

	try
	{
		int32_t port_number = std::stoi(input_port);
		if (port_number > 0 && port_number < 65536)
			correct_port = true;
	}
	catch (...)
	{
		correct_port = false;
	}

	if (address_name.empty())
	{
		correct_address = true;
	}
	else
	{
		asio::ip::address temp_address;
		if (address_name.front() == '[' || address_name.back() == ']')
		{
			if (address_name.front() == '[' && address_name.back() == ']')
			{
				address_name = address_name.substr(1);
				address_name.pop_back();

				asio::error_code ec;
				temp_address = asio::ip::make_address_v6(address_name, ec);
				correct_address = !ec;
			}
		}
		else
		{
			asio::error_code ec;
			temp_address = asio::ip::make_address_v4(address_name, ec);
			correct_address = !ec;
		}
	}

	if (!correct_address)
	{
		bool found_colon = address_name.find(':') != address_name.npos;
		size_t dot_pos = address_name.find_last_of('.');
		if (!found_colon && dot_pos != address_name.npos && dot_pos > 0)
		{
			std::string suffix = address_name.substr(dot_pos + 1);
			if (std::ranges::any_of(suffix, isdigit))
			{
				address_name.clear();
				error_msg.emplace_back("Address Incorrect");
			}
			else
			{
				correct_address = true;
			}
		}
	}

	if (!correct_port)
	{
		input_port.clear();
		error_msg.emplace_back("Port Number Incorrect");
	}

	return std::pair{ address_name, input_port };
}

void check_settings(user_settings &current_user_settings, std::vector<std::string> &error_msg)
{
	if (current_user_settings.mode == running_mode::relay)
	{
		if (current_user_settings.ingress == nullptr && current_user_settings.egress == nullptr)
		{
			error_msg.emplace_back("[listener] and [forwarder] are missing");
		}

		if (current_user_settings.ingress != nullptr || current_user_settings.egress != nullptr)
		{
			if (current_user_settings.ingress == nullptr)
				error_msg.emplace_back("[listener] is missing");

			if (current_user_settings.egress == nullptr)
				error_msg.emplace_back("[forwarder] is missing");
		}

		if (current_user_settings.mux_tunnels > 0)
			error_msg.emplace_back("mux_tunnels should not be set");
	}

	if (current_user_settings.ingress != nullptr)
		copy_settings(*current_user_settings.ingress, current_user_settings);

	if (current_user_settings.egress != nullptr)
		copy_settings(*current_user_settings.egress, current_user_settings);

	verify_kcp_settings(current_user_settings, error_msg);

	if (current_user_settings.dynamic_port_refresh < 0)
	{
		current_user_settings.dynamic_port_refresh = constant_values::dport_refresh_default;
	}
	else if (current_user_settings.dynamic_port_refresh == 0)
	{
	}
	else if (current_user_settings.dynamic_port_refresh < constant_values::dport_refresh_minimal)
	{
		current_user_settings.dynamic_port_refresh = constant_values::dport_refresh_minimal;
	}

	if (current_user_settings.udp_timeout == 0)
		current_user_settings.udp_timeout = constant_values::timeout_value;

	if (current_user_settings.encryption != encryption_mode::empty &&
		current_user_settings.encryption != encryption_mode::unknow &&
		current_user_settings.encryption != encryption_mode::none &&
		current_user_settings.encryption != encryption_mode::plain_xor &&
		current_user_settings.encryption_password.empty())
	{
		error_msg.emplace_back("encryption_password is not set");
	}

	if (current_user_settings.mode == running_mode::client)
	{
		if (current_user_settings.ignore_listen_port || current_user_settings.ignore_listen_address)
		{
			current_user_settings.listen_ports.clear();
			current_user_settings.listen_on.clear();

			if (current_user_settings.user_input_mappings == nullptr &&
				current_user_settings.user_input_mappings_tcp == nullptr &&
				current_user_settings.user_input_mappings_udp == nullptr)
				error_msg.emplace_back("custom address section tag is empty");
		}
		else
		{
			if (current_user_settings.listen_ports.empty())
				error_msg.emplace_back("listen_port is not set");
		}

		if (current_user_settings.ignore_destination_address)
			error_msg.emplace_back("destination_address can't be ignored");

		if (current_user_settings.ignore_destination_port)
			error_msg.emplace_back("destination_port can't be ignored");

		verify_client_destination(current_user_settings, error_msg);
	}

	if (current_user_settings.mode == running_mode::server)
	{
		if (current_user_settings.ignore_listen_address)
			error_msg.emplace_back("if listen_address should be ignored, please delete the whole line of listen_address");

		if (current_user_settings.ignore_listen_port)
			error_msg.emplace_back("listen_port can't be ignored");

		verify_server_listen_port(current_user_settings, error_msg);

		if (!current_user_settings.ignore_destination_address && !current_user_settings.ignore_destination_port)
		{
			if (current_user_settings.destination_ports.empty())
				error_msg.emplace_back("destination_port is not set");

			if (current_user_settings.destination_ports.size() > 1)
				error_msg.emplace_back("too many destination_port");

			if (current_user_settings.destination_address_list.size() != 1)
				error_msg.emplace_back("invalid destination_address setting");
		}

		if (current_user_settings.mux_tunnels > 0)
			error_msg.emplace_back("mux_tunnels should not be set");
	}

	if (current_user_settings.mode == running_mode::relay_ingress)
	{
		verify_server_listen_port(current_user_settings, error_msg);
	}

	if (current_user_settings.mode == running_mode::relay_egress)
	{
		verify_client_destination(current_user_settings, error_msg);
	}

	if (!current_user_settings.stun_server.empty() && current_user_settings.mode != running_mode::relay)
	{
		if (current_user_settings.listen_ports.size() > 1)
			error_msg.emplace_back("do not specify multiple listen ports when STUN Server is set");

		if (current_user_settings.listen_on.size() > 1)
			error_msg.emplace_back("do not specify multiple listen addresses when STUN Server is set");
	}

	if (!current_user_settings.log_directory.empty() &&
		current_user_settings.mode != running_mode::relay_ingress &&
		current_user_settings.mode != running_mode::relay_egress)
	{
		if (std::filesystem::exists(current_user_settings.log_directory))
		{
			if (std::filesystem::is_directory(current_user_settings.log_directory))
			{
				std::string filename;
				switch (current_user_settings.mode)
				{
				case running_mode::client:
					filename = "client_output.log";
					break;
				case running_mode::server:
					filename = "server_output.log";
					break;
				case running_mode::relay:
					filename = "relay_output.log";
					break;
				default:
					filename = "log_output.log";
					break;
				}
				current_user_settings.log_ip_address = current_user_settings.log_directory / "ip_address.log";
				current_user_settings.log_messages = current_user_settings.log_directory / filename;
			}
			else
				error_msg.emplace_back("Log Path is not directory");
		}
		else
		{
			error_msg.emplace_back("Log Path does not exist");
		}
	}

	if (current_user_settings.ip_version_only == (ip_only_options::ipv4 | ip_only_options::ipv6))
		error_msg.emplace_back("Both ipv4_only and ipv6_only are set as true");

	if (error_msg.empty() && current_user_settings.ingress != nullptr)
	{
		check_settings(*current_user_settings.ingress, error_msg);
		if (uint32_t sum = current_user_settings.ingress->udp_timeout + constant_values::extends_5_seconds; sum <= USHRT_MAX)
			current_user_settings.ingress->udp_timeout += constant_values::extends_5_seconds;
	}

	if (error_msg.empty() && current_user_settings.egress != nullptr)
	{
		check_settings(*current_user_settings.egress, error_msg);
		if (uint32_t sum = current_user_settings.egress->udp_timeout + constant_values::extends_5_seconds; sum <= USHRT_MAX)
			current_user_settings.egress->udp_timeout += constant_values::extends_5_seconds;
	}
}

void copy_settings(user_settings &inner, user_settings &outter)
{
	if (outter.mtu > 0)
		inner.mtu = outter.mtu;

	if (outter.fec_data > 0)
		inner.fec_data = outter.fec_data;

	if (outter.fec_redundant > 0)
		inner.fec_redundant = outter.fec_redundant;

	if (outter.kcp_setting != kcp_mode::unknow)
		inner.kcp_setting = outter.kcp_setting;

	if (outter.kcp_rcvwnd > 0)
		inner.kcp_rcvwnd = outter.kcp_rcvwnd;

	if (outter.kcp_sndwnd > 0)
		inner.kcp_sndwnd = outter.kcp_sndwnd;

	if (outter.outbound_bandwidth > 0)
		inner.outbound_bandwidth = outter.outbound_bandwidth;

	if (outter.inbound_bandwidth > 0)
		inner.inbound_bandwidth = outter.inbound_bandwidth;

	if (outter.encryption != encryption_mode::unknow &&
		outter.encryption != encryption_mode::empty &&
		outter.encryption != encryption_mode::none)
		inner.encryption = outter.encryption;

	if (!outter.encryption_password.empty())
		inner.encryption_password = outter.encryption_password;

	if (outter.udp_timeout > 0)
		inner.udp_timeout = outter.udp_timeout;

	if (outter.keep_alive > 0)
		inner.keep_alive = outter.keep_alive;

	if (outter.ip_version_only != ip_only_options::not_set)
		inner.ip_version_only = outter.ip_version_only;

	if (!outter.update_ipv4_path.empty())
		inner.update_ipv4_path = outter.update_ipv4_path;

	if (!outter.update_ipv6_path.empty())
		inner.update_ipv6_path = outter.update_ipv6_path;

	if (outter.blast)
		inner.blast = outter.blast;

	if (outter.fib_ingress)
		inner.fib_ingress = outter.fib_ingress;

	if (outter.fib_egress)
		inner.fib_egress = outter.fib_egress;
}

void verify_kcp_settings(user_settings &current_user_settings, std::vector<std::string> &error_msg)
{
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

		if (current_user_settings.kcp_sndwnd == 0)
			current_user_settings.kcp_sndwnd = constant_values::kcp_send_window * 2;

		if (current_user_settings.kcp_rcvwnd == 0)
			current_user_settings.kcp_rcvwnd = constant_values::kcp_receive_window * 2;

		break;
	}

	case kcp_mode::fast1:
	{
		current_user_settings.kcp_nodelay = 1;
		current_user_settings.kcp_interval = 0;
		current_user_settings.kcp_resend = 2;
		current_user_settings.kcp_nc = 1;
		if (current_user_settings.kcp_sndwnd == 0)
			current_user_settings.kcp_sndwnd = constant_values::kcp_send_window * 2;
		if (current_user_settings.kcp_rcvwnd == 0)
			current_user_settings.kcp_rcvwnd = constant_values::kcp_receive_window * 2;
		break;
	}

	case kcp_mode::fast2:
	{
		current_user_settings.kcp_nodelay = 2;
		current_user_settings.kcp_interval = 0;
		current_user_settings.kcp_resend = 2;
		current_user_settings.kcp_nc = 1;
		if (current_user_settings.kcp_sndwnd == 0)
			current_user_settings.kcp_sndwnd = constant_values::kcp_send_window * 2;
		if (current_user_settings.kcp_rcvwnd == 0)
			current_user_settings.kcp_rcvwnd = constant_values::kcp_receive_window * 2;
		break;
	}

	case kcp_mode::fast3:
	{
		current_user_settings.kcp_nodelay = 1;
		current_user_settings.kcp_interval = 1;
		current_user_settings.kcp_resend = 3;
		current_user_settings.kcp_nc = 1;
		if (current_user_settings.kcp_sndwnd == 0)
			current_user_settings.kcp_sndwnd = constant_values::kcp_send_window * 2;
		if (current_user_settings.kcp_rcvwnd == 0)
			current_user_settings.kcp_rcvwnd = constant_values::kcp_receive_window * 2;
		break;
	}

	case kcp_mode::fast4:
	{
		current_user_settings.kcp_nodelay = 2;
		current_user_settings.kcp_interval = 1;
		current_user_settings.kcp_resend = 3;
		current_user_settings.kcp_nc = 1;
		if (current_user_settings.kcp_sndwnd == 0)
			current_user_settings.kcp_sndwnd = constant_values::kcp_send_window * 2;
		if (current_user_settings.kcp_rcvwnd == 0)
			current_user_settings.kcp_rcvwnd = constant_values::kcp_receive_window * 2;
		break;
	}

	case kcp_mode::fast5:
	{
		current_user_settings.kcp_nodelay = 1;
		current_user_settings.kcp_interval = 1;
		current_user_settings.kcp_resend = 4;
		current_user_settings.kcp_nc = 1;
		if (current_user_settings.kcp_sndwnd == 0)
			current_user_settings.kcp_sndwnd = constant_values::kcp_send_window * 2;
		if (current_user_settings.kcp_rcvwnd == 0)
			current_user_settings.kcp_rcvwnd = constant_values::kcp_receive_window * 2;
		break;
	}

	case kcp_mode::fast6:
	{
		current_user_settings.kcp_nodelay = 2;
		current_user_settings.kcp_interval = 1;
		current_user_settings.kcp_resend = 4;
		current_user_settings.kcp_nc = 1;
		if (current_user_settings.kcp_sndwnd == 0)
			current_user_settings.kcp_sndwnd = constant_values::kcp_send_window * 2;
		if (current_user_settings.kcp_rcvwnd == 0)
			current_user_settings.kcp_rcvwnd = constant_values::kcp_receive_window * 2;
		break;
	}

	case kcp_mode::regular1:
	{
		current_user_settings.kcp_nodelay = 1;
		current_user_settings.kcp_interval = 1;
		current_user_settings.kcp_resend = 5;
		current_user_settings.kcp_nc = 1;
		if (current_user_settings.kcp_sndwnd == 0)
			current_user_settings.kcp_sndwnd = constant_values::kcp_send_window;
		if (current_user_settings.kcp_rcvwnd == 0)
			current_user_settings.kcp_rcvwnd = constant_values::kcp_receive_window;
		break;
	}

	case kcp_mode::regular2:
	{
		current_user_settings.kcp_nodelay = 2;
		current_user_settings.kcp_interval = 1;
		current_user_settings.kcp_resend = 5;
		current_user_settings.kcp_nc = 1;
		if (current_user_settings.kcp_sndwnd == 0)
			current_user_settings.kcp_sndwnd = constant_values::kcp_send_window;
		if (current_user_settings.kcp_rcvwnd == 0)
			current_user_settings.kcp_rcvwnd = constant_values::kcp_receive_window;
		break;
	}

	case kcp_mode::regular3:
	{
		current_user_settings.kcp_nodelay = 0;
		current_user_settings.kcp_interval = 1;
		current_user_settings.kcp_resend = 2;
		current_user_settings.kcp_nc = 1;
		if (current_user_settings.kcp_sndwnd == 0)
			current_user_settings.kcp_sndwnd = constant_values::kcp_send_window;
		if (current_user_settings.kcp_rcvwnd == 0)
			current_user_settings.kcp_rcvwnd = constant_values::kcp_receive_window;
		break;
	}

	case kcp_mode::regular4:
	{
		current_user_settings.kcp_nodelay = 0;
		current_user_settings.kcp_interval = 15;
		current_user_settings.kcp_resend = 2;
		current_user_settings.kcp_nc = 1;
		if (current_user_settings.kcp_sndwnd == 0)
			current_user_settings.kcp_sndwnd = constant_values::kcp_send_window;
		if (current_user_settings.kcp_rcvwnd == 0)
			current_user_settings.kcp_rcvwnd = constant_values::kcp_receive_window;
		break;
	}
	case kcp_mode::regular5:
		[[fallthrough]];
	case kcp_mode::unknow:
		[[fallthrough]];
	default:
	{
		current_user_settings.kcp_nodelay = 0;
		current_user_settings.kcp_interval = 30;
		current_user_settings.kcp_resend = 2;
		current_user_settings.kcp_nc = 1;
		if (current_user_settings.kcp_sndwnd == 0)
			current_user_settings.kcp_sndwnd = constant_values::kcp_send_window;
		if (current_user_settings.kcp_rcvwnd == 0)
			current_user_settings.kcp_rcvwnd = constant_values::kcp_receive_window;
		break;
	}
	}

	if (current_user_settings.mtu > 0)
	{
		int outter_verify_size = current_user_settings.encryption_password.empty() ?
			constant_values::iv_checksum_block_size : constant_values::encryption_block_reserve;
		int headers_length = constant_values::ip_header + constant_values::udp_header + constant_values::data_layer_header;

		if (current_user_settings.fec_data > 0 && current_user_settings.fec_redundant > 0)
			headers_length += constant_values::packet_layer_fec_header + constant_values::fec_container_header;
		else
			headers_length = constant_values::packet_layer_header;

		if (current_user_settings.mux_tunnels > 0)
			headers_length += constant_values::mux_data_wrapper_header;

		current_user_settings.kcp_mtu = current_user_settings.mtu - outter_verify_size - headers_length;
	}

	if (current_user_settings.kcp_mtu <= 0)
	{
		if (current_user_settings.fec_data > 0 && current_user_settings.fec_redundant > 0)
			current_user_settings.kcp_mtu = constant_values::kcp_mtu_with_fec;
		else
			current_user_settings.kcp_mtu = constant_values::kcp_mtu;
	}
}

void verify_server_listen_port(user_settings &current_user_settings, std::vector<std::string> &error_msg)
{
	if (current_user_settings.listen_ports.empty())
		error_msg.emplace_back("listen_port is not set");
}

void verify_client_destination(user_settings &current_user_settings, std::vector<std::string>& error_msg)
{
	if (current_user_settings.destination_dnstxt.empty())
	{
		if (current_user_settings.destination_ports.empty())
			error_msg.emplace_back("destination port setting incorrect");

		if (current_user_settings.destination_address_list.empty())
			error_msg.emplace_back("invalid destination_address setting");
	}
	else
	{
		if (!current_user_settings.destination_address_list.empty())
			error_msg.emplace_back("destination_address: DNS TXT setting exists");
		if (!current_user_settings.destination_ports.empty())
			error_msg.emplace_back("destination_port: DNS TXT setting exists");
	}
}

uint64_t bandwidth_from_string(const std::string &bandwidth, std::vector<std::string> &error_msg)
{
	if (bandwidth.empty())
		return 0;

	constexpr uint64_t kilo = 1000;
	constexpr uint64_t kibi = 1024;
	uint64_t full_bandwidth = 0;
	uint64_t bandwidth_expand = 1;
	std::string bandwidth_number = bandwidth;
	char unit = bandwidth.back();
	switch (unit)
	{
	case 'K':
		bandwidth_expand = kibi;
		break;
	case 'k':
		bandwidth_expand = kilo;
		break;
	case 'M':
		bandwidth_expand = kibi * kibi;
		break;
	case 'm':
		bandwidth_expand = kilo * kilo;
		break;
	case 'G':
		bandwidth_expand = kibi * kibi * kibi;
		break;
	case 'g':
		bandwidth_expand = kilo * kilo * kilo;
		break;
	case '0':
		break;
	case '1':
		break;
	case '2':
		break;
	case '3':
		break;
	case '4':
		break;
	case '5':
		break;
	case '6':
		break;
	case '7':
		break;
	case '8':
		break;
	case '9':
		break;
	default:
		error_msg.emplace_back("Unknow bandwidth unit");
		break;
	}

	if (bandwidth_expand > 0)
		bandwidth_number.pop_back();

	if (bandwidth_number.empty())
		return 0;

	try
	{
		full_bandwidth = std::stoi(bandwidth_number) * bandwidth_expand / 8;
	}
	catch (...)
	{
		error_msg.emplace_back("bandwidth convertion failed");
		return 0;
	}

	return full_bandwidth;
}
