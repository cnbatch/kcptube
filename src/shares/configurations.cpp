#include <climits>
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

	for (const std::string &arg : args)
	{
		auto line = trim_copy(arg);
		if (line.empty() || line[0] == '#')
			continue;
		auto eq = line.find_first_of("=");
		std::string name = line.substr(0, eq);
		trim(name);
		to_lower(name);
		std::string value;
		std::string original_value;
		if (eq == std::string::npos)
		{
			if (line[0] != '[' || line[line.length() - 1] != ']')
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
				current_settings->listen_on = original_value;
				break;

			case strhash("listen_port"):
				if (auto pos = value.find("-"); pos == std::string::npos)
				{
					if (auto port_number = std::stoi(value); port_number > 0 && port_number < USHRT_MAX)
						current_settings->listen_port = static_cast<uint16_t>(port_number);
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

					if (auto port_number = std::stoi(start_port); port_number > 0 && port_number < USHRT_MAX)
						current_settings->listen_port_start = static_cast<uint16_t>(port_number);
					else
						error_msg.emplace_back("invalid listen_port_start number: " + start_port);

					if (auto port_number = std::stoi(end_port); port_number > 0 && port_number < USHRT_MAX)
						current_settings->listen_port_end = static_cast<uint16_t>(port_number);
					else
						error_msg.emplace_back("invalid listen_port_end number: " + end_port);
				}
				break;

			case strhash("dport_refresh"):	// only for client and relay
				if (auto time_interval = std::stoi(value); time_interval >= 0 && time_interval <= SHRT_MAX)
					current_settings->dynamic_port_refresh = static_cast<int16_t>(time_interval);
				else if (time_interval > SHRT_MAX)
					current_settings->dynamic_port_refresh = SHRT_MAX;
				break;

			case strhash("destination_port"):
				if (auto pos = value.find("-"); pos == std::string::npos)
				{
					if (auto port_number = std::stoi(value); port_number > 0 && port_number < USHRT_MAX)
						current_settings->destination_port = static_cast<uint16_t>(port_number);
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

					if (auto port_number = std::stoi(start_port); port_number > 0 && port_number < USHRT_MAX)
						current_settings->destination_port_start = static_cast<uint16_t>(port_number);
					else
						error_msg.emplace_back("invalid destination_port_start number: " + start_port);

					if (auto port_number = std::stoi(end_port); port_number > 0 && port_number < USHRT_MAX)
						current_settings->destination_port_end = static_cast<uint16_t>(port_number);
					else
						error_msg.emplace_back("invalid destination_port_end number: " + end_port);
				}
				break;


			case strhash("destination_address"):
				current_settings->destination_address = value;
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
				current_settings->ipv4_only = yes;
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

			default:
				error_msg.emplace_back("unknow option: " + arg);
			}
		}
		catch (const std::exception &ex)
		{
			error_msg.emplace_back("invalid input: '" + arg + "'" + ", " + ex.what());
		}
	}

	return error_msg;
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

	if (current_user_settings.encryption == encryption_mode::empty ||
		current_user_settings.encryption == encryption_mode::unknow ||
		current_user_settings.encryption == encryption_mode::none)
	{
		current_user_settings.kcp_mtu -= constant_values::checksum_block_size;
	}
	else if (current_user_settings.encryption_password.empty())
	{
		error_msg.emplace_back("encryption_password is not set");
	}

	if (current_user_settings.mode == running_mode::client)
	{
		if (current_user_settings.listen_port == 0)
			error_msg.emplace_back("listen_port is not set");

		if (current_user_settings.listen_port_start > 0)
			error_msg.emplace_back("listen_port_start should not be set");

		if (current_user_settings.listen_port_end > 0)
			error_msg.emplace_back("listen_port_end should not be set");

		verify_client_destination(current_user_settings, error_msg);
	}

	if (current_user_settings.mode == running_mode::server)
	{
		verify_server_listen_port(current_user_settings, error_msg);

		if (current_user_settings.destination_port == 0)
			error_msg.emplace_back("destination_port is not set");

		if (current_user_settings.destination_port_start > 0)
			error_msg.emplace_back("destination_port_start should not be set");

		if (current_user_settings.destination_port_end > 0)
			error_msg.emplace_back("destination_port_end should not be set");

		if (current_user_settings.destination_address.empty())
			error_msg.emplace_back("invalid destination_address setting");
	
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
		if (current_user_settings.listen_port == 0)
			error_msg.emplace_back("do not specify multiple listen ports when STUN Server is set");
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

	if (outter.ipv4_only)
		inner.ipv4_only = outter.ipv4_only;
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
		current_user_settings.kcp_interval = 1;
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
		current_user_settings.kcp_interval = 1;
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
		current_user_settings.kcp_interval = 1;
		current_user_settings.kcp_resend = 3;
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
		current_user_settings.kcp_interval = 1;
		current_user_settings.kcp_resend = 0;
		current_user_settings.kcp_nc = 1;
		if (current_user_settings.kcp_sndwnd == 0)
			current_user_settings.kcp_sndwnd = constant_values::kcp_send_window;
		if (current_user_settings.kcp_rcvwnd == 0)
			current_user_settings.kcp_rcvwnd = constant_values::kcp_receive_window;
		break;
	}
	}

	if (current_user_settings.kcp_mtu < 0)
		current_user_settings.kcp_mtu = constant_values::kcp_mtu;
}

void verify_server_listen_port(user_settings &current_user_settings, std::vector<std::string> &error_msg)
{
	bool use_dynamic_ports = current_user_settings.listen_port_start || current_user_settings.listen_port_end;
	if (use_dynamic_ports)
	{
		if (current_user_settings.listen_port_start == 0)
			error_msg.emplace_back("listen_port_start is missing");

		if (current_user_settings.listen_port_end == 0)
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
		if (current_user_settings.listen_port == 0)
			error_msg.emplace_back("listen_port is not set");
	}
}

void verify_client_destination(user_settings &current_user_settings, std::vector<std::string>& error_msg)
{
	if (current_user_settings.destination_port == 0)
	{
		if(current_user_settings.destination_port_start == 0 ||
			current_user_settings.destination_port_end == 0)
		{
			error_msg.emplace_back("destination port setting incorrect");
		}
		
		if(current_user_settings.destination_port_start > current_user_settings.destination_port_end)
		{
			error_msg.emplace_back("destination end port must larger than start port");
		}
	}

	if (current_user_settings.destination_address.empty())
		error_msg.emplace_back("invalid destination_address setting");
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
