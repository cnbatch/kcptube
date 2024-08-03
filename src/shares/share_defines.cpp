#include <cmath>
#include <iterator>
#include <stdexcept>
#include <fstream>
#include <mutex>
#include "share_defines.hpp"
#include "string_utils.hpp"
#include "configurations.hpp"

user_settings parse_from_args(const std::vector<std::string> &args, std::vector<std::string> &error_msg)
{
	user_settings current_user_settings;
	error_msg.clear();

	if (std::vector<std::string> error_messages = parse_running_mode(args, current_user_settings);
		!error_messages.empty())
	{
		error_msg.insert(error_msg.end(),
			std::make_move_iterator( error_messages.begin() ),
			std::make_move_iterator( error_messages.end() )
		);
		return current_user_settings;
	}

	if (std::vector<std::string> error_messages = parse_the_rest(args, current_user_settings);
		!error_messages.empty())
	{
		error_msg.insert(error_msg.end(),
			std::make_move_iterator(error_messages.begin()),
			std::make_move_iterator(error_messages.end())
		);
		return current_user_settings;
	}

	check_settings(current_user_settings, error_msg);

	return current_user_settings;
}

std::set<uint16_t> convert_to_port_list(const user_settings &current_settings)
{
	std::set<uint16_t> listen_ports;
	if (current_settings.listen_port != 0)
		listen_ports.insert(current_settings.listen_port);

	for (uint16_t port_number = current_settings.listen_port_start; port_number <= current_settings.listen_port_end; ++port_number)
	{
		if (port_number != 0)
			listen_ports.insert(port_number);
	}
	return listen_ports;
}

std::vector<uint8_t> create_raw_random_data(size_t mtu_size)
{
	std::vector<uint8_t> temp_array(mtu_size, 0);
	uint8_t *ptr = temp_array.data() + (mtu_size / 2);
	uint64_t *ptr_force_uint64_t = reinterpret_cast<uint64_t *>(ptr);
	*ptr_force_uint64_t = generate_random_number<uint64_t>();
	return temp_array;
}

std::string time_to_string()
{
	std::time_t t = std::time(nullptr);
	std::tm tm = *std::localtime(&t);
	std::ostringstream oss;
	oss << std::put_time(&tm, "%F %T %z");
	return oss.str();
}

std::string time_to_string_with_square_brackets()
{
	return "[" + time_to_string() + "] ";
}

void print_ip_to_file(const std::string &message, const std::filesystem::path &log_file)
{
	if (log_file.empty())
		return;

	static std::ofstream output_file{};
	static std::mutex mtx;
	std::unique_lock locker{ mtx };
	output_file.open(log_file, std::ios::out | std::ios::trunc);
	if (output_file.is_open() && output_file.good())
		output_file << message;
	output_file.close();
}

void print_message_to_file(const std::string &message, const std::filesystem::path &log_file)
{
	if (log_file.empty())
		return;

	static std::ofstream output_file{};
	static std::mutex mtx;
	std::unique_lock locker{ mtx };
	output_file.open(log_file, std::ios::out | std::ios::app);
	if (output_file.is_open() && output_file.good())
		output_file << message;
	output_file.close();
}

void print_status_to_file(const std::string &message, const std::filesystem::path &log_file)
{
	if (log_file.empty())
		return;

	static std::ofstream output_file{};
	static std::mutex mtx;
	std::unique_lock locker{ mtx };
	output_file.open(log_file, std::ios::out | std::ios::trunc);
	if (output_file.is_open() && output_file.good())
		output_file << message;
	output_file.close();
}

std::string to_speed_unit(size_t value, size_t duration_seconds)
{
	if (value == 0)
		return "0 Byte/s";

	if (duration_seconds == 0)
		duration_seconds = 1;

	size_t value_per_second = value / duration_seconds;
	int64_t length = value_per_second == 0 ? 0 : (int64_t)std::log10(value_per_second);

	if (length == 0)
		return (std::to_string(value) + " Bytes / " + std::to_string(duration_seconds) + " seconds");

	if (length <= 3)
		return (std::to_string(value_per_second) + " Bytes/s");

	if (length <= 6)
		return (std::to_string((value_per_second / 1024)) + " KiB/s");

	if (length <= 9)
		return (std::to_string((value_per_second / 1024 / 1024)) + " MiB/s");

	return (std::to_string((value_per_second / 1024 / 1024 / 1024)) + " GiB/s");
}
