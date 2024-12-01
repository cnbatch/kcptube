#include <cmath>
#include <iterator>
#include <stdexcept>
#include <fstream>
#include <mutex>
#include "share_defines.hpp"
#include "string_utils.hpp"
#include "configurations.hpp"

using namespace str_utils;

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

std::set<uint16_t> port_range_to_vector(const std::string &input_str, std::vector<std::string> &error_msg, const std::string &acting_role)
{
	std::set<uint16_t> numbers;
	auto pos = input_str.find("-");
	if (pos == std::string::npos)
	{
		bool failed = false;
		std::string port_str = trim_copy(input_str);
		try
		{
			if (auto port_number = std::stoi(port_str); port_number > 0 && port_number <= USHRT_MAX)
				numbers.insert(static_cast<uint16_t>(port_number));
			else
				failed = true;
		}
		catch (...)
		{
			failed = true;
		}

		if (failed)
			error_msg.emplace_back("invalid " + acting_role + "_port number: " + port_str);
		return numbers;
	}
	std::string start_port = input_str.substr(0, pos);
	std::string end_port = input_str.substr(pos + 1);
	trim(start_port);
	trim(end_port);

	if (start_port.empty() || end_port.empty())
	{
		error_msg.emplace_back("invalid " + acting_role + "_port range: " + input_str);
		return numbers;
	}

	uint16_t temp_port_start = 0;
	uint16_t temp_port_end = 0;

	try
	{
		if (auto port_number = std::stoi(start_port); port_number > 0 && port_number <= USHRT_MAX)
			temp_port_start = static_cast<uint16_t>(port_number);
		else
			error_msg.emplace_back("invalid " + acting_role + "_port_start number: " + start_port);
	}
	catch (...)
	{
		error_msg.emplace_back("invalid " + acting_role + "_port_start number: " + start_port);
	}

	try
	{
		if (auto port_number = std::stoi(end_port); port_number > 0 && port_number <= USHRT_MAX)
			temp_port_end = static_cast<uint16_t>(port_number);
		else
			error_msg.emplace_back("invalid " + acting_role + "_port_end number: " + end_port);
	}
	catch (...)
	{
		error_msg.emplace_back("invalid " + acting_role + "_port_end number: " + end_port);
	}

	if (temp_port_start >= temp_port_end)
	{
		error_msg.emplace_back("invalid port range: " + start_port + "-" + end_port);
		return numbers;
	}

	for (uint16_t i = temp_port_start; i <= temp_port_end; i++)
	{
		numbers.insert(i);
	}

	return numbers;
}

std::vector<uint16_t> string_to_port_numbers(const std::string &input_str, std::vector<std::string> &error_msg, const std::string &acting_role)
{
	std::set<uint16_t> port_numbers;
	if (input_str.find(',') == input_str.npos)
	{
		port_numbers = port_range_to_vector(input_str, error_msg, acting_role);
	}
	else
	{
		std::string temp;
		std::istringstream isstream(input_str);
		while (std::getline(isstream, temp, ','))
		{
			trim(temp);
			std::set<uint16_t> numbers = port_range_to_vector(temp, error_msg, acting_role);
			port_numbers.merge(numbers);
		}
	}
	return std::vector<uint16_t>(port_numbers.begin(), port_numbers.end());
}

std::vector<std::string> string_to_address_list(const std::string &input_str)
{
	std::string temp;
	std::istringstream isstream(input_str);
	std::vector<std::string> address_list;
	if (input_str.find(',') == input_str.npos)
	{
		address_list.emplace_back(trim_copy(input_str));
	}
	else
	{
		std::set<std::string> temp_address_list;
		while (std::getline(isstream, temp, ','))
		{
			trim(temp);
			temp_address_list.insert(temp);
		}
		address_list = std::vector<std::string>(temp_address_list.begin(), temp_address_list.end());
	}
	return address_list;
}

bool is_continuous(const std::vector<uint16_t> &numbers)
{
	if (numbers.empty())
		return false;

	if (numbers.size() == 1)
		return true;

	for (auto prev = numbers.begin(), iter = prev + 1; iter != numbers.end(); ++iter, ++prev)
	{
		if ((int)(*iter) - (int)(*prev) != 1)
			return false;
	}

	return true;
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
