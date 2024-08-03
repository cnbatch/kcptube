#include <algorithm>
#include <cmath>
#include <iostream>
#include <iterator>
#include <fstream>
#include <limits>
#include <thread>

#include <asio.hpp>

#include "shares/share_defines.hpp"
#include "shares/string_utils.hpp"
#include "networks/connections.hpp"
#include "modes/client.hpp"
#include "modes/relay.hpp"
#include "modes/server.hpp"
#include "modes/tester.hpp"


int main(int argc, char *argv[])
{
#ifdef __cpp_lib_format
	std::cout << std::format("{} version 20240803\n", app_name);
	if (argc <= 1)
	{
		std::cout << std::format("Usage: {} config1.conf\n", app_name);
		std::cout << std::format("       {} config1.conf config2.conf...\n", app_name);
		std::cout << std::format("Connectivity Testing:\n");
		std::cout << std::format("       {} --try config1.conf\n", app_name);
		std::cout << std::format("       {} --try config1.conf config2.conf...\n", app_name);
		std::cout << std::format("       {} config1.conf --try\n", app_name);
		std::cout << std::format("       {} config1.conf config2.conf... --try\n", app_name);
		return 0;
	}
#else
	std::cout << app_name << " version 20240803\n";
	if (argc <= 1)
	{
		std::cout << "Usage: " << app_name << " config1.conf\n";
		std::cout << "       " << app_name << " config1.conf config2.conf...\n";
		std::cout << "Connectivity Testing:\n";
		std::cout << "       " << app_name << " --try config1.conf\n";
		std::cout << "       " << app_name << " --try config1.conf config2.conf...\n";
		std::cout << "       " << app_name << " config1.conf --try\n";
		std::cout << "       " << app_name << " config1.conf config2.conf... --try\n";
		return 0;
	}
#endif

	constexpr size_t task_count_limit = 8192u;
	uint16_t thread_group_count = 1;
	int io_thread_count = 1;
	if (std::thread::hardware_concurrency() > 3)
	{
		auto thread_counts = std::thread::hardware_concurrency();
		thread_group_count = (uint16_t)(thread_counts / 2);
		io_thread_count = (int)std::log2(thread_counts);
	}

	asio::io_context ioc{ io_thread_count };

	KCP::KCPUpdater kcp_updater;
	std::unique_ptr<ttp::task_group_pool> kcp_data_sender;
	ttp::task_group_pool task_groups_local{ thread_group_count };
	ttp::task_group_pool task_groups_peer{ thread_group_count };

	if (std::thread::hardware_concurrency() > 3)
		kcp_data_sender = std::make_unique<ttp::task_group_pool>(std::thread::hardware_concurrency());

	std::vector<client_mode> clients;
	std::vector<relay_mode> relays;
	std::vector<server_mode> servers;
	std::vector<test_mode> testers;
	std::vector<user_settings> profile_settings;

	bool error_found = false;
	bool check_config = false;
	bool test_connection = false;

	for (int i = 1; i < argc; ++i)
	{
		if (str_utils::to_lower_copy(argv[i]) == "--try")
		{
			test_connection = true;
			continue;
		}
		if (str_utils::to_lower_copy(argv[i]) == "--check-config")
		{
			check_config = true;
			continue;
		}

		std::vector<std::string> lines;
		std::string current_line;
		std::ifstream input(argv[i]);
		while (std::getline(input, current_line))
		{
			lines.emplace_back(current_line);
		}

		std::vector<std::string> error_msg;
		user_settings current_settings = parse_from_args(lines, error_msg);
		std::filesystem::path config_input_name = argv[i];
		current_settings.config_filename = argv[i];
		if (!current_settings.log_directory.empty())
			current_settings.log_status = current_settings.log_directory / (config_input_name.filename().string() + "_status.log");
		profile_settings.emplace_back(std::move(current_settings));
		if (error_msg.size() > 0)
		{
#ifdef __cpp_lib_format
			std::cout << std::format("Error(s) found in setting file {}\n", argv[i]);
#else
			printf("Error(s) found in setting file %s\n", argv[i]);
#endif
			for (const std::string &each_one : error_msg)
			{
				std::cerr << "\t" << each_one << "\n";
			}
			std::cerr << std::endl;
			error_found = true;
			continue;
		}
	}

	std::cout << "Error Found in Configuration File(s): " << (error_found ? "Yes" : "No") << "\n";
	if (error_found || check_config)
		return 0;

	for (user_settings &settings : profile_settings)
	{
		switch (settings.mode)
		{
		case running_mode::client:
			if (test_connection)
				testers.emplace_back(test_mode(ioc, kcp_updater, kcp_data_sender, task_groups_local, task_groups_peer, task_count_limit, settings));
			else
				clients.emplace_back(client_mode(ioc, kcp_updater, kcp_data_sender, task_groups_local, task_groups_peer, task_count_limit, settings));
			break;
		case running_mode::relay:
			if (test_connection)
				testers.emplace_back(test_mode(ioc, kcp_updater, kcp_data_sender, task_groups_local, task_groups_peer, task_count_limit, settings));
			else
				relays.emplace_back(relay_mode(ioc, kcp_updater, kcp_data_sender, task_groups_local, task_groups_peer, task_count_limit, settings));
			break;
		case running_mode::server:
			servers.emplace_back(server_mode(ioc, kcp_updater, kcp_data_sender, task_groups_local, task_groups_peer, task_count_limit, settings));
			break;
		default:
			break;
		}
	}

	if (test_connection)
	{
		for (test_mode &tester : testers)
		{
			if (tester.start())
				ioc.run();
		}
		return 0;
	}

	bool started_up = !servers.empty() || !relays.empty() || !clients.empty();

	std::cout << "Servers: " << servers.size() << "\n";
	std::cout << "Relays: " << relays.size() << "\n";
	std::cout << "Clients: " << clients.size() << "\n";

	for (server_mode &server : servers)
	{
		started_up = server.start() && started_up;
	}

	for (relay_mode &relay : relays)
	{
		started_up = relay.start() && started_up;
	}

	for (client_mode &client : clients)
	{
		started_up = client.start() && started_up;
	}

	if (started_up)
		ioc.run();

	return 0;
}