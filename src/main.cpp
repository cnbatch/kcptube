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
#include "networks/client.hpp"
#include "networks/relay.hpp"
#include "networks/server.hpp"


int main(int argc, char *argv[])
{
	printf("%.*s version 20240302\n", (int)app_name.length(), app_name.data());

	if (argc <= 1)
	{
		printf("Usage: %.*s config1.conf\n", (int)app_name.length(), app_name.data());
		printf("       %.*s config1.conf config2.conf...\n", (int)app_name.length(), app_name.data());
		printf("Connectivity Testing:\n");
		printf("       %.*s --try config1.conf\n", (int)app_name.length(), app_name.data());
		printf("       %.*s --try config1.conf config2.conf...\n", (int)app_name.length(), app_name.data());
		printf("       %.*s config1.conf --try\n", (int)app_name.length(), app_name.data());
		printf("       %.*s config1.conf config2.conf... --try\n", (int)app_name.length(), app_name.data());
		return 0;
	}

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
		profile_settings.emplace_back(parse_from_args(lines, error_msg));
		if (error_msg.size() > 0)
		{
			printf("Error(s) found in setting file %s\n", argv[i]);
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
			settings.test_only = test_connection;
			clients.emplace_back(client_mode(ioc, kcp_updater, kcp_data_sender, task_groups_local, task_groups_peer, task_count_limit, settings));
			break;
		case running_mode::relay:
			relays.emplace_back(relay_mode(ioc, kcp_updater, kcp_data_sender, task_groups_local, task_groups_peer, task_count_limit, settings));
			break;
		case running_mode::server:
			servers.emplace_back(server_mode(ioc, kcp_updater, kcp_data_sender, task_groups_local, task_groups_peer, task_count_limit, settings));
			break;
		default:
			break;
		}
	}

	std::cout << "Servers: " << servers.size() << "\n";
	std::cout << "Relays: " << relays.size() << "\n";
	std::cout << "Clients: " << clients.size() << "\n";

	bool started_up = !servers.empty() || !relays.empty() || !clients.empty();

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
	{
		ioc.run();
	}

	return 0;
}