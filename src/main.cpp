#include <algorithm>
#include <cmath>
#include <iostream>
#include <iterator>
#include <fstream>
#include <limits>
#include <thread>

#include <asio.hpp>

#include "shares/share_defines.hpp"
#include "networks/connections.hpp"
#include "networks/client.hpp"
#include "networks/server.hpp"


int main(int argc, char *argv[])
{
	if (argc <= 1)
	{
		char app_name[] = "kcptube";
		printf("%s version 20230423\n", app_name);
		printf("Usage: %s config1.conf\n", app_name);
		printf("       %s config1.conf config2.conf...\n", app_name);
		return 0;
	}

	constexpr size_t task_count_limit = (size_t)std::numeric_limits<int16_t>::max() >> 3;
	uint16_t thread_group_count = 1;
	int io_thread_count = 1;
	if (std::thread::hardware_concurrency() > 3)
	{
		auto thread_counts = std::thread::hardware_concurrency();
		thread_group_count = (uint16_t)(thread_counts / 2);
		io_thread_count = (int)std::log2(thread_counts);
	}

	ttp::task_group_pool task_groups_local{ thread_group_count };
	ttp::task_group_pool task_groups_peer{ thread_group_count };

	asio::io_context ioc{ io_thread_count };
	asio::io_context network_io{ io_thread_count };

	std::vector<client_mode> clients;
	std::vector<server_mode> servers;

	bool error_found = false;

	for (int i = 1; i < argc; ++i)
	{
		std::vector<std::string> lines;
		std::ifstream input(argv[i]);
		std::copy(
			std::istream_iterator<std::string>(input),
			std::istream_iterator<std::string>(),
			std::back_inserter(lines));

		std::vector<std::string> error_msg;
		user_settings settings = parse_from_args(lines, error_msg);
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

		switch (settings.mode)
		{
		case running_mode::client:
			clients.emplace_back(client_mode(ioc, network_io, task_groups_local, task_groups_peer, task_count_limit, settings));
			break;
		case running_mode::server:
			servers.emplace_back(server_mode(ioc, network_io, task_groups_local, task_groups_peer, task_count_limit, settings));
			break;
		default:
			break;
		}
	}

	std::cout << "error_found: " << (error_found ? "Yes" : "No") << "\n";
	std::cout << "Servers: " << servers.size() << "\n";
	std::cout << "Clients: " << clients.size() << "\n";

	bool started_up = true;

	for (server_mode &server : servers)
	{
		started_up = server.start() && started_up;
	}
	
	for (client_mode &client : clients)
	{
		started_up = client.start() && started_up;
	}

	if (!error_found && started_up)
	{
		std::thread([&] { network_io.run(); }).detach();
		ioc.run();
	}

	printf("bye\n");
	return 0;
}