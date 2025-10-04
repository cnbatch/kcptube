#include <iostream>
#include <limits>
#include <random>
#include <thread>
#include "tester.hpp"
#include "../shares/data_operations.hpp"
#include "../networks/dns_helper.hpp"

using namespace std::placeholders;
using namespace std::chrono;
using namespace std::literals;

test_mode::~test_mode()
{
	PrintResults();
}

bool test_mode::start()
{
	printf("Testing...\n");

	if (!current_settings.destination_dnstxt.empty())
	{
		std::vector<std::string> error_msg;
		std::string dnstxt_content = dns_helper::query_dns_txt(current_settings.destination_dnstxt, error_msg);
		if (!error_msg.empty())
		{
			for (auto &msg : error_msg)
			{
				std::cerr << msg << "\n";
			}
			return false;
		}

		auto [host_address, ip_address, port_num] = dns_helper::dns_split_address(dnstxt_content, error_msg);
		if (error_msg.empty())
		{
			current_settings.destination_address_list.resize(1);
			current_settings.destination_address_list.front() = ip_address.to_string();
			current_settings.destination_ports.resize(1);
			current_settings.destination_ports.front() = port_num;
			target_address.resize(1);
			target_address.front() = std::make_shared<asio::ip::address>(ip_address);
		}
	}

	switch (current_settings.mode)
	{
	case running_mode::client:
	{
		destination_ports = current_settings.destination_ports;
		break;
	}
	case running_mode::relay:
	{
		if (current_settings.egress == nullptr)
		{
			std::cerr << "Incorrect config file.";
			return false;
		}
		destination_ports = current_settings.egress->destination_ports;
		break;
	}
	default:
		return false;
		break;
	}

	if (destination_ports.empty())
		return false;

	target_address.resize(current_settings.destination_address_list.size());
	success_ports.resize(current_settings.destination_address_list.size());
	failure_ports.resize(current_settings.destination_address_list.size());

	for (size_t i = 0; i < current_settings.destination_address_list.size(); i++)
	{
		for (uint16_t destination_port : destination_ports)
		{
			std::shared_ptr<kcp_mappings> hs = create_handshake(i, destination_port);
			if (hs == nullptr)
			{
				std::string error_message = time_to_string_with_square_brackets() + "establish handshake failed\n";
				std::cerr << error_message;
				print_message_to_file(error_message, current_settings.log_messages);
				return false;
			}

			hs->egress_kcp->Update();
			uint32_t next_update_time = hs->egress_kcp->Refresh();
			kcp_updater.submit(hs->egress_kcp, next_update_time);

			std::unique_lock lock_handshake{ mutex_handshakes };
			handshakes[hs.get()] = hs;
			lock_handshake.unlock();
		}
	}

	timer_find_expires.expires_after(gbv_expring_update_interval);
	timer_find_expires.async_wait([this](const asio::error_code &e) { find_expires(e); });

	return true;
}

int test_mode::kcp_sender(const char *buf, int len, void *user)
{
	if (user == nullptr)
		return 0;

	kcp_mappings *kcp_mappings_ptr = (kcp_mappings *)user;
	if (current_settings.fec_data == 0 || current_settings.fec_redundant == 0)
	{
		auto [new_buffer, buffer_size] = packet::create_packet((const uint8_t *)buf, len);
		data_sender(kcp_mappings_ptr, std::move(new_buffer), buffer_size);
	}
	else
	{
		fec_control_data &fec_controllor = kcp_mappings_ptr->fec_egress_control;
		int conv = kcp_mappings_ptr->egress_kcp->GetConv();
		auto [fec_data_buffer, fec_data_buffer_size] = packet::create_fec_data_packet(
			(const uint8_t*)buf, len, fec_controllor.fec_snd_sn.load(), fec_controllor.fec_snd_sub_sn.load());
		data_sender(kcp_mappings_ptr, std::move(fec_data_buffer), fec_data_buffer_size);
	}

	return 0;
}

void test_mode::data_sender(kcp_mappings *kcp_mappings_ptr, std::unique_ptr<uint8_t[]> new_buffer, size_t buffer_size)
{
	auto [error_message, cipher_size] = encrypt_data(current_settings.encryption_password, current_settings.encryption, new_buffer.get(), (int)buffer_size);
	std::shared_ptr<forwarder> egress_forwarder = std::atomic_load(&(kcp_mappings_ptr->egress_forwarder));
	if (egress_forwarder == nullptr || !error_message.empty() || cipher_size == 0)
		return;
	std::shared_ptr<udp::endpoint> egress_target_endpoint = std::atomic_load(&(kcp_mappings_ptr->egress_target_endpoint));
	egress_forwarder->async_send_out(std::move(new_buffer), cipher_size, egress_target_endpoint);
}

std::unique_ptr<udp::endpoint> test_mode::get_udp_target(std::shared_ptr<forwarder> target_connector, size_t index)
{
	std::shared_ptr<asio::ip::address> target = std::atomic_load(&target_address[index]);
	if (target != nullptr)
	{
		return std::make_unique<udp::endpoint>(*target, 0);
	}

	return update_udp_target(target_connector, index);
}

std::unique_ptr<udp::endpoint> test_mode::update_udp_target(std::shared_ptr<forwarder> target_connector, size_t index)
{
	std::unique_ptr<udp::endpoint> udp_target;
	asio::error_code ec;
	for (int i = 0; i <= gbv_retry_times; ++i)
	{
		const std::string &destination_address = current_settings.destination_address_list[index];
		udp::resolver::results_type udp_endpoints = target_connector->get_remote_hostname(destination_address, 0, ec);
		if (ec)
		{
			std::string error_message = time_to_string_with_square_brackets() + ec.message() + "\n";
			std::cerr << error_message;
			print_message_to_file(error_message, current_settings.log_messages);
			std::this_thread::sleep_for(std::chrono::seconds(gbv_retry_waits));
		}
		else if (udp_endpoints.size() == 0)
		{
			std::string error_message = time_to_string_with_square_brackets() + "destination address not found\n";
			std::cerr << error_message;
			print_message_to_file(error_message, current_settings.log_messages);
			std::this_thread::sleep_for(std::chrono::seconds(gbv_retry_waits));
		}
		else
		{
			udp_target = std::make_unique<udp::endpoint>(*udp_endpoints.begin());
			std::atomic_store(&target_address[index], std::make_shared<asio::ip::address>(udp_target->address()));
			break;
		}
	}

	return std::move(udp_target);
}


bool test_mode::handshake_timeout_detection(kcp_mappings *kcp_mappings_ptr)
{
	if (kcp_mappings_ptr == nullptr)
		return true;

	int64_t right_now = packet::right_now();
	int64_t time_diff = calculate_difference(kcp_mappings_ptr->handshake_setup_time.load(), right_now);
	if (time_diff < gbv_handshake_timeout)
		return false;

	auto func = [this, kcp_mappings_ptr]() { handshake_test_failure(kcp_mappings_ptr); };
	asio::post(io_context, func);
	return true;
}

std::shared_ptr<kcp_mappings> test_mode::create_handshake(size_t index, asio::ip::port_type test_port)
{
	std::shared_ptr<KCP::KCP> handshake_kcp = std::make_shared<KCP::KCP>();
	std::shared_ptr<kcp_mappings> handshake_kcp_mappings = std::make_shared<kcp_mappings>();
	handshake_kcp->SetUserData(handshake_kcp_mappings.get());
	handshake_kcp_mappings->egress_kcp = handshake_kcp;
	handshake_kcp_mappings->connection_protocol = protocol_type::not_care;
	handshake_kcp_mappings->hopping_timestamp.store(LLONG_MAX);
	handshake_kcp_mappings->handshake_setup_time.store(packet::right_now());
	handshake_kcp_mappings->remote_output_address = "";
	handshake_kcp_mappings->remote_output_port = 0;
	std::atomic_store(&(handshake_kcp_mappings->ingress_source_endpoint), std::make_shared<udp::endpoint>());
	std::atomic_store(&(handshake_kcp_mappings->egress_target_endpoint), std::make_shared<udp::endpoint>());
	std::atomic_store(&(handshake_kcp_mappings->egress_previous_target_endpoint), std::make_shared<udp::endpoint>());

	std::shared_ptr<forwarder> udp_forwarder = nullptr;
	try
	{
		auto udp_func = std::bind(&test_mode::handle_handshake, this, _1, _2, _3, _4, _5);
		udp_forwarder = std::make_shared<forwarder>(io_context, handshake_kcp, udp_func, conn_options);
		if (udp_forwarder == nullptr)
			return nullptr;
	}
	catch (std::exception &ex)
	{
		std::string error_message = time_to_string_with_square_brackets() + "Cannnot create handshake connection. Error: " + ex.what() + "\n";
		std::cerr << error_message;
		print_message_to_file(error_message, current_settings.log_messages);
		return nullptr;
	}

	std::shared_ptr<udp::endpoint> egress_target_endpoint = get_udp_target(udp_forwarder, index);
	if (egress_target_endpoint == nullptr)
		return nullptr;
	egress_target_endpoint->port(test_port);
	std::atomic_store(&(handshake_kcp_mappings->egress_target_endpoint), egress_target_endpoint);
	handshake_kcp_mappings->egress_forwarder = udp_forwarder;
	handshake_kcp_mappings->egress_endpoint_index = index;
	if (current_settings.fec_data > 0 && current_settings.fec_redundant > 0)
	{
		size_t K = current_settings.fec_data;
		size_t N = K + current_settings.fec_redundant;
		handshake_kcp_mappings->fec_egress_control.fecc.reset_martix(K, N);
	}

	handshake_kcp->SetMTU(current_settings.kcp_mtu);
	handshake_kcp->NoDelay(1, 1, 3, 1);
	handshake_kcp->Update();
	handshake_kcp->RxMinRTO() = 10;
	handshake_kcp->SetBandwidth(current_settings.outbound_bandwidth, current_settings.inbound_bandwidth);
	handshake_kcp->SetOutput([this](const char *buf, int len, void *user) -> int
		{
			if (handshake_timeout_detection((kcp_mappings *)user))
				return 0;
			return kcp_sender(buf, len, user);
		});

	asio::error_code ec;
	if (current_settings.ip_version_only == ip_only_options::ipv4)
		udp_forwarder->send_out(create_raw_random_data(current_settings.kcp_mtu), local_empty_target_v4, ec);
	else
		udp_forwarder->send_out(create_raw_random_data(current_settings.kcp_mtu), local_empty_target_v6, ec);
	udp_forwarder->async_receive();

	std::vector<uint8_t> handshake_data = packet::create_test_connection_packet();
	if (handshake_kcp->Send((const char *)handshake_data.data(), handshake_data.size()) < 0)
		return nullptr;

	handshake_kcp->Update();

	return handshake_kcp_mappings;
}

void test_mode::on_handshake_test_success(kcp_mappings *handshake_ptr)
{
	std::shared_ptr<udp::endpoint> egress_target_endpoint = std::atomic_load(&(handshake_ptr->egress_target_endpoint));
	std::scoped_lock locker{ mutex_success_ports };
	success_ports[handshake_ptr->egress_endpoint_index].insert(egress_target_endpoint->port());
	handshake_test_cleanup(handshake_ptr);
}

void test_mode::handshake_test_failure(kcp_mappings *handshake_ptr)
{
	std::shared_ptr<udp::endpoint> egress_target_endpoint = std::atomic_load(&(handshake_ptr->egress_target_endpoint));
	std::scoped_lock locker{ mutex_failure_ports };
	failure_ports[handshake_ptr->egress_endpoint_index].insert(egress_target_endpoint->port());
	handshake_test_cleanup(handshake_ptr);
}

void test_mode::handshake_test_cleanup(kcp_mappings *handshake_ptr)
{
	std::shared_ptr<forwarder> egress_forwarder = std::atomic_load(&(handshake_ptr->egress_forwarder));
#if __GNUC__ == 12 && __GNUC_MINOR__ < 3
	handshake_ptr->egress_forwarder.store(nullptr);
#else
	handshake_ptr->egress_forwarder = nullptr;
#endif
	egress_forwarder->remove_callback();
	egress_forwarder->stop();
	std::unique_lock lock_handshake{ mutex_handshakes };
	auto session_iter = handshakes.find(handshake_ptr);
	if (session_iter == handshakes.end())
		return;
	if (session_iter->second != nullptr)
		kcp_updater.remove(handshake_ptr->egress_kcp);
	handshakes.erase(session_iter);
	lock_handshake.unlock();
}

void test_mode::handle_handshake(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number)
{
	if (data == nullptr || data_size == 0 || kcp_ptr == nullptr)
		return;

	auto [error_message, plain_size] = decrypt_data(current_settings.encryption_password, current_settings.encryption, data.get(), (int)data_size);

	if (!error_message.empty())
	{
		std::cerr << error_message << "\n";
		print_message_to_file(error_message, current_settings.log_messages);
		return;
	}

	auto [packet_timestamp, data_ptr, packet_data_size] = packet::unpack(data.get(), plain_size);
	if (packet_data_size == 0)
		return;
	auto timestamp = packet::right_now();
	if (calculate_difference<int64_t>((uint32_t)timestamp, packet_timestamp) > gbv_time_gap_seconds)
		return;

	if (current_settings.fec_data > 0 && current_settings.fec_redundant > 0)
	{
		auto [packet_header, kcp_data_ptr, kcp_data_size] = packet::unpack_fec(data.get(), plain_size);
		data_ptr = kcp_data_ptr;
		packet_data_size = kcp_data_size;
	}

	if (kcp_ptr->Input((const char *)data_ptr, (long)packet_data_size) < 0)
		return;

	kcp_mappings *kcp_mappings_ptr = (kcp_mappings *)kcp_ptr->GetUserData();
	if (kcp_mappings_ptr == nullptr)
		return;

	while (true)
	{
		int buffer_size = kcp_ptr->PeekSize();
		if (buffer_size <= 0)
			break;

		std::unique_ptr<uint8_t[]> buffer_cache = std::make_unique_for_overwrite<uint8_t[]>(buffer_size);
		uint8_t *buffer_ptr = buffer_cache.get();

		int kcp_data_size = 0;
		if (kcp_data_size = kcp_ptr->Receive((char *)buffer_ptr, buffer_size); kcp_data_size < 0)
			break;

		auto [ftr, prtcl, unbacked_data_ptr, unbacked_data_size] = packet::unpack_inner(buffer_ptr, kcp_data_size);
		switch (ftr)
		{
		case feature::test_connection:
		{
			on_handshake_test_success(kcp_mappings_ptr);
			break;
		}
		default:
			break;
		}
	}
}

void test_mode::PrintResults()
{
	for (size_t i = 0; i < target_address.size(); i++)
	{
		std::shared_ptr<asio::ip::address> target = std::atomic_load(&target_address[i]);
		if (target == nullptr)
			continue;

		std::cout << "Connection Test Result #" + std::to_string(i) + " of \"" + current_settings.destination_address_list[i] << "\":\n";
		std::cout << "Selected IP Address: " << *target << "\n";

		if (success_ports[i].empty())
		{
			std::cout << "Success: NONE\n";
		}
		else
		{
			if (success_ports[i].size() == destination_ports.size())
			{
				std::cout << "Success: ALL (" << success_ports[i].size() << ")\n";
			}
			else
			{
				std::cout << "Success (" << success_ports[i].size() << "): ";
				for (auto port_number : success_ports[i])
				{
					std::cout << port_number << " ";
				}
				std::cout << "\n";
			}
		}

		if (failure_ports[i].empty())
		{
			std::cout << "Failure: NONE\n";
		}
		else
		{
			if (failure_ports[i].size() == destination_ports.size())
			{
				std::cout << "Failure: ALL (" << failure_ports[i].size() << ")\n";
			}
			else
			{
				std::cout << "Failure (" << failure_ports[i].size() << "): ";
				for (auto port_number : failure_ports[i])
				{
					std::cout << port_number << " ";
				}
				std::cout << "\n";
			}
		}

		std::cout << std::endl;
	}
}

void test_mode::find_expires(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
		return;
	
	std::shared_lock locker_handshake{ mutex_handshakes };
	if (handshakes.size() == 0)
		return;
	for (auto iter = handshakes.begin(); iter != handshakes.end(); ++iter)
	{
		kcp_mappings *kcp_mappings_raw_ptr = iter->first;
		handshake_timeout_detection(kcp_mappings_raw_ptr);
	}
	locker_handshake.unlock();

	timer_find_expires.expires_after(gbv_expring_update_interval);
	timer_find_expires.async_wait([this](const asio::error_code &e) { find_expires(e); });
}
