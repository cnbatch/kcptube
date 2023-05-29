#include <iostream>
#include <limits>
#include <random>
#include <thread>
#include "client.hpp"
#include "../shares/data_operations.hpp"

using namespace std::placeholders;
using namespace std::chrono;
using namespace std::literals;


udp_to_forwarder::~udp_to_forwarder()
{
	timer_send_data.cancel();
	timer_expiring_kcp.cancel();
	timer_find_expires.cancel();
	timer_keep_alive.cancel();
}

bool udp_to_forwarder::start()
{
	printf("start_up() running in client mode (UDP)\n");

	uint16_t port_number = current_settings.listen_port;
	if (port_number == 0)
		return false;

	udp::endpoint listen_on_ep;
	if (current_settings.ipv4_only)
		listen_on_ep = udp::endpoint(udp::v4(), port_number);
	else
		listen_on_ep = udp::endpoint(udp::v6(), port_number);

	if (!current_settings.listen_on.empty())
	{
		asio::error_code ec;
		asio::ip::address local_address = asio::ip::make_address(current_settings.listen_on, ec);
		if (ec)
		{
			std::string error_message = time_to_string_with_square_brackets() + "Listen Address incorrect - " + current_settings.listen_on + "\n";
			std::cerr << error_message;
			print_message_to_file(error_message, current_settings.log_messages);
			return false;
		}

		if (local_address.is_v4() && !current_settings.ipv4_only)
			listen_on_ep.address(asio::ip::make_address_v6(asio::ip::v4_mapped, local_address.to_v4()));
		else
			listen_on_ep.address(local_address);
	}

	try
	{
		udp_callback_t udp_func_ap = std::bind(&udp_to_forwarder::udp_listener_incoming, this, _1, _2, _3, _4);
		udp_access_point = std::make_unique<udp_server>(network_io, sequence_task_pool_local, task_limit, listen_on_ep, udp_func_ap);

		timer_send_data.expires_after(EXPRING_UPDATE_INTERVAL);
		timer_send_data.async_wait([this](const asio::error_code &e) { kcp_loop_updates(e); });

		timer_expiring_kcp.expires_after(KCP_UPDATE_INTERVAL);
		timer_expiring_kcp.async_wait([this](const asio::error_code &e) { expiring_kcp_loops(e); });

		timer_find_expires.expires_after(FINDER_EXPIRES_INTERVAL);
		timer_find_expires.async_wait([this](const asio::error_code &e) { find_expires(e); });

		if (current_settings.keep_alive > 0)
		{
			timer_keep_alive.expires_after(KEEPALIVE_UPDATE_INTERVAL);
			timer_keep_alive.async_wait([this](const asio::error_code& e) { keep_alive(e); });
		}
	}
	catch (std::exception &ex)
	{
		std::string error_message = time_to_string_with_square_brackets() + ex.what() + "\n";
		std::cerr << error_message;
		print_message_to_file(error_message, current_settings.log_messages);
		return false;
	}

	return true;
}

void udp_to_forwarder::udp_listener_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number)
{
	if (data == nullptr || data_size == 0)
		return;

	uint8_t *data_ptr = data.get();
	std::shared_ptr<KCP::KCP> kcp_session = nullptr;
	
	{
		std::shared_lock shared_locker_udp_session_map_to_kcp{ mutex_udp_local_session_map_to_kcp, std::defer_lock };
		std::unique_lock unique_locker_udp_session_map_to_kcp{ mutex_udp_local_session_map_to_kcp, std::defer_lock };
		shared_locker_udp_session_map_to_kcp.lock();
		auto iter = udp_local_session_map_to_kcp.find(peer);
		if (iter == udp_local_session_map_to_kcp.end())
		{
			shared_locker_udp_session_map_to_kcp.unlock();
			unique_locker_udp_session_map_to_kcp.lock();
			iter = udp_local_session_map_to_kcp.find(peer);
			if (iter == udp_local_session_map_to_kcp.end())
			{
				std::unique_lock locker_udp_session_map_to_handshake{ mutex_udp_address_map_to_handshake };
				auto handshake_iter = udp_address_map_to_handshake.find(peer);
				if (handshake_iter != udp_address_map_to_handshake.end())
				{
					std::shared_ptr<handshake> hs = handshake_iter->second;
					std::unique_lock locker_udp_seesion_caches{ mutex_udp_seesion_caches };
					udp_seesion_caches[hs].emplace_back(std::vector<uint8_t>(data_ptr, data_ptr + data_size));
					return;
				}

				const std::string& destination_address = current_settings.destination_address;
				uint16_t destination_port = current_settings.destination_port;
				if (destination_port == 0)
					destination_port = generate_new_port_number(current_settings.destination_port_start, current_settings.destination_port_end);

				std::shared_ptr<handshake> hs = std::make_shared<handshake>(current_settings, io_context);
				hs->call_on_success = [this](std::shared_ptr<handshake> ptr, uint32_t conv, uint16_t start_port, uint16_t end_port)
				{
					on_handshake_success(ptr, conv, start_port, end_port);
				};
				hs->call_on_failure = [this](std::shared_ptr<handshake> ptr, const std::string &error_message)
				{
					on_handshake_failure(ptr, error_message);
				};

				if (!hs->send_handshake(protocol_type::udp, destination_address, destination_port))
				{
					std::string error_message = time_to_string_with_square_brackets() + "establish handshake failed\n";
					std::cerr << error_message;
					print_message_to_file(error_message, current_settings.log_messages);
					return;
				}

				udp_address_map_to_handshake[peer] = hs;
				udp_handshake_map_to_address[hs] = peer;

				std::unique_lock locker_udp_seesion_caches{ mutex_udp_seesion_caches };
				udp_seesion_caches[hs].emplace_back(std::vector<uint8_t>(data_ptr, data_ptr + data_size));
				return;
			}
			else
			{
				kcp_session = iter->second->egress_kcp;
			}
		}
		else
		{
			kcp_session = iter->second->egress_kcp;
		}
	}

	if (kcp_session->WaitingForSend() >= kcp_session->GetSendWindowSize())
		return;

	size_t new_data_size = packet::create_data_packet(protocol_type::udp, data_ptr, data_size);

	kcp_session->Send((const char *)data_ptr, new_data_size);
	uint32_t next_refresh_time = kcp_session->Check(time_now_for_kcp());
	uint32_t conv = kcp_session->GetConv();

	std::shared_lock locker_kcp_channels{ mutex_kcp_looping };
	if (auto iter = kcp_looping.find(kcp_session); iter != kcp_looping.end())
		iter->second.store(next_refresh_time);
}


void udp_to_forwarder::udp_forwarder_incoming_to_udp(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number)
{
	if (data == nullptr || data_size == 0 || kcp_ptr == nullptr)
		return;

	uint8_t *data_ptr = data.get();
	auto [error_message, plain_size] = decrypt_data(current_settings.encryption_password, current_settings.encryption, data_ptr, (int)data_size);

	if (!error_message.empty())
		return;

	udp_forwarder_incoming_to_udp_unpack(kcp_ptr, std::move(data), plain_size, peer, local_port_number);
}

void udp_to_forwarder::udp_forwarder_incoming_to_udp_unpack(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t plain_size, udp::endpoint peer, asio::ip::port_type local_port_number)
{
	uint8_t *data_ptr = data.get();
	uint32_t conv = KCP::KCP::GetConv(data_ptr);
	if (kcp_ptr->GetConv() != conv)
	{
		std::stringstream ss;
		ss << peer;
		std::string error_message = time_to_string_with_square_brackets() +
			"UDP<->KCP, conv is not the same as record : conv = " + std::to_string(conv) +
			", local kcp : " + std::to_string(kcp_ptr->GetConv()) + "\n";
		std::cerr << error_message;
		print_message_to_file(error_message, current_settings.log_messages);
		return;
	}

	if (kcp_ptr->Input((const char *)data_ptr, (long)plain_size) < 0)
		return;

	while (true)
	{
		int buffer_size = kcp_ptr->PeekSize();
		if (buffer_size <= 0)
			break;

		std::unique_ptr<uint8_t[]> buffer_cache = std::make_unique<uint8_t[]>(buffer_size);
		uint8_t *buffer_ptr = buffer_cache.get();

		int kcp_data_size = 0;
		if (kcp_data_size = kcp_ptr->Receive((char *)buffer_ptr, buffer_size); kcp_data_size < 0)
			break;

		auto [packet_timestamp, ftr, prtcl, unbacked_data_ptr, unbacked_data_size] = packet::unpack(buffer_ptr, kcp_data_size);
		if (prtcl != protocol_type::udp)
		{
			continue;
		}

		auto timestamp = packet::right_now();
		if (calculate_difference(timestamp, packet_timestamp) > TIME_GAP)
			continue;

		kcp_mappings *kcp_mappings_ptr = (kcp_mappings *)kcp_ptr->custom_data.load();
		udp::endpoint &udp_endpoint = kcp_mappings_ptr->ingress_source_endpoint;

		switch (ftr)
		{
		case feature::initialise:
		{
			std::string error_message = time_to_string_with_square_brackets() + "incorrect 'initialise' packet received\n";
			std::cerr << error_message;
			print_message_to_file(error_message, current_settings.log_messages);
			break;
		}
		case feature::failure:
		{
			std::string error_message = time_to_string_with_square_brackets() + "failure, error message: " + reinterpret_cast<char *>(unbacked_data_ptr) + "\n";
			std::cerr << error_message;
			print_message_to_file(error_message, current_settings.log_messages);
		}
		[[fallthrough]];
		case feature::disconnect:
		{
			process_disconnect(conv);
			break;
		}
		case feature::keep_alive:
			break;
		case feature::data:
		{
			udp_access_point->async_send_out(std::move(buffer_cache), unbacked_data_ptr, unbacked_data_size, udp_endpoint);

			std::shared_lock share_locker_egress{ kcp_mappings_ptr->mutex_egress_endpoint };
			if (kcp_mappings_ptr->egress_target_endpoint != peer && kcp_mappings_ptr->egress_previous_target_endpoint != peer)
			{
				share_locker_egress.unlock();
				std::scoped_lock lockers{ kcp_mappings_ptr->mutex_egress_endpoint, mutex_target_address };
				kcp_mappings_ptr->egress_previous_target_endpoint = kcp_mappings_ptr->egress_target_endpoint;
				kcp_mappings_ptr->egress_target_endpoint = peer;
				*target_address = peer.address();
			}
			break;
		}
		default:
			break;
		}
	}
}

int udp_to_forwarder::kcp_sender(const char *buf, int len, void * user)
{
	std::unique_ptr<uint8_t[]> new_buffer = std::make_unique<uint8_t[]>(len + BUFFER_EXPAND_SIZE);
	uint8_t *new_buffer_ptr = new_buffer.get();
	std::copy_n((const uint8_t *)buf, len, new_buffer_ptr);
	auto [error_message, cipher_size] = encrypt_data(current_settings.encryption_password, current_settings.encryption, new_buffer_ptr, len);
	if (!error_message.empty() || cipher_size == 0)
		return 0;

	kcp_mappings *kcp_mappings_ptr = (kcp_mappings *)user;
	kcp_mappings_ptr->egress_forwarder->async_send_out(std::move(new_buffer), cipher_size, kcp_mappings_ptr->egress_target_endpoint);
	change_new_port(kcp_mappings_ptr);
	return 0;
}

bool udp_to_forwarder::save_udp_target(std::shared_ptr<forwarder> target_connector, udp::endpoint & udp_target)
{
	if (target_address != nullptr)
	{
		uint16_t destination_port = current_settings.destination_port;
		if (destination_port == 0)
			destination_port = generate_new_port_number(current_settings.destination_port_start, current_settings.destination_port_end);

		udp_target = udp::endpoint(*target_address, destination_port);
		return true;
	}

	return update_udp_target(target_connector, udp_target);
}

bool udp_to_forwarder::update_udp_target(std::shared_ptr<forwarder> target_connector, udp::endpoint & udp_target)
{
	uint16_t destination_port = current_settings.destination_port;
	if (destination_port == 0)
		destination_port = generate_new_port_number(current_settings.destination_port_start, current_settings.destination_port_end);

	bool connect_success = false;
	asio::error_code ec;
	for (int i = 0; i <= RETRY_TIMES; ++i)
	{
		const std::string &destination_address = current_settings.destination_address;
		udp::resolver::results_type udp_endpoints = target_connector->get_remote_hostname(destination_address, destination_port, ec);
		if (ec)
		{
			std::string error_message = time_to_string_with_square_brackets() + ec.message() + "\n";
			std::cerr << error_message;
			print_message_to_file(error_message, current_settings.log_messages);
			std::this_thread::sleep_for(std::chrono::seconds(RETRY_WAITS));
		}
		else if (udp_endpoints.size() == 0)
		{
			std::string error_message = time_to_string_with_square_brackets() + "destination address not found\n";
			std::cerr << error_message;
			print_message_to_file(error_message, current_settings.log_messages);
			std::this_thread::sleep_for(std::chrono::seconds(RETRY_WAITS));
		}
		else
		{
			std::scoped_lock locker{ mutex_target_address };
			udp_target = *udp_endpoints.begin();
			target_address = std::make_unique<asio::ip::address>(udp_target.address());
			connect_success = true;
			break;
		}
	}

	return connect_success;
}

//udp::endpoint udp_to_forwarder::get_remote_address()
//{
//	udp::endpoint ep;
//	std::shared_lock locker{ mutex_udp_target };
//	ep = *udp_target;
//	locker.unlock();
//	return ep;
//}

void udp_to_forwarder::process_disconnect(uint32_t conv)
{
	std::scoped_lock lockers{ mutex_kcp_channels };
	auto kcp_channel_iter = kcp_channels.find(conv);
	if (kcp_channel_iter == kcp_channels.end())
		return;

	std::shared_ptr<kcp_mappings> kcp_mappings_ptr = kcp_channel_iter->second;
	std::shared_ptr<KCP::KCP> kcp_ptr = kcp_mappings_ptr->egress_kcp;

	if (std::scoped_lock locker_expiring_kcp{ mutex_expiring_kcp }; expiring_kcp.find(kcp_ptr) == expiring_kcp.end())
		expiring_kcp.insert({ kcp_mappings_ptr, packet::right_now() });

	if (std::scoped_lock locker_kcp_keepalive{mutex_kcp_keepalive}; kcp_keepalive.find(kcp_ptr) != kcp_keepalive.end())
		kcp_keepalive.erase(kcp_ptr);

	if (std::scoped_lock locker_kcp_looping{ mutex_kcp_looping }; kcp_looping.find(kcp_ptr) != kcp_looping.end())
		kcp_looping.erase(kcp_ptr);

	kcp_channels.erase(kcp_channel_iter);
}

void udp_to_forwarder::change_new_port(kcp_mappings *kcp_mappings_ptr)
{
	if (kcp_mappings_ptr->changeport_timestamp.load() > packet::right_now())
		return;
	kcp_mappings_ptr->changeport_timestamp += current_settings.dynamic_port_refresh;

	std::shared_ptr<KCP::KCP> kcp_ptr = kcp_mappings_ptr->egress_kcp;

	auto udp_func = std::bind(&udp_to_forwarder::udp_forwarder_incoming_to_udp, this, _1, _2, _3, _4, _5);
	auto udp_forwarder = std::make_shared<forwarder>(network_io, sequence_task_pool_peer, task_limit, kcp_ptr, udp_func, current_settings.ipv4_only);
	if (udp_forwarder == nullptr)
		return;

	uint16_t destination_port_start = current_settings.destination_port_start;
	uint16_t destination_port_end = current_settings.destination_port_end;
	if (destination_port_start != destination_port_end)
	{
		uint16_t new_port_numer = generate_new_port_number(destination_port_start, destination_port_end);
		std::shared_lock locker{ mutex_target_address };
		asio::ip::address temp_address = *target_address;
		locker.unlock();
		std::scoped_lock locker_egress{kcp_mappings_ptr->mutex_egress_endpoint};
		kcp_mappings_ptr->egress_target_endpoint.address(temp_address);
		kcp_mappings_ptr->egress_target_endpoint.port(new_port_numer);
	}

	asio::error_code ec;
	if (current_settings.ipv4_only)
		udp_forwarder->send_out(create_raw_random_data(current_settings.kcp_mtu), local_empty_target_v4, ec);
	else
		udp_forwarder->send_out(create_raw_random_data(current_settings.kcp_mtu), local_empty_target_v6, ec);

	if (ec)
		return;

	udp_forwarder->async_receive();

	std::shared_ptr<forwarder> old_forwarder = kcp_mappings_ptr->egress_forwarder;
	kcp_mappings_ptr->egress_forwarder = udp_forwarder;

	std::scoped_lock lock_expiring_forwarders{ mutex_expiring_forwarders };
	expiring_forwarders.insert({ old_forwarder, packet::right_now() });
}

void udp_to_forwarder::cleanup_expiring_forwarders()
{
	auto time_right_now = packet::right_now();

	std::scoped_lock lockers{ mutex_expiring_forwarders };
	for (auto iter = expiring_forwarders.begin(), next_iter = iter; iter != expiring_forwarders.end(); iter = next_iter)
	{
		++next_iter;
		auto &[udp_forwrder, expire_time] = *iter;
		int64_t time_elapsed = calculate_difference(time_right_now, expire_time);
		
		if (time_elapsed <= CLEANUP_WAITS / 2)
			continue;

		if (time_elapsed > CLEANUP_WAITS / 2 && time_elapsed < CLEANUP_WAITS)
		{
			udp_forwrder->remove_callback();
			udp_forwrder->stop();
			continue;
		}

		udp_forwrder->disconnect();
		expiring_forwarders.erase(iter);
	}
}

void udp_to_forwarder::cleanup_expiring_data_connections()
{
	auto time_right_now = packet::right_now();

	std::scoped_lock locker{ mutex_expiring_kcp };
	for (auto iter = expiring_kcp.begin(), next_iter = iter; iter != expiring_kcp.end(); iter = next_iter)
	{
		++next_iter;
		auto &[kcp_mappings_ptr, expire_time] = *iter;
		std::shared_ptr<KCP::KCP> kcp_ptr = kcp_mappings_ptr->egress_kcp;

		if (calculate_difference(time_right_now, expire_time) < CLEANUP_WAITS)
		{
			kcp_ptr->Update(time_now_for_kcp());
			continue;
		}

		kcp_ptr->SetOutput(empty_kcp_output);
		udp::endpoint &udp_endpoint = kcp_mappings_ptr->ingress_source_endpoint;
		//if (auto forwarder_iter = id_map_to_forwarder.find(conv);
		//	forwarder_iter != id_map_to_forwarder.end())
		{
			std::scoped_lock locker_expiring_forwarders{ mutex_expiring_forwarders };
			std::shared_ptr<forwarder> forwarder_ptr = kcp_mappings_ptr->egress_forwarder;
			forwarder_ptr->remove_callback();
			forwarder_ptr->stop();
			if (expiring_forwarders.find(forwarder_ptr) == expiring_forwarders.end())
				expiring_forwarders.insert({ forwarder_ptr, packet::right_now()});
		}

		{
			std::scoped_lock locker_udp_session_map_to_kcp {mutex_udp_local_session_map_to_kcp};
			udp_local_session_map_to_kcp.erase(udp_endpoint);
		}

		expiring_kcp.erase(iter);
	}
}

void udp_to_forwarder::loop_update_connections()
{
	std::shared_lock locker{ mutex_kcp_looping };
	for (auto iter = kcp_looping.begin(), next_iter = iter; iter != kcp_looping.end(); iter = next_iter)
	{
		++next_iter;
		auto &[kcp_ptr_weak, kcp_update_time] = *iter;
		std::shared_ptr<KCP::KCP> kcp_ptr = kcp_ptr_weak.lock();
		if (kcp_ptr == nullptr)
			continue;

		if (uint32_t kcp_refresh_time = time_now_for_kcp(); kcp_refresh_time >= kcp_update_time.load())
		{
			kcp_ptr->Update(kcp_refresh_time);
			uint32_t next_refresh_time = kcp_ptr->Check(kcp_refresh_time);
			kcp_update_time.store(next_refresh_time);
		}
	}
}

void udp_to_forwarder::loop_find_expires()
{
	std::scoped_lock locker{ mutex_kcp_channels };
	for (auto iter = kcp_channels.begin(), next_iter = iter; iter != kcp_channels.end(); iter = next_iter)
	{
		++next_iter;
		uint32_t conv = iter->first;
		std::shared_ptr<kcp_mappings> kcp_mappings_ptr = iter->second;
		std::shared_ptr<KCP::KCP> kcp_ptr = kcp_mappings_ptr->egress_kcp;

		forwarder *udp_forwarder = kcp_mappings_ptr->egress_forwarder.get();
		if (udp_forwarder->time_gap_of_receive() > current_settings.udp_timeout &&
			udp_forwarder->time_gap_of_send() > current_settings.udp_timeout)
		{
			if (std::scoped_lock locker_expiring_kcp{ mutex_expiring_kcp }; expiring_kcp.find(kcp_ptr) == expiring_kcp.end())
				expiring_kcp.insert({ kcp_mappings_ptr, packet::right_now() });

			if (std::scoped_lock locker_kcp_keepalive{mutex_kcp_keepalive}; kcp_keepalive.find(kcp_ptr) != kcp_keepalive.end())
				kcp_keepalive.erase(kcp_ptr);

			if (std::scoped_lock locker_kcp_looping{ mutex_kcp_looping }; kcp_looping.find(kcp_ptr) != kcp_looping.end())
				kcp_looping.erase(kcp_ptr);

			kcp_channels.erase(iter);
			kcp_ptr->SetOutput(empty_kcp_output);
		}
	}
}

void udp_to_forwarder::loop_keep_alive()
{
	std::shared_lock locker_kcp_looping{ mutex_kcp_keepalive };
	for (auto iter = kcp_keepalive.begin(), next_iter = iter; iter != kcp_keepalive.end(); iter = next_iter)
	{
		++next_iter;
		std::weak_ptr kcp_ptr_weak = iter->first;
		std::atomic<int64_t> &timestamp = iter->second;
		std::shared_ptr<KCP::KCP> kcp_ptr = kcp_ptr_weak.lock();
		if (kcp_ptr == nullptr)
			continue;

		if (timestamp.load() > packet::right_now())
			continue;
		timestamp += current_settings.keep_alive;
		
		std::vector<uint8_t> keep_alive_packet = packet::create_keep_alive_packet(protocol_type::udp);
		kcp_ptr->Send((const char*)keep_alive_packet.data(), keep_alive_packet.size());

		uint32_t next_refresh_time = kcp_ptr->Check(time_now_for_kcp());
		std::shared_lock locker_kcp_looping{ mutex_kcp_looping };
		if (auto iter = kcp_looping.find(kcp_ptr); iter != kcp_looping.end())
			iter->second.store(next_refresh_time);
		locker_kcp_looping.unlock();
	}
}

void udp_to_forwarder::kcp_loop_updates(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
		return;

	loop_update_connections();

	timer_send_data.expires_after(KCP_UPDATE_INTERVAL);
	timer_send_data.async_wait([this](const asio::error_code &e) { kcp_loop_updates(e); });
}

void udp_to_forwarder::expiring_kcp_loops(const asio::error_code & e)
{
	if (e == asio::error::operation_aborted)
		return;

	cleanup_expiring_forwarders();
	cleanup_expiring_data_connections();

	timer_expiring_kcp.expires_after(EXPRING_UPDATE_INTERVAL);
	timer_expiring_kcp.async_wait([this](const asio::error_code &e) { expiring_kcp_loops(e); });
}

void udp_to_forwarder::find_expires(const asio::error_code & e)
{
	if (e == asio::error::operation_aborted)
		return;

	loop_find_expires();

	timer_find_expires.expires_after(EXPRING_UPDATE_INTERVAL);
	timer_find_expires.async_wait([this](const asio::error_code &e) { find_expires(e); });
}

void udp_to_forwarder::keep_alive(const asio::error_code& e)
{
	if (e == asio::error::operation_aborted)
		return;

	loop_keep_alive();

	timer_keep_alive.expires_after(seconds{ current_settings.keep_alive });
	timer_keep_alive.async_wait([this](const asio::error_code &e) { keep_alive(e); });
}

void udp_to_forwarder::on_handshake_success(std::shared_ptr<handshake> handshake_ptr, uint32_t conv, uint16_t start_port, uint16_t end_port)
{
	auto [destination_address, destination_port] = handshake_ptr->get_cached_peer();
	if (start_port != 0 && end_port != 0)
	{
		current_settings.destination_port_start = start_port;
		current_settings.destination_port_end = end_port;
	}

	std::shared_ptr<kcp_mappings> kcp_mappings_ptr = std::make_shared<kcp_mappings>();
	std::scoped_lock handshake_lockers{ mutex_udp_address_map_to_handshake, mutex_udp_seesion_caches, mutex_udp_local_session_map_to_kcp };
	udp::endpoint peer = udp_handshake_map_to_address[handshake_ptr];

	std::shared_ptr<KCP::KCP> kcp_ptr = std::make_shared<KCP::KCP>(conv, nullptr);
	kcp_ptr->custom_data.store(kcp_mappings_ptr.get());
	auto udp_func = std::bind(&udp_to_forwarder::udp_forwarder_incoming_to_udp, this, _1, _2, _3, _4, _5);
	auto udp_forwarder = std::make_shared<forwarder>(network_io, sequence_task_pool_peer, task_limit, kcp_ptr, udp_func, current_settings.ipv4_only);
	if (udp_forwarder == nullptr)
		return;

	kcp_mappings_ptr->egress_kcp = kcp_ptr;
	kcp_mappings_ptr->egress_forwarder = udp_forwarder;
	kcp_mappings_ptr->ingress_source_endpoint = peer;
	bool success = save_udp_target(udp_forwarder, kcp_mappings_ptr->egress_target_endpoint);
	if (!success)
		return;
	kcp_mappings_ptr->egress_previous_target_endpoint = kcp_mappings_ptr->egress_target_endpoint;

	asio::error_code ec;
	if (current_settings.ipv4_only)
		udp_forwarder->send_out(create_raw_random_data(current_settings.kcp_mtu), local_empty_target_v4, ec);
	else
		udp_forwarder->send_out(create_raw_random_data(current_settings.kcp_mtu), local_empty_target_v6, ec);

	if (ec)
		return;
	udp_forwarder->async_receive();

	//kcp_ptr->ReplaceUserPtr(udp_forwarder.get());
	kcp_ptr->SetMTU(current_settings.kcp_mtu);
	kcp_ptr->SetWindowSize(current_settings.kcp_sndwnd, current_settings.kcp_rcvwnd);
	kcp_ptr->NoDelay(current_settings.kcp_nodelay, current_settings.kcp_interval, current_settings.kcp_resend, current_settings.kcp_nc);
	kcp_ptr->RxMinRTO() = 10;
	kcp_ptr->SetBandwidth(current_settings.outbound_bandwidth, current_settings.inbound_bandwidth);
	kcp_ptr->SetOutput([this](const char *buf, int len, void *user) -> int
		{
			return kcp_sender(buf, len, user);
		});
	kcp_ptr->Update(time_now_for_kcp());

	for (auto &data : udp_seesion_caches[handshake_ptr])
	{
		std::vector<uint8_t> new_data = packet::create_data_packet(protocol_type::udp, data);
		kcp_ptr->Send((const char *)new_data.data(), new_data.size());
		kcp_ptr->Update(time_now_for_kcp());
	}

	udp_address_map_to_handshake.erase(peer);
	udp_seesion_caches.erase(handshake_ptr);
	udp_handshake_map_to_address.erase(handshake_ptr);

	if (current_settings.dynamic_port_refresh == 0)
		kcp_mappings_ptr->changeport_timestamp.store(LLONG_MAX);
	else
		kcp_mappings_ptr->changeport_timestamp.store(packet::right_now() + current_settings.dynamic_port_refresh);

	if (current_settings.keep_alive > 0)
	{
		std::scoped_lock locker { mutex_kcp_keepalive };
		kcp_keepalive[kcp_ptr].store(packet::right_now() + current_settings.keep_alive);
	}

	std::scoped_lock lockers{ mutex_kcp_channels, mutex_kcp_looping };
	udp_local_session_map_to_kcp[peer] = kcp_mappings_ptr;
	kcp_channels[conv] = kcp_mappings_ptr;
	kcp_looping[kcp_ptr].store(0);
}

void udp_to_forwarder::on_handshake_failure(std::shared_ptr<handshake> handshake_ptr, const std::string &error_message)
{
	std::cerr << time_to_string_with_square_brackets()  << error_message << "\n";
	print_message_to_file(time_to_string_with_square_brackets() + error_message + "\n", current_settings.log_messages);
	std::scoped_lock lockers{ mutex_udp_address_map_to_handshake, mutex_udp_seesion_caches };
	auto session_iter = udp_handshake_map_to_address.find(handshake_ptr);
	if (session_iter == udp_handshake_map_to_address.end())
		return;
	udp::endpoint peer = session_iter->second;
	udp_address_map_to_handshake.erase(peer);
	udp_seesion_caches.erase(handshake_ptr);
	udp_handshake_map_to_address.erase(session_iter);
}
