#include <iostream>
#include <limits>
#include <random>
#include <thread>
#include "client.hpp"

using namespace std::placeholders;
using namespace std::chrono;
using namespace std::literals;


udp_to_forwarder::~udp_to_forwarder()
{
	timer_send_data.cancel();
	timer_expiring_kcp.cancel();
	timer_find_expires.cancel();
	timer_change_ports.cancel();
}

bool udp_to_forwarder::start()
{
	printf("start_up() running in client mode (UDP)\n");

	uint16_t port_number = current_settings.listen_port;
	if (port_number == 0)
		return false;

	udp::endpoint listen_on_ep(udp::v6(), port_number);
	if (!current_settings.listen_on.empty())
	{
		asio::error_code ec;
		asio::ip::address local_address = asio::ip::make_address(current_settings.listen_on, ec);
		if (ec)
		{
			std::cerr << "Listen Address incorrect - " << current_settings.listen_on << "\n";
			return false;
		}

		if (local_address.is_v4())
			listen_on_ep.address(asio::ip::make_address_v6(asio::ip::v4_mapped, local_address.to_v4()));
		else
			listen_on_ep.address(local_address);
	}

	try
	{
		udp_callback_t udp_func_ap = std::bind(&udp_to_forwarder::udp_server_incoming, this, _1, _2, _3, _4);
		udp_access_point = std::make_unique<udp_server>(network_io, asio_strand, listen_on_ep, udp_func_ap);

		timer_send_data.expires_after(EXPRING_UPDATE_INTERVAL);
		timer_send_data.async_wait([this](const asio::error_code &e) { kcp_loop_updates(e); });

		timer_expiring_kcp.expires_after(KCP_UPDATE_INTERVAL);
		timer_expiring_kcp.async_wait([this](const asio::error_code &e) { expiring_kcp_loops(e); });

		timer_find_expires.expires_after(FINDER_EXPIRES_INTERVAL);
		timer_find_expires.async_wait([this](const asio::error_code &e) { find_expires(e); });

		timer_change_ports.expires_after(CHANGEPORT_UPDATE_INTERVAL);
		timer_change_ports.async_wait([this](const asio::error_code &e) { change_new_port(e); });
	}
	catch (std::exception &ex)
	{
		std::cerr << ex.what() << std::endl;
		return false;
	}

	return true;
}

void udp_to_forwarder::udp_server_incoming(std::shared_ptr<uint8_t[]> data, size_t data_size, udp::endpoint &&peer, asio::ip::port_type port_number)
{
	if (data_size == 0)
		return;

	uint8_t *data_ptr = data.get();
	std::shared_lock shared_locker_udp_session_map_to_kcp{ mutex_udp_session_map_to_kcp, std::defer_lock };
	std::unique_lock unique_locker_udp_session_map_to_kcp{ mutex_udp_session_map_to_kcp, std::defer_lock };
	shared_locker_udp_session_map_to_kcp.lock();
	auto iter = udp_session_map_to_kcp.find(peer);
	if (iter == udp_session_map_to_kcp.end())
	{
		shared_locker_udp_session_map_to_kcp.unlock();
		unique_locker_udp_session_map_to_kcp.lock();
		iter = udp_session_map_to_kcp.find(peer);
		if (iter == udp_session_map_to_kcp.end())
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

			const std::string &destination_address = current_settings.destination_address;
			uint16_t destination_port = current_settings.destination_port;
			if (destination_port == 0)
				destination_port = generate_new_port_number(current_settings.destination_port_start, current_settings.destination_port_end);

			std::shared_ptr<handshake> hs = std::make_shared<handshake>(current_settings, network_io, asio_strand);
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
				std::cerr << "establish handshake failed\n";
				return;
			}

			udp_address_map_to_handshake[peer] = hs;
			udp_handshake_map_to_address[hs] = peer;

			std::unique_lock locker_udp_seesion_caches{ mutex_udp_seesion_caches };
			udp_seesion_caches[hs].emplace_back(std::vector<uint8_t>(data_ptr, data_ptr + data_size));
			return;
		}
		unique_locker_udp_session_map_to_kcp.unlock();
		shared_locker_udp_session_map_to_kcp.lock();
	}

	KCP::KCP *kcp_session = iter->second;
	shared_locker_udp_session_map_to_kcp.unlock();

	size_t new_data_size = packet::create_data_packet(protocol_type::udp, data_ptr, data_size);

	//asio::post(asio_strand, [kcp_session, data, new_data_size]()
	//	{
	//		kcp_session->Send((const char *)data.get(), new_data_size);
	//		kcp_session->Update(time_now_for_kcp());
	//	});

	kcp_session->Send((const char *)data_ptr, new_data_size);
	kcp_session->Update(time_now_for_kcp());
	kcp_session->Flush();
}


void udp_to_forwarder::udp_client_incoming_to_udp(KCP::KCP *kcp_ptr, std::shared_ptr<uint8_t[]> data, size_t data_size, udp::endpoint &&peer, asio::ip::port_type local_port_number)
{
	if (data_size == 0 || kcp_ptr == nullptr)
		return;

	uint8_t *data_ptr = data.get();
	auto [error_message, plain_size] = decrypt_data(current_settings.encryption_password, current_settings.encryption, data_ptr, (int)data_size);

	//std::string error_message;
	//auto plain_data = decrypt_data(current_settings.encryption_password, current_settings.encryption, std::move(data), error_message);
	if (!error_message.empty())
		return;

	uint32_t conv = KCP::KCP::GetConv(data_ptr);
	if (kcp_ptr->GetConv() != conv)
	{
		std::cerr << __FUNCTION__ << ":" << __LINE__ << "; kcp conv is not the same as record: conv = " << conv << ", local kcp_ptr: " << kcp_ptr->GetConv() << "\n";
		return;
	}

	if (kcp_ptr->Input((const char *)data_ptr, (long)plain_size) < 0)
		return;

	while (true)
	{
		int buffer_size = kcp_ptr->PeekSize();
		if (buffer_size <= 0)
			break;

		std::shared_ptr<uint8_t[]> buffer_cache(new uint8_t[buffer_size]());
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

		std::shared_lock lock_kcp_session_map_to_udp{ mutex_kcp_session_map_to_udp };
		auto session_iter = kcp_session_map_to_udp.find(conv);
		if (session_iter == kcp_session_map_to_udp.end())
			continue;
		udp::endpoint &udp_endpoint = session_iter->second;
		lock_kcp_session_map_to_udp.unlock();

		switch (ftr)
		{
		case feature::initialise:
		{
			std::cout << __FUNCTION__ << ":" << __LINE__ << ", case feature::initialise, should not be here\n";
			break;
		}
		case feature::failure:
		{
			std::cout << __FUNCTION__ << ":" << __LINE__ << ", case feature::failure, error message: " << unbacked_data_ptr << "\n";
		}
		[[fallthrough]];
		case feature::disconnect:
		{
			process_disconnect(conv);
			break;
		}
		case feature::data:
		{
			udp_access_point->async_send_out(buffer_cache, unbacked_data_ptr, unbacked_data_size, udp_endpoint);
			break;
		}
		default:
			break;
		}
	}
}

udp::endpoint udp_to_forwarder::get_remote_address()
{
	udp::endpoint ep;
	std::shared_lock locker{ mutex_udp_target };
	ep = *udp_target;
	locker.unlock();
	return ep;
}

void udp_to_forwarder::process_disconnect(uint32_t conv)
{
	std::scoped_lock lockers{ mutex_kcp_channels, mutex_expiring_kcp,
		mutex_id_map_to_forwarder, mutex_kcp_changeport_timestamp };
	auto kcp_channel_iter = kcp_channels.find(conv);
	if (kcp_channel_iter == kcp_channels.end())
		return;
	std::unique_ptr<KCP::KCP> kcp_ptr_owner = std::move(kcp_channel_iter->second);
	KCP::KCP *kcp_ptr = kcp_ptr_owner.get();
	kcp_channels.erase(kcp_channel_iter);
	if (expiring_kcpid.find(conv) != expiring_kcpid.end())
		return;
	expiring_kcpid.insert({ conv, std::pair{ std::move(kcp_ptr_owner), packet::right_now() } });
	kcp_changeport_timestamp.erase(kcp_ptr);
}

void udp_to_forwarder::cleanup_expiring_forwarders()
{
	auto time_right_now = packet::right_now();

	std::scoped_lock lockers{ mutex_expiring_forwarders };
	for (auto iter = expiring_forwarders.begin(), next_iter = iter; iter != expiring_forwarders.end(); iter = next_iter)
	{
		++next_iter;
		auto &[udp_forwrder, expire_time] = iter->second;
		forwarder *forwarder_ptr = udp_forwrder.get();

		int64_t time_elapsed = calculate_difference(time_right_now, expire_time);
		
		if (time_elapsed <= CLEANUP_WAITS / 2)
			continue;

		if (time_elapsed > CLEANUP_WAITS / 2 && time_elapsed < CLEANUP_WAITS)
		{
			forwarder_ptr->remove_callback();
			forwarder_ptr->stop();
			continue;
		}

		expiring_forwarders.erase(iter);
	}
}

void udp_to_forwarder::cleanup_expiring_data_connections()
{
	auto time_right_now = packet::right_now();

	std::scoped_lock locker{ mutex_expiring_kcp };
	for (auto iter = expiring_kcpid.begin(), next_iter = iter; iter != expiring_kcpid.end(); iter = next_iter)
	{
		++next_iter;
		uint32_t conv = iter->first;
		auto &[kcp_ptr, expire_time] = iter->second;

		if (calculate_difference(time_right_now, expire_time) < CLEANUP_WAITS)
		{
			kcp_ptr->Update(time_now_for_kcp());
			continue;
		}

		std::scoped_lock lockers{ mutex_udp_session_map_to_kcp, mutex_kcp_session_map_to_udp,
								  mutex_expiring_forwarders, mutex_kcp_changeport_timestamp,
								  mutex_kcp_channels, mutex_id_map_to_forwarder };
		udp::endpoint &udp_endpoint = kcp_session_map_to_udp[conv];
		if (auto forwarder_iter = id_map_to_forwarder.find(conv);
			forwarder_iter != id_map_to_forwarder.end())
		{
			std::unique_ptr<forwarder> forwarder_ptr_owner = std::move(forwarder_iter->second);
			forwarder *forwarder_ptr = forwarder_ptr_owner.get();
			forwarder_ptr->remove_callback();
			forwarder_ptr->stop();
			if (expiring_forwarders.find(forwarder_ptr) == expiring_forwarders.end())
				expiring_forwarders.insert({ forwarder_ptr, std::pair{std::move(forwarder_ptr_owner), packet::right_now()} });
			id_map_to_forwarder.erase(forwarder_iter);
		}

		udp_session_map_to_kcp.erase(udp_endpoint);
		kcp_session_map_to_udp.erase(conv);
		kcp_changeport_timestamp.erase(kcp_ptr.get());
		expiring_kcpid.erase(iter);
	}
}

void udp_to_forwarder::loop_update_connections()
{
	std::shared_lock lockers{ mutex_kcp_channels };
	for (auto &[conv, kcp_ptr] : kcp_channels)
	{
		//std::unique_lock locker_id_map_to_forwarder{ mutex_id_map_to_forwarder };
		//forwarder *udp_forwarder = id_map_to_forwarder.find(conv)->second.get();
		//locker_id_map_to_forwarder.unlock();

		kcp_ptr->Update(time_now_for_kcp());
	}
}

void udp_to_forwarder::loop_find_expires()
{
	std::scoped_lock lockers{ mutex_kcp_channels };
	for (auto iter = kcp_channels.begin(), next_iter = iter; iter != kcp_channels.end(); iter = next_iter)
	{
		++next_iter;
		uint32_t conv = iter->first;
		KCP::KCP *kcp_ptr = iter->second.get();

		std::unique_lock locker_id_map_to_forwarder{ mutex_id_map_to_forwarder };
		forwarder *udp_forwarder = id_map_to_forwarder.find(conv)->second.get();
		locker_id_map_to_forwarder.unlock();

		if (udp_forwarder->time_gap_of_receive() > current_settings.timeout && udp_forwarder->time_gap_of_send() > current_settings.timeout)
		{
			std::scoped_lock locker_expiring_kcp{ mutex_expiring_kcp };
			if (expiring_kcpid.find(conv) == expiring_kcpid.end())
				expiring_kcpid.insert({ conv, std::pair{ std::move(iter->second), packet::right_now() } });

			kcp_channels.erase(iter);
			std::scoped_lock locker_kcp_changeport_timestamp{ mutex_kcp_changeport_timestamp };
			kcp_changeport_timestamp.erase(kcp_ptr);
		}
		else
		{
			kcp_ptr->Update(time_now_for_kcp());
		}
	}
}

void udp_to_forwarder::loop_change_new_port()
{
	std::shared_lock locker{ mutex_kcp_changeport_timestamp };
	for (auto &[kcp_ptr, timestamp] : kcp_changeport_timestamp)
	{
		if (timestamp.load() > packet::right_now())
			continue;
		timestamp += current_settings.dynamic_port_refresh;

		uint32_t conv = kcp_ptr->GetConv();
		asio::error_code ec;

		auto udp_func = std::bind(&udp_to_forwarder::udp_client_incoming_to_udp, this, _1, _2, _3, _4, _5);
		auto udp_forwarder = std::make_unique<forwarder>(network_io, asio_strand, kcp_ptr, udp_func);
		if (udp_forwarder == nullptr)
			continue;

		uint16_t new_port_numer = current_settings.destination_port;
		if (current_settings.destination_port_start != current_settings.destination_port_end)
			new_port_numer = generate_new_port_number(current_settings.destination_port_start, current_settings.destination_port_end);

		udp::endpoint current_udp_target;
		std::shared_lock locker{ mutex_udp_target };
		if (current_settings.destination_port_start != current_settings.destination_port_end)
			current_udp_target = udp::endpoint(udp_target->address(), new_port_numer);
		else
			current_udp_target = *udp_target;
		locker.unlock();
		forwarder *new_forwarder_ptr = udp_forwarder.get();

		new_forwarder_ptr->send_out(create_raw_random_data(current_settings.kcp_mtu), local_empty_target, ec);
		if (ec)
		{
			timestamp += current_settings.dynamic_port_refresh;
			return;
		}
		new_forwarder_ptr->async_receive();

		std::unique_lock locker_id_map_to_forwarder{ mutex_id_map_to_forwarder };
		auto iter_forwarder = id_map_to_forwarder.find(conv);
		if (iter_forwarder == id_map_to_forwarder.end())
			continue;

		std::swap(udp_forwarder, iter_forwarder->second);
		locker_id_map_to_forwarder.unlock();
		kcp_ptr->ReplaceUserPtr(new_forwarder_ptr);
		forwarder *old_forwarder_ptr = iter_forwarder->second.get();

		std::scoped_lock lock_expiring_forwarders{ mutex_expiring_forwarders };
		expiring_forwarders.insert({ old_forwarder_ptr, std::pair{std::move(udp_forwarder), packet::right_now()} });
	}
}

void udp_to_forwarder::kcp_loop_updates(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
		return;

	loop_update_connections();

	timer_send_data.expires_after(KCP_UPDATE_INTERVAL);
	timer_send_data.async_wait([this](const asio::error_code &e) { kcp_loop_updates(e); });	// �ĳ���asio::post
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

void udp_to_forwarder::change_new_port(const asio::error_code & e)
{
	if (e == asio::error::operation_aborted)
		return;

	loop_change_new_port();

	timer_change_ports.expires_after(CHANGEPORT_UPDATE_INTERVAL);
	timer_change_ports.async_wait([this](const asio::error_code &e) { change_new_port(e); });
}

void udp_to_forwarder::on_handshake_success(std::shared_ptr<handshake> handshake_ptr, uint32_t conv, uint16_t start_port, uint16_t end_port)
{
	auto [destination_address, destination_port] = handshake_ptr->get_cached_peer();
	std::scoped_lock handshake_lockers{ mutex_udp_address_map_to_handshake, mutex_udp_seesion_caches };
	udp::endpoint peer = udp_handshake_map_to_address[handshake_ptr];

	if (start_port != 0 && end_port != 0)
	{
		current_settings.destination_port_start = start_port;
		current_settings.destination_port_end = end_port;
	}

	std::unique_ptr<KCP::KCP> kcp_ptr = std::make_unique<KCP::KCP>(conv, nullptr);
	auto udp_func = std::bind(&udp_to_forwarder::udp_client_incoming_to_udp, this, _1, _2, _3, _4, _5);
	auto udp_forwarder = std::make_unique<forwarder>(network_io, asio_strand, kcp_ptr.get(), udp_func);
	if (udp_forwarder == nullptr)
		return;

	asio::error_code ec;
	for (int i = 0; i < RETRY_TIMES; ++i)
	{
		udp::resolver::results_type udp_endpoints = udp_forwarder->get_remote_hostname(destination_address, destination_port, ec);
		if (ec)
		{
			std::cout << ec.message() << "\n";
			std::this_thread::sleep_for(std::chrono::seconds(RETRY_WAITS));
		}
		else if (udp_endpoints.size() == 0)
		{
			std::cerr << "destination address not found\n";
			std::this_thread::sleep_for(std::chrono::seconds(RETRY_WAITS));
		}
		else
		{
			std::scoped_lock locker{ mutex_udp_target };
			udp_target = std::make_unique<udp::endpoint>(*udp_endpoints.begin());
			break;
		}
	}

	if (ec)
		return;

	udp_forwarder->send_out(create_raw_random_data(current_settings.kcp_mtu), local_empty_target, ec);
	if (ec)
		return;
	udp_forwarder->async_receive();

	kcp_ptr->ReplaceUserPtr(udp_forwarder.get());
	kcp_ptr->SetMTU(current_settings.kcp_mtu);
	kcp_ptr->SetWindowSize(current_settings.kcp_sndwnd, current_settings.kcp_rcvwnd);
	kcp_ptr->NoDelay(current_settings.kcp_nodelay, current_settings.kcp_interval, current_settings.kcp_resend, current_settings.kcp_nc);
	kcp_ptr->RxMinRTO() = 10;
	kcp_ptr->Update(time_now_for_kcp());
	kcp_ptr->SetOutput([this, kcp_raw_ptr = kcp_ptr.get()](const char *buf, int len, void *user) -> int
	{
		std::shared_ptr<uint8_t[]> new_buffer(new uint8_t[len + BUFFER_EXPAND_SIZE]());
		uint8_t *new_buffer_ptr = new_buffer.get();
		std::copy_n((uint8_t *)buf, len, new_buffer_ptr);
		auto [error_message, cipher_size] = encrypt_data(current_settings.encryption_password, current_settings.encryption, new_buffer_ptr, len);
		if (!error_message.empty() || cipher_size == 0)
			return 0;

		forwarder *udp_forwarder = reinterpret_cast<forwarder*>(user);
		udp::endpoint ep = get_remote_address();
		udp_forwarder->async_send_out(new_buffer, cipher_size, ep);
		return 0;
	});

	for (auto &data : udp_seesion_caches[handshake_ptr])
	{
		std::vector<uint8_t> new_data = packet::create_data_packet(protocol_type::udp, data);
		kcp_ptr->Send((const char *)new_data.data(), new_data.size());
		kcp_ptr->Update(time_now_for_kcp());
	}

	udp_address_map_to_handshake.erase(peer);
	udp_seesion_caches.erase(handshake_ptr);
	udp_handshake_map_to_address.erase(handshake_ptr);

	std::unique_lock lock_kcp_changeport_timestamp{ mutex_kcp_changeport_timestamp };
	kcp_changeport_timestamp[kcp_ptr.get()].store(packet::right_now() + current_settings.dynamic_port_refresh);
	lock_kcp_changeport_timestamp.unlock();

	std::scoped_lock lockers{ mutex_udp_session_map_to_kcp, mutex_kcp_session_map_to_udp, mutex_id_map_to_forwarder, mutex_kcp_channels };
	udp_session_map_to_kcp.insert({ peer, kcp_ptr.get() });
	kcp_session_map_to_udp[conv] = peer;
	id_map_to_forwarder.insert({ conv, std::move(udp_forwarder) });
	kcp_channels.insert({ conv, std::move(kcp_ptr) });
}

void udp_to_forwarder::on_handshake_failure(std::shared_ptr<handshake> handshake_ptr, const std::string &error_message)
{
	std::cerr << error_message << "\n";
	std::scoped_lock lockers{ mutex_udp_address_map_to_handshake, mutex_udp_seesion_caches };
	udp::endpoint peer = udp_handshake_map_to_address[handshake_ptr];
	udp_address_map_to_handshake.erase(peer);
	udp_seesion_caches.erase(handshake_ptr);
	udp_handshake_map_to_address.erase(handshake_ptr);
}
