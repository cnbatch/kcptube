#include <iostream>
#include <limits>
#include <random>
#include <thread>
#include "client.hpp"
#include "../shares/data_operations.hpp"

using namespace std::placeholders;
using namespace std::chrono;
using namespace std::literals;

uint16_t generate_new_port_number(uint16_t start_port_num, uint16_t end_port_num)
{
	std::random_device rd;
	std::mt19937 mt(rd());
	std::uniform_int_distribution<uint16_t> uniform_dist(start_port_num, end_port_num);
	return uniform_dist(mt);
}

handshake::~handshake()
{
	timer_data_loop.cancel();
}

bool handshake::send_handshake(protocol_type ptype, const std::string &destination_address, uint16_t destination_port)
{
	kcp_ptr = std::make_unique<KCP::KCP>(0, nullptr);
	if (kcp_ptr == nullptr)
		return false;

	asio::ip::v6_only v6_option(false);
	udp_socket.open(udp::v6());
	udp_socket.set_option(v6_option);

	asio::error_code ec;
	udp::resolver resolver(ioc);
	for (int i = 0; i <= RETRY_TIMES; ++i)
	{
		udp::resolver::results_type udp_endpoints = resolver.resolve(udp::v6(), destination_address, std::to_string(destination_port),
			udp::resolver::numeric_service | udp::resolver::v4_mapped | udp::resolver::all_matching, ec);
		if (ec)
		{
			std::cerr << ec.message() << "\n";
			std::this_thread::sleep_for(std::chrono::seconds(RETRY_WAITS));
		}
		else if (udp_endpoints.size() == 0)
		{
			std::string error_message = time_to_string_with_square_brackets() + "destination address not found\n";
			std::cerr << error_message;
			if (!current_settings.log_messages.empty())
				print_message_to_file(error_message, current_settings.log_messages);
			std::this_thread::sleep_for(std::chrono::seconds(RETRY_WAITS));
		}
		else
		{
			remote_server = *udp_endpoints.begin();
			break;
		}
	}

	if (ec)
	{
		std::cerr << __FUNCTION__ << ":" << __LINE__ << ", error message: " << ec.message() << "\nError Number: " << ec.value() << "\n";
		return false;
	}

	std::vector<uint8_t> handshake_data = packet::request_initialise_packet(ptype);

	kcp_ptr->SetMTU(current_settings.kcp_mtu);
	kcp_ptr->SetOutput([this](const char *buf, int len, void *user) -> int
		{
			std::string error_message;
			auto data = encrypt_data(current_settings.encryption_password, current_settings.encryption, buf, len, error_message);
			if (!error_message.empty())
			{
				std::cerr << error_message << "\n";
				return 0;
			}
			auto asio_buffer = asio::buffer(data.data(), data.size());
			udp_socket.async_send_to(asio_buffer, remote_server,
				[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
			return 0;
		});

	udp_socket.send_to(asio::buffer(create_raw_random_data(current_settings.kcp_mtu)), local_empty_target, 0, ec);
	if (ec)
		return false;
	kcp_ptr->NoDelay(current_settings.kcp_nodelay, current_settings.kcp_interval, current_settings.kcp_resend, current_settings.kcp_nc);
	kcp_ptr->RxMinRTO() = 10;
	kcp_ptr->SetBandwidth(current_settings.outbound_bandwidth, current_settings.inbound_bandwidth);
	kcp_ptr->Update(time_now_for_kcp());
	if (kcp_ptr->Send((const char *)handshake_data.data(), (long)handshake_data.size()) < 0)
		return false;
	kcp_ptr->Flush();

	start_time = packet::right_now();
	start_receive();
	timer_data_loop.expires_after(10ms);
	timer_data_loop.async_wait([this](const asio::error_code &e) { loop_kcp_update(e); });

	destination_address_cache = destination_address;
	destination_port_cache = destination_port;

	return true;
}

std::pair<std::string, uint16_t> handshake::get_cached_peer()
{
	return { destination_address_cache , destination_port_cache };
}

void handshake::start_receive()
{
	if (stop)
		return;

	if (!udp_socket.is_open())
		return;

	if (calculate_difference(packet::right_now(), start_time) > handshake_timeout)
	{
		cancel_all();
		call_on_failure(shared_from_this(), "Receive: Handshake Timed out");
		//timer_waiting.cancel();
	}
	else
	{
		std::shared_ptr<udp::endpoint> udp_ep_ptr = std::make_shared<udp::endpoint>();
		std::unique_ptr<uint8_t[]> recv_buffer = std::make_unique<uint8_t[]>(BUFFER_SIZE);
		auto asio_buffer = asio::buffer(recv_buffer.get(), BUFFER_SIZE);
		udp_socket.async_receive_from(asio_buffer, *udp_ep_ptr,
			[/*this*/this_handshake = shared_from_this(), udp_ep_ptr, buffer_ptr = std::move(recv_buffer)](const asio::error_code &error, size_t bytes_transferred) mutable
			{
			this_handshake->handle_receive(std::move(buffer_ptr), error, bytes_transferred);
			});
	}
}

void handshake::handle_receive(std::unique_ptr<uint8_t[]> recv_buffer, const asio::error_code &error, std::size_t bytes_transferred)
{
	if (stop)
		return;

	if (error)
	{
		if (udp_socket.is_open())
			start_receive();
		return;
	}

	start_receive();
	process_handshake(std::move(recv_buffer), bytes_transferred);
	//asio::post(task_assigner, [/*this*/this_handshake = shared_from_this(), buffer_ = std::move(recv_buffer), bytes_transferred]() mutable
	//	{
	//		this_handshake->process_handshake(std::move(buffer_), bytes_transferred);
	//	});
}

void handshake::process_handshake(std::unique_ptr<uint8_t[]> recv_buffer, std::size_t bytes_transferred)
{
	//size_t plain_data_size = 0;
	uint8_t *data_ptr = recv_buffer.get();
	//std::string err_msg;
	auto [error_message, plain_data_size] = decrypt_data(current_settings.encryption_password, current_settings.encryption, data_ptr, (int)bytes_transferred);
	if (!error_message.empty() || plain_data_size == 0)
	{
		std::cerr << error_message << "\n";
		//error_message = err_msg;
		return;
	}
	kcp_ptr->Input((char *)data_ptr, (long)plain_data_size);
	//kcp_ptr->Update(time_now_for_kcp());
	int data_size = kcp_ptr->PeekSize();
	if (data_size <= 0)
	{
		return;
	}

	std::vector<uint8_t> data(data_size);
	if (kcp_ptr->Receive((char *)data.data(), (int)data.size()) < 0)
	{
		kcp_ptr->Update(time_now_for_kcp());
		return;
	}

	auto [packet_timestamp, ftr, prtcl, unbacked_data] = packet::unpack(data);
	auto timestamp = packet::right_now();
	if (calculate_difference(timestamp, packet_timestamp) > TIME_GAP)
	{
		return;
	}

	switch (ftr)
	{
	case feature::initialise:
	{
		auto [conv, start_port, end_port] = packet::get_initialise_details_from_unpacked_data(unbacked_data);
		cancel_all();
		call_on_success(shared_from_this(), conv, start_port, end_port);
		break;
	}
	case feature::failure:
	{
		error_message = packet::get_error_message_from_unpacked_data(unbacked_data);
		cancel_all();
		call_on_failure(shared_from_this(), error_message);
		break;
	}
	default:
		break;
	}
}

void handshake::loop_kcp_update(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
	{
		return;
	}

	auto waited_seconds = calculate_difference(packet::right_now(), start_time);

	if (kcp_ptr != nullptr && waited_seconds < handshake_timeout)
	{
		kcp_ptr->Update(time_now_for_kcp());
	}

	if (waited_seconds >= handshake_timeout)
	{
		cancel_all();
		call_on_failure(shared_from_this(), "Loop: Handshake Timed out");

		return;
	}

	timer_data_loop.expires_after(10ms);
	timer_data_loop.async_wait([this](const asio::error_code &e) { loop_kcp_update(e); });
}

void handshake::cancel_all()
{
	stop.store(true);
	timer_data_loop.cancel();
	if (udp_socket.is_open())
	{
		asio::error_code ec;
		udp_socket.close(ec);
	}
}
