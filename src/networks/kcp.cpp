// This is a wrapper of ikcp
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <chrono>
#include <limits>
#include <numeric>
#include <iostream>

#ifdef _WIN32
#include <Windows.h>
#endif // _WIN32

#ifdef __unix__
#include <unistd.h>
#endif //  __unix__

#include "kcp.hpp"

using namespace std::chrono;
using namespace std::literals;

int64_t right_now();

namespace KCP
{
	uint32_t TimeNowForKCP()
	{
		return static_cast<uint32_t>((duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count()) & 0xFFFF'FFFFul);
	}

	void empty_function(void *) {}

	void KCP::Initialise(uint32_t conv)
	{
		kcp_ptr = std::make_unique<kcp_core>();
		kcp_ptr->initialise(conv, this);
		last_input_time.store(right_now());
		post_update = empty_function;
	}

	void KCP::MoveKCP(KCP &other) noexcept
	{
		kcp_ptr = std::move(other.kcp_ptr);
		last_input_time.store(other.last_input_time.load());
		post_update = other.post_update;
	}

	//KCP::KCP(const KCP &other) noexcept
	//{
	//	ikcp_ptr = other.ikcp_ptr;
	//	((ikcpcb *)ikcp_ptr)->user = this;
	//	custom_data.store(other.custom_data.load());
	//	last_input_time.store(other.last_input_time.load());
	//	post_update = other.post_update;
	//}

	KCP::~KCP()
	{
		post_update = empty_function;
	}

	void KCP::ResetWindowValues(int32_t srtt)
	{
		if (outbound_bandwidth == 0 && inbound_bandwidth == 0)
			return;
		int32_t max_srtt = std::max(kcp_ptr->rx_srtt, srtt);
		int32_t min_srtt = std::min(kcp_ptr->rx_srtt, srtt);
		srtt = min_srtt <= 0 ? max_srtt : min_srtt;

		if (srtt <= 0)
			return;
		std::scoped_lock locker{ mtx };
		if (outbound_bandwidth > 0)
		{
			kcp_ptr->snd_wnd = (uint32_t)(outbound_bandwidth / kcp_ptr->mtu * srtt / 1000 * 1.2);
			if (kcp_ptr->snd_wnd < 32)
				kcp_ptr->snd_wnd = 32;
		}
		if (inbound_bandwidth > 0)
		{
			kcp_ptr->rcv_wnd = (uint32_t)(inbound_bandwidth / kcp_ptr->mtu * srtt / 1000 * 1.2);
			if (kcp_ptr->rcv_wnd < 32)
				kcp_ptr->rcv_wnd = 32;
		}
	}

	int32_t KCP::GetRxSRTT()
	{
		return kcp_ptr->rx_srtt;
	}

	void KCP::SetOutput(std::function<int(const char *, int, void *)> output_func)
	{
		kcp_ptr->set_output(output_func);
	}

	void KCP::SetPostUpdate(std::function<void(void *)> post_update_func)
	{
		post_update = post_update_func;
	}

	int KCP::Receive(char *buffer, int len)
	{
		std::scoped_lock locker{ mtx };
		return kcp_ptr->receive(buffer, len);
	}

	int KCP::Receive(std::vector<char> &buffer)
	{
		std::scoped_lock locker{ mtx };
		return kcp_ptr->receive(buffer.data(), (int)buffer.size());
	}

	int KCP::Send(const char *buffer, size_t len)
	{
		std::scoped_lock locker{ mtx };
		return kcp_ptr->send(buffer, (int)len);
	}

	void KCP::Update(uint32_t current)
	{
		std::unique_lock locker{ mtx };
		kcp_ptr->update(current);
		locker.unlock();
		post_update(kcp_ptr->user);
	}

	void KCP::Update()
	{
		std::unique_lock locker{ mtx };
		kcp_ptr->update(TimeNowForKCP());
		locker.unlock();
		post_update(kcp_ptr->user);
	}

	uint32_t KCP::Check(uint32_t current)
	{
		std::shared_lock locker{ mtx };
		return kcp_ptr->check(current);
	}

	uint32_t KCP::Check()
	{
		std::shared_lock locker{ mtx };
		return kcp_ptr->check(TimeNowForKCP());
	}

	uint32_t KCP::Refresh()
	{
		std::unique_lock unique_locker{ mtx };
		kcp_ptr->flush(TimeNowForKCP());
		return kcp_ptr->check(TimeNowForKCP());
	}

	// when you received a low level packet (eg. UDP packet), call it
	int KCP::Input(const char *data, long size)
	{
		std::unique_lock locker{ mtx };
		auto ret = kcp_ptr->input(data, size);
		locker.unlock();
		last_input_time.store(right_now());
		return ret;
	}

	// flush pending data
	void KCP::Flush()
	{
		std::unique_lock locker{ mtx };
		kcp_ptr->flush(TimeNowForKCP());
		locker.unlock();
		post_update(kcp_ptr->user);
	}

	// check the size of next message in the recv queue
	int KCP::PeekSize()
	{
		return kcp_ptr->peek_size();
	}

	// change MTU size, default is 1400
	int KCP::SetMTU(int mtu)
	{
		return kcp_ptr->set_mtu(mtu);
	}

	int KCP::GetMTU()
	{
		return kcp_ptr->mtu;
	}

	// set maximum window size: sndwnd=32, rcvwnd=32 by default
	void KCP::SetWindowSize(uint32_t sndwnd, uint32_t rcvwnd)
	{
		kcp_ptr->set_wndsize(sndwnd, rcvwnd);
	}

	void KCP::GetWindowSize(uint32_t &sndwnd, uint32_t &rcvwnd)
	{
		sndwnd = kcp_ptr->snd_wnd;
		rcvwnd = kcp_ptr->rcv_wnd;
	}
	std::pair<uint32_t, uint32_t> KCP::GetWindowSizes()
	{
		return std::pair<uint32_t, uint32_t>{ kcp_ptr->snd_wnd, kcp_ptr->rcv_wnd };
	}

	uint32_t KCP::GetSendWindowSize()
	{
		return kcp_ptr->snd_wnd;
	}

	uint32_t KCP::GetReceiveWindowSize()
	{
		return kcp_ptr->rcv_wnd;
	}

	//uint32_t KCP::GetRemoteWindowSize()
	//{
	//	return ((ikcpcb *)ikcp_ptr)->rmt_wnd;
	//}

	// get how many packet is waiting to be sent
	int KCP::WaitingForSend()
	{
		return kcp_ptr->get_waitsnd();
	}

	// fastest: NoDelay(1, 20, 2, 1)
	// nodelay: 0:disable(default), 1:enable
	// interval: internal update timer interval in millisec, default is 100ms 
	// resend: 0:disable fast resend(default), 1:enable fast resend
	// nc: 0:normal congestion control(default), 1:disable congestion control
	int KCP::NoDelay(int nodelay, int interval, int resend, bool nc)
	{
		int ret = kcp_ptr->set_nodelay(nodelay, interval, resend, nc);
		kcp_ptr->interval = interval;
		return ret;
	}

	uint32_t KCP::GetConv(const void *ptr)
	{
		return kcp_core::get_conv(ptr);
	}

	uint32_t KCP::GetConv()
	{
		return kcp_ptr->get_conv();
	}

	void KCP::SetStreamMode(bool enable)
	{
		kcp_ptr->stream = enable;
	}

	int32_t& KCP::RxMinRTO()
	{
		return kcp_ptr->rx_minrto;
	}

	void KCP::SetBandwidth(uint64_t out_bw, uint64_t in_bw)
	{
		outbound_bandwidth = out_bw;
		inbound_bandwidth = in_bw;
	}

	int64_t KCP::LastInputTime()
	{
		return last_input_time.load();
	}

	void* KCP::GetUserData()
	{
		return kcp_ptr->user;
	}

	void KCP::SetUserData(void *user_data)
	{
		kcp_ptr->user = user_data;
	}
}

int64_t right_now()
{
	auto right_now = system_clock::now();
	return duration_cast<seconds>(right_now.time_since_epoch()).count();
}
