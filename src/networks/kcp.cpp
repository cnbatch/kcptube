// This is a wrapper of ikcp
#include "kcp.hpp"
#include "ikcp.h"


int middle_layer_output(const char *buf, int len, IKCPCB *kcp, void *user);
void middle_layer_writelog(const char *buf, IKCPCB *kcp, void *user);


namespace KCP
{
	void KCP::Initialise(uint32_t conv, void *user)
	{
		ikcp_ptr = ikcp_create(conv, this);
		custom_data.store(user);
	}

	void KCP::MoveKCP(KCP &other) noexcept
	{
		ikcp_ptr = other.ikcp_ptr;
		((ikcpcb *)ikcp_ptr)->user = this;
		custom_data.store(other.custom_data.load());
		other.ikcp_ptr = nullptr;
		other.custom_data.store(nullptr);
	}

	KCP::KCP(const KCP &other) noexcept
	{
		ikcp_ptr = other.ikcp_ptr;
		((ikcpcb *)ikcp_ptr)->user = this;
		custom_data.store(other.custom_data.load());
	}

	KCP::~KCP()
	{
		ikcp_release((ikcpcb *)ikcp_ptr);
		custom_data.store(nullptr);
	}

	void KCP::ResetWindowValues()
	{
		ikcpcb *kcp_ptr = (ikcpcb *)ikcp_ptr;
		if (outbound_bandwidth > 0)
			kcp_ptr->snd_wnd = (uint32_t)(outbound_bandwidth / kcp_ptr->mtu * kcp_ptr->rx_rto) + 32;
		if (inbound_bandwidth > 0)
			kcp_ptr->rcv_wnd = (uint32_t)(inbound_bandwidth / kcp_ptr->mtu * kcp_ptr->rx_rto) + 32;
	}

	void KCP::SetOutput(std::function<int(const char *, int, void *)> output_func)
	{
		this->output = output_func;
		((ikcpcb *)ikcp_ptr)->output = middle_layer_output;
	}

	int KCP::Receive(char *buffer, int len)
	{
		std::scoped_lock locker{ mtx };
		return ikcp_recv((ikcpcb *)ikcp_ptr, buffer, len);
	}

	int KCP::Receive(std::vector<char> &buffer)
	{
		std::scoped_lock locker{ mtx };
		return ikcp_recv((ikcpcb *)ikcp_ptr, buffer.data(), (int)buffer.size());
	}

	int KCP::Send(const char *buffer, size_t len)
	{
		std::scoped_lock locker{ mtx };
		return ikcp_send((ikcpcb *)ikcp_ptr, buffer, (int)len);
	}

	void KCP::Update(uint32_t current)
	{
		std::scoped_lock locker{ mtx };
		ikcp_update((ikcpcb *)ikcp_ptr, current);
	}

	uint32_t KCP::Check(uint32_t current)
	{
		std::shared_lock locker{ mtx };
		return ikcp_check((ikcpcb *)ikcp_ptr, current);
	}

	void KCP::ReplaceUserPtr(void *user)
	{
		custom_data.store(user);
	}

	// when you received a low level packet (eg. UDP packet), call it
	int KCP::Input(const char *data, long size)
	{
		std::scoped_lock locker{ mtx };
		auto ret = ikcp_input((ikcpcb *)ikcp_ptr, data, size);
		ResetWindowValues();
		return ret;
	}

	// flush pending data
	void KCP::Flush()
	{
		std::scoped_lock locker{ mtx };
		ikcp_flush((ikcpcb *)ikcp_ptr);
	}

	// check the size of next message in the recv queue
	int KCP::PeekSize()
	{
		return ikcp_peeksize((ikcpcb *)ikcp_ptr);
	}

	// change MTU size, default is 1400
	int KCP::SetMTU(int mtu)
	{
		return ikcp_setmtu((ikcpcb *)ikcp_ptr, mtu);
	}

	int KCP::GetMTU()
	{
		return ((ikcpcb *)ikcp_ptr)->mtu;
	}

	// set maximum window size: sndwnd=32, rcvwnd=32 by default
	void KCP::SetWindowSize(int sndwnd, int rcvwnd)
	{
		ikcp_wndsize((ikcpcb *)ikcp_ptr, sndwnd, rcvwnd);
	}

	void KCP::GetWindowSize(int &sndwnd, int &rcvwnd)
	{
		sndwnd = ((ikcpcb *)ikcp_ptr)->snd_wnd;
		rcvwnd = ((ikcpcb *)ikcp_ptr)->rcv_wnd;
	}
	std::pair<int, int> KCP::GetWindowSize()
	{
		return std::pair<int, int>{ ((ikcpcb *)ikcp_ptr)->snd_wnd, ((ikcpcb *)ikcp_ptr)->rcv_wnd };
	}

	int KCP::GetSendWindowSize()
	{
		return ((ikcpcb *)ikcp_ptr)->snd_wnd;
	}

	int KCP::GetReceiveWindowSize()
	{
		return ((ikcpcb *)ikcp_ptr)->rcv_wnd;
	}

	// get how many packet is waiting to be sent
	int KCP::WaitingForSend()
	{
		return ikcp_waitsnd((ikcpcb *)ikcp_ptr);
	}

	// fastest: NoDelay(1, 20, 2, 1)
	// nodelay: 0:disable(default), 1:enable
	// interval: internal update timer interval in millisec, default is 100ms 
	// resend: 0:disable fast resend(default), 1:enable fast resend
	// nc: 0:normal congestion control(default), 1:disable congestion control
	int KCP::NoDelay(int nodelay, int interval, int resend, bool nc)
	{
		return ikcp_nodelay((ikcpcb *)ikcp_ptr, nodelay, interval, resend, nc);
	}

	uint32_t KCP::GetConv(const void *ptr)
	{
		return ikcp_getconv(ptr);
	}

	uint32_t KCP::GetConv()
	{
		return ikcp_getconv(ikcp_ptr);
	}

	int KCP::Interval(int interval)
	{
		return ikcp_interval((ikcpcb *)ikcp_ptr, interval);
	}

	void KCP::SetStreamMode(bool enable)
	{
		((IKCPCB *)ikcp_ptr)->stream = enable;
	}

	int32_t& KCP::RxMinRTO()
	{
		return ((IKCPCB *)ikcp_ptr)->rx_minrto;
	}

	void KCP::SetBandwidth(uint64_t out_bw, uint64_t in_bw)
	{
		outbound_bandwidth = out_bw;
		inbound_bandwidth = in_bw;
	}

	int proxy_output(KCP *kcp, const char *buf, int len)
	{
		return kcp->output(buf, len, kcp->custom_data.load());
	}

	void proxy_writelog(KCP *kcp, const char *buf)
	{
		kcp->writelog(buf, kcp->custom_data.load());
	}

}

int middle_layer_output(const char *buf, int len, struct IKCPCB *kcp, void *user)
{
	KCP::KCP *kcp_ptr = (KCP::KCP*)kcp->user;
	return KCP::proxy_output(kcp_ptr, buf, len);
}

void middle_layer_writelog(const char *buf, struct IKCPCB *kcp, void *user)
{
	KCP::KCP *kcp_ptr = (KCP::KCP*)kcp->user;
	return KCP::proxy_writelog(kcp_ptr, buf);
}

