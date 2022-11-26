//=====================================================================
//
// KCP - A Better ARQ Protocol Implementation
// Original author: skywind3000 (at) gmail.com, 2010-2011
// Modifier: cnbatch, 2021
//  
// Features:
// + Average RTT reduce 30% - 40% vs traditional ARQ like tcp.
// + Maximum RTT reduce three times vs tcp.
// + Lightweight, distributed as a single source file.
//
//=====================================================================
#include "kcp.hpp"

#include <cstdarg>
#include <cstdio>
#include <cstring>


namespace KCP
{
	using internal_impl::Segment;

	//=====================================================================
	// KCP BASIC
	//=====================================================================
	constexpr uint32_t IKCP_RTO_NDL = 30;		// no delay min rto
	constexpr uint32_t IKCP_RTO_MIN = 100;		// normal min rto
	constexpr uint32_t IKCP_RTO_DEF = 200;
	constexpr uint32_t IKCP_RTO_MAX = 60000;
	constexpr uint32_t IKCP_CMD_PUSH = 81;		// cmd: push data
	constexpr uint32_t IKCP_CMD_ACK = 82;		// cmd: ack
	constexpr uint32_t IKCP_CMD_WASK = 83;		// cmd: window probe (ask)
	constexpr uint32_t IKCP_CMD_WINS = 84;		// cmd: window size (tell)
	constexpr uint32_t IKCP_ASK_SEND = 1;		// need to send IKCP_CMD_WASK
	constexpr uint32_t IKCP_ASK_TELL = 2;		// need to send IKCP_CMD_WINS
	constexpr uint32_t IKCP_WND_SND = 32;
	constexpr uint32_t IKCP_WND_RCV = 128;       // must >= max fragment size
	constexpr uint32_t IKCP_MTU_DEF = 1400;
	constexpr uint32_t IKCP_ACK_FAST = 3;
	constexpr uint32_t IKCP_INTERVAL = 100;
	constexpr uint32_t IKCP_OVERHEAD = 24;
	constexpr uint32_t IKCP_DEADLINK = 20;
	constexpr uint32_t IKCP_THRESH_INIT = 2;
	constexpr uint32_t IKCP_THRESH_MIN = 2;
	constexpr uint32_t IKCP_PROBE_INIT = 7000;		// 7 secs to probe window size
	constexpr uint32_t IKCP_PROBE_LIMIT = 120000;	// up to 120 secs to probe window
	constexpr uint32_t IKCP_FASTACK_LIMIT = 5;		// max times to trigger fastack


	//---------------------------------------------------------------------
	// encode / decode
	//---------------------------------------------------------------------

	/* encode 8 bits unsigned int */
	inline char * KCP::Encode8u(char *p, unsigned char c)
	{
		*(unsigned char*)p++ = c;
		return p;
	}

	/* decode 8 bits unsigned int */
	inline const char * KCP::Decode8u(const char *p, unsigned char *c)
	{
		*c = *(unsigned char*)p++;
		return p;
	}

	/* encode 16 bits unsigned int (lsb) */
	inline char * KCP::Encode16u(char *p, unsigned short w)
	{
#if IWORDS_BIG_ENDIAN || IWORDS_MUST_ALIGN
		*(unsigned char*)(p + 0) = (w & 255);
		*(unsigned char*)(p + 1) = (w >> 8);
#else
		memcpy(p, &w, 2);
#endif
		p += 2;
		return p;
	}

	/* decode 16 bits unsigned int (lsb) */
	inline const char * KCP::Decode16u(const char *p, unsigned short *w)
	{
#if IWORDS_BIG_ENDIAN || IWORDS_MUST_ALIGN
		*w = *(const unsigned char*)(p + 1);
		*w = *(const unsigned char*)(p + 0) + (*w << 8);
#else
		memcpy(w, p, 2);
#endif
		p += 2;
		return p;
	}

	/* encode 32 bits unsigned int (lsb) */
	inline char * KCP::Encode32u(char *p, uint32_t l)
	{
#if IWORDS_BIG_ENDIAN || IWORDS_MUST_ALIGN
		*(unsigned char*)(p + 0) = (unsigned char)((l >> 0) & 0xff);
		*(unsigned char*)(p + 1) = (unsigned char)((l >> 8) & 0xff);
		*(unsigned char*)(p + 2) = (unsigned char)((l >> 16) & 0xff);
		*(unsigned char*)(p + 3) = (unsigned char)((l >> 24) & 0xff);
#else
		memcpy(p, &l, 4);
#endif
		p += 4;
		return p;
	}

	/* decode 32 bits unsigned int (lsb) */
	inline const char * KCP::Decode32u(const char *p, uint32_t *l)
	{
#if IWORDS_BIG_ENDIAN || IWORDS_MUST_ALIGN
		*l = *(const unsigned char*)(p + 3);
		*l = *(const unsigned char*)(p + 2) + (*l << 8);
		*l = *(const unsigned char*)(p + 1) + (*l << 8);
		*l = *(const unsigned char*)(p + 0) + (*l << 8);
#else 
		memcpy(l, p, 4);
#endif
		p += 4;
		return p;
	}

	//---------------------------------------------------------------------
	// EncodeSegment
	//---------------------------------------------------------------------
	char* KCP::EncodeSegment(char *ptr, const Segment &seg)
	{
		ptr = Encode32u(ptr, seg.conv);
		ptr = Encode8u(ptr, static_cast<uint8_t>(seg.cmd));
		ptr = Encode8u(ptr, static_cast<uint8_t>(seg.frg));
		ptr = Encode16u(ptr, static_cast<uint16_t>(seg.wnd));
		ptr = Encode32u(ptr, seg.ts);
		ptr = Encode32u(ptr, seg.sn);
		ptr = Encode32u(ptr, seg.una);
		ptr = Encode32u(ptr, static_cast<int>(seg.data.size()));
		return ptr;
	}

	static inline uint32_t _ibound_(uint32_t lower, uint32_t middle, uint32_t upper)
	{
		return std::min<uint32_t>(std::max<uint32_t>(lower, middle), upper);
	}

	static inline long _itimediff(uint32_t later, uint32_t earlier)
	{
		return static_cast<long>((int64_t)later - (int64_t)earlier);
	}

	// write log
	void KCP::WriteLog(int mask, const char *fmt, ...)
	{
		char buffer[1024] = { 0 };
		va_list argptr;
		if ((mask & this->logmask) == 0 || this->writelog == nullptr) return;
		va_start(argptr, fmt);
		vsprintf(buffer, fmt, argptr);
		va_end(argptr);
		this->writelog(buffer, this->user);
	}

	// check log mask
	bool KCP::CanLog(int mask)
	{
		return mask & this->logmask && this->writelog != nullptr;
	}

	// output segment
	int KCP::Output(const void *data, int size)
	{
		assert(this->output);
		if (CanLog(IKCP_LOG_OUTPUT))
		{
			WriteLog(IKCP_LOG_OUTPUT, "[RO] %ld bytes", static_cast<long>(size));
		}
		if (size == 0)
			return 0;

		return this->output((const char*)data, size, this->user);
	}

	// output queue
	void KCP::PrintQueue(const char *name, const std::list<Segment> &segment)
	{
#if 0
		printf("<%s>: [", name);
		for (auto seg = segment.cbegin(), next = seg; seg != segment.cend(); seg = next)
		{
			++next;
			printf("(%lu %d)", (unsigned long)seg->sn, (int)(seg->ts % 10000));
			if (next != segment.cend()) printf(",");
		}
		printf("]\n");
#endif
	}

	void KCP::Initialise(uint32_t conv, void *user)
	{
		this->conv = conv;
		this->user = user;
		this->snd_una.store(0);
		this->snd_nxt.store(0);
		this->rcv_nxt.store(0);
		this->ts_recent = 0;
		this->ts_lastack = 0;
		this->ts_probe = 0;
		this->probe_wait = 0;
		this->snd_wnd.store(IKCP_WND_SND);
		this->rcv_wnd.store(IKCP_WND_RCV);
		this->rmt_wnd.store(IKCP_WND_RCV);
		this->cwnd.store(0);
		this->incr.store(0);
		this->probe.store(0);
		this->mtu = IKCP_MTU_DEF;
		this->mss = this->mtu - IKCP_OVERHEAD;
		this->stream = false;

		this->buffer.resize(static_cast<size_t>(this->mtu) + IKCP_OVERHEAD);

		this->state = 0;
		this->rx_srtt = 0;
		this->rx_rttval = 0;
		this->rx_rto = IKCP_RTO_DEF;
		this->rx_minrto = IKCP_RTO_MIN;
		this->current.store(0);
		this->interval.store(IKCP_INTERVAL);
		this->ts_flush.store(IKCP_INTERVAL);
		this->nodelay = 0;
		this->updated.store(false);
		this->logmask = 0;
		this->ssthresh = IKCP_THRESH_INIT;
		this->fastresend = 0;
		this->fastlimit = IKCP_FASTACK_LIMIT;
		this->nocwnd.store(false);
		this->xmit.store(0);
		this->dead_link = IKCP_DEADLINK;
	}

	void KCP::MoveKCP(KCP &other) noexcept
	{
		this->conv = other.conv;
		this->user.store(other.user.load());
		this->snd_una.store(other.snd_una.load());
		this->snd_nxt.store(other.snd_nxt.load());
		this->rcv_nxt.store(other.rcv_nxt.load());
		this->ts_recent = other.ts_recent;
		this->ts_lastack = other.ts_lastack;
		this->ts_probe = other.ts_probe;
		this->probe_wait = other.probe_wait;
		this->snd_wnd.store(other.snd_wnd.load());
		this->rcv_wnd.store(other.rcv_wnd.load());
		this->rmt_wnd.store(other.rmt_wnd.load());
		this->cwnd.store(other.cwnd.load());
		this->incr.store(other.incr.load());
		this->probe.store(other.probe.load());
		this->mtu = other.mtu;
		this->mss = other.mss;
		this->stream = other.stream;

		this->buffer = std::move(other.buffer);

		this->state = other.state;
		this->rx_srtt = other.rx_srtt;
		this->rx_rttval = other.rx_rttval;
		this->rx_rto = other.rx_rto;
		this->rx_minrto = other.rx_minrto;
		this->current.store(other.current.load());
		this->interval.store(other.interval.load());
		this->ts_flush.store(other.ts_flush.load());
		this->nodelay = other.nodelay;
		this->updated.store(other.updated.load());
		this->logmask = other.logmask;
		this->ssthresh = other.ssthresh;
		this->fastresend = other.fastresend;
		this->fastlimit = other.fastlimit;
		this->nocwnd.store(other.nocwnd.load());
		this->xmit.store(other.xmit.load());
		this->dead_link = other.dead_link;
	}

	KCP::KCP(const KCP &other) noexcept
	{
		this->conv = other.conv;
		this->user.store(other.user.load());
		this->snd_una.store(other.snd_una.load());
		this->snd_nxt.store(other.snd_nxt.load());
		this->rcv_nxt.store(other.rcv_nxt.load());
		this->ts_recent = other.ts_recent;
		this->ts_lastack = other.ts_lastack;
		this->ts_probe = other.ts_probe;
		this->probe_wait = other.probe_wait;
		this->snd_wnd.store(other.snd_wnd.load());
		this->rcv_wnd.store(other.rcv_wnd.load());
		this->rmt_wnd.store(other.rmt_wnd.load());
		this->cwnd.store(other.cwnd.load());
		this->incr.store(other.incr.load());
		this->probe.store(other.probe.load());
		this->mtu = other.mtu;
		this->mss = other.mss;
		this->stream = other.stream;

		this->buffer = other.buffer;

		this->state = other.state;
		this->rx_srtt = other.rx_srtt;
		this->rx_rttval = other.rx_rttval;
		this->rx_rto = other.rx_rto;
		this->rx_minrto = other.rx_minrto;
		this->current.store(other.current.load());
		this->interval.store(other.interval.load());
		this->ts_flush.store(other.ts_flush.load());
		this->nodelay = other.nodelay;
		this->updated.store(other.updated.load());
		this->logmask = other.logmask;
		this->ssthresh = other.ssthresh;
		this->fastresend = other.fastresend;
		this->fastlimit = other.fastlimit;
		this->nocwnd.store(other.nocwnd.load());
		this->xmit.store(other.xmit.load());
		this->dead_link = other.dead_link;
	}


	//---------------------------------------------------------------------
	// set output callback, which will be invoked by kcp
	//---------------------------------------------------------------------
	void KCP::SetOutput(std::function<int(const char *, int, void *)> output)
	{
		this->output = output;
	}


	//---------------------------------------------------------------------
	// user/upper level recv: returns size, returns below zero for EAGAIN
	//---------------------------------------------------------------------
	int KCP::Receive(char *buffer, int len)
	{
		bool ispeek = len < 0;
		bool recover = false;

		std::unique_lock<std::shared_mutex> lock_rcv{ this->mtx_rcv };
		if (this->rcv_queue.empty())
			return -1;

		if (len < 0) len = -len;

		int peeksize = PeekSizeWithoutLock();

		if (peeksize < 0)
			return -2;

		if (peeksize > len)
			return -3;

		if (this->rcv_queue.size() >= this->rcv_wnd.load())
			recover = true;

		// merge fragment
		len = 0;
		for (auto seg = rcv_queue.begin(), next = seg; seg != this->rcv_queue.end(); seg = next)
		{
			int fragment;
			++next;
			if (buffer)
			{
				std::copy(seg->data.begin(), seg->data.end(), buffer);
				//memcpy(buffer, seg->data.data(), seg->data.size());
				buffer += seg->data.size();
			}

			len += static_cast<int>(seg->data.size());
			fragment = seg->frg;

			if (CanLog(IKCP_LOG_RECV))
			{
				WriteLog(IKCP_LOG_RECV, "recv sn=%lu", (unsigned long)seg->sn);
			}

			if (!ispeek)
			{
				seg = this->rcv_queue.erase(seg);
			}

			if (fragment == 0)
				break;
		}

		assert(len == peeksize);

		// move available data from rcv_buf -> rcv_queue
		while (!this->rcv_buf.empty())
		{
			auto seg = this->rcv_buf.begin();
			if (seg->sn == this->rcv_nxt.load() && this->rcv_queue.size() < this->rcv_wnd.load())
			{
				this->rcv_queue.splice(this->rcv_queue.end(), this->rcv_buf, seg);
				this->rcv_nxt++;
			}
			else
			{
				break;
			}
		}

		// fast recover
		if (this->rcv_queue.size() < this->rcv_wnd.load() && recover)
		{
			// ready to send back IKCP_CMD_WINS in Flush
			// tell remote my window size
			this->probe |= IKCP_ASK_TELL;
		}

		return len;
	}

	int KCP::Receive(std::vector<char> &buffer)
	{
		int peeksize = PeekSize();

		if (peeksize < 0)
			return -2;

		if (peeksize > buffer.size())
			buffer.resize(peeksize);

		return Receive(buffer.data(), static_cast<int>(buffer.size()));
	}

	//---------------------------------------------------------------------
	// peek data size
	//---------------------------------------------------------------------
	int KCP::PeekSize()
	{
		std::shared_lock<std::shared_mutex> lock_rcv{ mtx_rcv };
		return PeekSizeWithoutLock();
	}

	int KCP::KCP::PeekSizeWithoutLock()
	{
		int length = 0;

		if (this->rcv_queue.empty()) return -1;

		auto seg = this->rcv_queue.begin();
		if (seg->frg == 0) return static_cast<int>(seg->data.size());

		if (this->rcv_queue.size() < static_cast<size_t>(seg->frg) + 1) return -1;

		for (seg = this->rcv_queue.begin(); seg != this->rcv_queue.end(); ++seg)
		{
			length += static_cast<int>(seg->data.size());
			if (seg->frg == 0) break;
		}

		return length;
	}

	//---------------------------------------------------------------------
	// user/upper level send, returns below zero for error
	//---------------------------------------------------------------------
	int KCP::Send(const char *buffer, size_t len)
	{
		std::unique_lock<std::shared_mutex> lock_snd{ this->mtx_snd };
		assert(this->mss > 0);
		//if (len < 0) return -1;

		// append to previous segment in streaming mode (if possible)
		if (this->stream)
		{
			if (!this->snd_queue.empty())
			{
				auto &seg = this->snd_queue.back();
				if (seg.data.size() < this->mss)
				{
					size_t capacity = static_cast<size_t>(this->mss) - seg.data.size();
					size_t extend = (len < capacity) ? len : capacity;
					size_t old_size = seg.data.size();
					seg.data.resize(seg.data.size() + extend);
					//memcpy(seg->data.data(), old->data.data(), old->data.size());
					if (buffer)
					{
						std::copy_n(buffer, extend, seg.data.begin() + old_size);
						//memcpy(seg.data.data() + old_size, buffer, extend);
						buffer += extend;
					}
					seg.frg = 0;
					len -= extend;
				}
			}
			if (len <= 0)
			{
				return 0;
			}
		}

		uint32_t count;

		if (len <= this->mss) count = 1;
		else count = uint32_t(len + this->mss - 1) / this->mss;

		if (count >= IKCP_WND_RCV) return -2;

		if (count == 0) count = 1;

		// fragment
		for (uint32_t i = 0; i < count; i++)
		{
			size_t size = len > this->mss ? this->mss : len;
			this->snd_queue.emplace_back(Segment(size));
			auto &seg = snd_queue.back();
			if (buffer && len > 0)
			{
				std::copy_n(buffer, size, seg.data.begin());
				//memcpy(seg.data.data(), buffer, size);
			}
			seg.frg = this->stream ? 0 : (count - i - 1);
			if (buffer)
			{
				buffer += size;
			}
			len -= size;
		}

		return 0;
	}


	//---------------------------------------------------------------------
	// parse ack
	//---------------------------------------------------------------------
	void KCP::UpdateAck(int32_t rtt)
	{
		int32_t rto = 0;
		if (this->rx_srtt == 0)
		{
			this->rx_srtt = rtt;
			this->rx_rttval = rtt / 2;
		}
		else
		{
			long delta = rtt - this->rx_srtt;
			if (delta < 0) delta = -delta;
			this->rx_rttval = (3 * this->rx_rttval + delta) / 4;
			this->rx_srtt = (7 * this->rx_srtt + rtt) / 8;
			if (this->rx_srtt < 1) this->rx_srtt = 1;
		}
		rto = this->rx_srtt + std::max<uint32_t>(this->interval.load(), 4 * this->rx_rttval);
		this->rx_rto = _ibound_(this->rx_minrto, rto, IKCP_RTO_MAX);
	}

	void KCP::ShrinkBuffer()
	{
		if (!this->snd_buf.empty())
		{
			this->snd_una.store(this->snd_buf.front().sn);
		}
		else
		{
			this->snd_una.store(this->snd_nxt.load());
		}
	}

	void KCP::ParseAck(uint32_t sn)
	{
		if (_itimediff(sn, this->snd_una.load()) < 0 || _itimediff(sn, this->snd_nxt.load()) >= 0)
			return;

		for (auto seg = this->snd_buf.begin(); seg != this->snd_buf.end(); ++seg)
		{
			if (sn == seg->sn)
			{
				this->snd_buf.erase(seg);
				break;
			}
			if (_itimediff(sn, seg->sn) < 0)
			{
				break;
			}
		}
	}

	void KCP::ParseUna(uint32_t una)
	{
		for (auto seg = this->snd_buf.begin(); seg != this->snd_buf.end();)
		{
			if (_itimediff(una, seg->sn) > 0)
			{
				seg = this->snd_buf.erase(seg);
			}
			else
			{
				break;
			}
		}
	}

	void KCP::ParseFastAck(uint32_t sn, uint32_t ts)
	{
		if (_itimediff(sn, this->snd_una.load()) < 0 || _itimediff(sn, this->snd_nxt.load()) >= 0)
			return;

		for (auto seg = this->snd_buf.begin(); seg != this->snd_buf.end(); ++seg)
		{
			if (_itimediff(sn, seg->sn) < 0)
			{
				break;
			}
			else if (sn != seg->sn)
			{
#ifndef IKCP_FASTACK_CONSERVE
				seg->fastack++;
#else
				if (_itimediff(ts, seg->ts) >= 0)
					seg->fastack++;
#endif
			}
		}
	}


	//---------------------------------------------------------------------
	// ack append
	//---------------------------------------------------------------------
	//void KCP::AckPush(uint32_t sn, uint32_t ts)
	//{
	//	this->acklist.push_back({ sn , ts });
	//}

	//void KCP::AckGet(int p, uint32_t *sn, uint32_t *ts)
	//{
	//	if (sn) sn[0] = this->acklist[p].first;
	//	if (ts) ts[0] = this->acklist[p].second;
	//}


	//---------------------------------------------------------------------
	// parse data
	//---------------------------------------------------------------------
	void KCP::ParseData(Segment &newseg)
	{
		uint32_t sn = newseg.sn;
		bool repeat = false;

		if (_itimediff(sn, this->rcv_nxt.load() + this->rcv_wnd.load()) >= 0 ||
			_itimediff(sn, this->rcv_nxt.load()) < 0)
		{
			return;
		}

		decltype(this->rcv_buf.rbegin()) seg_riter;
		for (seg_riter = this->rcv_buf.rbegin(); seg_riter != this->rcv_buf.rend(); ++seg_riter)
		{
			if (seg_riter->sn == sn)
			{
				repeat = true;
				break;
			}
			if (_itimediff(sn, seg_riter->sn) > 0)
			{
				break;
			}
		}

		if (!repeat)
		{
			this->rcv_buf.insert(seg_riter.base(), std::move(newseg));
		}

#if 0
		PrintQueue("rcvbuf", &this->rcv_buf);
		printf("rcv_nxt=%lu\n", this->rcv_nxt);
#endif

		// move available data from rcv_buf -> rcv_queue
		while (!this->rcv_buf.empty())
		{
			auto seg = this->rcv_buf.begin();
			if (seg->sn == this->rcv_nxt.load() && this->rcv_queue.size() < this->rcv_wnd.load())
			{
				this->rcv_queue.splice(this->rcv_queue.end(), this->rcv_buf, seg);
				this->rcv_nxt++;
			}
			else
			{
				break;
			}
		}

#if 0
		PrintQueue("queue", &this->rcv_queue);
		printf("rcv_nxt=%lu\n", this->rcv_nxt);
#endif

#if 1
		//	printf("snd(buf=%d, queue=%d)\n", this->nsnd_buf, this->nsnd_que);
		//	printf("rcv(buf=%d, queue=%d)\n", this->nrcv_buf, this->nrcv_que);
#endif
	}


	//---------------------------------------------------------------------
	// input data
	//---------------------------------------------------------------------
	int KCP::Input(const char *data, long size)
	{
		std::scoped_lock lock_recv_snd{ this->mtx_rcv, this->mtx_snd };

		uint32_t prev_una = this->snd_una.load();
		uint32_t maxack = 0, latest_ts = 0;
		int flag = 0;

		if (CanLog(IKCP_LOG_INPUT))
		{
			WriteLog(IKCP_LOG_INPUT, "[RI] %d bytes", (int)size);
		}

		if (data == NULL || (int)size < (int)IKCP_OVERHEAD) return -1;

		while (1)
		{
			uint32_t ts, sn, len, una, conv;
			uint16_t wnd;
			uint8_t cmd, frg;

			if (size < (int)IKCP_OVERHEAD) break;

			data = Decode32u(data, &conv);
			if (conv != this->conv) return -1;

			data = Decode8u(data, &cmd);
			data = Decode8u(data, &frg);
			data = Decode16u(data, &wnd);
			data = Decode32u(data, &ts);
			data = Decode32u(data, &sn);
			data = Decode32u(data, &una);
			data = Decode32u(data, &len);

			size -= IKCP_OVERHEAD;

			if ((long)size < (long)len || (int)len < 0) return -2;

			if (cmd != IKCP_CMD_PUSH && cmd != IKCP_CMD_ACK &&
				cmd != IKCP_CMD_WASK && cmd != IKCP_CMD_WINS)
				return -3;

			this->rmt_wnd.store(wnd);
			ParseUna(una);
			ShrinkBuffer();

			if (cmd == IKCP_CMD_ACK)
			{
				if (_itimediff(this->current.load(), ts) >= 0)
				{
					UpdateAck(_itimediff(this->current.load(), ts));
				}
				ParseAck(sn);
				ShrinkBuffer();
				if (flag == 0)
				{
					flag = 1;
					maxack = sn;
					latest_ts = ts;
				}
				else
				{
					if (_itimediff(sn, maxack) > 0)
					{
#ifndef IKCP_FASTACK_CONSERVE
						maxack = sn;
						latest_ts = ts;
#else
						if (_itimediff(ts, latest_ts) > 0)
						{
							maxack = sn;
							latest_ts = ts;
						}
#endif
					}
				}
				if (CanLog(IKCP_LOG_IN_ACK))
				{
					WriteLog(IKCP_LOG_IN_ACK,
						"input ack: sn=%lu rtt=%ld rto=%ld", (unsigned long)sn,
						(long)_itimediff(this->current.load(), ts),
						(long)this->rx_rto);
				}
			}
			else if (cmd == IKCP_CMD_PUSH)
			{
				if (CanLog(IKCP_LOG_IN_DATA))
				{
					WriteLog(IKCP_LOG_IN_DATA,
						"input psh: sn=%lu ts=%lu", (unsigned long)sn, (unsigned long)ts);
				}
				if (_itimediff(sn, this->rcv_nxt.load() + this->rcv_wnd.load()) < 0)
				{
					std::unique_lock<std::shared_mutex> lock_ack{ this->mtx_ack };
					// ack append
					this->acklist.push_back({ sn , ts });
					lock_ack.unlock();
					if (_itimediff(sn, this->rcv_nxt.load()) >= 0)
					{
						Segment seg(len);
						seg.conv = conv;
						seg.cmd = cmd;
						seg.frg = frg;
						seg.wnd = wnd;
						seg.ts = ts;
						seg.sn = sn;
						seg.una = una;

						if (len > 0)
						{
							std::copy_n(data, len, seg.data.begin());
							//memcpy(seg.data.data(), data, len);
						}

						ParseData(seg);
					}
				}
			}
			else if (cmd == IKCP_CMD_WASK)
			{
				// ready to send back IKCP_CMD_WINS in Flush
				// tell remote my window size
				this->probe |= IKCP_ASK_TELL;
				if (CanLog(IKCP_LOG_IN_PROBE))
				{
					WriteLog(IKCP_LOG_IN_PROBE, "input probe");
				}
			}
			else if (cmd == IKCP_CMD_WINS)
			{
				// do nothing
				if (CanLog(IKCP_LOG_IN_WINS))
				{
					WriteLog(IKCP_LOG_IN_WINS,
						"input wins: %lu", (unsigned long)(wnd));
				}
			}
			else
			{
				return -3;
			}

			data += len;
			size -= len;
		}

		if (flag != 0)
		{
			ParseFastAck(maxack, latest_ts);
		}

		if (_itimediff(this->snd_una.load(), prev_una) > 0)
		{
			if (this->cwnd.load() < this->rmt_wnd.load())
			{
				uint32_t mss = this->mss;
				if (this->cwnd.load() < this->ssthresh)
				{
					this->cwnd++;
					this->incr += mss;
				}
				else
				{
					if (this->incr.load() < mss) this->incr.store(mss);
					this->incr += (mss * mss) / this->incr.load() + (mss / 16);
					if ((this->cwnd.load() + 1) * mss <= this->incr.load())
					{
#if 1
						this->cwnd.store((this->incr.load() + mss - 1) / ((mss > 0) ? mss : 1));
#else
						this->cwnd++;
#endif
					}
				}
				if (this->cwnd.load() > this->rmt_wnd.load())
				{
					this->cwnd.store(this->rmt_wnd.load());
					this->incr = this->rmt_wnd.load() * mss;
				}
			}
		}

		return 0;
	}

	int KCP::WindowUnused()
	{
		if (this->rcv_queue.size() < this->rcv_wnd.load())
		{
			return this->rcv_wnd.load() - static_cast<int>(this->rcv_queue.size());
		}
		return 0;
	}


	//---------------------------------------------------------------------
	// Flush
	//---------------------------------------------------------------------
	void KCP::Flush()
	{
		uint32_t current = this->current.load();
		char *buffer = this->buffer.data();
		char *ptr = buffer;
		int size, i;
		uint32_t resent, cwnd;
		uint32_t rtomin;
		int change = 0;
		int lost = 0;

		// 'Update' haven't been called. 
		if (!this->updated.load()) return;

		Segment seg;
		seg.conv = this->conv;
		seg.cmd = IKCP_CMD_ACK;
		seg.frg = 0;
		seg.wnd = WindowUnused();
		seg.una = this->rcv_nxt.load();
		seg.sn = 0;
		seg.ts = 0;

		std::unique_lock<std::shared_mutex> lock_ack{ this->mtx_ack };
		// flush acknowledges
		for (i = 0; i < this->acklist.size(); i++)
		{
			size = (int)(ptr - buffer);
			if (size + (int)IKCP_OVERHEAD > (int)this->mtu)
			{
				Output(buffer, size);
				ptr = buffer;
			}
			seg.sn = this->acklist[i].first;
			seg.ts = this->acklist[i].second;
			ptr = EncodeSegment(ptr, seg);
		}

		this->acklist.clear();
		lock_ack.unlock();

		// probe window size (if remote window size equals zero)
		if (this->rmt_wnd.load() == 0)
		{
			if (this->probe_wait == 0)
			{
				this->probe_wait = IKCP_PROBE_INIT;
				this->ts_probe = this->current.load() + this->probe_wait;
			}
			else
			{
				if (_itimediff(this->current.load(), this->ts_probe) >= 0)
				{
					if (this->probe_wait < IKCP_PROBE_INIT)
						this->probe_wait = IKCP_PROBE_INIT;
					this->probe_wait += this->probe_wait / 2;
					if (this->probe_wait > IKCP_PROBE_LIMIT)
						this->probe_wait = IKCP_PROBE_LIMIT;
					this->ts_probe = this->current.load() + this->probe_wait;
					this->probe |= IKCP_ASK_SEND;
				}
			}
		}
		else
		{
			this->ts_probe = 0;
			this->probe_wait = 0;
		}

		// flush window probing commands
		if (this->probe.load() & IKCP_ASK_SEND)
		{
			seg.cmd = IKCP_CMD_WASK;
			size = (int)(ptr - buffer);
			if (size + (int)IKCP_OVERHEAD > (int)this->mtu)
			{
				Output(buffer, size);
				ptr = buffer;
			}
			ptr = EncodeSegment(ptr, seg);
		}

		// flush window probing commands
		if (this->probe.load() & IKCP_ASK_TELL)
		{
			seg.cmd = IKCP_CMD_WINS;
			size = (int)(ptr - buffer);
			if (size + (int)IKCP_OVERHEAD > (int)this->mtu)
			{
				Output(buffer, size);
				ptr = buffer;
			}
			ptr = EncodeSegment(ptr, seg);
		}

		this->probe.store(0);

		// calculate window size
		cwnd = std::min<uint32_t>(this->snd_wnd.load(), this->rmt_wnd.load());
		if (this->nocwnd == false) cwnd = std::min<uint32_t>(this->cwnd.load(), cwnd);

		std::unique_lock<std::shared_mutex> lock_snd{ this->mtx_snd };
		// move data from snd_queue to snd_buf
		while (_itimediff(this->snd_nxt.load(), this->snd_una.load() + cwnd) < 0)
		{
			if (this->snd_queue.empty()) break;

			auto newseg = this->snd_queue.begin();

			this->snd_buf.splice(this->snd_buf.end(), this->snd_queue, newseg);

			newseg->conv = this->conv;
			newseg->cmd = IKCP_CMD_PUSH;
			newseg->wnd = seg.wnd;
			newseg->ts = current;
			newseg->sn = this->snd_nxt++;
			newseg->una = this->rcv_nxt.load();
			newseg->resendts = current;
			newseg->rto = this->rx_rto;
			newseg->fastack = 0;
			newseg->xmit = 0;
		}

		// calculate resent
		resent = (this->fastresend > 0) ? (uint32_t)this->fastresend : 0xffffffff;
		rtomin = (this->nodelay == 0) ? (this->rx_rto >> 3) : 0;

		// flush data segments
		for (auto segment = this->snd_buf.begin(); segment != this->snd_buf.end(); ++segment)
		{
			bool needsend = false;
			if (segment->xmit == 0)
			{
				needsend = true;
				segment->xmit++;
				segment->rto = this->rx_rto;
				segment->resendts = current + segment->rto + rtomin;
			}
			else if (_itimediff(current, segment->resendts) >= 0)
			{
				needsend = true;
				segment->xmit++;
				this->xmit++;
				if (this->nodelay == 0)
				{
					segment->rto += std::max<uint32_t>(segment->rto, static_cast<uint32_t>(this->rx_rto));
				}
				else
				{
					int32_t step = (this->nodelay < 2) ? static_cast<int32_t>(segment->rto) : this->rx_rto;
					segment->rto += step / 2;
				}
				segment->resendts = current + segment->rto;
				lost = 1;
			}
			else if (segment->fastack >= resent)
			{
				if ((int)segment->xmit <= this->fastlimit ||
					this->fastlimit <= 0)
				{
					needsend = true;
					segment->xmit++;
					segment->fastack = 0;
					segment->resendts = current + segment->rto;
					change++;
				}
			}

			if (needsend)
			{
				int need;
				segment->ts = current;
				segment->wnd = seg.wnd;
				segment->una = this->rcv_nxt.load();

				size = (int)(ptr - buffer);
				need = IKCP_OVERHEAD + static_cast<int>(segment->data.size());

				if (size + need > (int)this->mtu)
				{
					Output(buffer, size);
					ptr = buffer;
				}

				ptr = EncodeSegment(ptr, *segment);

				if (segment->data.size() > 0)
				{
					std::copy(segment->data.begin(), segment->data.end(), ptr);
					//memcpy(ptr, segment->data.data(), segment->data.size());
					ptr += segment->data.size();
				}

				if (segment->xmit >= this->dead_link)
				{
					this->state = (uint32_t)-1;
				}
			}
		}

		// flash remain segments
		size = (int)(ptr - buffer);
		if (size > 0)
		{
			Output(buffer, size);
		}

		// update ssthresh
		if (change)
		{
			uint32_t inflight = this->snd_nxt.load() - this->snd_una.load();
			this->ssthresh = inflight / 2;
			if (this->ssthresh < IKCP_THRESH_MIN)
				this->ssthresh = IKCP_THRESH_MIN;
			this->cwnd.store(this->ssthresh + resent);
			this->incr.store(this->cwnd.load() * this->mss);
		}

		if (lost)
		{
			this->ssthresh = cwnd / 2;
			if (this->ssthresh < IKCP_THRESH_MIN)
				this->ssthresh = IKCP_THRESH_MIN;
			this->cwnd.store(1);
			this->incr.store(this->mss);
		}

		if (this->cwnd.load() < 1)
		{
			this->cwnd.store(1);
			this->incr.store(this->mss);
		}
	}


	//---------------------------------------------------------------------
	// update state (call it repeatedly, every 10ms-100ms), or you can ask 
	// Check() when to call it again (without Input/Send calling).
	// 'current' - current timestamp in millisec. 
	//---------------------------------------------------------------------
	void KCP::Update(uint32_t current)
	{
		this->current.store(current);

		if (!this->updated.load())
		{
			this->updated.store(true);
			this->ts_flush.store(this->current.load());
		}

		int32_t slap = _itimediff(this->current.load(), this->ts_flush.load());

		if (slap >= 10000 || slap < -10000)
		{
			this->ts_flush.store(this->current.load());
			slap = 0;
		}

		if (slap >= 0)
		{
			this->ts_flush += this->interval.load();
			if (_itimediff(this->current.load(), this->ts_flush.load()) >= 0)
			{
				this->ts_flush.store(this->current.load() + this->interval.load());
			}
			Flush();
		}
	}


	//---------------------------------------------------------------------
	// Determine when should you invoke Update:
	// returns when you should invoke Update in millisec, if there 
	// is no Input/Send calling. you can call Update in that
	// time, instead of call update repeatly.
	// Important to reduce unnacessary Update invoking. use it to 
	// schedule Update (eg. implementing an epoll-like mechanism, 
	// or optimize Update when handling massive kcp connections)
	//---------------------------------------------------------------------
	uint32_t KCP::Check(uint32_t current)
	{
		uint32_t ts_flush = this->ts_flush.load();
		int32_t tm_flush = 0x7fffffff;
		int32_t tm_packet = 0x7fffffff;

		if (!this->updated.load())
		{
			return current;
		}

		if (_itimediff(current, ts_flush) >= 10000 ||
			_itimediff(current, ts_flush) < -10000)
		{
			ts_flush = current;
		}

		if (_itimediff(current, ts_flush) >= 0)
		{
			return current;
		}

		tm_flush = _itimediff(ts_flush, current);

		std::unique_lock<std::shared_mutex> lock_snd{ this->mtx_snd };
		for (auto seg = this->snd_buf.cbegin(); seg != this->snd_buf.cend(); ++seg)
		{
			int32_t diff = _itimediff(seg->resendts, current);
			if (diff <= 0)
			{
				return current;
			}
			if (diff < tm_packet) tm_packet = diff;
		}
		lock_snd.unlock();

		uint32_t minimal = static_cast<uint32_t>(tm_packet < tm_flush ? tm_packet : tm_flush);
		if (minimal >= this->interval.load()) minimal = this->interval.load();

		return current + minimal;
	}

	void KCP::ReplaceUserPtr(void *user)
	{
		this->user.store(user);
	}

	int KCP::SetMTU(int mtu)
	{
		if (mtu < 50 || mtu < (int)IKCP_OVERHEAD)
			return -1;
		if (this->mtu == mtu)
			return 0;
		this->mtu = mtu;
		this->mss = this->mtu - IKCP_OVERHEAD;
		this->buffer.resize(static_cast<size_t>(mtu) + IKCP_OVERHEAD);
		return 0;
	}
	
	int KCP::GetMTU()
	{
		return this->mtu;
	}

	int KCP::Interval(int interval)
	{
		if (interval > 5000) interval = 5000;
		else if (interval < 1) interval = 1;
		this->interval.store(interval);
		return 0;
	}

	int KCP::NoDelay(int nodelay, int interval, int resend, bool nc)
	{
		if (nodelay >= 0)
		{
			this->nodelay = nodelay;
			if (nodelay)
			{
				this->rx_minrto = IKCP_RTO_NDL;
			}
			else
			{
				this->rx_minrto = IKCP_RTO_MIN;
			}
		}
		if (interval >= 0)
		{
			if (interval > 5000) interval = 5000;
			else if (interval < 10) interval = 10;
			this->interval.store(interval);
		}
		if (resend >= 0)
		{
			this->fastresend = resend;
		}
		this->nocwnd.store(nc);
		return 0;
	}


	void KCP::SetWindowSize(int sndwnd, int rcvwnd)
	{
		if (sndwnd > 0)
		{
			this->snd_wnd.store(sndwnd);
		}
		if (rcvwnd > 0)
		{   // must >= max fragment size
			this->rcv_wnd.store(std::max<uint32_t>(rcvwnd, IKCP_WND_RCV));
		}
	}

	void KCP::GetWindowSize(int &sndwnd, int &rcvwnd)
	{
		sndwnd = this->snd_wnd.load();
		rcvwnd = this->rcv_wnd.load();
	}

	std::pair<int, int> KCP::KCP::GetWindowSize()
	{
		return { this->snd_wnd.load(), this->rcv_wnd.load() };
	}

	int KCP::GetSendWindowSize()
	{
		return this->snd_wnd.load();
	}

	int KCP::GetReceiveWindowSize()
	{
		return this->rcv_wnd.load();
	}

	int KCP::WaitingForSend()
	{
		return static_cast<int>(this->snd_buf.size() + this->snd_queue.size());
	}

	// read conv
	uint32_t KCP::GetConv(const void *ptr)
	{
		uint32_t conv;
		Decode32u(static_cast<const char*>(ptr), &conv);
		return conv;
	}

	uint32_t KCP::GetConv()
	{
		return this->conv;
	}

	void KCP::SetStreamMode(bool enable)
	{
		this->stream = enable;
	}

	int32_t& KCP::RxMinRTO()
	{
		return this->rx_minrto;
	}

	int& KCP::LogMask()
	{
		return this->logmask;
	}
}
