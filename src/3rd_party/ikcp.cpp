//=====================================================================
//
// KCP - A Better ARQ Protocol Implementation
// skywind3000 (at) gmail.com, 2010-2011
// Modifier: cnbatch, 2023
//  
// Features:
// + Average RTT reduce 30% - 40% vs traditional ARQ like tcp.
// + Maximum RTT reduce three times vs tcp.
// + Lightweight, distributed as a single source file.
//
//=====================================================================
#include "ikcp.hpp"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>


//---------------------------------------------------------------------
// BYTE ORDER & ALIGNMENT
//---------------------------------------------------------------------
#ifndef IWORDS_BIG_ENDIAN
#ifdef _BIG_ENDIAN_
#if _BIG_ENDIAN_
#define IWORDS_BIG_ENDIAN 1
#endif
#endif
#ifndef IWORDS_BIG_ENDIAN
#if defined(__hppa__) || \
            defined(__m68k__) || defined(mc68000) || defined(_M_M68K) || \
            (defined(__MIPS__) && defined(__MIPSEB__)) || \
            defined(__ppc__) || defined(__POWERPC__) || defined(_M_PPC) || \
            defined(__sparc__) || defined(__powerpc__) || \
            defined(__mc68000__) || defined(__s390x__) || defined(__s390__)
#define IWORDS_BIG_ENDIAN 1
#endif
#endif
#ifndef IWORDS_BIG_ENDIAN
#define IWORDS_BIG_ENDIAN  0
#endif
#endif

#ifndef IWORDS_MUST_ALIGN
#if defined(__i386__) || defined(__i386) || defined(_i386_)
#define IWORDS_MUST_ALIGN 0
#elif defined(_M_IX86) || defined(_X86_) || defined(__x86_64__)
#define IWORDS_MUST_ALIGN 0
#elif defined(__amd64) || defined(__amd64__)
#define IWORDS_MUST_ALIGN 0
#else
#define IWORDS_MUST_ALIGN 1
#endif
#endif


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
static inline char *ikcp_encode8u(char *p, unsigned char c)
{
	*(unsigned char*)p++ = c;
	return p;
}

/* decode 8 bits unsigned int */
static inline const char *ikcp_decode8u(const char *p, unsigned char *c)
{
	*c = *(unsigned char*)p++;
	return p;
}

/* encode 16 bits unsigned int (lsb) */
static inline char *ikcp_encode16u(char *p, unsigned short w)
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
static inline const char *ikcp_decode16u(const char *p, unsigned short *w)
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
static inline char *ikcp_encode32u(char *p, uint32_t l)
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
static inline const char *ikcp_decode32u(const char *p, uint32_t *l)
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

static inline uint32_t _imin_(uint32_t a, uint32_t b)
{
	return a <= b ? a : b;
}

static inline uint32_t _imax_(uint32_t a, uint32_t b)
{
	return a >= b ? a : b;
}

static inline uint32_t _ibound_(uint32_t lower, uint32_t middle, uint32_t upper)
{
	return _imin_(_imax_(lower, middle), upper);
}

static inline long _itimediff(uint32_t later, uint32_t earlier)
{
	return ((int32_t)(later - earlier));
}

// output queue
void ikcp_qprint(const char *name, const struct IQUEUEHEAD *head)
{
#if 0
	const struct IQUEUEHEAD *p;
	printf("<%s>: [", name);
	for (p = head->next; p != head; p = p->next)
	{
		const IKCPSEG *seg = iqueue_entry(p, const IKCPSEG, node);
		printf("(%lu %d)", (unsigned long)seg->sn, (int)(seg->ts % 10000));
		if (p->next != head) printf(",");
	}
	printf("]\n");
#endif
}

namespace KCP
{
	// write log
	void kcp_core::ikcp_log(int mask, const char *fmt, ...)
	{
		char buffer[1024];
		va_list argptr;
		if ((mask & this->logmask) == 0 || this->writelog == 0) return;
		va_start(argptr, fmt);
		vsprintf(buffer, fmt, argptr);
		va_end(argptr);
		this->writelog(buffer, this->user);
	}

	// check log mask
	int kcp_core::ikcp_canlog(int mask)
	{
		if ((mask & this->logmask) == 0 || this->writelog == nullptr) return 0;
		return 1;
	}

	// output segment
	int kcp_core::call_output(const void *data, int size)
	{
		if (ikcp_canlog(IKCP_LOG_OUTPUT))
		{
			ikcp_log(IKCP_LOG_OUTPUT, "[RO] %ld bytes", (long)size);
		}
		if (size == 0) return 0;
		return this->output_callback((const char*)data, size, this->user);
	}

	//---------------------------------------------------------------------
	// create a new kcpcb
	//---------------------------------------------------------------------
	bool kcp_core::initialise(uint32_t conv, void *user)
	{
		this->conv = conv;
		this->user = user;
		this->snd_una = 0;
		this->snd_nxt = 0;
		this->rcv_nxt = 0;
		this->ts_recent = 0;
		this->ts_lastack = 0;
		this->ts_probe = 0;
		this->probe_wait = 0;
		this->snd_wnd = IKCP_WND_SND;
		this->rcv_wnd = IKCP_WND_RCV;
		this->rmt_wnd = IKCP_WND_RCV;
		this->cwnd = 0;
		this->incr = 0;
		this->probe = 0;
		this->mtu = IKCP_MTU_DEF;
		this->mss = this->mtu - IKCP_OVERHEAD;
		this->stream = 0;

		this->buffer = std::make_unique<char[]>((this->mtu + IKCP_OVERHEAD) * 3);
		if (this->buffer == nullptr)
			return false;

		this->state = 0;
		this->rx_srtt = 0;
		this->rx_rttval = 0;
		this->rx_rto = IKCP_RTO_DEF;
		this->rx_minrto = IKCP_RTO_MIN;
		this->current = 0;
		this->interval = IKCP_INTERVAL;
		this->ts_flush = IKCP_INTERVAL;
		this->nodelay = 0;
		this->updated = 0;
		this->logmask = 0;
		this->ssthresh = IKCP_THRESH_INIT;
		this->fastresend = 0;
		this->fastlimit = IKCP_FASTACK_LIMIT;
		this->nocwnd = 0;
		this->xmit = 0;
		this->dead_link = IKCP_DEADLINK;

		return true;
	}

	void kcp_core::move_kcp(kcp_core &other)
	{
		this->conv = other.conv;
		this->user = other.user;
		this->snd_una = other.snd_una;
		this->snd_nxt = other.snd_nxt;
		this->rcv_nxt = other.rcv_nxt;
		this->ts_recent = other.ts_recent;
		this->ts_lastack = other.ts_lastack;
		this->ts_probe = other.ts_probe;
		this->probe_wait = other.probe_wait;
		this->snd_wnd = other.snd_wnd;
		this->rcv_wnd = other.rcv_wnd;
		this->rmt_wnd = other.rmt_wnd;
		this->cwnd = other.cwnd;
		this->incr = other.incr;
		this->probe = other.probe;
		this->mtu = other.mtu;
		this->mss = other.mss;
		this->stream = other.stream;
		this->buffer = std::move(other.buffer);
		this->state = other.state;
		this->rx_srtt = other.rx_srtt;
		this->rx_rttval = other.rx_rttval;
		this->rx_rto = other.rx_rto;
		this->rx_minrto = other.rx_minrto;
		this->current = other.current;
		this->interval = other.interval;
		this->ts_flush = other.ts_flush;
		this->nodelay = other.nodelay;
		this->updated = other.updated;
		this->logmask = other.logmask;
		this->ssthresh = other.ssthresh;
		this->fastresend = other.fastresend;
		this->fastlimit = other.fastlimit;
		this->nocwnd = other.nocwnd;
		this->xmit = other.xmit;
		this->dead_link = other.dead_link;
	}



	//---------------------------------------------------------------------
	// set output callback, which will be invoked by kcp
	//---------------------------------------------------------------------
	void kcp_core::set_output(std::function<int(const char *, int, void *)> output_callback)
	{
		this->output_callback = output_callback;
	}


	//---------------------------------------------------------------------
	// user/upper level recv: returns size, returns below zero for EAGAIN
	//---------------------------------------------------------------------
	int kcp_core::receive(char *buffer, int len)
	{
		bool ispeek = (len < 0);
		int peeksize;
		int recover = 0;

		if (this->rcv_queue.empty())
			return -1;

		if (len < 0) len = -len;

		peeksize = peek_size();

		if (peeksize < 0)
			return -2;

		if (peeksize > len)
			return -3;

		if (this->rcv_queue.size() >= this->rcv_wnd)
			recover = 1;

		len = 0;
		// merge fragment
		for (auto seg = rcv_queue.begin(), next = seg; seg != this->rcv_queue.end(); seg = next)
		{
			int fragment;
			++next;

			if (buffer)
			{
				std::copy_n(seg->data.get(), seg->len, buffer);
				buffer += seg->len;
			}

			len += (int)seg->len;
			fragment = seg->frg;

			if (ikcp_canlog(IKCP_LOG_RECV))
			{
				ikcp_log(IKCP_LOG_RECV, "recv sn=%lu", (unsigned long)seg->sn);
			}

			if (ispeek == false)
				this->rcv_queue.erase(seg);

			if (fragment == 0)
				break;
		}

		assert(len == peeksize);

		// move available data from rcv_buf -> rcv_queue
		while (!this->rcv_buf.empty())
		{
			auto iter = this->rcv_buf.begin();
			uint32_t seg_sn = iter->first;
			segment *seg = iter->second.get();
			if (seg->sn == this->rcv_nxt && this->rcv_queue.size() < this->rcv_wnd)
			{
				this->rcv_queue.emplace_back(std::move(*seg));
				this->rcv_nxt++;
				rcv_buf.erase(iter);
			}
			else break;
		}

		// fast recover
		if (this->rcv_queue.size() < this->rcv_wnd && recover) {
			// ready to send back IKCP_CMD_WINS in ikcp_flush
			// tell remote my window size
			this->probe |= IKCP_ASK_TELL;
		}

		return len;
	}


	//---------------------------------------------------------------------
	// peek data size
	//---------------------------------------------------------------------
	int kcp_core::peek_size()
	{
		int length = 0;

		if (this->rcv_queue.empty()) return -1;

		auto seg = this->rcv_queue.begin();
		if (seg->frg == 0) return (int)seg->len;

		if (this->rcv_queue.size() < (size_t)(seg->frg) + 1) return -1;

		for (seg = this->rcv_queue.begin(); seg != this->rcv_queue.end(); ++seg)
		{
			length += (int)seg->len;
			if (seg->frg == 0) break;
		}

		return length;
	}


	//---------------------------------------------------------------------
	// user/upper level send, returns below zero for error
	//---------------------------------------------------------------------
	int kcp_core::send(const char *buffer, int len)
	{
		int count, i;
		int sent = 0;

		assert(this->mss > 0);
		if (len < 0) return -1;

		// append to previous segment in streaming mode (if possible)
		if (this->stream != 0)
		{
			if (!this->snd_queue.empty())
			{
				auto &seg = this->snd_queue.back();
				if (seg->len < this->mss)
				{
					int capacity = (int)((int64_t)this->mss - (int64_t)seg->len);
					int extend = (len < capacity) ? len : capacity;
					uint32_t old_size = seg->len;
					bool resized = seg->resize(old_size + (uint32_t)extend);
					if (!resized)
						return -2;

					if (buffer)
					{
						std::copy_n(buffer, extend, seg->data.get() + old_size);
						buffer += extend;
					}
					seg->len = old_size + extend;
					seg->frg = 0;
					len -= extend;
					sent = extend;
				}
			}
			if (len <= 0)
				return sent;
		}

		if (len <= (int)this->mss) count = 1;
		else count = (len + this->mss - 1) / this->mss;

		if (count >= (int)IKCP_WND_RCV)
		{
			if (this->stream != 0 && sent > 0)
				return sent;
			return -2;
		}

		if (count == 0) count = 1;

		// fragment
		for (i = 0; i < count; i++)
		{
			int size = len > (int)this->mss ? (int)this->mss : len;
			std::unique_ptr<segment> seg = std::make_unique<segment>(size);
			if (seg == nullptr)
				return -2;

			if (buffer && len > 0)
				std::copy_n(buffer, size, seg->data.get());

			seg->len = size;
			seg->frg = (this->stream == 0) ? (count - i - 1) : 0;
			this->snd_queue.emplace_back(std::move(seg));
			if (buffer)
				buffer += size;

			len -= size;
			sent += size;
		}

		return sent;
	}


	//---------------------------------------------------------------------
	// parse ack
	//---------------------------------------------------------------------
	void kcp_core::update_ack(int32_t rtt)
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
		rto = this->rx_srtt + _imax_(this->interval, 4 * this->rx_rttval);
		this->rx_rto = _ibound_(this->rx_minrto, rto, IKCP_RTO_MAX);
	}

	void kcp_core::shrink_buf()
	{
		if (!this->snd_buf.empty())
			this->snd_una = this->snd_buf.begin()->first;
		else
			this->snd_una = this->snd_nxt;
	}

	void kcp_core::parse_ack(uint32_t sn)
	{
		if (sn < this->snd_una || sn >= this->snd_nxt)
			return;

		if (auto iter = this->snd_buf.find(sn); iter != this->snd_buf.end())
		{
			std::shared_ptr<segment> seg = iter->second;

			if (auto resendts_iter = this->resendts_buf.find(seg->resendts); resendts_iter != this->resendts_buf.end())
				if (auto um_iter = resendts_iter->second.find(sn); um_iter != resendts_iter->second.end())
					resendts_iter->second.erase(um_iter);

			if (auto fastack_iter = this->fastack_buf.find(seg->fastack); fastack_iter != this->fastack_buf.end())
				if (auto um_iter = fastack_iter->second.find(sn); um_iter != fastack_iter->second.end())
					fastack_iter->second.erase(um_iter);

			this->snd_buf.erase(iter);
		}
	}

	void kcp_core::parse_una(uint32_t una)
	{
		for (auto iter = this->snd_buf.begin(), next = iter; iter != this->snd_buf.end(); iter = next)
		{
			++next;
			uint32_t sn = iter->first;
			std::shared_ptr<segment> seg = iter->second;
			if (una > sn)
			{
				if (auto resendts_iter = this->resendts_buf.find(seg->resendts); resendts_iter != this->resendts_buf.end())
					if (auto um_iter = resendts_iter->second.find(sn); um_iter != resendts_iter->second.end())
						resendts_iter->second.erase(um_iter);

				if (auto fastack_iter = this->fastack_buf.find(seg->fastack); fastack_iter != this->fastack_buf.end())
					if (auto um_iter = fastack_iter->second.find(sn); um_iter != fastack_iter->second.end())
						fastack_iter->second.erase(um_iter);

				this->snd_buf.erase(iter);
			}
			else break;
		}
	}

	void kcp_core::parse_fastack(uint32_t sn, uint32_t ts)
	{
		if (sn < this->snd_una || sn >= this->snd_nxt)
			return;

		for (auto &[seg_sn, seg] : this->snd_buf)
		{
			if (sn < seg_sn) break;
			else if (sn != seg_sn)
			{
				if (auto fastack_iter = this->fastack_buf.find(seg->fastack); fastack_iter != this->fastack_buf.end())
					if (auto um_iter = fastack_iter->second.find(seg_sn); um_iter != fastack_iter->second.end())
						fastack_iter->second.erase(um_iter);

				seg->fastack++;
				this->fastack_buf[seg->fastack][seg_sn] = seg;
			}
		}
	}

	//---------------------------------------------------------------------
	// parse data
	//---------------------------------------------------------------------
	void kcp_core::parse_data(segment &newseg)
	{
		uint32_t sn = newseg.sn;

		if (sn >= this->rcv_nxt + this->rcv_wnd || sn < this->rcv_nxt)
			return;

		if (auto iter = this->rcv_buf.find(sn); iter == this->rcv_buf.end())
			this->rcv_buf.insert({ sn, std::make_unique<segment>(std::move(newseg))});

#if 0
		PrintQueue("rcvbuf", &this->rcv_buf);
		printf("rcv_nxt=%lu\n", this->rcv_nxt);
#endif

		// move available data from rcv_buf -> rcv_queue
		while (!this->rcv_buf.empty())
		{
			auto iter = this->rcv_buf.begin();
			uint32_t seg_sn = iter->first;
			segment *seg = iter->second.get();
			if (seg->sn == this->rcv_nxt && this->rcv_queue.size() < this->rcv_wnd)
			{
				this->rcv_queue.emplace_back(std::move(*seg));
				this->rcv_nxt++;
				rcv_buf.erase(iter);
			}
			else break;
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
	int kcp_core::input(const char *data, long size)
	{
		uint32_t prev_una = this->snd_una;
		uint32_t maxack = 0, latest_ts = 0;
		int flag = 0;

		if (ikcp_canlog(IKCP_LOG_INPUT))
			ikcp_log(IKCP_LOG_INPUT, "[RI] %d bytes", (int)size);

		if (data == nullptr || size < (long)IKCP_OVERHEAD) return -1;

		while (size >= (long)IKCP_OVERHEAD)
		{
			uint32_t ts, sn, len, una, conv;
			uint16_t wnd;
			uint8_t cmd, frg;

			data = ikcp_decode32u(data, &conv);
			if (conv != this->conv) return -1;

			data = ikcp_decode8u(data, &cmd);
			data = ikcp_decode8u(data, &frg);
			data = ikcp_decode16u(data, &wnd);
			data = ikcp_decode32u(data, &ts);
			data = ikcp_decode32u(data, &sn);
			data = ikcp_decode32u(data, &una);
			data = ikcp_decode32u(data, &len);

			size -= IKCP_OVERHEAD;

			if (size < (long)len || (int)len < 0) return -2;

			if (cmd != IKCP_CMD_PUSH && cmd != IKCP_CMD_ACK &&
				cmd != IKCP_CMD_WASK && cmd != IKCP_CMD_WINS)
				return -3;

			this->rmt_wnd = wnd;
			parse_una(una);
			shrink_buf();

			if (cmd == IKCP_CMD_ACK)
			{
				if (this->current >= ts)
					update_ack(_itimediff(this->current, ts));

				parse_ack(sn);
				shrink_buf();
				if (flag == 0)
				{
					flag = 1;
					maxack = sn;
					latest_ts = ts;
				}
				else
				{
					if (sn > maxack)
					{
						maxack = sn;
						latest_ts = ts;
					}
				}
				if (ikcp_canlog(IKCP_LOG_IN_ACK))
				{
					ikcp_log(IKCP_LOG_IN_ACK,
						"input ack: sn=%lu rtt=%ld rto=%ld", (unsigned long)sn,
						(long)_itimediff(this->current, ts),
						(long)this->rx_rto);
				}
			}
			else if (cmd == IKCP_CMD_PUSH)
			{
				if (ikcp_canlog(IKCP_LOG_IN_DATA))
					ikcp_log(IKCP_LOG_IN_DATA, "input psh: sn=%lu ts=%lu", (unsigned long)sn, (unsigned long)ts);

				if (sn < this->rcv_nxt + this->rcv_wnd)
				{
					this->acklist.push_back({ sn , ts });
					if (sn >= this->rcv_nxt)
					{
						segment seg(len);
						seg.conv = conv;
						seg.cmd = cmd;
						seg.frg = frg;
						seg.wnd = wnd;
						seg.ts = ts;
						seg.sn = sn;
						seg.una = una;
						seg.len = len;

						if (len > 0)
							std::copy_n(data, len, seg.data.get());

						parse_data(seg);
					}
				}
			}
			else if (cmd == IKCP_CMD_WASK)
			{
				// ready to send back IKCP_CMD_WINS in ikcp_flush
				// tell remote my window size
				this->probe |= IKCP_ASK_TELL;
				if (ikcp_canlog(IKCP_LOG_IN_PROBE))
					ikcp_log(IKCP_LOG_IN_PROBE, "input probe");
			}
			else if (cmd == IKCP_CMD_WINS)
			{
				// do nothing
				if (ikcp_canlog(IKCP_LOG_IN_WINS))
					ikcp_log(IKCP_LOG_IN_WINS, "input wins: %lu", (unsigned long)(wnd));
			}
			else
				return -3;

			data += len;
			size -= len;
		}

		if (flag != 0)
			parse_fastack(maxack, latest_ts);

		if (this->snd_una > prev_una)
		{
			if (this->cwnd < this->rmt_wnd)
			{
				uint32_t mss = this->mss;
				if (this->cwnd < this->ssthresh)
				{
					this->cwnd++;
					this->incr += mss;
				}
				else
				{
					if (this->incr < mss) this->incr = mss;
					this->incr += (mss * mss) / this->incr + (mss / 16);
					if ((this->cwnd + 1) * mss <= this->incr)
					{
#if 1
						this->cwnd = (this->incr + mss - 1) / ((mss > 0) ? mss : 1);
#else
						this->cwnd++;
#endif
					}
				}
				if (this->cwnd > this->rmt_wnd)
				{
					this->cwnd = this->rmt_wnd;
					this->incr = this->rmt_wnd * mss;
				}
			}
		}

		return 0;
	}


	//---------------------------------------------------------------------
	// ikcp_encode_seg
	//---------------------------------------------------------------------
	static char *ikcp_encode_seg(char *ptr, const segment *seg)
	{
		ptr = ikcp_encode32u(ptr, seg->conv);
		ptr = ikcp_encode8u(ptr, (uint8_t)seg->cmd);
		ptr = ikcp_encode8u(ptr, (uint8_t)seg->frg);
		ptr = ikcp_encode16u(ptr, (uint16_t)seg->wnd);
		ptr = ikcp_encode32u(ptr, seg->ts);
		ptr = ikcp_encode32u(ptr, seg->sn);
		ptr = ikcp_encode32u(ptr, seg->una);
		ptr = ikcp_encode32u(ptr, seg->len);
		return ptr;
	}

	static char *ikcp_encode_seg(char *ptr, const segment &seg)
	{
		ptr = ikcp_encode32u(ptr, seg.conv);
		ptr = ikcp_encode8u(ptr, (uint8_t)seg.cmd);
		ptr = ikcp_encode8u(ptr, (uint8_t)seg.frg);
		ptr = ikcp_encode16u(ptr, (uint16_t)seg.wnd);
		ptr = ikcp_encode32u(ptr, seg.ts);
		ptr = ikcp_encode32u(ptr, seg.sn);
		ptr = ikcp_encode32u(ptr, seg.una);
		ptr = ikcp_encode32u(ptr, seg.len);
		return ptr;
	}

	int kcp_core::get_wnd_unused()
	{
		if (this->rcv_queue.size() < this->rcv_wnd)
			return (int)((int64_t)this->rcv_wnd - (int64_t)this->rcv_queue.size());

		return 0;
	}


	//---------------------------------------------------------------------
	// ikcp_flush
	//---------------------------------------------------------------------
	void kcp_core::flush(uint32_t current)
	{
		// 'ikcp_update' haven't been called. 
		if (this->updated == 0) return;

		if (current == 0)
			current = this->current;
		else
			this->current = current;

		char *buffer = this->buffer.get();
		char *ptr = buffer;
		uint32_t resent, cwnd;
		uint32_t rtomin;
		int change = 0;
		int lost = 0;
		segment seg;

		seg.conv = this->conv;
		seg.cmd = IKCP_CMD_ACK;
		seg.frg = 0;
		seg.wnd = get_wnd_unused();
		seg.una = this->rcv_nxt;
		seg.sn = 0;
		seg.ts = 0;

		// flush acknowledges
		for (auto [ack_sn, ack_ts] : this->acklist)
		{
			int size = (int)(ptr - buffer);
			if (size + (int)IKCP_OVERHEAD > (int)this->mtu)
			{
				call_output(buffer, size);
				ptr = buffer;
			}
			seg.sn = ack_sn;
			seg.ts = ack_ts;
			ptr = ikcp_encode_seg(ptr, seg);
		}

		this->acklist.clear();

		// probe window size (if remote window size equals zero)
		if (this->rmt_wnd == 0)
		{
			if (this->probe_wait == 0)
			{
				this->probe_wait = IKCP_PROBE_INIT;
				this->ts_probe = this->current + this->probe_wait;
			}
			else
			{
				if (this->current >= this->ts_probe)
				{
					if (this->probe_wait < IKCP_PROBE_INIT)
						this->probe_wait = IKCP_PROBE_INIT;
					this->probe_wait += this->probe_wait / 2;
					if (this->probe_wait > IKCP_PROBE_LIMIT)
						this->probe_wait = IKCP_PROBE_LIMIT;
					this->ts_probe = this->current + this->probe_wait;
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
		if (this->probe & IKCP_ASK_SEND)
		{
			seg.cmd = IKCP_CMD_WASK;
			int size = (int)(ptr - buffer);
			if (size + (int)IKCP_OVERHEAD > (int)this->mtu)
			{
				call_output(buffer, size);
				ptr = buffer;
			}
			ptr = ikcp_encode_seg(ptr, seg);
		}

		// flush window probing commands
		if (this->probe & IKCP_ASK_TELL)
		{
			seg.cmd = IKCP_CMD_WINS;
			int size = (int)(ptr - buffer);
			if (size + (int)IKCP_OVERHEAD > (int)this->mtu)
			{
				call_output(buffer, size);
				ptr = buffer;
			}
			ptr = ikcp_encode_seg(ptr, seg);
		}

		this->probe = 0;

		// calculate window size
		cwnd = _imin_(this->snd_wnd, this->rmt_wnd);
		if (this->nocwnd == 0) cwnd = _imin_(this->cwnd, cwnd);

		// calculate resent
		resent = (this->fastresend > 0) ? (uint32_t)this->fastresend : 0xffffffff;
		rtomin = (this->nodelay == 0) ? (this->rx_rto >> 3) : 0;

		// flush data segments

		for (auto iter = this->resendts_buf.begin(), next = iter; iter != this->resendts_buf.end(); iter = next)
		{
			++next;
			auto &[resend_ts, seg_list] = *iter;
			if (seg_list.empty())
			{
				this->resendts_buf.erase(iter);
				continue;
			}

			if (current < resend_ts) break;

			for (auto seg_iter = seg_list.begin(), seg_next = seg_iter;
				seg_iter != seg_list.end();
				seg_iter = seg_next)
			{
				++seg_next;
				auto [seg_sn, seg_weak] = *seg_iter;
				std::shared_ptr segptr = seg_weak.lock();
				if (segptr == nullptr)
				{
					seg_list.erase(seg_iter);
					continue;
				}

				segptr->xmit++;
				this->xmit++;
				if (this->nodelay == 0)
				{
					segptr->rto += _imax_(segptr->rto, (uint32_t)this->rx_rto);
				}
				else
				{
					int32_t step = (this->nodelay < 2) ?
						((int32_t)(segptr->rto)) : this->rx_rto;
					segptr->rto += step / 2;
				}
				segptr->resendts = current + segptr->rto;
				lost = 1;

				seg_list.erase(seg_iter);
				this->resendts_buf[segptr->resendts][seg_sn] = segptr;

				segptr->ts = current;
				segptr->wnd = seg.wnd;
				segptr->una = this->rcv_nxt;
				ptr = send_out(ptr, buffer, segptr.get());
			}

			if (seg_list.empty())
				this->resendts_buf.erase(iter);
		}

		for (auto iter = this->fastack_buf.rbegin(), next = iter; iter != this->fastack_buf.rend(); iter = next)
		{
			++next;
			auto &[fast_ack, seg_list] = *iter;
			if (seg_list.empty())
				continue;

			if (fast_ack < resent) break;

			for (auto seg_iter = seg_list.begin(), seg_next = seg_iter;
				seg_iter != seg_list.end();
				seg_iter = seg_next)
			{
				++seg_next;
				auto [seg_sn, seg_weak] = *seg_iter;
				std::shared_ptr segptr = seg_weak.lock();
				if (segptr == nullptr)
				{
					seg_list.erase(seg_iter);
					continue;
				}

				if ((int)segptr->xmit <= this->fastlimit || this->fastlimit <= 0)
				{
					uint32_t old_resendtrs = segptr->resendts;
					segptr->xmit++;
					segptr->fastack = 0;
					segptr->resendts = current + segptr->rto;
					change++;

					seg_list.erase(seg_iter);
					this->fastack_buf[segptr->fastack][seg_sn] = segptr;

					if (auto resendts_iter = this->resendts_buf.find(old_resendtrs); resendts_iter != this->resendts_buf.end())
						if (auto um_iter = resendts_iter->second.find(seg_sn); um_iter != resendts_iter->second.end())
							resendts_iter->second.erase(um_iter);

					this->resendts_buf[segptr->resendts][seg_sn] = segptr;

					segptr->ts = current;
					segptr->wnd = seg.wnd;
					segptr->una = this->rcv_nxt;
					ptr = send_out(ptr, buffer, segptr.get());
				}
			}
		}

		// move data from snd_queue to snd_buf
		while (this->snd_nxt < this->snd_una + cwnd && !this->snd_queue.empty())
		{
			auto iter = this->snd_queue.begin();
			std::shared_ptr<segment> newseg = std::move(*iter);

			newseg->conv = this->conv;
			newseg->cmd = IKCP_CMD_PUSH;
			newseg->wnd = seg.wnd;
			newseg->ts = current;
			newseg->sn = this->snd_nxt++;
			newseg->una = this->rcv_nxt;
			newseg->resendts = current + this->rx_rto + rtomin;
			newseg->rto = this->rx_rto;
			newseg->fastack = 0;
			newseg->xmit = 1;

			this->snd_buf[newseg->sn] = newseg;
			this->snd_queue.pop_front();
			resendts_buf[newseg->resendts][newseg->sn] = newseg;
			fastack_buf[newseg->fastack][newseg->sn] = newseg;

			ptr = send_out(ptr, buffer, newseg.get());
		}

		// flash remain segments	
		if (int size = (int)(ptr - buffer); size > 0)
			call_output(buffer, size);


		// update ssthresh
		if (change)
		{
			uint32_t inflight = this->snd_nxt - this->snd_una;
			this->ssthresh = inflight / 2;
			if (this->ssthresh < IKCP_THRESH_MIN)
				this->ssthresh = IKCP_THRESH_MIN;
			this->cwnd = this->ssthresh + resent;
			this->incr = this->cwnd * this->mss;
		}

		if (lost)
		{
			this->ssthresh = cwnd / 2;
			if (this->ssthresh < IKCP_THRESH_MIN)
				this->ssthresh = IKCP_THRESH_MIN;
			this->cwnd = 1;
			this->incr = this->mss;
		}

		if (this->cwnd < 1)
		{
			this->cwnd = 1;
			this->incr = this->mss;
		}
	}


	//---------------------------------------------------------------------
	// update state (call it repeatedly, every 10ms-100ms), or you can ask 
	// ikcp_check when to call it again (without ikcp_input/_send calling).
	// 'current' - current timestamp in millisec. 
	//---------------------------------------------------------------------
	void kcp_core::update(uint32_t current)
	{
		int32_t slap;

		this->current = current;

		if (this->updated == 0)
		{
			this->updated = 1;
			this->ts_flush = this->current;
		}

		slap = _itimediff(this->current, this->ts_flush);

		if (slap >= 10000 || slap < -10000)
		{
			this->ts_flush = this->current;
			slap = 0;
		}

		if (slap >= 0)
		{
			this->ts_flush += this->interval;
			if (this->current >= this->ts_flush)
				this->ts_flush = this->current + this->interval;

			flush();
		}
	}


	//---------------------------------------------------------------------
	// Determine when should you invoke ikcp_update:
	// returns when you should invoke ikcp_update in millisec, if there 
	// is no ikcp_input/_send calling. you can call ikcp_update in that
	// time, instead of call update repeatly.
	// Important to reduce unnacessary ikcp_update invoking. use it to 
	// schedule ikcp_update (eg. implementing an epoll-like mechanism, 
	// or optimize ikcp_update when handling massive kcp connections)
	//---------------------------------------------------------------------
	uint32_t kcp_core::check(uint32_t current)
	{
		uint32_t ts_flush = this->ts_flush;
		int32_t tm_flush = 0x7fffffff;
		int32_t tm_packet = 0x7fffffff;
		uint32_t minimal = 0;

		if (this->updated == 0)
			return current;

		if (_itimediff(current, ts_flush) >= 10000 || _itimediff(current, ts_flush) < -10000)
			ts_flush = current;

		if (current >= ts_flush)
			return current;

		tm_flush = _itimediff(ts_flush, current);

		if (!this->resendts_buf.empty())
		{
			auto &[resend_ts, seg_list] = *this->resendts_buf.begin();

			int32_t diff = _itimediff(resend_ts, current);
			if (diff <= 0)
				return current;

			if (diff < tm_packet)
				tm_packet = diff;
		}

		minimal = (uint32_t)(tm_packet < tm_flush ? tm_packet : tm_flush);
		if (minimal >= this->interval) minimal = this->interval;

		return current + minimal;
	}

	int kcp_core::set_mtu(int mtu)
	{
		if (mtu < 50 || mtu < (int)IKCP_OVERHEAD)
			return -1;
		std::unique_ptr<char[]> buffer = std::make_unique<char[]>((mtu + IKCP_OVERHEAD) * 3);
		if (buffer == nullptr)
			return -2;
		this->mtu = mtu;
		this->mss = this->mtu - IKCP_OVERHEAD;
		this->buffer = std::move(buffer);
		return 0;
	}

	int kcp_core::set_interval(int interval)
	{
		if (interval > 5000) interval = 5000;
		else if (interval <= 0) interval = 1;
		this->interval = interval;
		return 0;
	}

	int kcp_core::set_nodelay(int nodelay, int interval, int resend, int nc)
	{
		if (nodelay >= 0)
		{
			this->nodelay = nodelay;
			if (nodelay)
				this->rx_minrto = IKCP_RTO_NDL;
			else
				this->rx_minrto = IKCP_RTO_MIN;
		}
		if (interval >= 0)
		{
			if (interval > 5000) interval = 5000;
			else if (interval <= 0) interval = 1;
			this->interval = interval;
		}
		if (resend >= 0)
			this->fastresend = resend;

		if (nc >= 0)
			this->nocwnd = nc;

		return 0;
	}

	int kcp_core::set_wndsize(int sndwnd, int rcvwnd)
	{
		if (sndwnd > 0)
			this->snd_wnd = sndwnd;

		if (rcvwnd > 0)   // must >= max fragment size
			this->rcv_wnd = _imax_(rcvwnd, IKCP_WND_RCV);

		return 0;
	}

	int kcp_core::get_waitsnd()
	{
		return (int)(this->snd_buf.size() + this->snd_queue.size());
	}

	// read conv
	uint32_t kcp_core::get_conv(const void *ptr)
	{
		uint32_t kcp_conv;
		ikcp_decode32u((const char*)ptr, &kcp_conv);
		return kcp_conv;
	}

	uint32_t kcp_core::get_conv()
	{
		return conv;
	}

	char* KCP::kcp_core::send_out(char *ptr, char *buffer, segment *segptr)
	{
		int size = (int)(ptr - buffer);
		int need = (int)IKCP_OVERHEAD + (int)segptr->len;

		if (size + need > (int)this->mtu)
		{
			call_output(buffer, size);
			ptr = buffer;
		}

		ptr = ikcp_encode_seg(ptr, segptr);

		if (segptr->len > 0)
		{
			std::copy_n(segptr->data.get(), segptr->len, ptr);
			ptr += segptr->len;
		}

		if (segptr->xmit >= this->dead_link)
			this->state = (uint32_t)-1;

		return ptr;
	}
}

