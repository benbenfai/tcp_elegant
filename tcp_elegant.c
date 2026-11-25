#include <linux/mm.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/bitops.h>
#include <linux/math64.h>
#include <linux/version.h>
#include <net/tcp.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
#define tcp_snd_cwnd(tp)		((tp)->snd_cwnd)
#define tcp_snd_cwnd_set(tp, val)	((tp)->snd_cwnd = (val))
#endif

#define ELEGANT_MD_SCALE	3

#define ELEGANT_SCALE		3
#define ELEGANT_UNIT		(1 << ELEGANT_SCALE)
#define ELEGANT_UNIT_SQ_SHIFT	(2 * ELEGANT_SCALE)
#define ELEGANT_RATIO_MAX	(8 * ELEGANT_UNIT)

#define BW_SCALE	24
#define BW_UNIT		(1 << BW_SCALE)

#define FILTER_RESET_JIFFIES	(10 * HZ)
#define FILTER_ROUND_THRESH	12

struct elegant {
	u32 rtt_hi[2];
	u32 bw_hi[2];
	u32 rtt_curr;
	u32 rtt_round_min;
	u32 ratio;
	u32 round;
	u32 next_rtt_delivered;
	u32 prior_cwnd;
	u32 filter_stamp;
	u8  prev_ca_state:3,
	    packet_conservation:1,
	    ss_delay_rounds:2;
};

static u32 elegant_min_rtt(const struct sock *sk)
{
	u32 m = tcp_min_rtt(tcp_sk(sk));

	return m == ~0U ? 0 : m;
}

static u32 elegant_max_rtt(const struct elegant *ca)
{
	return max(ca->rtt_hi[0], ca->rtt_hi[1]);
}

static u32 elegant_max_bw(const struct sock *sk)
{
	const struct elegant *ca = inet_csk_ca(sk);

	return max(ca->bw_hi[0], ca->bw_hi[1]);
}

static void elegant_advance_filters(struct sock *sk)
{
	struct elegant *ca = inet_csk_ca(sk);

	ca->filter_stamp = tcp_jiffies32;
	ca->round = 0;
	if (ca->bw_hi[1]) {
		ca->bw_hi[0] = ca->bw_hi[1];
		ca->bw_hi[1] = 0;
	}
	if (ca->rtt_hi[1]) {
		ca->rtt_hi[0] = ca->rtt_hi[1];
		ca->rtt_hi[1] = 0;
	}
}

static u32 elegant_avg_delay(const struct sock *sk)
{
	u32 base = elegant_min_rtt(sk);
	u32 srtt = tcp_sk(sk)->srtt_us >> 3;

	if (!base || srtt <= base)
		return 0;
	return srtt - base;
}

static u32 elegant_max_delay(const struct sock *sk)
{
	const struct elegant *ca = inet_csk_ca(sk);
	u32 base = elegant_min_rtt(sk);
	u32 peak = elegant_max_rtt(ca);

	if (!base || peak <= base)
		return 0;
	return peak - base;
}

static bool elegant_delay_stale(const struct sock *sk)
{
	u32 dm = elegant_max_delay(sk);

	return dm && elegant_avg_delay(sk) >= dm - dm / 5;
}

static u32 elegant_bw_sample(const struct rate_sample *rs)
{
	u64 bw;

	if (rs->interval_us <= 0 || rs->delivered <= 0)
		return 0;
	bw = DIV_ROUND_UP_ULL((u64)rs->delivered * BW_UNIT, rs->interval_us);
	return min_t(u64, bw, U32_MAX);
}

static u32 elegant_bdp(const struct sock *sk)
{
	u32 bw = elegant_max_bw(sk);
	u32 rtt = elegant_min_rtt(sk);
	u64 bdp;

	if (!bw || !rtt)
		return 0;
	bdp = ((u64)bw * rtt) >> BW_SCALE;
	return (u32)clamp_t(u64, bdp, 2, U32_MAX);
}

static u64 fast_sqrt(u64 x)
{
	u64 result = 0;
	u64 bit;

	if (x < 2)
		return x;
	bit = 1ULL << ((fls64(x) - 1) & ~1U);
	while (bit) {
		if (x >= result + bit) {
			x -= result + bit;
			result = (result >> 1) + bit;
		} else {
			result >>= 1;
		}
		bit >>= 2;
	}
	return result;
}

static u32 elegant_wwf_ratio(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);
	u32 rtt_curr = ca->rtt_curr ? ca->rtt_curr : (tp->srtt_us >> 3);
	u32 rtt_max = elegant_max_rtt(ca);
	u32 ratio;
	u64 sq;

	if (ca->ratio)
		return ca->ratio;

	if (!rtt_curr || rtt_max <= rtt_curr) {
		ratio = ELEGANT_UNIT;
	} else {
		sq = DIV_ROUND_UP_ULL((u64)rtt_max << ELEGANT_UNIT_SQ_SHIFT,
				      rtt_curr);
		ratio = (u32)fast_sqrt(sq + 1);
		ratio = clamp_t(u32, ratio, ELEGANT_UNIT, ELEGANT_RATIO_MAX);
	}
	ca->ratio = ratio;
	return ratio;
}

static void elegant_cong_avoid(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 acked = rs->acked_sacked;
	u32 cwnd, wwf;

	if (!acked || !tcp_is_cwnd_limited(sk))
		return;

	if (tcp_in_slow_start(tp)) {
		acked = tcp_slow_start(tp, acked);
		if (!acked)
			return;
	}

	{
		u32 base = elegant_min_rtt(sk);
		u32 da = elegant_avg_delay(sk);

		if (base && da > (base >> 3))
			return;
	}

	cwnd = tcp_snd_cwnd(tp);
	wwf = ((u32)fast_sqrt(cwnd) * elegant_wwf_ratio(sk)) >> ELEGANT_SCALE;
	wwf = max(wwf, 1U);
	tcp_cong_avoid_ai(tp, cwnd, min_t(u64, (u64)wwf * acked, U32_MAX));
}

static void elegant_save_cwnd(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	if (ca->prev_ca_state < TCP_CA_Recovery && !tcp_in_slow_start(tp))
		ca->prior_cwnd = tcp_snd_cwnd(tp);
	else
		ca->prior_cwnd = max(ca->prior_cwnd, tcp_snd_cwnd(tp));
}

static bool elegant_recovery_cwnd(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);
	u8 state = inet_csk(sk)->icsk_ca_state;
	u32 cwnd = tcp_snd_cwnd(tp);

	if (rs->losses > 0)
		cwnd = max_t(s32, (s32)cwnd - rs->losses, 1);

	if (state == TCP_CA_Recovery && ca->prev_ca_state != TCP_CA_Recovery) {
		ca->packet_conservation = 1;
		ca->next_rtt_delivered = tp->delivered;
		cwnd = tcp_packets_in_flight(tp) + rs->acked_sacked;
	} else if (ca->prev_ca_state >= TCP_CA_Recovery &&
		   state < TCP_CA_Recovery) {
		cwnd = max(cwnd, min(ca->prior_cwnd, tp->snd_ssthresh));
		ca->packet_conservation = 0;
	}
	ca->prev_ca_state = state;

	if (ca->packet_conservation) {
		cwnd = max(cwnd, tcp_packets_in_flight(tp) + rs->acked_sacked);
		tcp_snd_cwnd_set(tp, min(cwnd, tp->snd_cwnd_clamp));
		return true;
	}
	tcp_snd_cwnd_set(tp, min(max(cwnd, 2U), tp->snd_cwnd_clamp));
	return false;
}

static u32 tcp_elegant_ssthresh(struct sock *sk)
{
	u32 cwnd = tcp_snd_cwnd(tcp_sk(sk));
	u32 cut = cwnd - (cwnd >> ELEGANT_MD_SCALE);
	u32 bdp = elegant_bdp(sk);

	elegant_save_cwnd(sk);
	if (bdp)
		cut = max(cut, min(bdp, cwnd));
	return max(cut, 2U);
}

static u32 tcp_elegant_undo_cwnd(struct sock *sk)
{
	struct elegant *ca = inet_csk_ca(sk);

	return max(tcp_snd_cwnd(tcp_sk(sk)), ca->prior_cwnd);
}

static void elegant_slow_start_exit(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);
	u32 cwnd = tcp_snd_cwnd(tp);
	u32 base = elegant_min_rtt(sk);
	u32 bdp = elegant_bdp(sk);

	if (!tcp_in_slow_start(tp) || !base || !bdp ||
	    elegant_avg_delay(sk) < base) {
		ca->ss_delay_rounds = 0;
		return;
	}
	if (ca->ss_delay_rounds < 2)
		ca->ss_delay_rounds++;
	if (ca->ss_delay_rounds < 2)
		return;

	tp->snd_ssthresh = min(tp->snd_ssthresh,
			       max(bdp, cwnd - (cwnd >> 2)));
}

static void elegant_round(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	if (rs->interval_us <= 0 ||
	    before(rs->prior_delivered, ca->next_rtt_delivered))
		return;

	ca->next_rtt_delivered = tp->delivered;
	ca->round++;
	ca->ratio = 0;
	ca->packet_conservation = 0;

	if (ca->rtt_round_min) {
		ca->rtt_curr = ca->rtt_round_min;
		ca->rtt_round_min = 0;
	}

	{
		u32 base = elegant_min_rtt(sk);
		u32 da = elegant_avg_delay(sk);
		u32 cwnd = tcp_snd_cwnd(tp);

		if (base && da > (base >> 3) && cwnd > 4 &&
		    !tcp_in_slow_start(tp)) {
			u32 step = 1U;

			tcp_snd_cwnd_set(tp, max(cwnd - step, 4U));
		}
	}

	elegant_slow_start_exit(sk);

	if (after(tcp_jiffies32, ca->filter_stamp + FILTER_RESET_JIFFIES) ||
	    (ca->round >= FILTER_ROUND_THRESH && elegant_delay_stale(sk)))
		elegant_advance_filters(sk);
}

static void tcp_elegant_cong_control(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);
	u32 bw;

	bw = elegant_bw_sample(rs);
	if (bw && (!rs->is_app_limited || bw > elegant_max_bw(sk)))
		ca->bw_hi[1] = max(bw, ca->bw_hi[1]);

	if (rs->rtt_us > 0 &&
	    (!rs->is_ack_delayed || tcp_in_slow_start(tp))) {
		u32 rtt_us = max_t(u32, (u32)rs->rtt_us, 1U);

		ca->rtt_round_min = ca->rtt_round_min ?
			min(ca->rtt_round_min, rtt_us) : rtt_us;
		ca->rtt_hi[1] = max(ca->rtt_hi[1], rtt_us);
	}

	elegant_round(sk, rs);

	if (!elegant_recovery_cwnd(sk, rs))
		elegant_cong_avoid(sk, rs);
}

static void tcp_elegant_set_state(struct sock *sk, u8 new_state)
{
	struct elegant *ca = inet_csk_ca(sk);

	if (new_state == TCP_CA_Loss) {
		ca->ratio = 0;
		ca->prev_ca_state = TCP_CA_Loss;
		ca->packet_conservation = 0;
	}
}

static void elegant_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	memset(ca, 0, sizeof(*ca));
	ca->next_rtt_delivered = tp->delivered;
	ca->prior_cwnd = tcp_snd_cwnd(tp);
	ca->prev_ca_state = TCP_CA_Open;
	ca->filter_stamp = tcp_jiffies32;

	cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
}

static struct tcp_congestion_ops tcp_elegant __read_mostly = {
	.name		= "elegant",
	.owner		= THIS_MODULE,
	.init		= elegant_init,
	.ssthresh	= tcp_elegant_ssthresh,
	.undo_cwnd	= tcp_elegant_undo_cwnd,
	.cong_control	= tcp_elegant_cong_control,
	.set_state	= tcp_elegant_set_state,
};

static int __init elegant_register(void)
{
	BUILD_BUG_ON(sizeof(struct elegant) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&tcp_elegant);
}

static void __exit elegant_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_elegant);
}

module_init(elegant_register);
module_exit(elegant_unregister);

MODULE_AUTHOR("benhoklfai@gmail.com");
MODULE_DESCRIPTION("Elegant TCP");
