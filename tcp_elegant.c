#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/math64.h>
#include <linux/version.h>
#include <net/tcp.h>

#define BETA_SHIFT		6
#define BETA_SCALE		(1U << BETA_SHIFT)
#define BETA_MIN		(BETA_SCALE / 8)
#define BETA_MAX		(BETA_SCALE / 2)
#define BETA_BASE		BETA_MAX
#define GAIN_UNITY_BETA		24

#define ELEGANT_SCALE		3
#define ELEGANT_UNIT		(1U << ELEGANT_SCALE)
#define ELEGANT_RATIO_MAX	64

#define FILTER_RESET_JIFFIES	(10 * HZ)
#define FILTER_ROUND_THRESH	12

static int win_thresh __read_mostly = 15;
module_param(win_thresh, int, 0444);
MODULE_PARM_DESC(win_thresh, "packets in flight below which delay is ignored");

static int inv_beta_init __read_mostly = 80;
module_param(inv_beta_init, int, 0444);
MODULE_PARM_DESC(inv_beta_init, "initial Q6 increase gain");

static int inv_beta_base __read_mostly = 88;
module_param(inv_beta_base, int, 0444);
MODULE_PARM_DESC(inv_beta_base, "Q6 increase gain cap");

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
#define tcp_snd_cwnd(tp)	((tp)->snd_cwnd)
#endif

struct elegant {
	u64 sum_rtt;
	u32 cnt_rtt;
	u32 round_rtt_min;
	u32 round_rtt_max;
	u32 rtt_lo[2];
	u32 rtt_hi[2];
	u32 rtt_curr;
	u32 beta;
	u32 inv_beta;
	u32 ratio;
	u32 round;
	u32 end_seq;
	u32 filter_stamp;
};

static u32 fast_sqrt(u64 x)
{
	u64 bit = 1ULL << 62;
	u64 res = 0;

	while (bit > x)
		bit >>= 2;
	while (bit) {
		if (x >= res + bit) {
			x -= res + bit;
			res = (res >> 1) + bit;
		} else {
			res >>= 1;
		}
		bit >>= 2;
	}
	return (u32)res;
}

static u32 elegant_min_rtt(const struct elegant *ca)
{
	if (!ca->rtt_lo[0])
		return ca->rtt_lo[1];
	if (!ca->rtt_lo[1])
		return ca->rtt_lo[0];
	return min(ca->rtt_lo[0], ca->rtt_lo[1]);
}

static u32 elegant_max_rtt(const struct elegant *ca)
{
	return max(ca->rtt_hi[0], ca->rtt_hi[1]);
}

static u32 elegant_avg_delay(const struct elegant *ca)
{
	u32 base = elegant_min_rtt(ca);

	return ca->rtt_curr > base ? ca->rtt_curr - base : 0;
}

static u32 elegant_max_delay(const struct elegant *ca)
{
	u32 base = elegant_min_rtt(ca);
	u32 peak = elegant_max_rtt(ca);

	return peak > base ? peak - base : 0;
}

static u32 elegant_beta(u32 da, u32 dm)
{
	u64 d2, d3, num;

	d2 = dm / 10;
	if (da <= d2)
		return BETA_MIN;

	d3 = ((u64)dm * 8) / 10;
	if (da >= d3 || d3 <= d2)
		return BETA_MAX;

	num = BETA_MIN * d3 + (u64)(BETA_MAX - BETA_MIN) * da;
	if (num <= (u64)BETA_MAX * d2)
		return BETA_MIN;
	num -= (u64)BETA_MAX * d2;
	return clamp_t(u32, div64_u64(num, d3 - d2), BETA_MIN, BETA_MAX);
}

static u32 elegant_cut(const struct elegant *ca, u32 cwnd)
{
	return cwnd - (u32)(((u64)cwnd * ca->beta) >> BETA_SHIFT);
}

static u32 elegant_bdp(const struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct elegant *ca = inet_csk_ca(sk);
	u32 cwnd = tcp_snd_cwnd(tp);
	u32 base = elegant_min_rtt(ca);
	u32 rtt = ca->rtt_curr ? ca->rtt_curr : (tp->srtt_us >> 3);

	if (!base || !rtt || base >= rtt)
		return cwnd;
	return max_t(u32, div_u64((u64)cwnd * base, rtt), 2U);
}

static void elegant_round_reset(struct elegant *ca)
{
	ca->sum_rtt = 0;
	ca->cnt_rtt = 0;
	ca->round_rtt_min = UINT_MAX;
	ca->round_rtt_max = 0;
}

static void elegant_advance_filters(struct sock *sk)
{
	struct elegant *ca = inet_csk_ca(sk);

	ca->filter_stamp = tcp_jiffies32;
	ca->round = 0;
	if (ca->rtt_lo[1]) {
		ca->rtt_lo[0] = ca->rtt_lo[1];
		ca->rtt_lo[1] = 0;
	}
	if (ca->rtt_hi[1]) {
		ca->rtt_hi[0] = ca->rtt_hi[1];
		ca->rtt_hi[1] = 0;
	}
}

static void elegant_update_params(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);
	u32 da = elegant_avg_delay(ca);
	u32 dm = elegant_max_delay(ca);
	u32 rtt = ca->rtt_curr ? ca->rtt_curr : max(tp->srtt_us >> 3, 1U);
	u32 peak = elegant_max_rtt(ca);
	u64 queued = div_u64((u64)tcp_snd_cwnd(tp) * da, rtt);
	u32 thresh = max_t(u32, win_thresh,
			   queued ? 2 * (fls64(queued) - 1) : 0);

	if (!ca->cnt_rtt || queued < thresh || !dm) {
		ca->beta = BETA_BASE;
	} else {
		ca->beta = elegant_beta(da, dm);
	}

	if (ca->beta <= BETA_MIN)
		ca->inv_beta = min_t(u32, inv_beta_base, inv_beta_init);
	else
		ca->inv_beta = clamp_t(u32, BETA_SCALE + BETA_MAX - ca->beta,
				       BETA_SCALE, (u32)inv_beta_base);

	if (!rtt || peak <= rtt) {
		ca->ratio = ELEGANT_UNIT;
	} else {
		u64 q = div_u64((u64)peak * ELEGANT_UNIT * ELEGANT_UNIT, rtt);

		ca->ratio = clamp_t(u32, fast_sqrt(q), ELEGANT_UNIT,
				    ELEGANT_RATIO_MAX * ELEGANT_UNIT);
	}
}

static void elegant_round(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	ca->end_seq = tp->snd_nxt;
	ca->round++;

	if (ca->round_rtt_min != UINT_MAX) {
		ca->rtt_lo[1] = ca->rtt_lo[1] ?
			min(ca->rtt_lo[1], ca->round_rtt_min) :
			ca->round_rtt_min;
		ca->rtt_hi[1] = max(ca->rtt_hi[1], ca->round_rtt_max);
	}

	if (ca->cnt_rtt) {
		u64 avg = ca->sum_rtt;

		do_div(avg, ca->cnt_rtt);
		ca->rtt_curr = max_t(u32, avg, 1U);
	} else if (tp->srtt_us) {
		ca->rtt_curr = max(tp->srtt_us >> 3, 1U);
	}

	elegant_update_params(sk);
	elegant_round_reset(ca);

	if (after(tcp_jiffies32, ca->filter_stamp + FILTER_RESET_JIFFIES) ||
	    (ca->beta > GAIN_UNITY_BETA && ca->round >= FILTER_ROUND_THRESH))
		elegant_advance_filters(sk);
}

static void tcp_elegant_acked(struct sock *sk, const struct ack_sample *sample)
{
	struct elegant *ca = inet_csk_ca(sk);
	u32 rtt_us;

	if (sample->rtt_us < 0)
		return;

	rtt_us = max_t(u32, sample->rtt_us, 1U);
	ca->sum_rtt += rtt_us;
	ca->cnt_rtt++;
	if (rtt_us < ca->round_rtt_min)
		ca->round_rtt_min = rtt_us;
	if (rtt_us > ca->round_rtt_max)
		ca->round_rtt_max = rtt_us;
}

static void tcp_elegant_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);
	u32 cwnd, wwf;

	if (after(ack, ca->end_seq))
		elegant_round(sk);

	if (!tcp_is_cwnd_limited(sk))
		return;

	if (tcp_in_slow_start(tp)) {
		u32 base = elegant_min_rtt(ca);

		if (base && elegant_avg_delay(ca) >= base)
			tp->snd_ssthresh = min(tp->snd_ssthresh,
					       elegant_bdp(sk));
		acked = tcp_slow_start(tp, acked);
		if (!acked)
			return;
	}

	cwnd = tcp_snd_cwnd(tp);
	wwf = (fast_sqrt(cwnd) * ca->ratio) >> ELEGANT_SCALE;
	if (ca->beta < GAIN_UNITY_BETA)
		wwf = (u32)(((u64)wwf * ca->inv_beta) >> BETA_SHIFT);
	wwf = max(wwf, 1U);

	tcp_cong_avoid_ai(tp, cwnd, min_t(u64, (u64)wwf * acked, U32_MAX));
}

static u32 tcp_elegant_ssthresh(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	const struct elegant *ca = inet_csk_ca(sk);

	return max(min(elegant_cut(ca, tcp_snd_cwnd(tp)), elegant_bdp(sk)), 2U);
}

static void tcp_elegant_set_state(struct sock *sk, u8 new_state)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	if (new_state == TCP_CA_Loss) {
		ca->beta = BETA_BASE;
		ca->inv_beta = inv_beta_init;
		ca->ratio = ELEGANT_UNIT;
		ca->end_seq = tp->snd_nxt;
		elegant_round_reset(ca);
	}
}

static void tcp_elegant_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	memset(ca, 0, sizeof(*ca));
	ca->round_rtt_min = UINT_MAX;
	ca->beta = BETA_BASE;
	ca->inv_beta = inv_beta_init;
	ca->ratio = ELEGANT_UNIT;
	ca->end_seq = tp->snd_nxt;
	ca->filter_stamp = tcp_jiffies32;
}

static struct tcp_congestion_ops tcp_elegant __read_mostly = {
	.init		= tcp_elegant_init,
	.ssthresh	= tcp_elegant_ssthresh,
	.undo_cwnd	= tcp_reno_undo_cwnd,
	.cong_avoid	= tcp_elegant_cong_avoid,
	.pkts_acked	= tcp_elegant_acked,
	.set_state	= tcp_elegant_set_state,
	.owner		= THIS_MODULE,
	.name		= "elegant",
};

static int __init tcp_elegant_register(void)
{
	BUILD_BUG_ON(sizeof(struct elegant) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&tcp_elegant);
}

static void __exit tcp_elegant_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_elegant);
}

module_init(tcp_elegant_register);
module_exit(tcp_elegant_unregister);

MODULE_AUTHOR("benhoklfai@gmail.com");
MODULE_DESCRIPTION("Elegant TCP");
