#include <linux/mm.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/bitops.h>
#include <linux/math64.h>
#include <linux/version.h>
#include <net/tcp.h>

/* tcp_snd_cwnd()/tcp_snd_cwnd_set() arrived in v6.0 (40570375356c). */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
#define tcp_snd_cwnd(tp)		((tp)->snd_cwnd)
#define tcp_snd_cwnd_set(tp, val)	((tp)->snd_cwnd = (val))
#endif

#define BETA_SHIFT	6
#define BETA_SCALE	(1u << BETA_SHIFT)
#define BETA_MIN	(BETA_SCALE >> 3)	/* 0.125 */
#define BETA_MAX	(BETA_SCALE >> 1)	/* 0.5   */
#define BETA_BASE	BETA_MAX

/* Q6 gain applied to the increase and to the pacing rate:
 *   gain = (inv_beta_base - beta) / BETA_SCALE
 * beta = BETA_MIN -> 1.25 (probe), 24 -> 1.0, BETA_MAX -> 0.875 (drain).
 */
#define GAIN_UNITY_BETA	24	/* Q6: 0.375, the beta where gain == 1.0 */

#define ELEGANT_SCALE		3
#define ELEGANT_UNIT		(1 << ELEGANT_SCALE)
#define ELEGANT_UNIT_SQ_SHIFT	(2 * ELEGANT_SCALE)
#define ELEGANT_RATIO_MAX	(8 * ELEGANT_UNIT)	/* sqrt ratio <= 8 */

#define BW_SCALE	24
#define BW_UNIT		(1 << BW_SCALE)
#define PACING_SHIFT	(BETA_SHIFT + BW_SCALE)	/* Q6 gain + Q24 bandwidth */
#define PACING_MARGIN_PERCENT	1

#define FILTER_RESET_JIFFIES	(10 * HZ)
#define FILTER_ROUND_THRESH	12

static int win_thresh __read_mostly = 15;
static int inv_beta_init __read_mostly = 80;	/* Q6 1.25 */
static int inv_beta_base __read_mostly = 88;

module_param(win_thresh, int, 0644);
MODULE_PARM_DESC(win_thresh, "cwnd below which the standard 1/2 cut is used");
module_param(inv_beta_init, int, 0644);
MODULE_PARM_DESC(inv_beta_init, "Q6 increase/pacing gain before the delay signal is usable");
module_param(inv_beta_base, int, 0644);
MODULE_PARM_DESC(inv_beta_base, "Q6 gain numerator; gain = (inv_beta_base - beta) / 64");

struct elegant {
	u64 sum_rtt;		/* sum of RTT samples in the current round */
	u32 cnt_rtt;		/* number of RTT samples in the current round */
	u32 last_rtt;		/* most recent RTT sample */
	u32 round_rtt_min;	/* min RTT in the current round */
	u32 round_rtt_max;	/* max RTT in the current round */
	u32 rtt_lo[2];		/* windowed min RTT: [0] previous, [1] current */
	u32 rtt_hi[2];		/* windowed max RTT: [0] previous, [1] current */
	u32 rtt_curr;		/* average RTT of the last completed round */
	u32 beta;		/* multiplicative decrease factor, Q6 */
	u32 inv_beta;		/* increase and pacing gain, Q6 */
	u32 ratio;		/* cached sqrt(rtt_max / rtt_curr), Q3 */
	u32 round;		/* rounds since the last filter advance */
	u32 next_rtt_delivered;	/* round boundary, compared to tp->delivered */
	u32 bw_hi[2];		/* windowed max bw, packets/us Q24 */
	u32 prior_cwnd;		/* cwnd saved before a loss episode */
	u32 filter_stamp;	/* tcp_jiffies32 of the last filter advance */
	u8  prev_ca_state:3,
	    packet_conservation:1,
	    delay_valid:1,	/* beta came from measurement, not default */
	    has_seen_rtt:1;
};

/* ---------------------------------------------------------------- filters */

static u32 elegant_min_rtt(const struct elegant *ca)
{
	u32 lo0 = ca->rtt_lo[0], lo1 = ca->rtt_lo[1];

	if (!lo0)
		return lo1;
	if (!lo1)
		return lo0;
	return min(lo0, lo1);
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

/* Advance all three windows by one. An empty current window leaves the
 * previous one in place, so a silent period cannot erase the estimates.
 */
static void elegant_advance_filters(struct sock *sk)
{
	struct elegant *ca = inet_csk_ca(sk);

	ca->filter_stamp = tcp_jiffies32;
	ca->round = 0;
	if (ca->bw_hi[1]) {
		ca->bw_hi[0] = ca->bw_hi[1];
		ca->bw_hi[1] = 0;
	}
	if (ca->rtt_lo[1]) {
		ca->rtt_lo[0] = ca->rtt_lo[1];
		ca->rtt_lo[1] = 0;
	}
	if (ca->rtt_hi[1]) {
		ca->rtt_hi[0] = ca->rtt_hi[1];
		ca->rtt_hi[1] = 0;
	}
}

/* Average queueing delay of the last completed round, in us.
 * Never zero: it is a divisor in beta() and a factor in the threshold.
 */
static u32 elegant_avg_delay(const struct elegant *ca)
{
	u32 base = elegant_min_rtt(ca);

	if (!base || ca->rtt_curr <= base)
		return 1;
	return ca->rtt_curr - base;
}

/* Spread of the delay signal, in us. Zero means "nothing measured yet". */
static u32 elegant_max_delay(const struct elegant *ca)
{
	u32 base = elegant_min_rtt(ca);
	u32 peak = elegant_max_rtt(ca);

	if (!base || peak <= base)
		return 0;
	return peak - base;
}

/* --------------------------------------------------------------- bandwidth */

/* Delivery rate of one sample, packets/us in Q24. */
static u32 elegant_bw_sample(const struct rate_sample *rs)
{
	u64 bw;

	if (rs->interval_us <= 0 || rs->delivered <= 0)
		return 0;
	bw = DIV_ROUND_UP_ULL((u64)rs->delivered * BW_UNIT, rs->interval_us);
	return min_t(u64, bw, U32_MAX);
}

/* Bandwidth-delay product in packets: Westwood's bw * min_rtt, with the
 * units fixed (bw is packets/us in Q24, so no mss division).
 */
static u32 elegant_bdp(const struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct elegant *ca = inet_csk_ca(sk);
	u32 rtt = elegant_min_rtt(ca);
	u64 bdp;

	if (!rtt)
		rtt = tp->srtt_us ? max(tp->srtt_us >> 3, 1U) : USEC_PER_MSEC;
	bdp = ((u64)elegant_max_bw(sk) * rtt) >> BW_SCALE;
	if (!bdp)
		return TCP_INFINITE_SSTHRESH;
	return max_t(u32, min_t(u64, bdp, tp->snd_cwnd_clamp), 2U);
}

/* Bytes per second for the pacer, at the current Q6 gain.
 * Shift order follows bbr_rate_bytes_per_sec(): the intermediate stays below
 * 2^63 for input rates up to ~2.9 Tbit/s.
 */
static unsigned long elegant_bw_to_pacing_rate(struct sock *sk, u32 bw)
{
	const struct elegant *ca = inet_csk_ca(sk);
	u64 rate = bw;

	rate *= tcp_mss_to_mtu(sk, tcp_sk(sk)->mss_cache);
	rate *= ca->inv_beta;
	rate >>= BETA_SHIFT;
	rate *= USEC_PER_SEC / 100 * (100 - PACING_MARGIN_PERCENT);
	rate >>= BW_SCALE;
	rate = max(rate, 1ULL);
	return min_t(u64, rate, READ_ONCE(sk->sk_max_pacing_rate));
}

static void elegant_init_pacing_rate_from_rtt(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);
	u32 rtt_us;
	u64 bw;

	if (tp->srtt_us) {
		rtt_us = max(tp->srtt_us >> 3, 1U);
		ca->has_seen_rtt = 1;
	} else {
		rtt_us = USEC_PER_MSEC;
	}
	bw = (u64)tcp_snd_cwnd(tp) * BW_UNIT;
	do_div(bw, rtt_us);
	WRITE_ONCE(sk->sk_pacing_rate,
		   elegant_bw_to_pacing_rate(sk, min_t(u64, bw, U32_MAX)));
}

static void elegant_set_pacing_rate(struct sock *sk, u32 bw)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);
	unsigned long rate;

	if (unlikely(!ca->has_seen_rtt && tp->srtt_us))
		elegant_init_pacing_rate_from_rtt(sk);
	if (!bw)
		return;
	rate = elegant_bw_to_pacing_rate(sk, bw);
	/* While the delay signal is still defaulted the estimate is climbing,
	 * so only raise. Once beta is measured, the gain below unity is
	 * allowed to drain the queue (F7, F18).
	 */
	if (ca->delay_valid || rate > READ_ONCE(sk->sk_pacing_rate))
		WRITE_ONCE(sk->sk_pacing_rate, rate);
}

/* ------------------------------------------------------------- delay -> beta */

static u32 beta_scale(const struct elegant *ca, u32 value)
{
	return value - (u32)(((u64)value * ca->beta) >> BETA_SHIFT);
}

/* tcp_illinois.c beta(): linear interpolation between (dm/10, BETA_MIN) and
 * (0.8*dm, BETA_MAX). F1/F3: divide by (d3 - d2), in u64, no reciprocals.
 */
static u32 elegant_beta(u32 da, u32 dm)
{
	u32 d2 = dm / 10;
	u32 d3 = dm - dm / 5;		/* 0.8 * dm without overflow */
	u64 num;

	if (da <= d2)
		return BETA_MIN;
	if (da >= d3 || d3 <= d2)	/* includes "no spread measured" */
		return BETA_MAX;

	num = (u64)BETA_MIN * d3 + (u64)(BETA_MAX - BETA_MIN) * da;
	num -= (u64)BETA_MAX * d2;	/* ordered so num stays >= 0 */
	return clamp_t(u32, div_u64(num, d3 - d2), BETA_MIN, BETA_MAX);
}

static void elegant_update_params(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);
	u32 da = elegant_avg_delay(ca);
	u32 dm = elegant_max_delay(ca);
	u64 queued;
	u32 thresh;

	/* Packets the average queueing delay accounts for, log-scaled: below
	 * that many packets in flight the delay signal is noise (F8).
	 */
	queued = ((u64)elegant_max_bw(sk) * da) >> BW_SCALE;
	thresh = max_t(u32, win_thresh, queued ? 2 * (fls64(queued) - 1) : 0);

	if (tcp_snd_cwnd(tp) < thresh || !ca->cnt_rtt) {
		ca->beta = BETA_BASE;		/* standard 1/2 cut (F8) */
		ca->inv_beta = inv_beta_init;
	} else {
		ca->beta = elegant_beta(da, dm);
		ca->inv_beta = inv_beta_base - ca->beta;
		ca->delay_valid = 1;
	}
}

/* --------------------------------------------------------------- increase */

/* Integer square root, base-4 digit by digit. F11: the x < 2 guard comes
 * first and the seed is the largest power of 4 <= x, so no shift is wider
 * than the type. Checked against an exact isqrt in the userspace probe.
 */
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

/* sqrt(rtt_max / rtt_curr) in Q3, recomputed once per round. */
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
		ratio = ELEGANT_UNIT;			/* sqrt(1) in Q3 */
	} else {
		sq = DIV_ROUND_UP_ULL((u64)rtt_max << ELEGANT_UNIT_SQ_SHIFT,
				      rtt_curr);
		ratio = (u32)fast_sqrt(sq + 1);
		ratio = clamp_t(u32, ratio, ELEGANT_UNIT, ELEGANT_RATIO_MAX);
	}
	ca->ratio = ratio;			/* F10: one assignment */
	return ratio;
}

static void elegant_cong_avoid(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);
	u32 acked = rs->acked_sacked;
	u32 cwnd, wwf;

	if (!acked || !tcp_is_cwnd_limited(sk))
		return;

	if (tcp_in_slow_start(tp)) {
		/* Leave slow start on a measurement, not on a loss: once the
		 * average queueing delay reaches the propagation RTT there is
		 * about one BDP of self-inflicted queue, so stop doubling.
		 * This replaces both the Copa target and BBR's plateau test.
		 */
		if (elegant_avg_delay(ca) >= elegant_min_rtt(ca) &&
		    elegant_min_rtt(ca))
			tp->snd_ssthresh = min(tp->snd_ssthresh,
					       elegant_bdp(sk));
		acked = tcp_slow_start(tp, acked);
		if (!acked)
			return;
	}

	/* Elastic-TCP: cwnd += wwf / cwnd per ACKed packet, with
	 * wwf = sqrt(cwnd) * sqrt(rtt_max / rtt_curr) * gain.
	 */
	cwnd = tcp_snd_cwnd(tp);
	wwf = ((u32)fast_sqrt(cwnd) * elegant_wwf_ratio(sk)) >> ELEGANT_SCALE;
	if (ca->beta < GAIN_UNITY_BETA)
		wwf = (u32)(((u64)wwf * ca->inv_beta) >> BETA_SHIFT);
	wwf = max(wwf, 1U);
	tcp_cong_avoid_ai(tp, cwnd, min_t(u64, (u64)wwf * acked, U32_MAX));
}

/* --------------------------------------------------------------- decrease */

static void elegant_save_cwnd(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	if (ca->prev_ca_state < TCP_CA_Recovery && !tcp_in_slow_start(tp))
		ca->prior_cwnd = tcp_snd_cwnd(tp);
	else
		ca->prior_cwnd = max(ca->prior_cwnd, tcp_snd_cwnd(tp));
}

/* .cong_control means tcp_cwnd_reduction() (PRR) never runs, so the decrease
 * belongs to this module (F13). Mirrors bbr_set_cwnd_to_recover_or_restore()
 * with one deliberate difference, noted at the restore.
 * Returns true when recovery owns cwnd for this ACK.
 */
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
		/* Restore to the cut, not to the pre-loss window. BBR may
		 * restore prior_cwnd because its cwnd is BDP-bounded; here
		 * cwnd is AIMD-driven, so restoring it would undo the
		 * decrease that .ssthresh just computed.
		 */
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

/* The single ssthresh authority (F14). Called by tcp_enter_recovery() and by
 * tcp_enter_loss(), in both cases before the stack touches cwnd.
 */
static u32 tcp_elegant_ssthresh(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);
	u32 cut;

	elegant_save_cwnd(sk);
	cut = beta_scale(ca, tcp_snd_cwnd(tp));	/* (1 - beta) * cwnd */
	return max(min(cut, elegant_bdp(sk)), 2U);
}

static u32 tcp_elegant_undo_cwnd(struct sock *sk)
{
	struct elegant *ca = inet_csk_ca(sk);

	return max(tcp_snd_cwnd(tcp_sk(sk)), ca->prior_cwnd);
}

/* ------------------------------------------------------------- round, acks */

static void elegant_update_rtt(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);
	u32 rtt_us;

	if (rs->rtt_us <= 0)
		return;
	/* Outside slow start a delayed ACK inflates the sample; early on
	 * there are too few samples to be choosy.
	 */
	if (rs->is_ack_delayed && !tcp_in_slow_start(tp))
		return;

	rtt_us = rs->rtt_us;
	ca->has_seen_rtt = 1;
	ca->sum_rtt += rtt_us;
	ca->cnt_rtt++;
	ca->last_rtt = rtt_us;
	if (rtt_us < ca->round_rtt_min)
		ca->round_rtt_min = rtt_us;
	if (rtt_us > ca->round_rtt_max)
		ca->round_rtt_max = rtt_us;
}

static void elegant_round_reset(struct elegant *ca)
{
	ca->sum_rtt = 0;
	ca->cnt_rtt = 0;
	ca->round_rtt_min = UINT_MAX;
	ca->round_rtt_max = 0;
	ca->ratio = 0;
}

/* rtt_curr is written here only, once per round, in us (F12). */
static void elegant_update_rtt_curr(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);
	u64 t = ca->sum_rtt;

	if (ca->cnt_rtt) {
		do_div(t, ca->cnt_rtt);
		ca->rtt_curr = (u32)t;
	} else if (tp->srtt_us) {
		ca->rtt_curr = max(tp->srtt_us >> 3, 1U);
	}
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

	if (ca->round_rtt_min != UINT_MAX) {
		ca->rtt_lo[1] = ca->rtt_lo[1] ?
			min(ca->rtt_lo[1], ca->round_rtt_min) : ca->round_rtt_min;
		ca->rtt_hi[1] = max(ca->rtt_hi[1], ca->round_rtt_max);
	}

	elegant_update_rtt_curr(sk);
	elegant_update_params(sk);
	elegant_round_reset(ca);

	/* Refresh the windows on a timer, or sooner when the delay signal
	 * says the stored maximum is stale enough to be hurting.
	 */
	if (after(tcp_jiffies32, ca->filter_stamp + FILTER_RESET_JIFFIES) ||
	    (ca->beta > GAIN_UNITY_BETA && ca->round >= FILTER_ROUND_THRESH))
		elegant_advance_filters(sk);
}

static void tcp_elegant_cong_control(struct sock *sk, const struct rate_sample *rs)
{
	struct elegant *ca = inet_csk_ca(sk);
	u32 bw;

	elegant_update_rtt(sk, rs);

	bw = elegant_bw_sample(rs);
	/* An app-limited sample can only raise the estimate. */
	if (bw && (!rs->is_app_limited || bw > elegant_max_bw(sk)))
		ca->bw_hi[1] = max(bw, ca->bw_hi[1]);

	elegant_round(sk, rs);

	if (!elegant_recovery_cwnd(sk, rs))
		elegant_cong_avoid(sk, rs);

	elegant_set_pacing_rate(sk, elegant_max_bw(sk));
}

static void tcp_elegant_set_state(struct sock *sk, u8 new_state)
{
	struct elegant *ca = inet_csk_ca(sk);

	if (new_state == TCP_CA_Loss) {
		/* The RTO'd sample is not a path measurement. cwnd and
		 * ssthresh were already handled in .ssthresh (F14).
		 */
		if (ca->cnt_rtt && ca->last_rtt && ca->sum_rtt >= ca->last_rtt) {
			ca->sum_rtt -= ca->last_rtt;
			ca->cnt_rtt--;
		}
		ca->last_rtt = 0;
		ca->round_rtt_min = UINT_MAX;
		ca->round_rtt_max = 0;
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
	ca->round_rtt_min = UINT_MAX;
	ca->beta = BETA_BASE;
	ca->inv_beta = inv_beta_init;
	ca->next_rtt_delivered = tp->delivered;
	ca->prior_cwnd = tcp_snd_cwnd(tp);
	ca->prev_ca_state = TCP_CA_Open;
	ca->filter_stamp = tcp_jiffies32;

	elegant_init_pacing_rate_from_rtt(sk);
	/* F16: without this the pacer may ignore sk_pacing_rate. */
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
	/* F17: gain = (inv_beta_base - beta) / 64 must stay positive. */
	if (inv_beta_base <= (int)BETA_MAX)
		inv_beta_base = (int)BETA_MAX + 1;
	if (inv_beta_init <= 0)
		inv_beta_init = 80;
	if (win_thresh < 2)
		win_thresh = 2;
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
