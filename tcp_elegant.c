#include <linux/mm.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <asm/div64.h>
#include <linux/bitops.h>
#include <linux/math64.h>
#include <net/tcp.h>

#define BETA_SHIFT	6
#define BETA_SCALE	(1u<<BETA_SHIFT)
#define BETA_MIN (BETA_SCALE >> 3) /* 0.125 */
#define BETA_MAX (BETA_SCALE >> 1) /* 0.5 */
#define BETA_BASE	BETA_MAX

#define ELEGANT_SCALE 3
#define ELEGANT_UNIT (1 << ELEGANT_SCALE)
#define ELEGANT_UNIT_SQ_SHIFT (2 * ELEGANT_SCALE)
#define ELEGANT_RATIO_SHIFT (1ULL << ELEGANT_UNIT_SQ_SHIFT)

#define BW_SCALE 24
#define BW_UNIT (1 << BW_SCALE)

#define BBR_SCALE 8	/* scaling factor for fractions in BBR (e.g. gains) */
#define BBR_UNIT (1 << BBR_SCALE)

static int win_thresh __read_mostly = 15U;
static int inv_beta_init __read_mostly = 80U;
static int inv_beta_base __read_mostly = 88U;

struct elegant {
    u64 sum_rtt;               /* Sum of RTTs in last round */
    u32 cnt_rtt;               /* Samples in this RTT */
    u32 round_base_rtt;        /* Min RTT in current round */
    u32 round_rtt_max;         /* Max RTT in current round */
    u32 base_rtt;              /* Min of all RTTs */
    u32 rtt_max;               /* Max RTT seen */
    u32 rtt_curr;              /* Current avg RTT */
    u32 beta;                  /* Multiplicative decrease factor */
    u32 inv_beta;              /* Inverse beta for pacing gain */
	u32 ratio;                 /* Cached rtt_max / rtt_curr ratio */
    u32 round;                 /* Round counter */
	u32 next_rtt_delivered;    /* Next RTT boundary (matches tp->delivered) */
    u32 bw_hi[2];              /* Max recent measured BW samples) */
	u32 reset_time;            /* Time for BW filter reset */
};

static inline u32 beta_scale(const struct elegant *ca, u32 value)
{
    return value - ((value * ca->beta) >> BETA_SHIFT);
}

/* Return rate in bytes per second, optionally with a gain.
 * The order here is chosen carefully to avoid overflow of u64. This should
 * work for input rates of up to 2.9Tbit/sec and gain of 2.89x.
 */
static u64 bbr_rate_bytes_per_sec(struct sock *sk, const struct elegant *ca, u64 rate, int margin)
{
	unsigned int mss = tcp_sk(sk)->mss_cache;

	rate *= mss;
	rate = (rate * (ca->inv_beta)) >> BETA_SHIFT;
	rate >>= BBR_SCALE;
	rate *= USEC_PER_SEC / 100 * (100 - margin);
	rate >>= BW_SCALE;
	rate = max(rate, 1ULL);
	return rate;
}

static unsigned long bbr_bw_to_pacing_rate(struct sock *sk, u32 bw)
{
	struct elegant *ca = inet_csk_ca(sk);
	u64 rate = bw;
	rate = bbr_rate_bytes_per_sec(sk, ca, rate, 1);
	rate = min(rate, (u64)READ_ONCE(sk->sk_max_pacing_rate));
	return rate;
}

static void bbr_init_pacing_rate_from_rtt(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u64 bw;
	u32 rtt_us;

	if (tp->srtt_us) {		/* any RTT sample yet? */
		rtt_us = max(tp->srtt_us >> 3, 1U);
	} else {			 /* no RTT sample yet */
		rtt_us = USEC_PER_MSEC;	 /* use nominal default RTT */
	}
	bw = (u64)tp->snd_cwnd * BW_UNIT;
	do_div(bw, rtt_us);
	WRITE_ONCE(sk->sk_pacing_rate, bbr_bw_to_pacing_rate(sk, bw));
}

static void bbr_set_pacing_rate(struct sock *sk, u64 bw)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);
	u64 rate = bbr_bw_to_pacing_rate(sk, bw);

	if (unlikely(ca->cnt_rtt > 0 && tp->srtt_us))
		bbr_init_pacing_rate_from_rtt(sk);
	rate = max(rate, 120ULL);
	if (rate > READ_ONCE(sk->sk_pacing_rate))
		WRITE_ONCE(sk->sk_pacing_rate, rate);
}

static u64 bbr_calculate_bw_sample(struct sock *sk, const struct rate_sample *rs)
{
	if (rs->interval_us <= 0)
        return 0;
    return DIV_ROUND_UP_ULL((u64)rs->delivered * BW_UNIT, rs->interval_us);
}

static u32 bbr_max_bw(const struct sock *sk)
{
	const struct elegant *ca= inet_csk_ca(sk);
	return max(ca->bw_hi[0], ca->bw_hi[1]);
}

static void bbr_take_max_bw_sample(struct sock *sk, u32 bw)
{
	struct elegant *ca = inet_csk_ca(sk);
	ca->bw_hi[1] = max(bw, ca->bw_hi[1]);
}

static void bbr_advance_max_bw_filter(struct sock *sk)
{
	struct elegant *ca = inet_csk_ca(sk);
	if (!ca->bw_hi[1])
		return;  /* no samples in this window; remember old window */
	ca->bw_hi[0] = ca->bw_hi[1];
	ca->bw_hi[1] = 0;
}

static void elegant_init(struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct elegant *ca = inet_csk_ca(sk);

    ca->sum_rtt = 0;
    ca->cnt_rtt = 0;
    ca->round_base_rtt = UINT_MAX;
    ca->round_rtt_max = 0;
    ca->base_rtt = UINT_MAX;
    ca->rtt_max = 0;
    ca->rtt_curr = 0;
    ca->beta = BETA_MIN;
    ca->inv_beta = inv_beta_init;
	ca->ratio = 0;
    ca->round = 0;
    ca->next_rtt_delivered = tp->delivered;
    ca->bw_hi[0] = 0;
    ca->bw_hi[1] = 0;
	ca->reset_time = tcp_jiffies32;

    bbr_init_pacing_rate_from_rtt(sk);
}

/* Maximum queuing delay */
static inline u32 max_delay(const struct elegant *ca)
{
    return ca->rtt_max - ca->base_rtt;
}

/* Average queuing delay */
static inline u32 avg_delay(struct tcp_sock *tp, struct elegant *ca)
{
	u64 t = ca->sum_rtt;

    if (ca->cnt_rtt == 0) {
		u32 srtt = tp->srtt_us;
        u32 base = ca->round_base_rtt;
		ca->rtt_curr = srtt;
        if (srtt > base)
            return srtt - base;

        return max(srtt >> 4, 1U);
    }

	do_div(t, ca->cnt_rtt);
	ca->rtt_curr = (u32)t;
	return t - ca->base_rtt;
}

static u32 beta(u32 da, u32 dm)
{
	u32 d2, d3;

	d2 = dm / 10;
	if (da <= d2)
		return BETA_MIN;

	d3 = d2 << 3;
	if (da >= d3)
		return BETA_MAX;

	/*
	 * Based on:
	 *
	 *       bmin d3 - bmax d2
	 * k3 = -------------------
	 *         d3 - d2
	 *
	 *       bmax - bmin
	 * k4 = -------------
	 *         d3 - d2
	 *
	 * b = k3 + k4 da
	 */
	return (BETA_MIN * d3 - BETA_MAX * d2 + (BETA_MAX - BETA_MIN) * da) / (d3 - d2);
}

static inline void rtt_reset(struct tcp_sock *tp, struct elegant *ca)
{
	ca->sum_rtt = 0;
	ca->cnt_rtt = 0;
}

static inline u32 copa_ssthresh(struct tcp_sock *tp, struct elegant *ca)
{
	return max(2U, ca->rtt_curr * BETA_SCALE / (avg_delay(tp, ca) * (BETA_SCALE - ca->beta)));
}

static u32 tcp_elegant_ssthresh(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);
	return max(copa_ssthresh(tp, ca), beta_scale(ca, tp->snd_cwnd));
}

static void update_params(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	u32 da = avg_delay(tp, ca);
    u64 thresh_arg = ((u64)bbr_max_bw(sk) * da) / tp->mss_cache;
    u32 thresh = max_t(u32, win_thresh, 2 * (thresh_arg ? ilog2(thresh_arg) : 0));

    if (tp->snd_cwnd < thresh) {
        ca->beta = BETA_MIN;
		ca->inv_beta = inv_beta_init;
    } else if (ca->cnt_rtt > 0) {
		u32 dm = max_delay(ca);

		ca->beta = beta(da, dm);
		ca->inv_beta = inv_beta_base - ca->beta;
	}

	rtt_reset(tp, ca);
}

static void elegant_cong_avoid(struct sock *sk, struct elegant *ca, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (!tcp_is_cwnd_limited(sk))
		return;

	if (tcp_in_slow_start(tp)) {
		tp->snd_ssthresh = copa_ssthresh(tp, ca);
		tcp_slow_start(tp, rs->acked_sacked);
	} else {
		u32 wwf;
		u32 ratio = ca->ratio;
		if (ratio == 0) {
			ratio = ((u64)ca->rtt_max << ELEGANT_UNIT_SQ_SHIFT);
			ratio = DIV_ROUND_UP_ULL(ratio, ca->rtt_curr);
			ca->ratio = ratio;
		}
		wwf = int_sqrt64(tp->snd_cwnd * ratio) >> ELEGANT_SCALE;
		tcp_cong_avoid_ai(tp, tp->snd_cwnd, wwf);
	}
}

static void elegant_update_rtt(struct elegant *ca, const struct rate_sample *rs)
{
	u32 rtt_us;

	/* dup ack, no rtt sample */
	if (rs->rtt_us < 0)
		return;

	rtt_us = rs->rtt_us;

	ca->sum_rtt += rtt_us;
	ca->cnt_rtt++;

	/* keep track of minimum RTT seen so far */
	if (rtt_us < ca->round_base_rtt)
		ca->round_base_rtt = rtt_us;

	if (rtt_us > ca->round_rtt_max)
		ca->round_rtt_max = rtt_us;
}

static void tcp_elegant_round(struct sock *sk, struct elegant *ca, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* See if we've reached the next RTT */
	if (rs->interval_us > 0 && !before(rs->prior_delivered, ca->next_rtt_delivered)) {
		if (ca->round_base_rtt != UINT_MAX) {
			ca->base_rtt = ca->round_base_rtt;
			ca->rtt_max = ca->round_rtt_max;
			update_params(sk);
			ca->round_base_rtt = UINT_MAX;
			ca->round_rtt_max = 0;
			ca->ratio = 0;
		}
		ca->round++;
		ca->next_rtt_delivered = tp->delivered;
	}
}

static void tcp_elegant_cong_control(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	bool filter_expired;
	u64 bw = 0;

	if (tcp_in_slow_start(tp) || (rs->rtt_us > 0 && !rs->is_ack_delayed))
		elegant_update_rtt(ca, rs);

	tcp_elegant_round(sk, ca, rs);

	if (rs->interval_us > 0 && rs->acked_sacked) {
		bw = bbr_calculate_bw_sample(sk, rs);
		if (unlikely(bw > bbr_max_bw(sk))) {
			bbr_take_max_bw_sample(sk, bw);
			bbr_set_pacing_rate(sk, bw);
		} else if (!rs->is_app_limited) {
			bbr_take_max_bw_sample(sk, bw);
		}
		filter_expired = after(tcp_jiffies32, ca->reset_time + 10 * HZ);
		if (filter_expired || (ca->beta > 24 && ca->round >= 12)) {
			bbr_advance_max_bw_filter(sk);
			ca->round = 0;
			ca->reset_time = tcp_jiffies32;
			bbr_set_pacing_rate(sk, bbr_max_bw(sk));
		}
		elegant_cong_avoid(sk, ca, rs);
	}
}

static void tcp_elegant_set_state(struct sock *sk, u8 new_state)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	if (new_state == TCP_CA_Loss) {
		rtt_reset(tp, ca);
		ca->round_base_rtt = UINT_MAX;
		ca->round_rtt_max = 0;
	}
}

static u32 tcp_elegant_undo_cwnd(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

    return max(tp->snd_cwnd, tp->prior_cwnd);
}

static struct tcp_congestion_ops tcp_elegant __read_mostly = {
	.name		= "elegant",
	.owner		= THIS_MODULE,
	.init		= elegant_init,
	.ssthresh	= tcp_elegant_ssthresh,
	.undo_cwnd	= tcp_elegant_undo_cwnd,
	.cong_control	= tcp_elegant_cong_control,
	.set_state  = tcp_elegant_set_state
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

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Elegant TCP");
