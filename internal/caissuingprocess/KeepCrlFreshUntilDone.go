package caissuingprocess

import (
	"context"
	"time"

	"github.com/tomaluca95/simple-ca/internal/types"
)

// crlRefreshIntervalDivisor is how many times a CRL is refreshed before it
// expires. With a refresh every crl_ttl/4, the CRL written at time T is
// replaced at T+N/4, T+N/2 and T+3N/4, and the one written at T+N arrives no
// later than its own nextUpdate (T+N), so the published CRL never expires: a
// refresh that fails gets three more chances before the verifiers start
// rejecting it.
const crlRefreshIntervalDivisor = 4

// KeepCrlFreshUntilDone rewrites the CRL of this CA every crl_ttl/4 until ctx
// is done, so the server keeps publishing one that has not expired yet.
//
// It is what the HTTP server needs and the CLI does not: a CLI run writes the
// CRL when it loads the CA (and when it revokes) and then exits, while a server
// would otherwise publish the CRL of its startup until the first revoke, and
// stop publishing a valid one crl_ttl later.
//
// The first refresh happens after one interval, not right away, because the
// caller has just written one.
func (oneCa *OneCaType) KeepCrlFreshUntilDone(ctx context.Context, logger types.Logger) {
	crlTtl := oneCa.caConfig.CrlTtl
	interval := crlTtl / crlRefreshIntervalDivisor
	if interval <= 0 {
		// crl_ttl is validated to be positive, but anything below 4ns leaves no
		// interval to tick on, and a ticker cannot be built from it.
		logger.WarnContext(
			ctx,
			"crl_ttl is too short to refresh the CRL, it will not be refreshed",
			"crl_ttl", crlTtl,
		)
		return
	}

	logger.InfoContext(ctx, "refreshing the CRL periodically", "interval", interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// A failed refresh is logged and the next tick tries again, which
			// is the point of refreshing more often than the CRL expires: the
			// published CRL stays valid until there is time left to fix it.
			if err := oneCa.UpdateCrl(); err != nil {
				logger.ErrorContext(ctx, "failed refreshing the CRL", "err", err)
			}
		}
	}
}
