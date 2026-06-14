package lifecycle

import (
	"time"
)

type Status string

const (
	StatusValid         Status = "valid"
	StatusExpiringSoon  Status = "expiring_soon"
	StatusExpired       Status = "expired"
	StatusRevoked       Status = "revoked"
)

func Compute(notAfter time.Time, expiringSoonDays int, revoked bool) (Status, int) {
	now := time.Now().UTC()
	days := int(notAfter.Sub(now).Hours() / 24)

	if revoked {
		return StatusRevoked, days
	}
	if notAfter.Before(now) {
		return StatusExpired, days
	}
	if days <= expiringSoonDays {
		return StatusExpiringSoon, days
	}
	return StatusValid, days
}
