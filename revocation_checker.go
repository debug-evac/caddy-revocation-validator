package revocation

import (
	"crypto/x509"
	"errors"

	"github.com/caddyserver/caddy/v2"
	"github.com/gr33nbl00d/caddy-revocation-validator/config"
	"github.com/gr33nbl00d/caddy-revocation-validator/core"
	"github.com/gr33nbl00d/caddy-revocation-validator/crl"
	"github.com/gr33nbl00d/caddy-revocation-validator/ocsp"
	"go.uber.org/zap"
)

type IRevocationChecker interface {
	IsRevoked(clientCertificate *x509.Certificate, verifiedChains [][]*x509.Certificate) (*core.RevocationStatus, error)
	Cleanup() error
}

type RevocationChecker struct {
	RevocationConfig   *ParsedRevocationConfig
	revocationCheckers []IRevocationChecker
}

func (c *RevocationChecker) Provision(ctx caddy.Context, logger *zap.Logger, revocationConfig *ParsedRevocationConfig) error {
	c.RevocationConfig = revocationConfig

	var crl_err, ocsp_err error

	if c.RevocationConfig.IsCRLCheckingEnabled() {
		crlRevocationChecker := &crl.CRLRevocationChecker{}
		logger.Info("crl checking was enabled start CRL provisioning")
		crl_err = crlRevocationChecker.Provision(revocationConfig.CRLConfigParsed, logger, revocationConfig.ConfigHash)
		c.revocationCheckers = append(c.revocationCheckers, crlRevocationChecker)
	}

	if c.RevocationConfig.IsOCSPCheckingEnabled() {
		ocspRevocationChecker := &ocsp.OCSPRevocationChecker{}
		logger.Info("ocsp checking was enabled start ocsp provisioning")
		ocsp_err = ocspRevocationChecker.Provision(revocationConfig.OCSPConfigParsed, logger)
		c.revocationCheckers = append(c.revocationCheckers, ocspRevocationChecker)
	}

	// swap ocsp with crl checker, if ocsp is preferred
	if c.RevocationConfig.ModeParsed == config.RevocationCheckModePreferOCSP {
		c.revocationCheckers[0], c.revocationCheckers[1] = c.revocationCheckers[1], c.revocationCheckers[0]
	}

	return errors.Join(crl_err, ocsp_err)
}

func (c *RevocationChecker) VerifyClientCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(verifiedChains) > 0 {
		clientCertificate := verifiedChains[0][0]

		for i := range len(c.revocationCheckers) {
			revoked, err := c.revocationCheckers[i].IsRevoked(clientCertificate, verifiedChains)
			if err != nil {
				return err
			}
			if revoked.Revoked {
				return errors.New("client certificate was revoked")
			}
		}
	}
	return nil
}

func (c *RevocationChecker) Cleanup() error {
	var rc_errors []error

	for _, revocationChecker := range c.revocationCheckers {
		rc_errors = append(rc_errors, revocationChecker.Cleanup())
	}

	return errors.Join(rc_errors...)
}
