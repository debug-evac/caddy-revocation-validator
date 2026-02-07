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

type RevocationChecker struct {
	RevocationConfig      *ParsedRevocationConfig
	crlRevocationChecker  *crl.CRLRevocationChecker
	ocspRevocationChecker *ocsp.OCSPRevocationChecker
	checkOrder            [](func(*x509.Certificate, [][]*x509.Certificate) (*core.RevocationStatus, error))
}

func (c *RevocationChecker) Provision(ctx caddy.Context, logger *zap.Logger, revocationConfig *ParsedRevocationConfig) error {
	c.RevocationConfig = revocationConfig

	var crl_err, ocsp_err error

	if c.RevocationConfig.IsCRLCheckingEnabled() {
		c.crlRevocationChecker = &crl.CRLRevocationChecker{}
		logger.Info("crl checking was enabled start CRL provisioning")
		crl_err = c.crlRevocationChecker.Provision(revocationConfig.CRLConfigParsed, logger, revocationConfig.ConfigHash)
	}

	if c.RevocationConfig.IsOCSPCheckingEnabled() {
		c.ocspRevocationChecker = &ocsp.OCSPRevocationChecker{}
		logger.Info("ocsp checking was enabled start ocsp provisioning")
		ocsp_err = c.ocspRevocationChecker.Provision(revocationConfig.OCSPConfigParsed, logger)
	}

	switch c.RevocationConfig.ModeParsed {
	case config.RevocationCheckModePreferOCSP:
		c.checkOrder = append(c.checkOrder, c.ocspRevocationChecker.IsRevoked, c.crlRevocationChecker.IsRevoked)
	case config.RevocationCheckModePreferCRL:
		c.checkOrder = append(c.checkOrder, c.crlRevocationChecker.IsRevoked, c.ocspRevocationChecker.IsRevoked)
	case config.RevocationCheckModeCRLOnly:
		c.checkOrder = append(c.checkOrder, c.crlRevocationChecker.IsRevoked)
	case config.RevocationCheckModeOCSPOnly:
		c.checkOrder = append(c.checkOrder, c.ocspRevocationChecker.IsRevoked)
	case config.RevocationCheckModeDisabled:
	}

	return errors.Join(crl_err, ocsp_err)
}

func (c *RevocationChecker) VerifyClientCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(verifiedChains) > 0 {
		clientCertificate := verifiedChains[0][0]

		for i := range len(c.checkOrder) {
			revoked, err := c.checkOrder[i](clientCertificate, verifiedChains)
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
	var crl_err, ocsp_err error

	if c.RevocationConfig.IsCRLCheckingEnabled() {
		crl_err = c.crlRevocationChecker.Cleanup()
	}
	if c.RevocationConfig.IsOCSPCheckingEnabled() {
		ocsp_err = c.ocspRevocationChecker.Cleanup()
	}

	return errors.Join(crl_err, ocsp_err)

}
