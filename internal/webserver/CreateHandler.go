package webserver

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tomaluca95/simple-ca/internal/caissuingprocess"
	"github.com/tomaluca95/simple-ca/internal/opa"
	"github.com/tomaluca95/simple-ca/internal/pemhelper"
	"github.com/tomaluca95/simple-ca/internal/types"
)

func CreateHandler(
	ctx context.Context,
	logger types.Logger,
	configFile types.ConfigFileType,
) (http.Handler, error) {
	if err := configFile.Validate(); err != nil {
		return nil, err
	}

	// Held for the whole process lifetime. The returned unlock is deliberately
	// dropped: LockDataDirectory keeps the lock file itself reachable, so the
	// lock cannot be released by a garbage collection behind our back, and the
	// operating system releases it when the server exits.
	if _, err := caissuingprocess.LockDataDirectory(configFile.DataDirectory); err != nil {
		return nil, err
	}

	// gin is put in release mode: the request access log below is structured
	// and traced, gin's debug output would just duplicate it untraced.
	gin.SetMode(gin.ReleaseMode)
	httpHandler := gin.New()
	httpHandler.Use(requestLoggerMiddleware(logger))
	httpHandler.Use(gin.Recovery())

	for caId, caConfig := range configFile.AllCaConfigs {
		oneCa, err := caissuingprocess.LoadOneCa(
			ctx,
			logger,
			caId,
			configFile.DataDirectory,
			caConfig,
		)
		if err != nil {
			return nil, err
		}
		if err := oneCa.UpdateCrl(); err != nil {
			return nil, err
		}
		caLogger := logger.With("ca_id", caId)
		httpWrapper := &httpWrapperType{
			oneCa: oneCa,

			OpaUrlSign:    *caConfig.OpaUrlSign,
			OpaUrlRevoke:  *caConfig.OpaUrlRevoke,
			OpaUrlIssueCa: *caConfig.OpaUrlIssueCa,

			OpaTimeoutSign:    caConfig.OpaTimeoutSign,
			OpaTimeoutRevoke:  caConfig.OpaTimeoutRevoke,
			OpaTimeoutIssueCa: caConfig.OpaTimeoutIssueCa,

			logger: caLogger,
		}

		// The CRL written above would be the only one this server publishes
		// until the first revoke, and it expires crl_ttl after that. It is kept
		// fresh until the caller cancels ctx, which is what stops it on
		// shutdown.
		go oneCa.KeepCrlFreshUntilDone(ctx, caLogger)

		caHttpGroup := httpHandler.Group(
			"/ca/" + caId,
		)

		caHttpGroup.GET("/issuer.pem", httpWrapper.Issuer)
		caHttpGroup.POST("/csr/sign", httpWrapper.CsrSign)
		caHttpGroup.POST("/crt/revoke", httpWrapper.CrtRevokeCertificate)
		caHttpGroup.POST("/crt/revoke/:crtSerial", httpWrapper.CrtRevokeSerial)
		caHttpGroup.GET("/crt/crl.pem", httpWrapper.CrtCrlPem)
	}

	return httpHandler, nil
}

type httpWrapperType struct {
	oneCa *caissuingprocess.OneCaType

	OpaUrlSign    string
	OpaUrlRevoke  string
	OpaUrlIssueCa string

	OpaTimeoutSign    time.Duration
	OpaTimeoutRevoke  time.Duration
	OpaTimeoutIssueCa time.Duration

	logger types.Logger
}

const (
	pemContentType = "application/x-pem-file"
	// crlNextUpdateHeader carries the CRL's own expiry, in ISO 8601: the
	// moment the served list stops being authoritative, which is what a client
	// needs to know to decide whether the copy it holds may still be trusted.
	crlNextUpdateHeader = "X-Crl-Next-Update"
	// maxRevokeSerialLength is the most characters a serial can have: a
	// certificate serial is 128 bits, 39 decimal digits. Nothing larger can
	// name a certificate this CA issued, and letting a longer path reach the
	// parser is how a request line buys seconds of big.Int work.
	maxRevokeSerialLength = 40
)

func (httpWrapper *httpWrapperType) Issuer(c *gin.Context) {
	fileContent, err := httpWrapper.oneCa.GetIssuerPem()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unexpected error in getting issuer"})
		return
	}
	c.Data(http.StatusOK, pemContentType, fileContent)
}

func (httpWrapper *httpWrapperType) CrtCrlPem(c *gin.Context) {
	fileContent, fileModTime, err := httpWrapper.oneCa.GetCrlPemAndModTime()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// The CRL file is missing: removed by hand, or simply absent from a
			// restored data directory. Answer with No Content: a distinct,
			// honest answer for "there is no CRL body", which a client cannot
			// mistake for "nothing is revoked" the way it could a 200 with an
			// empty body.
			c.Status(http.StatusNoContent)
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unexpected error in signing CRL (get CRL file)"})
		return
	}

	// Revocation freshness is the one thing a CRL must never be served
	// without: a client that reuses a stored copy without asking is trusting a
	// revocation list of unknown age. So the copy may be kept, but it is never
	// fresh. no-cache turns every use into a revalidation request and
	// must-revalidate forbids serving the stored copy at all while the server
	// cannot confirm it. The ETag -- a strong tag over the exact body -- and the
	// Last-Modified are what make that revalidation cheap: an unchanged CRL
	// answers 304 with no body, so the client learns nothing changed without
	// transferring the list again. No Expires: the response has no window in
	// which it may be used as-is.
	//
	// The expiry is reported from the CRL itself, not from the clock: a CRL
	// states the moment it stops being authoritative, and that is the only
	// value true of this document. It is written in ISO 8601 (RFC 3339), the
	// format the rest of the tool writes timestamps in, so a client can read
	// it without knowing HTTP.
	nextUpdate, err := crlNextUpdate(fileContent)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unexpected error in reading CRL (parse CRL)"})
		return
	}

	digest := sha256.Sum256(fileContent)
	etag := `"` + hex.EncodeToString(digest[:]) + `"`
	c.Header("ETag", etag)
	c.Header("Cache-Control", "no-cache, must-revalidate")
	c.Header("Last-Modified", fileModTime.UTC().Format(http.TimeFormat))
	c.Header(crlNextUpdateHeader, nextUpdate.UTC().Format(time.RFC3339))

	// "Not changed" is only an honest answer while the copy the client holds
	// is still authoritative. A CRL past its nextUpdate is unchanged and
	// useless at once, and a 304 would leave the client trusting a list that
	// has expired, so the expiry decides first and the validator only after it.
	crlExpired := !nextUpdate.After(time.Now())
	if crlExpired {
		httpWrapper.logger.WarnContext(
			c.Request.Context(),
			"serving a CRL that is past its nextUpdate",
			"next_update", nextUpdate.UTC().Format(time.RFC3339),
			"path", c.Request.URL.Path,
		)
	} else if ifNoneMatch := c.GetHeader("If-None-Match"); ifNoneMatch != "" {
		// A matching If-None-Match wins over any If-Modified-Since: RFC 9110
		// makes the validator the first word, so tell a cache holding the exact
		// CRL body that it is still current with no body at all.
		if weakETagMatches(ifNoneMatch, etag) {
			c.Status(http.StatusNotModified)
			return
		}
	} else if ifModifiedSince := c.GetHeader("If-Modified-Since"); ifModifiedSince != "" {
		if modifiedSince, parseErr := http.ParseTime(ifModifiedSince); parseErr == nil && !fileModTime.Truncate(time.Second).After(modifiedSince) {
			c.Status(http.StatusNotModified)
			return
		}
	}

	c.Data(http.StatusOK, pemContentType, fileContent)
}

// crlNextUpdate reads the moment a served CRL stops being authoritative out of
// the CRL itself. A CRL that has expired is still a well-formed document, and
// only its NextUpdate says how long it was worth.
func crlNextUpdate(crlPem []byte) (time.Time, error) {
	pemBlock, _ := pem.Decode(crlPem)
	if pemBlock == nil {
		return time.Time{}, errors.New("the CRL file holds no PEM block")
	}
	crlInfo, err := x509.ParseRevocationList(pemBlock.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return crlInfo.NextUpdate, nil
}

// weakETagMatches reports whether an If-None-Match header list names etag
// under the weak comparison RFC 9110 requires for If-None-Match: a W/ prefix
// on a candidate entity tag is ignored, and "*" matches any current
// representation.
func weakETagMatches(ifNoneMatchHeader, etag string) bool {
	for _, candidate := range strings.Split(ifNoneMatchHeader, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if candidate == "*" {
			return true
		}
		candidate = strings.TrimPrefix(candidate, "W/")
		if candidate == etag {
			return true
		}
	}
	return false
}

type csrSignRequest struct {
	Csr      string `json:"csr"`
	NotAfter string `json:"not_after"`
}

func (httpWrapper *httpWrapperType) CsrSign(c *gin.Context) {
	defer c.Request.Body.Close()
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 32*1024)

	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	var request csrSignRequest
	if err := decoder.Decode(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request payload"})
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request payload"})
		return
	}

	csrContent := []byte(strings.TrimSpace(request.Csr))
	if len(csrContent) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing csr"})
		return
	}

	var notAfter *time.Time
	if notAfterValue := strings.TrimSpace(request.NotAfter); notAfterValue != "" {
		parsed, parseErr := time.Parse(time.RFC3339Nano, notAfterValue)
		if parseErr != nil {
			httpWrapper.logger.WarnContext(c.Request.Context(), "invalid not_after in request", "not_after", notAfterValue, "err", parseErr)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid not_after"})
			return
		}
		notAfter = &parsed
	}

	remoteAddr := c.Request.RemoteAddr
	authorization := c.GetHeader("Authorization")

	csrFile, err := os.CreateTemp("", "csr-*.pem")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unexpected error in signing CSR (create CSR file)"})
		return
	}
	csrFilename := csrFile.Name()
	defer os.Remove(csrFilename)

	if _, err := csrFile.Write(csrContent); err != nil {
		csrFile.Close()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unexpected error in signing CSR (writing CSR file)"})
		return
	}
	csrFile.Close()

	authorize := func(ctx context.Context, proposedCertificate *x509.Certificate) error {
		opaUrl := httpWrapper.OpaUrlSign
		opaTimeout := httpWrapper.OpaTimeoutSign
		if proposedCertificate.IsCA {
			opaUrl = httpWrapper.OpaUrlIssueCa
			opaTimeout = httpWrapper.OpaTimeoutIssueCa
		}
		return opa.Check(ctx, opaUrl, opaTimeout, map[string]any{
			"runtime":              "http",
			"remote_addr":          remoteAddr,
			"authorization":        authorization,
			"proposed_certificate": caissuingprocess.NewCertificateView(proposedCertificate),
		})
	}

	pemBytes, err := httpWrapper.oneCa.SignCsrFile(c.Request.Context(), csrFilename, notAfter, authorize)
	if err != nil {
		switch {
		case errors.Is(err, opa.ErrNotAuthorized):
			httpWrapper.logger.WarnContext(c.Request.Context(), "authorization denied signing", "err", err)
			c.JSON(http.StatusForbidden, gin.H{"error": "not authorized to sign certificate"})
		case errors.Is(err, opa.ErrUnavailable):
			httpWrapper.logger.ErrorContext(c.Request.Context(), "authorization unavailable for signing", "err", err)
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "unexpected error in authorization check"})
		case errors.Is(err, caissuingprocess.ErrInvalidLifetime):
			httpWrapper.logger.WarnContext(c.Request.Context(), "invalid lifetime requested", "err", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid not_after: not in the future"})
		case errors.Is(err, caissuingprocess.ErrInvalidCsr):
			// The reason is only in the error, and the client is not told
			// which part of its CSR was refused, so it goes in the log.
			httpWrapper.logger.WarnContext(c.Request.Context(), "refused to sign a CSR", "err", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid CSR"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "unexpected error in signing CSR (signing CSR file)"})
		}
		return
	}

	c.Data(http.StatusOK, pemContentType, pemBytes)
}

type crtRevokeRequest struct {
	Certificate string `json:"certificate"`
}

// CrtRevokeCertificate revokes the certificate in the request body. The serial
// is read from that certificate, so the policy is asked about the certificate
// that ends up in the CRL and the client has nothing to name.
func (httpWrapper *httpWrapperType) CrtRevokeCertificate(c *gin.Context) {
	defer c.Request.Body.Close()
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 32*1024)

	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	var request crtRevokeRequest
	if err := decoder.Decode(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request payload"})
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request payload"})
		return
	}

	certificateContent := []byte(strings.TrimSpace(request.Certificate))
	if len(certificateContent) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing certificate"})
		return
	}
	issuedCertificate, err := pemhelper.FromPemToCertificate(certificateContent)
	if err != nil {
		httpWrapper.logger.WarnContext(c.Request.Context(), "refused to revoke: unparseable certificate", "err", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid certificate"})
		return
	}

	httpWrapper.logger.DebugContext(c.Request.Context(), "revoke request by certificate", "serial", issuedCertificate.SerialNumber.String())
	httpWrapper.revoke(c, func(ctx context.Context, authorize caissuingprocess.RevokeAuthorizer) error {
		return httpWrapper.oneCa.RevokeCertificate(ctx, issuedCertificate, authorize)
	})
}

// CrtRevokeSerial revokes the certificate stored under a serial. The serial
// names the file to read, so it is checked against the certificate in it before
// anything is revoked.
func (httpWrapper *httpWrapperType) CrtRevokeSerial(c *gin.Context) {
	crtSerial := c.Param("crtSerial")

	// The guard runs before the parser and the log: a serial too long to
	// exist is refused outright, so neither big.Int nor a log line ever sees
	// it. The client is not told the offending value, only that it is refused.
	if len(crtSerial) > maxRevokeSerialLength {
		c.JSON(http.StatusBadRequest, gin.H{"error": "serial too long"})
		return
	}

	httpWrapper.logger.DebugContext(c.Request.Context(), "revoke request by serial", "serial", crtSerial)

	n := new(big.Int)
	if _, isInt := n.SetString(crtSerial, 10); !isInt {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Errorf("invalid serial %#v", crtSerial).Error()})
		return
	}

	httpWrapper.revoke(c, func(ctx context.Context, authorize caissuingprocess.RevokeAuthorizer) error {
		return httpWrapper.oneCa.RevokeSerial(ctx, n, authorize)
	})
}

// revoke is the part both revoking paths share: asking the policy, and turning
// the answer into a status code. The serial handed to the policy is the one on
// the certificate that was verified, so the policy decides about the same
// certificate the CRL is about to name.
func (httpWrapper *httpWrapperType) revoke(
	c *gin.Context,
	revoke func(ctx context.Context, authorize caissuingprocess.RevokeAuthorizer) error,
) {
	remoteAddr := c.Request.RemoteAddr
	authorization := c.GetHeader("Authorization")

	authorize := func(ctx context.Context, issuedCertificate *x509.Certificate) error {
		return opa.Check(ctx, httpWrapper.OpaUrlRevoke, httpWrapper.OpaTimeoutRevoke, map[string]any{
			"runtime":       "http",
			"remote_addr":   remoteAddr,
			"authorization": authorization,
			"serial":        issuedCertificate.SerialNumber,
			"certificate":   caissuingprocess.NewCertificateView(issuedCertificate),
		})
	}

	if err := revoke(c.Request.Context(), authorize); err != nil {
		switch {
		case errors.Is(err, caissuingprocess.ErrUnknownSerial):
			c.JSON(http.StatusNotFound, gin.H{"error": "certificate serial not found"})
		case errors.Is(err, opa.ErrNotAuthorized):
			httpWrapper.logger.WarnContext(c.Request.Context(), "authorization denied revoking", "err", err)
			c.JSON(http.StatusForbidden, gin.H{"error": "not authorized to revoke certificate"})
		case errors.Is(err, opa.ErrUnavailable):
			httpWrapper.logger.ErrorContext(c.Request.Context(), "authorization unavailable for revoking", "err", err)
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "unexpected error in authorization check"})
		case errors.Is(err, caissuingprocess.ErrCertificateNotIssuedByThisCa),
			errors.Is(err, caissuingprocess.ErrCannotRevokeCaCertificate),
			errors.Is(err, caissuingprocess.ErrRevokeSerialMismatch):
			// The request is well formed and this CA refuses to act on it.
			// The reason is in the error and not in the answer: which
			// certificate is a serial, and which certificate is this CA's
			// own, are not the client's to be told about.
			httpWrapper.logger.WarnContext(c.Request.Context(), "refused to revoke", "err", err)
			c.JSON(http.StatusConflict, gin.H{"error": "certificate cannot be revoked"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "unexpected error in revoking certificate"})
		}
		return
	}

	c.Status(http.StatusAccepted)
}
