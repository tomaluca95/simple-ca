package webserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/tomaluca95/simple-ca/internal/caissuingprocess"
	"github.com/tomaluca95/simple-ca/internal/types"
)

func CreateHandler(
	ctx context.Context,
	logger types.Logger,
	configFile types.ConfigFileType,
) (http.Handler, error) {
	httpHandler := gin.New()
	httpHandler.Use(gin.Logger())
	httpHandler.Use(gin.Recovery())

	for caId, caConfig := range configFile.AllCaConfigs {
		missingConfig := []string{}
		if caConfig.OpaUrlSign == nil || strings.TrimSpace(*caConfig.OpaUrlSign) == "" {
			missingConfig = append(missingConfig, "opa_url_sign")
		}
		if caConfig.OpaUrlRevoke == nil || strings.TrimSpace(*caConfig.OpaUrlRevoke) == "" {
			missingConfig = append(missingConfig, "opa_url_revoke")
		}
		if len(missingConfig) > 0 {
			return nil, fmt.Errorf(
				"missing OPA URL configuration for CA %q: %s",
				caId,
				strings.Join(missingConfig, ", "),
			)
		}

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
		httpWrapper := &httpWrapperType{
			caId:  caId,
			oneCa: oneCa,

			OpaUrlSign:   *caConfig.OpaUrlSign,
			OpaUrlRevoke: *caConfig.OpaUrlRevoke,

			logger: logger,
		}

		caHttpGroup := httpHandler.Group(
			"/ca/" + caId,
		)

		caHttpGroup.GET("/issuer.pem", httpWrapper.Issuer)
		caHttpGroup.POST("/csr/sign", httpWrapper.CsrSign)
		caHttpGroup.POST("/crt/revoke/:crtSerial", httpWrapper.CrtRevokeCrtSerial)
		caHttpGroup.GET("/crt/crl.pem", httpWrapper.CrtCrlPem)
	}

	return httpHandler, nil
}

type httpWrapperType struct {
	caId  string
	oneCa *caissuingprocess.OneCaType

	OpaUrlSign   string
	OpaUrlRevoke string

	logger types.Logger
}

func (httpWrapper *httpWrapperType) Issuer(c *gin.Context) {
	fileContent, err := httpWrapper.oneCa.GetIssuerPem()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unexpected error in getting issuer"})
		return
	}
	c.Writer.Write(fileContent)
}

func (httpWrapper *httpWrapperType) CrtCrlPem(c *gin.Context) {
	fileContent, err := httpWrapper.oneCa.GetCrlPem()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unexpected error in signing CRL (get CRL file)"})
		return
	}
	c.Writer.Write(fileContent)
}

func (httpWrapper *httpWrapperType) CsrSign(c *gin.Context) {
	defer c.Request.Body.Close()
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 32*1024)
	csrContent, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unexpected error in signing CSR (reading CSR content)"})
		return
	}

	if err := httpWrapper.opaWrapper(c.Request.Context(), httpWrapper.OpaUrlSign, map[string]string{
		"remote_addr":   c.Request.RemoteAddr,
		"authorization": c.GetHeader("Authorization"),
		"csr_content":   string(csrContent),
	}); err != nil {
		if errors.Is(err, ErrNotAuthorized) {
			httpWrapper.logger.Debug("OPA denied the sign request: %v", err)
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
			return
		} else {
			httpWrapper.logger.Debug("Unexpected error: %v", err)
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "unexpected error in authorization check"})
			return
		}
	}

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

	pemBytes, err := httpWrapper.oneCa.SignCsrFile(csrFilename)
	if err != nil {
		if errors.Is(err, caissuingprocess.ErrInvalidCsr) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid CSR"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unexpected error in signing CSR (signing CSR file)"})
		return
	}

	c.Writer.Write(pemBytes)
}

func (httpWrapper *httpWrapperType) CrtRevokeCrtSerial(c *gin.Context) {
	crtSerial := c.Param("crtSerial")
	httpWrapper.logger.Debug("Request revoking: %s", crtSerial)

	n := new(big.Int)
	if _, isInt := n.SetString(crtSerial, 10); !isInt {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Errorf("invalid serial %#v", crtSerial).Error()})
		return
	}

	if err := httpWrapper.opaWrapper(c.Request.Context(), httpWrapper.OpaUrlRevoke, map[string]string{
		"remote_addr":   c.Request.RemoteAddr,
		"authorization": c.GetHeader("Authorization"),
		"serial":        crtSerial,
	}); err != nil {
		if errors.Is(err, ErrNotAuthorized) {
			httpWrapper.logger.Debug("OPA denied the revoke request: %v", err)
			c.JSON(http.StatusForbidden, gin.H{"error": "not authorized to revoke certificate"})
			return
		} else {
			httpWrapper.logger.Debug("Unexpected error: %v", err)
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "unexpected error in authorization check"})
			return
		}
	}

	if err := httpWrapper.oneCa.RevokeOneSerial(n); err != nil {
		if errors.Is(err, caissuingprocess.ErrUnknownSerial) {
			c.JSON(http.StatusNotFound, gin.H{"error": "certificate serial not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unexpected error in revoking certificate"})
		return
	}

	c.Status(http.StatusAccepted)
}
