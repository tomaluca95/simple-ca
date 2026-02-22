package webserver

import (
	"context"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"

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
		if caConfig.OpaUrlSign != nil && caConfig.OpaUrlRevoke != nil {
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Writer.Write(fileContent)
}

func (httpWrapper *httpWrapperType) CrtCrlPem(c *gin.Context) {
	fileContent, err := httpWrapper.oneCa.GetCrlPem()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Writer.Write(fileContent)
}

func (httpWrapper *httpWrapperType) CsrSign(c *gin.Context) {
	defer c.Request.Body.Close()
	csrContent, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := httpWrapper.opaWrapper(httpWrapper.OpaUrlSign, map[string]string{
		"remote_addr":   c.Request.RemoteAddr,
		"authorization": c.GetHeader("Authorization"),
		"csr_content":   string(csrContent),
	}); err != nil {
		httpWrapper.logger.Debug("OPA denied the sign request: %v", err)
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}

	csrFile, err := os.CreateTemp("", "csr-*.pem")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	csrFilename := csrFile.Name()
	defer os.Remove(csrFilename)

	if _, err := csrFile.Write(csrContent); err != nil {
		csrFile.Close()
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	csrFile.Close()

	pemBytes, err := httpWrapper.oneCa.SignCsrFile(csrFilename)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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

	if err := httpWrapper.opaWrapper(httpWrapper.OpaUrlRevoke, map[string]string{
		"remote_addr":   c.Request.RemoteAddr,
		"authorization": c.GetHeader("Authorization"),
		"serial":        crtSerial,
	}); err != nil {
		httpWrapper.logger.Debug("OPA denied the revoke request: %v", err)
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}

	if err := httpWrapper.oneCa.RevokeOneSerial(n); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.Status(http.StatusAccepted)
}
