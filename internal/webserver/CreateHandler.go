package webserver

import (
	"context"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tomaluca95/simple-ca/internal/caissuingprocess"
	"github.com/tomaluca95/simple-ca/internal/types"
)

func CreateHandler(
	ctx context.Context,
	configFile types.ConfigFileType,
) (http.Handler, error) {
	httpHandler := gin.New()
	httpHandler.Use(gin.Logger())
	httpHandler.Use(gin.Recovery())

	for caId, caConfig := range configFile.AllCaConfigs {
		if caConfig.HttpServerOptions != nil {
			oneCa, err := caissuingprocess.LoadOneCa(
				ctx,
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
			}

			caHttpGroup := httpHandler.Group(
				"/ca/"+caId,
				gin.BasicAuth(
					gin.Accounts(caConfig.HttpServerOptions.Users),
				),
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

	csrFilename := filepath.Join(os.TempDir(), fmt.Sprint(time.Now().Unix()))
	defer os.Remove(csrFilename)

	if err := os.WriteFile(csrFilename, csrContent, os.FileMode(0o644)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	pemBytes, err := httpWrapper.oneCa.SignCsrFile(csrFilename)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Writer.Write(pemBytes)
}

func (httpWrapper *httpWrapperType) CrtRevokeCrtSerial(c *gin.Context) {
	crtSerial := c.Param("crtSerial")
	log.Println("Request revoking: " + crtSerial)

	n := new(big.Int)
	if _, isInt := n.SetString(crtSerial, 10); !isInt {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Errorf("invalid serial %#v", crtSerial).Error()})
		return
	}

	if err := httpWrapper.oneCa.RevokeOneSerial(n); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.Status(http.StatusAccepted)
}
