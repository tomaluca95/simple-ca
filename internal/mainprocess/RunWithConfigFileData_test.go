package mainprocess_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tomaluca95/simple-ca/internal/mainprocess"
	"github.com/tomaluca95/simple-ca/internal/types"
)

func TestRsaStandardRun(t *testing.T) {
	logger := &types.StdLogger{}

	dataDirectory := t.TempDir()
	caId := "ca_id_1"

	configObject := types.ConfigFileType{
		DataDirectory: dataDirectory,
		AllCaConfigs: map[string]types.CertificateAuthorityType{
			caId: {
				Subject: types.CertificateAuthoritySubjectType{
					CommonName: "test_ca_1",
				},
				KeyConfig: types.KeyConfigType{
					Type: "rsa",
					Config: types.KeyTypeRsaConfigType{
						Size: 2048,
					},
				},
				CrlTtl: 12 * time.Hour,
			},
		},
	}

	if err := mainprocess.RunWithConfigFileData(context.Background(), logger, configObject); err != nil {
		t.Error(err)
		return
	}
}

func TestRsaInvalidDatadir(t *testing.T) {
	logger := &types.StdLogger{}
	dataDirectory := filepath.Join(t.TempDir(), "testinvaliddir")
	if err := os.WriteFile(dataDirectory, []byte{}, os.FileMode(0o644)); err != nil {
		t.Error(err)
		return
	}
	caId := "ca_id_1"

	configObject := types.ConfigFileType{
		DataDirectory: dataDirectory,
		AllCaConfigs: map[string]types.CertificateAuthorityType{
			caId: {
				Subject: types.CertificateAuthoritySubjectType{
					CommonName: "test_ca_1",
				},
				KeyConfig: types.KeyConfigType{
					Type: "rsa",
					Config: types.KeyTypeRsaConfigType{
						Size: 2048,
					},
				},
				CrlTtl: 12 * time.Hour,
			},
		},
	}

	if err := mainprocess.RunWithConfigFileData(context.Background(), logger, configObject); err == nil {
		t.Error("erro expected")
		return
	} else {
		t.Log(err)
	}
}

func TestRsaInvalidCaId(t *testing.T) {
	logger := &types.StdLogger{}
	dataDirectory := t.TempDir()
	caId := "ca.invalid"

	configObject := types.ConfigFileType{
		DataDirectory: dataDirectory,
		AllCaConfigs: map[string]types.CertificateAuthorityType{
			caId: {
				Subject: types.CertificateAuthoritySubjectType{
					CommonName: "test_ca_1",
				},
				KeyConfig: types.KeyConfigType{
					Type: "rsa",
					Config: types.KeyTypeRsaConfigType{
						Size: 2048,
					},
				},
				CrlTtl: 12 * time.Hour,
			},
		},
	}

	if err := mainprocess.RunWithConfigFileData(context.Background(), logger, configObject); err == nil {
		t.Error("erro expected")
		return
	} else {
		t.Log(err)
	}
}
