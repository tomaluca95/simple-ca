package pemhelper_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"testing"

	"github.com/tomaluca95/simple-ca/internal/pemhelper"
)

func TestMakePemFromNil(t *testing.T) {
	outputBytes, err := pemhelper.ToPem(nil)
	if err != nil {
		if !errors.Is(err, pemhelper.ErrPemInvalidObject) {
			t.Error(err)
		}
	} else if outputBytes != nil {
		t.Errorf("found bytes from invalid obect")
	} else {
		t.Errorf("invalid result data")
	}
}

func TestMakePemFromString(t *testing.T) {
	outputBytes, err := pemhelper.ToPem("TESTME")
	if err != nil {
		if !errors.Is(err, pemhelper.ErrPemInvalidObject) {
			t.Error(err)
		}
	} else if outputBytes != nil {
		t.Errorf("found bytes from invalid obect")
	} else {
		t.Errorf("invalid result data")
	}
}

func TestMakePemFromCertificate(t *testing.T) {
	expectedPem := `-----BEGIN CERTIFICATE-----
-----END CERTIFICATE-----
`
	outputBytes, err := pemhelper.ToPem(x509.Certificate{})
	if err != nil {
		t.Error(err)
	} else if string(outputBytes) == expectedPem {

	} else {
		t.Errorf("%#v != %#v", string(outputBytes), expectedPem)
	}
}
func TestMakePemFromPtrCertificate(t *testing.T) {
	expectedPem := `-----BEGIN CERTIFICATE-----
-----END CERTIFICATE-----
`
	outputBytes, err := pemhelper.ToPem(&x509.Certificate{})
	if err != nil {
		t.Error(err)
	} else if string(outputBytes) == expectedPem {

	} else {
		t.Errorf("%#v != %#v", string(outputBytes), expectedPem)
	}
}

func TestMakePemFromPrivateKey(t *testing.T) {
	var pk rsa.PrivateKey
	pkJson := `{
		"N":25525256352543118112066061231360906633773132181085424640658822321176083632993570267232732531628014652750382096205372478950085493371389175133122566773330573253435291089055507605723043270194414398919567126820848455124944467587611113285972391586006794946032696691584999562328030770846851061510123117380400411690408336736236752256915216485384710284762300278592033714996369089680610926751016085170097254158324714732299713813079849969841093162930370652969796119679174436243074292420910693419552694069323747908606421214960135710293324634125071272949423180501407857136599354256826500534674903982403094992810527051252842312979,
		"E":65537,
		"D":2770360993570642524545308658294858307307754233548386796298368908716076153645776665255144826547905278316271233811569257713535226121895893964049328126992391588746589339097789425813021755357933222752260264782896608958355280192115565997880916449505871987596786114214018064403913558341603240925301825440999559460329064034596003172992215424335204304470503477247778803729402265750813539277914574114140678535666902323068696874661652218427737951370809981116052373033953654236761474982578566541460779340840518144615907828102511157867751496223137370853959892494345734190310610837913202189953674100351966247612627561109043734689,
		"Primes":[
			142008498161137455966163872308299329547903312540430452781216154473667500540889753690890981623040064837730905633305066037891196060428228107992507517073465176241406342649771340671933935674610943263929533379238027429955667932850082341541259862326024584082239526155185142845903455840073678262490121481736270162083,
			179744569395977524358187680606808185344667402100010479983487492986914335298178145943084010593487689744568360116411828577092781663307882214258502665374411546278254933331767566521312685618013094586516793454960928222249813342920461464283747533780340902517260643160784119965870570943571253934061615681648809007313
		],
		"Precomputed":{
			"Dp":115650999776529127626868247809799962097139684456419954472921400319255619060514042811601452037269288807608093540540325154345893271483830794938494342261044247547684220001621156990450126627111553394658147077987567908494802395288271431635284841111538674736734519881604233167743490677819436805222778794340753274651,
			"Dq":119974158775312278949670596769217652009050320238382264009607960285328603434449315899938461623228489253191301782692510021458819309393777554366601165664254675685429357518117100720330532671229455263325916854506780050263146541231863928675835819730644253470788250521466355551627969778225749303318603481667538966017,
			"Qinv":28452530849348197449941974995531288672021013323588892466511896225967617134045378478865367433374326074150696298422939932034982494054625617109263577677671756770325185225197813443683198973272731049236161357318380174611036103400212738164998235482119426965180283725093628604951078911008395723592881147664410643246
		},
		"CRTValues":[]
	}`
	if err := json.Unmarshal([]byte(pkJson), &pk); err != nil {
		t.Error(err)
		return
	}

	expectedPem := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAyjLwRrNo6wOcbHt4THbtujYCkxXdTSQT91WTFTkb/ZqxFAnM\nbQ0Ca0cqXmuUzTqouJrT1eFjsaViqVxtsJIYkZRUVQKMxlAPg9TKndAytA7vQ3En\ndqRNmAgSUBnp4DWhHJVIC2eg/Fcn90qYXKprFkCQDyqipbJe2cm4hKfplQUT//Ej\nGvLExETP+pdovYs/UBO9qiBZ+cEqTXIdy1EtPR2UpI1PIa6KoScCw3qQ4OKIOzUU\nTfVxfulSq5q3Q7wD4VxZryTZ4p5uYhZyxHnfrzsnnc3RwgBzGSfWxasrEwMIyn9G\n+VWh1CgcaW/2D8ooRnT5X+o+UlK84pCalH81EwIDAQABAoIBABXyC2QRCt0fCjY3\n/GmIKusf+42NPPSnasdYcVtHVINk6706Bwb6930/Pxj6Yi8YI8HNhBpdmR1pztiE\n4J7ebG44hCKp4S+Q9u4fBVK1ixtB17QhLuBQmt9aWOp6tYiRKYhZp3UdbTqWFw9e\n+ERudqr2nOwYe4iyYFsQ6sbzFoYG0lbzW6FktaHkIELoBD0zzOu7+zkgws0pWCW/\nbSDE1N6rhzuHKwTCNy+eYjWW0/2N+nFycaku2d0XSjqF4/lAe0yAvtJaNeVPUoyN\nwY98sbjeIMjKgVqIFp0qk3REOIjauVBRkCeknQlkbprY66azqRKfv5KmVZhhpgw9\n+4jW6KECgYEAyjoQfDaIEFEx6kKawW7RWVLudaQEUJ+/ZAKW2+j/ms0fPsCrkkoi\nhd9vUpWC1iZ8UV3AnvBP7k1eOXvnZRoAMczOwAxOt0B3DupVYlpPX7qqlOThMQKJ\nFUl7vo5SsE9yr5WgOnpmgDhmVotpo59WAyYDdJiIS/9F8puXbaQ8qKMCgYEA//b6\nuV1Crr3MdWQw8UKPWm9GW6uzvSBqv2EBhQkCg5djghWbLT4lsyLoPti9sSQRfi7M\nIJX0AYWlwXv+9HmLSSMgrm9edUjjwICiABD4+C3d7dpikDobFOvhxR60MLqXytzh\nDBevlWzqn0aFo2U2pT4R68TnEP+dhzshoweQ2NECgYEApLFHDbHne8p0aUEXAaN7\nkVBt7ZbHANYoq41ESRJnYC3fXV7SG9CObxJ5eftTU46CPk2o+ofhwMR3kT8sQvU6\n5VPTqSoczTcN/zKumOvNqru+AoaoMx7Kf3CZ+6WzB+2cDA1CMX3PjmrgRWlCfkPc\na7IArGswzRu3Xo6Cc4OG9xsCgYEAqtlPwSpeuAQ31KNrh53F0bc0XzvcXQCmP9eg\nDAxXgT4rTUjeqvQwdcF3A3voIbTReEgEODvfAqUSXnNFWilGryqjRctQYTilzHgP\nqbuqcv0qhPifkWU3bl+D8u7rlxr09pM4I7ormLF6aZXI3adRMjqb+6MSGGaF3x24\n9fi21gECgYAohIswid6AcGGVTHLL9qEEP6mozowL1eGbdLIGEJ8WVJ/XIjw3JWWU\n7exRV6zKAnGzv7p7p7rrssgPfekGHCcN6sau+GZQutxzFiBpnng/gAjRF5ggvQKq\ndj1LlYeOI3+/93Yki0kvcgOaTlXqPZKrmQOZskcHz+eYvb0NG/yLLg==\n-----END RSA PRIVATE KEY-----\n"

	outputBytes, err := pemhelper.ToPem(pk)
	if err != nil {
		t.Error(err)
	} else if string(outputBytes) == expectedPem {

	} else {
		t.Errorf("%#v != %#v", string(outputBytes), expectedPem)
	}
}

func TestMakePemFromPtrPrivateKey(t *testing.T) {
	var pk rsa.PrivateKey
	pkJson := `{
		"N":25525256352543118112066061231360906633773132181085424640658822321176083632993570267232732531628014652750382096205372478950085493371389175133122566773330573253435291089055507605723043270194414398919567126820848455124944467587611113285972391586006794946032696691584999562328030770846851061510123117380400411690408336736236752256915216485384710284762300278592033714996369089680610926751016085170097254158324714732299713813079849969841093162930370652969796119679174436243074292420910693419552694069323747908606421214960135710293324634125071272949423180501407857136599354256826500534674903982403094992810527051252842312979,
		"E":65537,
		"D":2770360993570642524545308658294858307307754233548386796298368908716076153645776665255144826547905278316271233811569257713535226121895893964049328126992391588746589339097789425813021755357933222752260264782896608958355280192115565997880916449505871987596786114214018064403913558341603240925301825440999559460329064034596003172992215424335204304470503477247778803729402265750813539277914574114140678535666902323068696874661652218427737951370809981116052373033953654236761474982578566541460779340840518144615907828102511157867751496223137370853959892494345734190310610837913202189953674100351966247612627561109043734689,
		"Primes":[
			142008498161137455966163872308299329547903312540430452781216154473667500540889753690890981623040064837730905633305066037891196060428228107992507517073465176241406342649771340671933935674610943263929533379238027429955667932850082341541259862326024584082239526155185142845903455840073678262490121481736270162083,
			179744569395977524358187680606808185344667402100010479983487492986914335298178145943084010593487689744568360116411828577092781663307882214258502665374411546278254933331767566521312685618013094586516793454960928222249813342920461464283747533780340902517260643160784119965870570943571253934061615681648809007313
		],
		"Precomputed":{
			"Dp":115650999776529127626868247809799962097139684456419954472921400319255619060514042811601452037269288807608093540540325154345893271483830794938494342261044247547684220001621156990450126627111553394658147077987567908494802395288271431635284841111538674736734519881604233167743490677819436805222778794340753274651,
			"Dq":119974158775312278949670596769217652009050320238382264009607960285328603434449315899938461623228489253191301782692510021458819309393777554366601165664254675685429357518117100720330532671229455263325916854506780050263146541231863928675835819730644253470788250521466355551627969778225749303318603481667538966017,
			"Qinv":28452530849348197449941974995531288672021013323588892466511896225967617134045378478865367433374326074150696298422939932034982494054625617109263577677671756770325185225197813443683198973272731049236161357318380174611036103400212738164998235482119426965180283725093628604951078911008395723592881147664410643246
		},
		"CRTValues":[]
	}`
	if err := json.Unmarshal([]byte(pkJson), &pk); err != nil {
		t.Error(err)
		return
	}

	expectedPem := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAyjLwRrNo6wOcbHt4THbtujYCkxXdTSQT91WTFTkb/ZqxFAnM\nbQ0Ca0cqXmuUzTqouJrT1eFjsaViqVxtsJIYkZRUVQKMxlAPg9TKndAytA7vQ3En\ndqRNmAgSUBnp4DWhHJVIC2eg/Fcn90qYXKprFkCQDyqipbJe2cm4hKfplQUT//Ej\nGvLExETP+pdovYs/UBO9qiBZ+cEqTXIdy1EtPR2UpI1PIa6KoScCw3qQ4OKIOzUU\nTfVxfulSq5q3Q7wD4VxZryTZ4p5uYhZyxHnfrzsnnc3RwgBzGSfWxasrEwMIyn9G\n+VWh1CgcaW/2D8ooRnT5X+o+UlK84pCalH81EwIDAQABAoIBABXyC2QRCt0fCjY3\n/GmIKusf+42NPPSnasdYcVtHVINk6706Bwb6930/Pxj6Yi8YI8HNhBpdmR1pztiE\n4J7ebG44hCKp4S+Q9u4fBVK1ixtB17QhLuBQmt9aWOp6tYiRKYhZp3UdbTqWFw9e\n+ERudqr2nOwYe4iyYFsQ6sbzFoYG0lbzW6FktaHkIELoBD0zzOu7+zkgws0pWCW/\nbSDE1N6rhzuHKwTCNy+eYjWW0/2N+nFycaku2d0XSjqF4/lAe0yAvtJaNeVPUoyN\nwY98sbjeIMjKgVqIFp0qk3REOIjauVBRkCeknQlkbprY66azqRKfv5KmVZhhpgw9\n+4jW6KECgYEAyjoQfDaIEFEx6kKawW7RWVLudaQEUJ+/ZAKW2+j/ms0fPsCrkkoi\nhd9vUpWC1iZ8UV3AnvBP7k1eOXvnZRoAMczOwAxOt0B3DupVYlpPX7qqlOThMQKJ\nFUl7vo5SsE9yr5WgOnpmgDhmVotpo59WAyYDdJiIS/9F8puXbaQ8qKMCgYEA//b6\nuV1Crr3MdWQw8UKPWm9GW6uzvSBqv2EBhQkCg5djghWbLT4lsyLoPti9sSQRfi7M\nIJX0AYWlwXv+9HmLSSMgrm9edUjjwICiABD4+C3d7dpikDobFOvhxR60MLqXytzh\nDBevlWzqn0aFo2U2pT4R68TnEP+dhzshoweQ2NECgYEApLFHDbHne8p0aUEXAaN7\nkVBt7ZbHANYoq41ESRJnYC3fXV7SG9CObxJ5eftTU46CPk2o+ofhwMR3kT8sQvU6\n5VPTqSoczTcN/zKumOvNqru+AoaoMx7Kf3CZ+6WzB+2cDA1CMX3PjmrgRWlCfkPc\na7IArGswzRu3Xo6Cc4OG9xsCgYEAqtlPwSpeuAQ31KNrh53F0bc0XzvcXQCmP9eg\nDAxXgT4rTUjeqvQwdcF3A3voIbTReEgEODvfAqUSXnNFWilGryqjRctQYTilzHgP\nqbuqcv0qhPifkWU3bl+D8u7rlxr09pM4I7ormLF6aZXI3adRMjqb+6MSGGaF3x24\n9fi21gECgYAohIswid6AcGGVTHLL9qEEP6mozowL1eGbdLIGEJ8WVJ/XIjw3JWWU\n7exRV6zKAnGzv7p7p7rrssgPfekGHCcN6sau+GZQutxzFiBpnng/gAjRF5ggvQKq\ndj1LlYeOI3+/93Yki0kvcgOaTlXqPZKrmQOZskcHz+eYvb0NG/yLLg==\n-----END RSA PRIVATE KEY-----\n"

	outputBytes, err := pemhelper.ToPem(&pk)
	if err != nil {
		t.Error(err)
	} else if string(outputBytes) == expectedPem {

	} else {
		t.Errorf("%#v != %#v", string(outputBytes), expectedPem)
	}
}
