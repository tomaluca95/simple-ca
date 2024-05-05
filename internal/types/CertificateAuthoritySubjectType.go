package types

type CertificateAuthoritySubjectType struct {
	CommonName string `yaml:"common_name"`

	Country            []string `yaml:"country"`
	Organization       []string `yaml:"organization"`
	OrganizationalUnit []string `yaml:"organizational_unit"`
	Locality           []string `yaml:"locality"`
	Province           []string `yaml:"province"`
	StreetAddress      []string `yaml:"street_address"`
	PostalCode         []string `yaml:"postal_code"`
}
