package chainer

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
)

type CertificateChain struct {
	Url          string        `json:"url"`
	Certificates []Certificate `json:"certificates"`
}

type Certificate struct {
	SubjectCommonName    string `json:"subjectCommonName"`
	IssuerCommonName     string `json:"issuerCommonName"`
	CertificateAuthority bool   `json:"certificateAuthority"`
	SignatureAlgorithm   string `json:"signatureAlgorithm"`
}

func GrabCertChain(url string, followRedirects bool) *CertificateChain {
	peerCerts, err := grabPeerCertificates(url, followRedirects)
	if err != nil {
		return &CertificateChain{Url: url}
	}

	var certificates []Certificate

	for _, cert := range peerCerts {

		certificates = append(certificates, Certificate{
			SubjectCommonName:    cert.Subject.CommonName,
			IssuerCommonName:     cert.Issuer.CommonName,
			CertificateAuthority: cert.IsCA,
			SignatureAlgorithm:   cert.SignatureAlgorithm.String(),
		})
	}

	return &CertificateChain{
		Url:          url,
		Certificates: certificates,
	}
}

func grabPeerCertificates(url string, followRedirects bool) ([]*x509.Certificate, error) {
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}

	client := http.Client{
		Transport: transport,
	}

	if followRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("Error occured when initializing HTTP Client: %s\n", err)
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error occured when making HTTP request: %s\n", err)
		return nil, err
	}

	return resp.TLS.PeerCertificates, nil
}
