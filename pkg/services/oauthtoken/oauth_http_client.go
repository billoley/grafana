package oauthtoken

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/grafana/grafana/pkg/setting"
	"io/ioutil"
	"net/http"
)

func GetOAuthHttpClient(name string) (*http.Client, error) {
	info, ok := setting.OAuthService.OAuthInfos[name]
	if !ok {
		return nil, fmt.Errorf("Could not find %s in OAuth Settings", name)
	}

	// handle call back
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: info.TlsSkipVerify,
		},
	}
	oauthClient := &http.Client{
		Transport: tr,
	}

	if info.TlsClientCert != "" || info.TlsClientKey != "" {
		cert, err := tls.LoadX509KeyPair(info.TlsClientCert, info.TlsClientKey)
		if err != nil {
			return nil, fmt.Errorf("Failed to setup TlsClientCert error: %s", err)
		}

		tr.TLSClientConfig.Certificates = append(tr.TLSClientConfig.Certificates, cert)
	}

	if info.TlsClientCa != "" {
		caCert, err := ioutil.ReadFile(info.TlsClientCa)
		if err != nil {
			return nil, fmt.Errorf("Failed to setup TlsClientCa error: %s", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tr.TLSClientConfig.RootCAs = caCertPool
	}
	return oauthClient, nil
}
