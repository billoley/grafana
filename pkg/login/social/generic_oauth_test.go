package social

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/stretchr/testify/require"

	"testing"

	"github.com/grafana/grafana/pkg/infra/log"
	"golang.org/x/oauth2"
)

func TestSearchJSONForEmail(t *testing.T) {
	t.Run("Given a generic OAuth provider", func(t *testing.T) {
		provider := SocialGenericOAuth{
			SocialBase: &SocialBase{
				log: log.New("generic_oauth_test"),
			},
		}

		tests := []struct {
			Name                 string
			UserInfoJSONResponse []byte
			EmailAttributePath   string
			ExpectedResult       string
			ExpectedError        string
		}{
			{
				Name:                 "Given an invalid user info JSON response",
				UserInfoJSONResponse: []byte("{"),
				EmailAttributePath:   "attributes.email",
				ExpectedResult:       "",
				ExpectedError:        "failed to unmarshal user info JSON response: unexpected end of JSON input",
			},
			{
				Name:                 "Given an empty user info JSON response and empty JMES path",
				UserInfoJSONResponse: []byte{},
				EmailAttributePath:   "",
				ExpectedResult:       "",
				ExpectedError:        "no attribute path specified",
			},
			{
				Name:                 "Given an empty user info JSON response and valid JMES path",
				UserInfoJSONResponse: []byte{},
				EmailAttributePath:   "attributes.email",
				ExpectedResult:       "",
				ExpectedError:        "empty user info JSON response provided",
			},
			{
				Name: "Given a simple user info JSON response and valid JMES path",
				UserInfoJSONResponse: []byte(`{
	"attributes": {
		"email": "grafana@localhost"
	}
}`),
				EmailAttributePath: "attributes.email",
				ExpectedResult:     "grafana@localhost",
			},
			{
				Name: "Given a user info JSON response with e-mails array and valid JMES path",
				UserInfoJSONResponse: []byte(`{
	"attributes": {
		"emails": ["grafana@localhost", "admin@localhost"]
	}
}`),
				EmailAttributePath: "attributes.emails[0]",
				ExpectedResult:     "grafana@localhost",
			},
			{
				Name: "Given a nested user info JSON response and valid JMES path",
				UserInfoJSONResponse: []byte(`{
	"identities": [
		{
			"userId": "grafana@localhost"
		},
		{
			"userId": "admin@localhost"
		}
	]
}`),
				EmailAttributePath: "identities[0].userId",
				ExpectedResult:     "grafana@localhost",
			},
		}

		for _, test := range tests {
			provider.emailAttributePath = test.EmailAttributePath
			t.Run(test.Name, func(t *testing.T) {
				actualResult, err := provider.searchJSONForAttr(test.EmailAttributePath, test.UserInfoJSONResponse)
				if test.ExpectedError == "" {
					require.NoError(t, err, "Testing case %q", test.Name)
				} else {
					require.EqualError(t, err, test.ExpectedError, "Testing case %q", test.Name)
				}
				require.Equal(t, test.ExpectedResult, actualResult)
			})
		}
	})
}

func TestSearchJSONForRole(t *testing.T) {
	t.Run("Given a generic OAuth provider", func(t *testing.T) {
		provider := SocialGenericOAuth{
			SocialBase: &SocialBase{
				log: log.New("generic_oauth_test"),
			},
		}

		tests := []struct {
			Name                 string
			UserInfoJSONResponse []byte
			RoleAttributePath    string
			ExpectedResult       string
			ExpectedError        string
		}{
			{
				Name:                 "Given an invalid user info JSON response",
				UserInfoJSONResponse: []byte("{"),
				RoleAttributePath:    "attributes.role",
				ExpectedResult:       "",
				ExpectedError:        "failed to unmarshal user info JSON response: unexpected end of JSON input",
			},
			{
				Name:                 "Given an empty user info JSON response and empty JMES path",
				UserInfoJSONResponse: []byte{},
				RoleAttributePath:    "",
				ExpectedResult:       "",
				ExpectedError:        "no attribute path specified",
			},
			{
				Name:                 "Given an empty user info JSON response and valid JMES path",
				UserInfoJSONResponse: []byte{},
				RoleAttributePath:    "attributes.role",
				ExpectedResult:       "",
				ExpectedError:        "empty user info JSON response provided",
			},
			{
				Name: "Given a simple user info JSON response and valid JMES path",
				UserInfoJSONResponse: []byte(`{
	"attributes": {
		"role": "admin"
	}
}`),
				RoleAttributePath: "attributes.role",
				ExpectedResult:    "admin",
			},
		}

		for _, test := range tests {
			provider.roleAttributePath = test.RoleAttributePath
			t.Run(test.Name, func(t *testing.T) {
				actualResult, err := provider.searchJSONForAttr(test.RoleAttributePath, test.UserInfoJSONResponse)
				if test.ExpectedError == "" {
					require.NoError(t, err, "Testing case %q", test.Name)
				} else {
					require.EqualError(t, err, test.ExpectedError, "Testing case %q", test.Name)
				}
				require.Equal(t, test.ExpectedResult, actualResult)
			})
		}
	})
}

func TestUserInfoSearchesForEmailAndRole(t *testing.T) {
	t.Run("Given a generic OAuth provider", func(t *testing.T) {
		provider := SocialGenericOAuth{
			SocialBase: &SocialBase{
				log: log.New("generic_oauth_test"),
			},
			emailAttributePath: "email",
		}

		tests := []struct {
			Name              string
			APIURLResponse    interface{}
			OAuth2Extra       interface{}
			RoleAttributePath string
			ExpectedEmail     string
			ExpectedRole      string
		}{
			{
				Name: "Given a valid id_token with no role, a valid role path, a valid api response with no email, merge",
				OAuth2Extra: map[string]interface{}{
					// { "email": "john.doe@example.com" }
					"id_token": "eyJhbGciOiJSUzUxMiIsInppcCI6IkdaSVAifQ.H4sIAAAAAAAAAM1U32_aMBD-VyI_pw-tyARomeQkBJhWqCC0D1NUmeAOTyaObGddi_jfd5c4NEJ95GEPzt33-Xy-X86RmHpLxqQow1chpWAH79VTkr_5nqrDrVLvHpOSl96eHYS0qgT-c7oIa_P1Om6-EZ-wegdhJTSjT_RxAoQwBoh4EUpVMLlXxvrechNabqwof_leDAfBjP-tyPg2GA1Gd8NhEPik0qIsRMUkHP95JLuSjI-Y9G9e2GRxtdTbCGuur-nz5JPacJ29VRycbtaTVVMZu8dcSPL07Kjv0XK9fqbJ_XwBCPhOTZdL-EYUjZJJCt-HTfRjHqOymj_SDCtL0QQWsgks5NB0CmsGa05yn2jIormVwvVKi3e-20BozeXKGLo7iFIYq5lVSF7iVKkVeMCbmHZawl-c9lBvpSg6oMUfZrlDKKiTkZOxk4mTEydTJ6dOzpw8J5ApjP6eVRWMDM5BuwtZNSbtGUCzDk0RTRFdpN0rf_6RE7BY67wLB3CKqJcfUK4F-aelg_1-N_PLUrYXnzf7xULXrql5VxjgzihpDncoRhR3KGpi7xBtGo2o6xtmArOUf3QNfcFE5TCjhebMClVm4sDbxzcc3A2CIBh9aR6k0L3tm1uflAy1_-2nc8pP_wCNwmogDwUAAA.FT0YsBNTb6EwstD3LaZbP1k0zBJUrJ-2ycm9pyHLQNVV6ilkwrg0KzjGu6S-eux8yLDPaIAriA8iYX346j43Vg2u-pE9r8cvsjE3ijbjCzLa5lq-MvZuvqbgXKloscIAqDscXjw4_c6N5cFNxPn99Cdszd9J6KTOJiSuzvqmBlfH7zwO_ZJPMPjYAu7ZYy_rsBA-FV36v4O13mSTLapG4lTsme6LGazcsm6sAMkx41ZRtmH-Cxln3darGTZZY8akFzEfyNU1AEjZcOuWCftKxDYPpttDxvOfPVc9M7aT2rpwW6KfsN7Dg2yo1Dt-UVh23ocVuVOQUYiWRgxrod__7Q",
				},
				APIURLReponse: map[string]interface{}{
					"role": "FromResponse",
				},
				RoleAttributePath: "role",
				ExpectedEmail:     "john.doe@example.com",
				ExpectedRole:      "FromResponse",
			},
			{
				Name: "Given a valid id_token, a valid role path, no api response, use id_token",
				OAuth2Extra: map[string]interface{}{
					// { "role": "Admin", "email": "john.doe@example.com" }
					"id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiQWRtaW4iLCJlbWFpbCI6ImpvaG4uZG9lQGV4YW1wbGUuY29tIn0.9PtHcCaXxZa2HDlASyKIaFGfOKlw2ILQo32xlvhvhRg",
				},
				RoleAttributePath: "role",
				ExpectedEmail:     "john.doe@example.com",
				ExpectedRole:      "Admin",
			},
			{
				Name: "Given a valid id_token, no role path, no api response, use id_token",
				OAuth2Extra: map[string]interface{}{
					// { "email": "john.doe@example.com" }
					"id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImpvaG4uZG9lQGV4YW1wbGUuY29tIn0.k5GwPcZvGe2BE_jgwN0ntz0nz4KlYhEd0hRRLApkTJ4",
				},
				RoleAttributePath: "",
				ExpectedEmail:     "john.doe@example.com",
				ExpectedRole:      "",
			},
			{
				Name: "Given a valid id_token, an invalid role path, no api response, use id_token",
				OAuth2Extra: map[string]interface{}{
					// { "role": "Admin", "email": "john.doe@example.com" }
					"id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiQWRtaW4iLCJlbWFpbCI6ImpvaG4uZG9lQGV4YW1wbGUuY29tIn0.9PtHcCaXxZa2HDlASyKIaFGfOKlw2ILQo32xlvhvhRg",
				},
				RoleAttributePath: "invalid_path",
				ExpectedEmail:     "john.doe@example.com",
				ExpectedRole:      "",
			},
			{
				Name: "Given no id_token, a valid role path, a valid api response, use api response",
				APIURLResponse: map[string]interface{}{
					"role":  "Admin",
					"email": "john.doe@example.com",
				},
				RoleAttributePath: "role",
				ExpectedEmail:     "john.doe@example.com",
				ExpectedRole:      "Admin",
			},
			{
				Name: "Given no id_token, no role path, a valid api response, use api response",
				APIURLResponse: map[string]interface{}{
					"email": "john.doe@example.com",
				},
				RoleAttributePath: "",
				ExpectedEmail:     "john.doe@example.com",
				ExpectedRole:      "",
			},
			{
				Name: "Given no id_token, a role path, a valid api response without a role, use api response",
				APIURLResponse: map[string]interface{}{
					"email": "john.doe@example.com",
				},
				RoleAttributePath: "role",
				ExpectedEmail:     "john.doe@example.com",
				ExpectedRole:      "",
			},
			{
				Name:              "Given no id_token, a valid role path, no api response, no data",
				RoleAttributePath: "role",
				ExpectedEmail:     "",
				ExpectedRole:      "",
			},
			{
				Name: "Given a valid id_token, a valid role path, a valid api response, prefer id_token",
				OAuth2Extra: map[string]interface{}{
					// { "role": "Admin", "email": "john.doe@example.com" }
					"id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiQWRtaW4iLCJlbWFpbCI6ImpvaG4uZG9lQGV4YW1wbGUuY29tIn0.9PtHcCaXxZa2HDlASyKIaFGfOKlw2ILQo32xlvhvhRg",
				},
				APIURLResponse: map[string]interface{}{
					"role":  "FromResponse",
					"email": "from_response@example.com",
				},
				RoleAttributePath: "role",
				ExpectedEmail:     "john.doe@example.com",
				ExpectedRole:      "Admin",
			},
			{
				Name: "Given a valid id_token, an invalid role path, a valid api response, prefer id_token",
				OAuth2Extra: map[string]interface{}{
					// { "role": "Admin", "email": "john.doe@example.com" }
					"id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiQWRtaW4iLCJlbWFpbCI6ImpvaG4uZG9lQGV4YW1wbGUuY29tIn0.9PtHcCaXxZa2HDlASyKIaFGfOKlw2ILQo32xlvhvhRg",
				},
				APIURLResponse: map[string]interface{}{
					"role":  "FromResponse",
					"email": "from_response@example.com",
				},
				RoleAttributePath: "invalid_path",
				ExpectedEmail:     "john.doe@example.com",
				ExpectedRole:      "",
			},
			{
				Name: "Given a valid id_token with no email, a valid role path, a valid api response with no role, merge",
				OAuth2Extra: map[string]interface{}{
					// { "role": "Admin" }
					"id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiQWRtaW4ifQ.k5GwPcZvGe2BE_jgwN0ntz0nz4KlYhEd0hRRLApkTJ4",
				},
				APIURLResponse: map[string]interface{}{
					"email": "from_response@example.com",
				},
				RoleAttributePath: "role",
				ExpectedEmail:     "from_response@example.com",
				ExpectedRole:      "Admin",
			},
			{
				Name: "Given a valid id_token with no role, a valid role path, a valid api response with no email, merge",
				OAuth2Extra: map[string]interface{}{
					// { "email": "john.doe@example.com" }
					"id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImpvaG4uZG9lQGV4YW1wbGUuY29tIn0.k5GwPcZvGe2BE_jgwN0ntz0nz4KlYhEd0hRRLApkTJ4",
				},
				APIURLResponse: map[string]interface{}{
					"role": "FromResponse",
				},
				RoleAttributePath: "role",
				ExpectedEmail:     "john.doe@example.com",
				ExpectedRole:      "FromResponse",
			},
		}

		for _, test := range tests {
			provider.roleAttributePath = test.RoleAttributePath
			t.Run(test.Name, func(t *testing.T) {
				response, err := json.Marshal(test.APIURLResponse)
				require.NoError(t, err)
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Header().Set("Content-Type", "application/json")
					_, err = io.WriteString(w, string(response))
					require.NoError(t, err)
				}))
				provider.apiUrl = ts.URL
				staticToken := oauth2.Token{
					AccessToken:  "",
					TokenType:    "",
					RefreshToken: "",
					Expiry:       time.Now(),
				}

				token := staticToken.WithExtra(test.OAuth2Extra)
				actualResult, err := provider.UserInfo(ts.Client(), token)
				require.NoError(t, err)
				require.Equal(t, test.ExpectedEmail, actualResult.Email)
				require.Equal(t, test.ExpectedEmail, actualResult.Login)
				require.Equal(t, test.ExpectedRole, actualResult.Role)
			})
		}
	})
}
