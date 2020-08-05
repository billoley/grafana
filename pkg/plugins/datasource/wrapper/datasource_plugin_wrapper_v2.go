package wrapper

import (
	"context"
	"fmt"
	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/login/social"
	"golang.org/x/oauth2"
	"strings"

	"github.com/grafana/grafana-plugin-sdk-go/backend/grpcplugin"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/genproto/pluginv2"
	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/tsdb"
)

func NewDatasourcePluginWrapperV2(log log.Logger, pluginId, pluginType string, client grpcplugin.DataClient) *DatasourcePluginWrapperV2 {
	return &DatasourcePluginWrapperV2{DataClient: client, logger: log, pluginId: pluginId, pluginType: pluginType}
}

type DatasourcePluginWrapperV2 struct {
	grpcplugin.DataClient
	logger     log.Logger
	pluginId   string
	pluginType string
}

func ModelToInstanceSettings(ds *models.DataSource) (*backend.DataSourceInstanceSettings, error) {
	jsonDataBytes, err := ds.JsonData.MarshalJSON()
	if err != nil {
		return nil, err
	}

	return &backend.DataSourceInstanceSettings{
		ID:                      ds.Id,
		Name:                    ds.Name,
		URL:                     ds.Url,
		Database:                ds.Database,
		User:                    ds.User,
		BasicAuthEnabled:        ds.BasicAuth,
		BasicAuthUser:           ds.BasicAuthUser,
		JSONData:                jsonDataBytes,
		DecryptedSecureJSONData: ds.DecryptedValues(),
		Updated:                 ds.Updated,
	}, nil
}

//func (t *DatasourcePluginWrapperV2) getClient(name string) (*http.Client) {
//
//	name = strings.TrimPrefix(name, "oauth_")
//
//	// handle call back
//	tr := &http.Transport{
//		Proxy: http.ProxyFromEnvironment,
//		TLSClientConfig: &tls.Config{
//			InsecureSkipVerify: setting.OAuthService.OAuthInfos[name].TlsSkipVerify,
//		},
//	}
//	oauthClient := &http.Client{
//		Transport: tr,
//	}
//
//	if setting.OAuthService.OAuthInfos[name].TlsClientCert != "" || setting.OAuthService.OAuthInfos[name].TlsClientKey != "" {
//		cert, err := tls.LoadX509KeyPair(setting.OAuthService.OAuthInfos[name].TlsClientCert, setting.OAuthService.OAuthInfos[name].TlsClientKey)
//		if err != nil {
//			t.logger.Error("Failed to setup TlsClientCert", "oauth", name, "error", err)
//			return nil
//		}
//
//		tr.TLSClientConfig.Certificates = append(tr.TLSClientConfig.Certificates, cert)
//	}
//
//	if setting.OAuthService.OAuthInfos[name].TlsClientCa != "" {
//		caCert, err := ioutil.ReadFile(setting.OAuthService.OAuthInfos[name].TlsClientCa)
//		if err != nil {
//			t.logger.Error("Failed to setup TlsClientCa", "oauth", name, "error", err)
//			return nil
//		}
//		caCertPool := x509.NewCertPool()
//		caCertPool.AppendCertsFromPEM(caCert)
//
//		tr.TLSClientConfig.RootCAs = caCertPool
//	}
//	return oauthClient;
//}

//func (t *DatasourcePluginWrapperV2) addOAuthPassThruAuth(ctx context.Context, query *tsdb.TsdbQuery) {
//	t.logger.Error("addOAuthPassThruAuth")
//	authInfoQuery := &models.GetAuthInfoQuery{UserId: query.User.UserId}
//	if err := bus.Dispatch(authInfoQuery); err != nil {
//		t.logger.Error("Error fetching oauth information for user", "error", err)
//		return
//	}
//
//	provider := authInfoQuery.Result.AuthModule
//	connect, ok := social.SocialMap[strings.TrimPrefix(provider, "oauth_")] // The socialMap keys don't have "oauth_" prefix, but everywhere else in the system does
//	if !ok {
//		t.logger.Error("Failed to find oauth provider with given name", "provider", provider)
//		return
//	}
//
//	client, err := social.GetOAuthHttpClient(strings.TrimPrefix(provider, "oauth_"))
//	if (err != nil) {
//		t.logger.Error("Failed to create http client for oauth operation", "error", err)
//	}
//	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
//
//	// TokenSource handles refreshing the token if it has expired
//	token, err := connect.TokenSource(ctx, &oauth2.Token{
//		AccessToken:  authInfoQuery.Result.OAuthAccessToken,
//		Expiry:       authInfoQuery.Result.OAuthExpiry,
//		RefreshToken: authInfoQuery.Result.OAuthRefreshToken,
//		TokenType:    authInfoQuery.Result.OAuthTokenType,
//	}).Token()
//	if err != nil {
//		t.logger.Error("Failed to retrieve access token from oauth provider", "provider", authInfoQuery.Result.AuthModule, "error", err)
//		return
//	}
//
//	// If the tokens are not the same, update the entry in the DB
//	if token.AccessToken != authInfoQuery.Result.OAuthAccessToken {
//		updateAuthCommand := &models.UpdateAuthInfoCommand{
//			UserId:     authInfoQuery.Result.UserId,
//			AuthModule: authInfoQuery.Result.AuthModule,
//			AuthId:     authInfoQuery.Result.AuthId,
//			OAuthToken: token,
//		}
//		if err := bus.Dispatch(updateAuthCommand); err != nil {
//			t.logger.Error("Failed to update access token during token refresh", "error", err)
//			return
//		}
//	}
//	delete(query.Headers, "Authorization")
//	query.Headers["Authorization"] = fmt.Sprintf("%s %s", token.Type(), token.AccessToken)
//}

func (tw *DatasourcePluginWrapperV2) Query(ctx context.Context, ds *models.DataSource, query *tsdb.TsdbQuery) (*tsdb.Response, error) {
	instanceSettings, err := ModelToInstanceSettings(ds)
	if err != nil {
		return nil, err
	}

	if query.Headers == nil {
		query.Headers = make(map[string]string)
	}
	social.AddOAuthPassThruAuth(ctx, query)

	pbQuery := &pluginv2.QueryDataRequest{
		PluginContext: &pluginv2.PluginContext{
			OrgId:                      ds.OrgId,
			PluginId:                   tw.pluginId,
			User:                       backend.ToProto().User(BackendUserFromSignedInUser(query.User)),
			DataSourceInstanceSettings: backend.ToProto().DataSourceInstanceSettings(instanceSettings),
		},
		Queries: []*pluginv2.DataQuery{},
		Headers: query.Headers,
	}

	for _, q := range query.Queries {
		modelJSON, err := q.Model.MarshalJSON()
		if err != nil {
			return nil, err
		}
		pbQuery.Queries = append(pbQuery.Queries, &pluginv2.DataQuery{
			Json:          modelJSON,
			IntervalMS:    q.IntervalMs,
			RefId:         q.RefId,
			MaxDataPoints: q.MaxDataPoints,
			TimeRange: &pluginv2.TimeRange{
				ToEpochMS:   query.TimeRange.GetToAsMsEpoch(),
				FromEpochMS: query.TimeRange.GetFromAsMsEpoch(),
			},
			QueryType: q.QueryType,
		})
	}

	pbRes, err := tw.DataClient.QueryData(ctx, pbQuery)
	if err != nil {
		return nil, err
	}

	tR := &tsdb.Response{
		Results: make(map[string]*tsdb.QueryResult, len(pbRes.Responses)),
	}

	for refID, pRes := range pbRes.Responses {
		qr := &tsdb.QueryResult{
			RefId:      refID,
			Dataframes: tsdb.NewEncodedDataFrames(pRes.Frames),
		}
		if len(pRes.JsonMeta) != 0 {
			qr.Meta = simplejson.NewFromAny(pRes.JsonMeta)
		}
		if pRes.Error != "" {
			qr.Error = fmt.Errorf(pRes.Error)
			qr.ErrorString = pRes.Error
		}
		tR.Results[refID] = qr
	}

	return tR, nil
}

// BackendUserFromSignedInUser converts Grafana's SignedInUser model
// to the backend plugin's model.
func BackendUserFromSignedInUser(su *models.SignedInUser) *backend.User {
	if su == nil {
		return nil
	}
	return &backend.User{
		Login: su.Login,
		Name:  su.Name,
		Email: su.Name,
		Role:  string(su.OrgRole),
	}
}
