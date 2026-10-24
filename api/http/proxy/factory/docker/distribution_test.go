package docker

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	portainer "github.com/portainer/portainer/api"
	"github.com/portainer/portainer/api/dataservices"
	"github.com/portainer/portainer/api/datastore"
	"github.com/portainer/portainer/api/http/security"
	"github.com/segmentio/encoding/json"
	"github.com/stretchr/testify/require"
)

func TestTransport_proxyDistributionRequest(t *testing.T) {
	admin := portainer.User{ID: 1, Username: "admin", Role: portainer.AdministratorRole}
	std := portainer.User{ID: 2, Username: "std", Role: portainer.StandardUserRole}

	_, ds := datastore.MustNewTestStore(t, true, false)

	require.NoError(t, ds.UpdateTx(func(tx dataservices.DataStoreTx) error {
		require.NoError(t, tx.User().Create(&admin))
		require.NoError(t, tx.User().Create(&std))
		require.NoError(t, tx.Endpoint().Create(&portainer.Endpoint{ID: 1, Name: "env"}))
		require.NoError(t, tx.Registry().Create(&portainer.Registry{
			ID: 1, Type: portainer.CustomRegistry, Name: "ghcr", URL: "ghcr.io",
			Authentication: true, Username: "octocat", Password: "secret",
		}))
		require.NoError(t, tx.Registry().Create(&portainer.Registry{
			ID: 2, Type: portainer.CustomRegistry, Name: "open", URL: "registry.example.com",
			Authentication: false,
		}))

		require.NoError(t, tx.Registry().Create(&portainer.Registry{
			ID: 3, Type: portainer.DockerHubRegistry, Name: "hub", URL: "docker.io",
			Authentication: true, Username: "hubuser", Password: "hubsecret",
		}))

		return nil
	}))

	var receivedHeader string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("X-Registry-Auth")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
	}))
	defer srv.Close()

	transport := &Transport{
		endpoint:      &portainer.Endpoint{ID: 1, URL: srv.URL},
		dataStore:     ds,
		HTTPTransport: &http.Transport{},
	}

	adminToken := portainer.TokenData{ID: admin.ID, Username: admin.Username, Role: admin.Role}
	stdToken := portainer.TokenData{ID: std.ID, Username: std.Username, Role: std.Role}

	tests := []struct {
		name         string
		image        string
		token        portainer.TokenData
		clientHeader string
		wantUser     string
		wantHeader   string
	}{
		{name: "admin gets the registry credentials", image: "ghcr.io/octocat/private:edge", token: adminToken, wantUser: "octocat"},
		{name: "user without registry access gets none", image: "ghcr.io/octocat/other:edge", token: stdToken},
		{name: "registry without authentication gets none", image: "registry.example.com/team/app:1", token: adminToken},
		{name: "image from another registry gets none", image: "quay.io/team/app:1", token: adminToken},
		{name: "header sent by the client is kept", image: "ghcr.io/octocat/kept:edge", token: adminToken, clientHeader: "client", wantHeader: "client"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			receivedHeader = ""
			path := "/distribution/" + tt.image + "/json"

			req := httptest.NewRequest(http.MethodGet, srv.URL+"/v1.41"+path, nil)
			req = req.WithContext(security.StoreTokenData(req, &tt.token))

			if tt.clientHeader != "" {
				req.Header.Set("X-Registry-Auth", tt.clientHeader)
			}

			resp, err := transport.proxyDistributionRequest(req, path)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())

			if tt.wantUser == "" {
				require.Equal(t, tt.wantHeader, receivedHeader)

				return
			}

			decoded, err := base64.URLEncoding.DecodeString(receivedHeader)
			require.NoError(t, err)

			var got registryAuthenticationHeader
			require.NoError(t, json.Unmarshal(decoded, &got))
			require.Equal(t, registryAuthenticationHeader{Username: "octocat", Password: "secret", Serveraddress: "ghcr.io"}, got)
		})
	}
}
