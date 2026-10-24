package docker

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/portainer/portainer/api/docker/images"

	"github.com/rs/zerolog/log"
	"github.com/segmentio/encoding/json"
)

// proxyDistributionRequest adds the credentials of the matching registry to
// /distribution/{image}/json, as the daemon only authenticates to the registry
// with the X-Registry-Auth header of the request.
func (transport *Transport) proxyDistributionRequest(request *http.Request, unversionedPath string) (*http.Response, error) {
	if request.Header.Get("X-Registry-Auth") == "" {
		header, err := transport.distributionRegistryAuthHeader(request, unversionedPath)
		if err != nil {
			log.Debug().Err(err).Str("path", unversionedPath).Msg("no registry credentials added to the distribution request")
		} else if header != "" {
			request.Header.Set("X-Registry-Auth", header)
		}
	}

	return transport.executeDockerRequest(request)
}

func (transport *Transport) distributionRegistryAuthHeader(request *http.Request, unversionedPath string) (string, error) {
	imageName := strings.TrimSuffix(strings.TrimPrefix(unversionedPath, "/distribution/"), "/json")

	image, err := images.ParseImage(images.ParseImageOptions{Name: imageName})
	if err != nil {
		return "", err
	}

	accessContext, err := transport.createRegistryAccessContext(request)
	if err != nil {
		return "", err
	}

	registry, err := images.BestMatchRegistry(image.Name(), accessContext.registries)
	if err != nil {
		return "", err
	}

	// Never send credentials to a registry other than the one the image comes from
	registryHost := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(registry.URL, "https://"), "http://"), "/")
	if !registry.Authentication || registryHost == "" || !strings.HasPrefix(image.Name()+"/", registryHost+"/") {
		return "", nil
	}

	authenticationHeader, err := createRegistryAuthenticationHeader(transport.dataStore, registry.ID, accessContext)
	if err != nil || authenticationHeader.Username == "" {
		return "", err
	}

	headerData, err := json.Marshal(authenticationHeader)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(headerData), nil
}
