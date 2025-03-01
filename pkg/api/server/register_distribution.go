//go:build !remote

package server

import (
	"net/http"

	"github.com/containers/podman/v5/pkg/api/handlers/compat"
	"github.com/gorilla/mux"
)

func (s *APIServer) registerDistributionHandlers(r *mux.Router) error {
	r.HandleFunc(VersionedPath("/distribution/{name:.*}/json"), s.APIHandler(compat.InspectDistribution)).Methods(http.MethodGet)
	r.HandleFunc(VersionedPath("/libpod/distribution/{name:.*}/json"), s.APIHandler(compat.InspectDistribution)).Methods(http.MethodGet)
	// Added non version path to URI to support docker non versioned paths
	r.HandleFunc("/distribution/{name:.*}/json", s.APIHandler(compat.InspectDistribution)).Methods(http.MethodGet)
	return nil
}
