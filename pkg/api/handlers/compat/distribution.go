//go:build !remote

package compat

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/containers/image/v5/docker"
	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/image"
	"github.com/containers/image/v5/manifest"
	"github.com/containers/image/v5/types"
	"github.com/containers/podman/v5/pkg/api/handlers/utils"
	registrytypes "github.com/docker/docker/api/types/registry"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func InspectDistribution(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	name := utils.GetName(r)

	namedRef, imgRef, err := parseImageReference(name)
	if err != nil {
		utils.Error(w, http.StatusUnauthorized, err)
		return
	}

	manBlob, manType, digest, err := getManifestAndDigest(r, imgRef)
	if err != nil {
		utils.Error(w, http.StatusInternalServerError, err)
		return
	}

	if err := validateDigest(namedRef, digest); err != nil {
		utils.Error(w, http.StatusInternalServerError, err)
		return
	}

	distributionInspect := registrytypes.DistributionInspect{
		Descriptor: ocispec.Descriptor{
			Digest:    digest,
			Size:      int64(len(manBlob)),
			MediaType: manType,
		},
	}

	platforms, err := getPlatformsFromManifest(manBlob, manType)
	if err != nil {
		utils.Error(w, http.StatusInternalServerError, err)
		return
	}
	distributionInspect.Platforms = platforms

	populateDescriptorByManifestType(&distributionInspect.Descriptor, manBlob, manType)

	utils.WriteResponse(w, http.StatusOK, distributionInspect)
}

func parseImageReference(name string) (reference.Named, types.ImageReference, error) {
	namedRef, err := reference.ParseNormalizedNamed(name)
	if err != nil {
		return nil, nil, fmt.Errorf("not a valid image reference: %q", name)
	}

	namedRef = reference.TagNameOnly(namedRef)

	imgRef, err := docker.NewReference(namedRef)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating image reference: %w", err)
	}

	return namedRef, imgRef, nil
}

func getManifestAndDigest(ctx *http.Request, imgRef types.ImageReference) ([]byte, string, digest.Digest, error) {
	imgSrc, err := imgRef.NewImageSource(ctx.Context(), nil)
	if err != nil {
		var msg string
		var unauthErr docker.ErrUnauthorizedForCredentials
		if errors.As(err, &unauthErr) {
			msg = "401 Unauthorized"
		} else {
			msg = err.Error()
		}
		return nil, "", "", fmt.Errorf("error getting image source: %s", msg)
	}
	defer imgSrc.Close()

	manBlob, manType, err := image.UnparsedInstance(imgSrc, nil).Manifest(ctx.Context())
	if err != nil {
		return nil, "", "", fmt.Errorf("error getting manifest: %w", err)
	}

	digest, err := manifest.Digest(manBlob)
	if err != nil {
		return nil, "", "", fmt.Errorf("error getting manifest digest: %w", err)
	}

	return manBlob, manType, digest, nil
}

func validateDigest(namedRef reference.Named, calculatedDigest digest.Digest) error {
	if digested, ok := namedRef.(reference.Digested); ok {
		expectedDigest := digested.Digest()
		if calculatedDigest != expectedDigest {
			return fmt.Errorf("manifest digest %s does not match reference digest %s", calculatedDigest, expectedDigest)
		}
	}
	return nil
}

func getPlatformsFromManifest(manBlob []byte, manType string) ([]ocispec.Platform, error) {
	if manType == "" {
		manType = manifest.GuessMIMEType(manBlob)
	}

	if manifest.MIMETypeIsMultiImage(manType) {
		manifestList, err := manifest.ListFromBlob(manBlob, manType)
		if err != nil {
			return nil, fmt.Errorf("error parsing manifest list: %w", err)
		}

		instanceDigests := manifestList.Instances()
		platforms := make([]ocispec.Platform, 0, len(instanceDigests))
		for _, digest := range instanceDigests {
			instance, err := manifestList.Instance(digest)
			if err != nil {
				return nil, fmt.Errorf("error getting manifest list instance: %w", err)
			}
			platforms = append(platforms, *instance.ReadOnly.Platform)
		}
		return platforms, nil

	} else {
		// todo: handle non-multi-image manifests
		return []ocispec.Platform{}, nil
	}
}

func populateDescriptorByManifestType(descriptor *ocispec.Descriptor, manBlob []byte, manType string) {
	switch manType {
	case ocispec.MediaTypeImageIndex:
		if ociIndex, err := manifest.OCI1IndexFromManifest(manBlob); err == nil {
			descriptor.Annotations = ociIndex.Annotations
			descriptor.ArtifactType = ociIndex.ArtifactType
		}
	}
}
