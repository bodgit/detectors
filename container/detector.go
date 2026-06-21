// Package container provides an OpenTelemetry detector for detecting
// container-level attributes.
package container

import (
	"context"
	"os"

	"github.com/bodgit/nri-plugin-runtime/pkg/runtime"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
)

type detectorUtils interface {
	lookupEnv(key string) (string, bool)
}

type containerDetectorUtils struct{}

func (utils *containerDetectorUtils) lookupEnv(key string) (string, bool) {
	return os.LookupEnv(key)
}

type resourceDetector struct {
	utils detectorUtils
}

func (detector *resourceDetector) Detect(_ context.Context) (*resource.Resource, error) {
	attributes := make([]attribute.KeyValue, 0, 3)

	for _, s := range []struct {
		env string
		fn  func(string) attribute.KeyValue
	}{
		{
			runtime.ContainerIDEnv,
			semconv.ContainerID,
		},
		{
			runtime.ContainerRuntimeNameEnv,
			semconv.ContainerRuntimeName,
		},
		{
			runtime.ContainerRuntimeVersionEnv,
			semconv.ContainerRuntimeVersion,
		},
	} {
		if v, _ := detector.utils.lookupEnv(s.env); v != "" {
			attributes = append(attributes, s.fn(v))
		}
	}

	if len(attributes) == 0 {
		return resource.Empty(), nil
	}

	return resource.NewWithAttributes(semconv.SchemaURL, attributes...), nil
}

var _ resource.Detector = new(resourceDetector)

// NewResourceDetector returns a [resource.Detector] that will detect container
// resources.
func NewResourceDetector() resource.Detector {
	return &resourceDetector{
		utils: new(containerDetectorUtils),
	}
}
