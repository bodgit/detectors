package container

import (
	"context"
	"os"

	"github.com/bodgit/nri-plugin-runtime/pkg/runtime"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.34.0"
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
	attributes := make([]attribute.KeyValue, 0, 2)

	if containerID, _ := detector.utils.lookupEnv(runtime.ContainerIDName); containerID != "" {
		attributes = append(attributes, semconv.ContainerID(containerID))
	}

	if containerRuntime, _ := detector.utils.lookupEnv(runtime.ContainerRuntimeName); containerRuntime != "" {
		attributes = append(attributes, semconv.ContainerRuntime(containerRuntime))
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
