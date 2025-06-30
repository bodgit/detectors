package container

import (
	"testing"

	"github.com/bodgit/nri-plugin-runtime/pkg/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.34.0"
)

type mockDetectorUtils struct {
	mock.Mock
}

func (utils *mockDetectorUtils) lookupEnv(key string) (string, bool) {
	args := utils.Called(key)

	return args.String(0), args.Bool(1)
}

func TestContainer(t *testing.T) {
	t.Parallel()

	utils := new(mockDetectorUtils)
	utils.On("lookupEnv", runtime.ContainerIDName).Return("abc123", true).Once()
	utils.On("lookupEnv", runtime.ContainerRuntimeName).Return("containerd", true).Once()

	containerResourceDetector := resourceDetector{utils: utils}

	r, err := containerResourceDetector.Detect(t.Context())
	require.NoError(t, err)
	assert.Equal(t, resource.NewWithAttributes(semconv.SchemaURL, []attribute.KeyValue{
		semconv.ContainerID("abc123"),
		semconv.ContainerRuntime("containerd"),
	}...), r)

	utils.AssertExpectations(t)
}

func TestNoPlugin(t *testing.T) {
	t.Parallel()

	utils := new(mockDetectorUtils)
	utils.On("lookupEnv", mock.Anything).Return("", false).Twice()

	containerResourceDetector := resourceDetector{utils: utils}

	r, err := containerResourceDetector.Detect(t.Context())
	require.NoError(t, err)
	assert.Equal(t, resource.Empty(), r)

	utils.AssertExpectations(t)
}
