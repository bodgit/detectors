//nolint:forcetypeassert,funlen,lll,wrapcheck
package eks

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.34.0"
	"k8s.io/client-go/rest"
)

const testHost = "192.0.2.1:443"

type mockTLSConn struct {
	mock.Mock
}

func (conn *mockTLSConn) Close() error {
	return conn.Called().Error(0)
}

func (conn *mockTLSConn) ConnectionState() tls.ConnectionState {
	return conn.Called().Get(0).(tls.ConnectionState)
}

type mockDetectorUtils struct {
	mock.Mock
}

func (utils *mockDetectorUtils) inClusterConfig() (*rest.Config, error) {
	args := utils.Called()

	if config := args.Get(0); config != nil {
		return args.Get(0).(*rest.Config), args.Error(1)
	}

	return nil, args.Error(1)
}

func (utils *mockDetectorUtils) dial(ctx context.Context, network, addr string, tlsConfig *tls.Config) (tlsConn, error) {
	args := utils.Called(ctx, network, addr, tlsConfig)

	return args.Get(0).(tlsConn), args.Error(1)
}

func (utils *mockDetectorUtils) stsClient(config aws.Config) stsAPIClient {
	return utils.Called(config).Get(0).(stsAPIClient)
}

func (utils *mockDetectorUtils) eksClient(config aws.Config) eksAPIClient {
	return utils.Called(config).Get(0).(eksAPIClient)
}

type mockSTSClient struct {
	mock.Mock
}

func (client *mockSTSClient) GetCallerIdentity(ctx context.Context, input *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	args := client.Called(ctx, input, optFns)

	if output := args.Get(0); output != nil {
		return output.(*sts.GetCallerIdentityOutput), args.Error(1)
	}

	return nil, args.Error(1)
}

type mockEKSClient struct {
	mock.Mock
}

func (client *mockEKSClient) ListClusters(ctx context.Context, input *eks.ListClustersInput, optFns ...func(*eks.Options)) (*eks.ListClustersOutput, error) {
	args := client.Called(ctx, input, optFns)

	if output := args.Get(0); output != nil {
		return output.(*eks.ListClustersOutput), args.Error(1)
	}

	return nil, args.Error(1)
}

func (client *mockEKSClient) DescribeCluster(ctx context.Context, input *eks.DescribeClusterInput, optFns ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
	args := client.Called(ctx, input, optFns)

	if output := args.Get(0); output != nil {
		return output.(*eks.DescribeClusterOutput), args.Error(1)
	}

	return nil, args.Error(1)
}

func TestNotInCluster(t *testing.T) {
	t.Parallel()

	utils := new(mockDetectorUtils)
	utils.On("inClusterConfig").Return(nil, rest.ErrNotInCluster).Once()

	eksResourceDetector := resourceDetector{utils: utils}

	r, err := eksResourceDetector.Detect(t.Context())
	require.NoError(t, err)
	assert.Equal(t, resource.Empty(), r)

	utils.AssertExpectations(t)
}

func TestNotEKS(t *testing.T) {
	t.Parallel()

	utils := new(mockDetectorUtils)
	utils.On("inClusterConfig").Return(&rest.Config{Host: testHost}, nil).Once()

	conn := new(mockTLSConn)
	conn.On("Close").Return(nil).Once()
	conn.On("ConnectionState").Return(tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{
				DNSNames: []string{
					"kubernetes",
					"kubernetes.default",
					"kubernetes.default.svc",
					"kubernetes.default.svc.cluster.local",
				},
			},
		},
	}).Once()

	utils.On("dial", mock.Anything, "tcp", testHost, mock.Anything).Return(conn, nil).Once()

	eksResourceDetector := resourceDetector{utils: utils}

	r, err := eksResourceDetector.Detect(t.Context())
	require.NoError(t, err)
	assert.Equal(t, resource.Empty(), r)

	utils.AssertExpectations(t)
	conn.AssertExpectations(t)
}

func TestEKS(t *testing.T) {
	t.Parallel()

	utils := new(mockDetectorUtils)
	utils.On("inClusterConfig").Return(&rest.Config{Host: testHost}, nil).Once()

	conn := new(mockTLSConn)
	conn.On("Close").Return(nil).Once()
	conn.On("ConnectionState").Return(tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{
				DNSNames: []string{
					"abc123.eu-west-1.eks.amazonaws.com",
					"kubernetes",
					"kubernetes.default",
					"kubernetes.default.svc",
					"kubernetes.default.svc.cluster.local",
				},
			},
		},
	}).Once()

	utils.On("dial", mock.Anything, "tcp", testHost, mock.Anything).Return(conn, nil).Once()

	stsClient := new(mockSTSClient)
	stsClient.On("GetCallerIdentity", mock.Anything, mock.Anything, mock.Anything).Return(&sts.GetCallerIdentityOutput{
		Arn: aws.String("arn:aws:iam:eu-west-1:0123456789012:role/test"),
	}, nil).Once()

	utils.On("stsClient", mock.Anything).Return(stsClient).Once()

	eksClient := new(mockEKSClient)
	eksClient.On("ListClusters", mock.Anything, mock.Anything, mock.Anything).Return(&eks.ListClustersOutput{
		Clusters: []string{
			"test-cluster1",
			"test-cluster2",
		},
		NextToken: aws.String("token"),
	}, nil).Once()
	eksClient.On("ListClusters", mock.Anything, mock.Anything, mock.Anything).Return(new(eks.ListClustersOutput), nil).Once()
	eksClient.On("DescribeCluster", mock.Anything, &eks.DescribeClusterInput{
		Name: aws.String("test-cluster1"),
	}, mock.Anything).Return(nil, new(ekstypes.AccessDeniedException)).Once()
	eksClient.On("DescribeCluster", mock.Anything, &eks.DescribeClusterInput{
		Name: aws.String("test-cluster2"),
	}, mock.Anything).Return(&eks.DescribeClusterOutput{
		Cluster: &ekstypes.Cluster{
			Endpoint: aws.String("https://ABC123.eu-west-1.eks.amazonaws.com"),
		},
	}, nil).Once()

	utils.On("eksClient", mock.Anything).Return(eksClient).Once()

	eksResourceDetector := resourceDetector{utils: utils}

	expected := resource.NewWithAttributes(semconv.SchemaURL, []attribute.KeyValue{
		semconv.CloudProviderAWS,
		semconv.CloudPlatformAWSEKS,
		semconv.CloudAccountID("0123456789012"),
		semconv.CloudRegion("eu-west-1"),
		semconv.K8SClusterName("test-cluster2"),
	}...)

	r, err := eksResourceDetector.Detect(t.Context())
	require.NoError(t, err)
	assert.Equal(t, expected, r)

	utils.AssertExpectations(t)
	conn.AssertExpectations(t)
	eksClient.AssertExpectations(t)
}
