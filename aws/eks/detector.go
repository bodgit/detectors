package eks

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.34.0"
	"k8s.io/client-go/rest"
)

type tlsConn interface {
	Close() error
	ConnectionState() tls.ConnectionState
}

type dialer interface {
	dial(ctx context.Context, network, addr string, tlsConfig *tls.Config) (tlsConn, error)
}

type eksListClustersPaginatorAPI interface {
	HasMorePages() bool
	NextPage(ctx context.Context, fn ...func(*eks.Options)) (*eks.ListClustersOutput, error)
}

type eksAPIClient interface {
	eks.ListClustersAPIClient
	eks.DescribeClusterAPIClient
}

type stsAPIClient interface {
	//nolint:lll
	GetCallerIdentity(ctx context.Context, input *sts.GetCallerIdentityInput, fn ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

type detectorUtils interface {
	dialer
	inClusterConfig() (*rest.Config, error)
	stsClient(config aws.Config) stsAPIClient
	eksClient(config aws.Config) eksAPIClient
}

type eksDetectorUtils struct{}

func (utils *eksDetectorUtils) inClusterConfig() (*rest.Config, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("error getting Kubernetes config: %w", err)
	}

	return config, nil
}

func (utils *eksDetectorUtils) dial(ctx context.Context, network, addr string, config *tls.Config) (tlsConn, error) {
	dialer := &tls.Dialer{
		Config: config,
	}

	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("error dialing: %w", err)
	}

	//nolint:forcetypeassert
	return conn.(*tls.Conn), nil
}

func (utils *eksDetectorUtils) stsClient(cfg aws.Config) stsAPIClient {
	return sts.NewFromConfig(cfg)
}

func (utils *eksDetectorUtils) eksClient(cfg aws.Config) eksAPIClient {
	return eks.NewFromConfig(cfg)
}

type resourceDetector struct {
	utils detectorUtils
}

func (detector *resourceDetector) Detect(ctx context.Context) (*resource.Resource, error) {
	k8sConfig, err := detector.utils.inClusterConfig()
	if err != nil {
		// Not in a K8S cluster of any sort
		if errors.Is(err, rest.ErrNotInCluster) {
			return resource.Empty(), nil
		}

		return nil, err
	}

	names, err := getK8SCertificateDNSNames(ctx, k8sConfig, detector.utils)
	if err != nil {
		return nil, err
	}

	endpoint, region, ok := detectEKS(names)
	if !ok {
		// It's a K8S cluster, but not EKS
		return resource.Empty(), nil
	}

	attributes := []attribute.KeyValue{
		semconv.CloudProviderAWS,
		semconv.CloudPlatformAWSEKS,
		semconv.CloudRegion(region),
	}

	awsConfig, err := config.LoadDefaultConfig(ctx, config.WithRetryer(func() aws.Retryer {
		return new(aws.NopRetryer)
	}))
	if err != nil {
		return nil, fmt.Errorf("unable to load AWS config: %w", err)
	}

	stsClient := detector.utils.stsClient(awsConfig)

	accountID, err := getAccountID(ctx, stsClient)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return resource.NewWithAttributes(semconv.SchemaURL, attributes...), nil
		}

		return nil, err
	}

	attributes = append(attributes, semconv.CloudAccountID(accountID))

	eksClient := detector.utils.eksClient(awsConfig)

	clusterName, err := findEKSClusterByEndpoint(ctx, eksClient, endpoint)
	if err != nil {
		return nil, err
	}

	if clusterName != "" {
		attributes = append(attributes, semconv.K8SClusterName(clusterName))
	}

	return resource.NewWithAttributes(semconv.SchemaURL, attributes...), nil
}

var _ resource.Detector = new(resourceDetector)

// NewResourceDetector returns a [resource.Detector] that will detect AWS EKS resources.
func NewResourceDetector() resource.Detector {
	return &resourceDetector{
		utils: new(eksDetectorUtils),
	}
}

//nolint:nonamedreturns
func getK8SCertificateDNSNames(ctx context.Context, config *rest.Config, dialer dialer) (names []string, err error) {
	var (
		tlsConfig *tls.Config
		conn      tlsConn
	)

	tlsConfig, err = rest.TLSConfigFor(config)
	if err != nil {
		return
	}

	conn, err = dialer.dial(ctx, "tcp", strings.TrimPrefix(config.Host, "https://"), tlsConfig)
	if err != nil {
		return
	}

	defer func() {
		err = conn.Close()
	}()

	for _, cert := range conn.ConnectionState().PeerCertificates {
		names = append(names, cert.DNSNames...)
	}

	return
}

//nolint:lll
var eksEndpointRegexp = regexp.MustCompile(`\.(?P<region>[^.]+)\.(?:eks\.amazonaws\.com|api\.aws|(?:api\.)?amazonwebservices\.com\.cn)$`)

func detectEKS(names []string) (string, string, bool) {
	for _, name := range names {
		if match := eksEndpointRegexp.FindStringSubmatch(name); match != nil {
			m := make(map[string]string)

			for i, name := range eksEndpointRegexp.SubexpNames() {
				if i > 0 {
					m[name] = match[i]
				}
			}

			return name, m["region"], true
		}
	}

	return "", "", false
}

func getAccountID(ctx context.Context, client stsAPIClient) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	output, err := client.GetCallerIdentity(ctx, new(sts.GetCallerIdentityInput))
	if err != nil {
		return "", fmt.Errorf("error issuing `sts:GetCallerIdentity`: %w", err)
	}

	arn, err := arn.Parse(*output.Arn)
	if err != nil {
		return "", fmt.Errorf("error parsing ARN: %w", err)
	}

	return arn.AccountID, nil
}

func listEKSClustersPaginated(ctx context.Context, paginator eksListClustersPaginatorAPI) ([]string, error) {
	var clusters []string

	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("error issuing `eks:ListClusters`: %w", err)
		}

		clusters = append(clusters, output.Clusters...)
	}

	return clusters, nil
}

func listEKSClusters(ctx context.Context, client eks.ListClustersAPIClient) ([]string, error) {
	paginator := eks.NewListClustersPaginator(client,
		new(eks.ListClustersInput),
		func(o *eks.ListClustersPaginatorOptions) {
			o.Limit = 20
		})

	output, err := listEKSClustersPaginated(ctx, paginator)
	if err != nil {
		return nil, err
	}

	return output, nil
}

func describeEKSClusterEndpoint(ctx context.Context, client eks.DescribeClusterAPIClient, name string) (string, error) {
	input := &eks.DescribeClusterInput{
		Name: aws.String(name),
	}

	output, err := client.DescribeCluster(ctx, input)
	if err != nil {
		return "", fmt.Errorf("error issuing `eks:DescribeCluster`: %w", err)
	}

	return *output.Cluster.Endpoint, nil
}

func findEKSClusterByEndpoint(ctx context.Context, client eksAPIClient, endpoint string) (string, error) {
	const accessDeniedException = "AccessDeniedException"

	clusters, err := listEKSClusters(ctx, client)
	if err != nil {
		var ae smithy.APIError
		if errors.As(err, &ae) && ae.ErrorCode() == accessDeniedException {
			return "", nil
		}

		return "", err
	}

	if len(clusters) == 1 {
		return clusters[0], nil
	}

	for _, cluster := range clusters {
		ep, err := describeEKSClusterEndpoint(ctx, client, cluster)
		if err != nil {
			var ae smithy.APIError
			if errors.As(err, &ae) && ae.ErrorCode() == accessDeniedException {
				continue
			}

			return "", err
		}

		if strings.TrimPrefix(strings.ToLower(ep), "https://") == endpoint {
			return cluster, nil
		}
	}

	return "", nil
}
