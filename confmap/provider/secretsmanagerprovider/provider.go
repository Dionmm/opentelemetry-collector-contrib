// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package secretsmanagerprovider // import "github.com/open-telemetry/opentelemetry-collector-contrib/confmap/provider/secretsmanagerprovider"

import (
	"context"
	"fmt"
	"strings"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"go.opentelemetry.io/collector/confmap"
)

const (
	schemeName = "secretsmanager"
)

type provider struct {
	client *secretsmanager.Client
}

// New returns a new confmap.Provider that reads the configuration from the given AWS Secrets Manager Name or ARN.
//
// This Provider supports "secretsmanager" scheme, and can be called with a selector:
// `secretsmanager:NAME_OR_ARN`
func New() confmap.Provider {
	return &provider{}
}

func (provider *provider) Retrieve(ctx context.Context, uri string, _ confmap.WatcherFunc) (*confmap.Retrieved, error) {
	if !strings.HasPrefix(uri, schemeName+":") {
		return nil, fmt.Errorf("%q uri is not supported by %q provider", uri, schemeName)
	}
	secretArn, secretStringKey, keyFound := strings.Cut(uri, "#")

	input := &secretsmanager.GetSecretValueInput{
		SecretId: &secretArn,
	}

	response, err := provider.client.GetSecretValue(ctx, input)
	if err != nil {
		return nil, err
	}

	if response.SecretString == nil {
		return nil, nil
	}

	if keyFound {
		conf := make(map[string]interface{})
		err = json.Unmarshal([]byte(*response.SecretString), &conf)
		if err != nil {
			return nil, err
		}
		return confmap.NewRetrieved(conf[secretStringKey])
	}

	return confmap.NewRetrieved(*response.SecretString)
}

func (*provider) Scheme() string {
	return schemeName
}

func (*provider) Shutdown(context.Context) error {
	return nil
}
