/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Command policy-tester verifies an image against a ClusterImagePolicy and
// prints the result as JSON. It is adapted from the upstream
// github.com/sigstore/policy-controller/cmd/tester, which only prints JSON
// when verification fails and so drops the warnings that `mode: warn`
// policies produce on success. This version always prints the result.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/policy-controller/pkg/policy"
	"github.com/sigstore/policy-controller/pkg/webhook"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"knative.dev/pkg/apis"
	"knative.dev/pkg/logging"
	"sigs.k8s.io/yaml"
)

type output struct {
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

func main() {
	cipFilePath := flag.String("policy", "", "path to ClusterImagePolicy or URL to fetch from (http/https)")
	image := flag.String("image", "", "image to compare against policy")
	resourceFilePath := flag.String("resource", "", "path to a kubernetes resource to use with includeSpec, includeObjectMeta")
	flag.Parse()

	if *cipFilePath == "" || *image == "" {
		flag.Usage()
		os.Exit(1)
	}

	logger, err := zap.NewDevelopment()
	if err != nil {
		log.Fatal(err)
	}
	ctx := logging.WithLogger(context.Background(), logger.Sugar())

	src := policy.Source{Path: *cipFilePath}
	if strings.HasPrefix(*cipFilePath, "https://") || strings.HasPrefix(*cipFilePath, "http://") {
		src = policy.Source{URL: *cipFilePath}
	}
	v := policy.Verification{
		NoMatchPolicy: "deny",
		Policies:      &[]policy.Source{src},
	}
	if err := v.Validate(ctx); err != nil {
		// CIP validation can return warnings, so only exit on errors.
		if warnFE := err.Filter(apis.WarningLevel); warnFE != nil {
			log.Printf("CIP has warnings:\n%s\n", warnFE.Error())
		}
		if errorFE := err.Filter(apis.ErrorLevel); errorFE != nil {
			log.Fatalf("CIP is invalid: %s", errorFE.Error())
		}
	}

	ref, err := name.ParseReference(*image)
	if err != nil {
		log.Fatal(err)
	}

	out := output{}
	vfy, err := policy.Compile(ctx, v, func(s string, i ...any) {
		out.Warnings = append(out.Warnings, fmt.Sprintf(s, i...))
	})
	if err != nil {
		log.Fatal(err)
	}

	if *resourceFilePath != "" {
		ctx, err = includeResource(ctx, *resourceFilePath)
		if err != nil {
			log.Fatal(err)
		}
	}

	if err := vfy.Verify(ctx, ref, authn.DefaultKeychain); err != nil {
		out.Errors = append(out.Errors, strings.Trim(err.Error(), "\n"))
	}

	if err := json.NewEncoder(os.Stdout).Encode(&out); err != nil {
		log.Fatal(err)
	}
	if len(out.Errors) != 0 {
		os.Exit(1)
	}
}

// includeResource makes the Kubernetes resource at path available to
// policies that use includeSpec, includeObjectMeta or includeTypeMeta.
func includeResource(ctx context.Context, path string) (context.Context, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	uo := &unstructured.Unstructured{}
	if err := yaml.Unmarshal(raw, uo); err != nil {
		return nil, err
	}
	for _, key := range []string{"metadata", "spec", "kind", "apiVersion"} {
		if _, ok := uo.Object[key]; !ok {
			return nil, fmt.Errorf("kubernetes resource is missing %s key", key)
		}
	}
	ctx = webhook.IncludeObjectMeta(ctx, uo.Object["metadata"])
	ctx = webhook.IncludeSpec(ctx, uo.Object["spec"])
	return webhook.IncludeTypeMeta(ctx, map[string]any{
		"kind":       uo.Object["kind"],
		"apiVersion": uo.Object["apiVersion"],
	}), nil
}
