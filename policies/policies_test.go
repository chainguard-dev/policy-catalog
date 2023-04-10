/*
Copyright 2022 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package chainguard_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/sigstore/policy-controller/pkg/apis/policy/v1alpha1"
	"github.com/sigstore/policy-controller/pkg/apis/policy/v1beta1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"knative.dev/pkg/apis"
	"sigs.k8s.io/yaml"
)

const (
	titleAnn     = "catalog.chainguard.dev/title"
	descAnn      = "catalog.chainguard.dev/description"
	labelAnn     = "catalog.chainguard.dev/labels"
	learnMoreAnn = "catalog.chainguard.dev/learnMoreLink"
)

var (
	requiredAnnotations = []string{titleAnn, descAnn, labelAnn}

	// cue and rego policies are considered the same.
	normalizedPathRegex = regexp.MustCompile(`(-)(cue|rego)(\.yaml)$`)

	uniqCheckers = []uniqChecker{
		func(cip *v1beta1.ClusterImagePolicy, path string) (attrName, attrValue, normalizedPath string) {
			// Name must be globally unique.
			return "name", cip.GetName(), path
		},
		func(cip *v1beta1.ClusterImagePolicy, path string) (attrName, attrValue, normalizedPath string) {
			// Title must be unique across policies. cue & rego policies are allowed (and should) have the same title.
			normalizedPath = normalizedPathRegex.ReplaceAllString(path, "$1%$3")
			return "title", cip.Annotations[titleAnn], normalizedPath
		},
		func(cip *v1beta1.ClusterImagePolicy, path string) (attrName, attrValue, normalizedPath string) {
			// Description must be unique across policies. cue & rego policies are allowed (and should) have the same title.
			normalizedPath = normalizedPathRegex.ReplaceAllString(path, "$1%$3")
			return "description", cip.Annotations[descAnn], normalizedPath
		},
	}
)

type uniqMap map[string]sets.Set[string]

type uniqChecker func(cip *v1beta1.ClusterImagePolicy, path string) (attrName, attrValue, normalizedPath string)

func TestPolicies(t *testing.T) {
	ctx := context.TODO()

	uniq := make(map[string]uniqMap)

	err := filepath.Walk(".",
		func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if strings.Contains(p, "testdata") {
				// Ignore policies inside `testdata` folders.
				return nil
			}

			if !strings.HasSuffix(p, ".yaml") {
				// Ignore non-yaml files.
				return nil
			}

			data, err := os.ReadFile(p)
			if err != nil {
				return fmt.Errorf("Error reading file %q: %w", p, err)
			}

			cip, warn, err := parsePolicy(ctx, string(data))
			if err != nil {
				return fmt.Errorf("Error parsing file %q: %w", p, err)
			}
			if warn != nil {
				t.Logf("WARNING: parsing file %q: %v", p, warn)
			}

			// Ensures the name of a policy matches its file name.
			_, file := path.Split(p)
			fileName := strings.TrimSuffix(file, filepath.Ext(file))
			if fileName != cip.Name {
				t.Errorf("Policy %q, name is invalid. Got: %q, wanted: %q", p, cip.Name, file)
			}

			// Ensures the name of cue or rego policies end with `cue` or `rego`.
			pt, err := getPolicyType(cip)
			if err != nil {
				t.Errorf("Policy %q, conflicting policy types: %s", p, err)
			}
			pts := ""
			if pt != "" {
				pts = "-" + pt
			}
			if !strings.HasSuffix(cip.Name, pt) {
				t.Errorf("Policy %q, name is invalid. Policy was detected as a %q policy. name is expected to end with %q", p, pt, pts)
			}

			// Keep track of fields that must be unique across all policies.
			for _, checker := range uniqCheckers {
				attrName, attrValue, normalizedPath := checker(cip, p)
				if uniq[attrName] == nil {
					uniq[attrName] = make(uniqMap, 1)
				}
				if uniq[attrName][attrValue] == nil {
					uniq[attrName][attrValue] = sets.New[string]()
				}
				uniq[attrName][attrValue] = uniq[attrName][attrValue].Insert(normalizedPath)
			}

			// Ensure all policies have the correct annotations set.
			for _, ann := range requiredAnnotations {
				if cip.Annotations[ann] == "" {
					t.Errorf("Policy %q, missing annotation %q", p, ann)
				}
			}

			// Ensure the learn more link is valid.
			learnMoreLink := cip.Annotations[learnMoreAnn]
			if learnMoreLink != "" {
				_, err := url.Parse(learnMoreLink)
				if err != nil {
					t.Errorf("Policy %q, invalid annotation %q: %v", p, learnMoreAnn, err)
				}
			}

			return nil
		})

	if err != nil {
		t.Fatal(err)
	}

	// Ensure uniqueness of attributes.
	for field, attributeToPath := range uniq {
		for name, paths := range attributeToPath {
			if len(paths) > 1 {
				t.Errorf("Found policies with duplicate %s %q in paths: %v", field, name, sets.List(paths))
			}
		}
	}
}

// parsePolicy returns a ClusterImagePolicy object
func parsePolicy(ctx context.Context, document string) (*v1beta1.ClusterImagePolicy, error, error) {
	obj, err := parse(ctx, document)
	if err != nil {
		return nil, nil, err
	}
	gv, err := schema.ParseGroupVersion(obj.GetAPIVersion())
	if err != nil {
		// Practically unstructured.Unstructured won't let this happen.
		return nil, nil, fmt.Errorf("error parsing apiVersion of: %w", err)
	}

	cip := &v1beta1.ClusterImagePolicy{}
	switch gv.WithKind(obj.GetKind()) {
	case v1alpha1.SchemeGroupVersion.WithKind("ClusterImagePolicy"):
		return nil, nil, fmt.Errorf("version v1alpha1 not supported")

	case v1beta1.SchemeGroupVersion.WithKind("ClusterImagePolicy"):
		// This is allowed, but we should convert things.
		if err := convert(obj, cip); err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, fmt.Errorf("Invalid policy version")
	}

	cip.SetDefaults(ctx)
	if err := cip.Validate(ctx); err != nil {
		if warnFE := err.Filter(apis.WarningLevel); warnFE != nil {
			return cip, warnFE, nil
		}
		return nil, nil, err
	}
	return cip, nil, nil
}

func parse(ctx context.Context, document string) (*unstructured.Unstructured, error) {
	obj := &unstructured.Unstructured{}
	if err := yaml.Unmarshal([]byte(strings.TrimSpace(document)), obj); err != nil {
		return nil, fmt.Errorf("decoding object: %w", err)
	}
	if obj.GetAPIVersion() == "" {
		return nil, apis.ErrMissingField("apiVersion")
	}
	if obj.GetName() == "" {
		return nil, apis.ErrMissingField("metadata.name")
	}
	return obj, nil
}

func convert(from interface{}, to runtime.Object) error {
	bs, err := json.Marshal(from)
	if err != nil {
		return fmt.Errorf("Marshal() = %w", err)
	}
	if err := json.Unmarshal(bs, to); err != nil {
		return fmt.Errorf("Unmarshal() = %w", err)
	}
	return nil
}

func getPolicyType(p *v1beta1.ClusterImagePolicy) (string, error) {
	lang := ""
	if p.Spec.Policy != nil {
		lang = p.Spec.Policy.Type
	}

	for _, ay := range p.Spec.Authorities {
		for _, a := range ay.Attestations {
			if a.Policy == nil {
				continue
			}

			if lang == "" {
				lang = a.Policy.Type
			}

			if lang != a.Policy.Type {
				return "", fmt.Errorf("policy %q has multiple types of policies. Found %q and %q", p.Name, lang, a.Policy.Type)
			}
		}
	}

	return lang, nil
}
