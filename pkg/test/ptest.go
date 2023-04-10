/*
Copyright 2022 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/sigstore/policy-controller/pkg/webhook"
	"k8s.io/apimachinery/pkg/util/wait"
)

type Result struct {
	Errors   []string              `json:"errors,omitempty"`
	Warnings []string              `json:"warnings,omitempty"`
	Result   *webhook.PolicyResult `json:"result"`
}

func Run(policy, image string, opts ...RunOption) (*Result, error) {
	t := &test{
		policy: policy,
		image:  image,
	}
	for _, opt := range opts {
		opt(t)
	}

	var result *Result

	err := wait.ExponentialBackoff(
		wait.Backoff{
			Duration: 1 * time.Second,
			Factor:   2.0,
			Jitter:   0.1,
			Steps:    5, // We'll try at most 5 times.
		},
		func() (bool, error) {
			var err error
			result, err = runTest(t)
			if err != nil {
				return false, err
			}

			for _, v := range result.Errors {
				// Retry when we get `TOOMANYREQUESTS: Rate exceeded` from ECS.
				if strings.Contains(v, "TOOMANYREQUESTS") {
					return false, nil
				}
			}
			return true, nil
		},
	)

	return result, err
}

func runTest(t *test) (*Result, error) {
	dir, err := os.MkdirTemp("", "policy-tester")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	cmd := exec.Command("policy-tester", t.args()...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("TUF_ROOT=%s", dir))
	buf := &bytes.Buffer{}
	cmd.Stdout = buf
	obuf := &bytes.Buffer{}
	cmd.Stderr = obuf

	// Ignore this error, since it errors on policy failures, which we want to
	// check in a structured way (below).
	_ = cmd.Run()

	r := &Result{}
	if err := json.Unmarshal(buf.Bytes(), r); err != nil {
		// When we hit a failure, dump the stderr for debugging.
		log.Printf("[%q %q]: %v", t.policy, t.image, obuf.String())
		return nil, err
	}
	return r, nil
}

type RunOption func(*test)

type test struct {
	policy string
	image  string

	resource string
}

func (t *test) args() (args []string) {
	args = []string{
		"-policy", t.policy,
		"-image", t.image,
	}
	if t.resource != "" {
		args = append(args,
			"-resource", t.resource,
		)
	}
	return args
}

func WithResource(resource string) RunOption {
	return func(t *test) {
		t.resource = resource
	}
}
