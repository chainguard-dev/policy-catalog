/*
Copyright 2022 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package test

import (
	"strings"
	"testing"
)

type Check func(t *testing.T, r *Result)

func All(checks ...Check) Check {
	return func(t *testing.T, r *Result) {
		for _, chk := range checks {
			chk(t, r)
		}
	}
}

func CheckWarning(msg string) Check {
	return func(t *testing.T, r *Result) {
		for _, warn := range r.Warnings {
			if strings.Contains(warn, msg) {
				return
			}
		}
		t.Errorf("Did not find warning containing %q in %v", msg, r.Warnings)
	}
}

func CheckError(msg string) Check {
	return func(t *testing.T, r *Result) {
		for _, err := range r.Errors {
			if strings.Contains(err, msg) {
				return
			}
		}
		t.Errorf("Did not find error containing %q in %v", msg, r.Errors)
	}
}

func NoWarnings(t *testing.T, r *Result) {
	if len(r.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", r.Warnings)
	}
}

func NoErrors(t *testing.T, r *Result) {
	if len(r.Errors) != 0 {
		t.Errorf("unexpected errors: %v", r.Errors)
	}
}
