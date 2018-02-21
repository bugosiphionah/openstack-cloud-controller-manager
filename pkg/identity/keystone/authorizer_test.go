/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package keystone

import (
	"testing"

	"os"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

func TestAuthorizer(t *testing.T) {

	authUrl := os.Getenv("OS_AUTH_URL")

	provider, _ := openstack.NewClient(authUrl)
	cli := &gophercloud.ServiceClient{
		ProviderClient: provider,
		Endpoint:       authUrl,
	}
	path := os.Getenv("OS_POLICY_PATH")
	policy, _ := NewFromFile(path)
	authz := NewAuthorizer(authUrl, cli, policy).(*KeystoneAuthorizer)

	node0 := &user.DefaultInfo{Name: "system:node:node0", Groups: []string{"system:nodes"}}

	tests := []struct {
		name   string
		attrs  authorizer.AttributesRecord
		expect authorizer.Decision
	}{
		{
			name:   "allowed configmap",
			attrs:  authorizer.AttributesRecord{User: node0, ResourceRequest: true, Verb: "get", Resource: "configmaps", Name: "configmap0-pod0-node0", Namespace: "ns0"},
			expect: authorizer.DecisionAllow,
		},
		{
			name:   "allowed secret via pod",
			attrs:  authorizer.AttributesRecord{User: node0, ResourceRequest: true, Verb: "get", Resource: "secrets", Name: "secret0-pod0-node0", Namespace: "ns0"},
			expect: authorizer.DecisionAllow,
		},
		{
			name:   "allowed shared secret via pod",
			attrs:  authorizer.AttributesRecord{User: node0, ResourceRequest: true, Verb: "get", Resource: "secrets", Name: "secret0-shared", Namespace: "ns0"},
			expect: authorizer.DecisionAllow,
		},
		{
			name:   "allowed shared secret via pvc",
			attrs:  authorizer.AttributesRecord{User: node0, ResourceRequest: true, Verb: "get", Resource: "secrets", Name: "secret-pv0-pod0-node0-ns0", Namespace: "ns0"},
			expect: authorizer.DecisionAllow,
		},
		{
			name:   "allowed pvc",
			attrs:  authorizer.AttributesRecord{User: node0, ResourceRequest: true, Verb: "get", Resource: "persistentvolumeclaims", Name: "pvc0-pod0-node0", Namespace: "ns0"},
			expect: authorizer.DecisionAllow,
		},
		{
			name:   "allowed pv",
			attrs:  authorizer.AttributesRecord{User: node0, ResourceRequest: true, Verb: "get", Resource: "persistentvolumes", Name: "pv0-pod0-node0-ns0", Namespace: ""},
			expect: authorizer.DecisionAllow,
		},

		{
			name:   "disallowed configmap",
			attrs:  authorizer.AttributesRecord{User: node0, ResourceRequest: true, Verb: "get", Resource: "configmaps", Name: "configmap0-pod0-node1", Namespace: "ns0"},
			expect: authorizer.DecisionNoOpinion,
		},
		{
			name:   "disallowed secret via pod",
			attrs:  authorizer.AttributesRecord{User: node0, ResourceRequest: true, Verb: "get", Resource: "secrets", Name: "secret0-pod0-node1", Namespace: "ns0"},
			expect: authorizer.DecisionNoOpinion,
		},
		{
			name:   "disallowed shared secret via pvc",
			attrs:  authorizer.AttributesRecord{User: node0, ResourceRequest: true, Verb: "get", Resource: "secrets", Name: "secret-pv0-pod0-node1-ns0", Namespace: "ns0"},
			expect: authorizer.DecisionNoOpinion,
		},
		{
			name:   "disallowed pvc",
			attrs:  authorizer.AttributesRecord{User: node0, ResourceRequest: true, Verb: "get", Resource: "persistentvolumeclaims", Name: "pvc0-pod0-node1", Namespace: "ns0"},
			expect: authorizer.DecisionNoOpinion,
		},
		{
			name:   "disallowed pv",
			attrs:  authorizer.AttributesRecord{User: node0, ResourceRequest: true, Verb: "get", Resource: "persistentvolumes", Name: "pv0-pod0-node1-ns0", Namespace: ""},
			expect: authorizer.DecisionNoOpinion,
		},
		{
			name:   "disallowed attachment - no relationship",
			attrs:  authorizer.AttributesRecord{User: node0, ResourceRequest: true, Verb: "get", Resource: "volumeattachments", APIGroup: "storage.k8s.io", Name: "attachment0-node1"},
			expect: authorizer.DecisionNoOpinion,
		},
		{
			name:   "disallowed attachment - feature disabled",
			attrs:  authorizer.AttributesRecord{User: node0, ResourceRequest: true, Verb: "get", Resource: "volumeattachments", APIGroup: "storage.k8s.io", Name: "attachment0-node0"},
			expect: authorizer.DecisionNoOpinion,
		},
		{
			name:   "allowed attachment - feature enabled",
			attrs:  authorizer.AttributesRecord{User: node0, ResourceRequest: true, Verb: "get", Resource: "volumeattachments", APIGroup: "storage.k8s.io", Name: "attachment0-node0"},
			expect: authorizer.DecisionAllow,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			decision, _, _ := authz.Authorize(tc.attrs)
			if decision != tc.expect {
				t.Errorf("expected %v, got %v", tc.expect, decision)
			}
		})
	}
}
