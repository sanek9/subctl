/*
SPDX-License-Identifier: Apache-2.0

Copyright Contributors to the Submariner project.

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

package diagnose

import (
	"context"
	"strings"

	"github.com/pkg/errors"
	"github.com/submariner-io/admiral/pkg/names"
	"github.com/submariner-io/admiral/pkg/reporter"
	"github.com/submariner-io/subctl/pkg/cluster"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ciliumCNI matches github.com/submariner-io/submariner/pkg/cni.Cilium.
// Inline until that constant is in subctl's released submariner dependency.
const ciliumCNI = "cilium"

const (
	ciliumConfigMapName     = "cilium-config"
	ciliumCMTLSSecretName   = "submariner-cilium-cm-tls"
	ciliumClusterMeshSecret = "cilium-clustermesh"
	ciliumCMRemoteName      = "submariner"
	ciliumCMListenURLEnv    = "SUBMARINER_CILIUM_CM_LISTEN_URL"
)

func checkCiliumClusterMeshPublisher(ctx context.Context, info *cluster.Info, status reporter.Interface) error {
	if !strings.EqualFold(info.Submariner.Status.NetworkPlugin, ciliumCNI) {
		return nil
	}

	status.Start("Cilium CNI detected, checking ClusterMesh-shaped publisher wiring")
	defer status.End()

	tracker := reporter.NewTracker(status)
	client := info.ClientProducer.ForKubernetes()

	checkCiliumClusterID(ctx, client, tracker)
	checkCiliumCMTLSSecret(ctx, client, info.Submariner.Namespace, tracker)
	checkCiliumClusterMeshPeer(ctx, client, tracker)
	checkCiliumCMRouteAgentEnv(ctx, client, info.Submariner.Namespace, tracker)

	if tracker.HasFailures() {
		return errors.New("failures while diagnosing Cilium CNI publisher wiring")
	}

	status.Success("Cilium ClusterMesh-shaped publisher prerequisites look OK")

	return nil
}

func checkCiliumClusterID(ctx context.Context, client kubernetes.Interface, status reporter.Interface) {
	cm, err := client.CoreV1().ConfigMaps(metav1.NamespaceSystem).Get(ctx, ciliumConfigMapName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			status.Failure("ConfigMap %q not found in %q; cannot validate Cilium cluster-id",
				ciliumConfigMapName, metav1.NamespaceSystem)

			return
		}

		status.Failure("Error reading ConfigMap %q: %v", ciliumConfigMapName, err)

		return
	}

	clusterID := cm.Data["cluster-id"]
	clusterName := cm.Data["cluster-name"]

	if clusterID == "" || clusterID == "0" {
		status.Failure("cilium-config cluster-id is %q; set to 1..255 for the ClusterMesh-shaped publisher",
			clusterID)
	}

	if clusterName == "" || clusterName == "default" {
		status.Failure("cilium-config cluster-name is %q; set a non-default name for ClusterMesh",
			clusterName)
	}
}

func checkCiliumCMTLSSecret(ctx context.Context, client kubernetes.Interface, namespace string, status reporter.Interface) {
	if namespace == "" {
		namespace = metav1.NamespaceDefault
	}

	secret, err := client.CoreV1().Secrets(namespace).Get(ctx, ciliumCMTLSSecretName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			status.Failure("Secret %q not found in namespace %q (operator should create it when NetworkPlugin is cilium)",
				ciliumCMTLSSecretName, namespace)

			return
		}

		status.Failure("Error reading Secret %q: %v", ciliumCMTLSSecretName, err)

		return
	}

	for _, key := range []string{"ca.crt", "tls.crt", "tls.key", "client.crt", "client.key"} {
		if len(secret.Data[key]) == 0 {
			status.Failure("Secret %q is missing key %q", ciliumCMTLSSecretName, key)
		}
	}
}

func checkCiliumClusterMeshPeer(ctx context.Context, client kubernetes.Interface, status reporter.Interface) {
	secret, err := client.CoreV1().Secrets(metav1.NamespaceSystem).Get(ctx, ciliumClusterMeshSecret, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			status.Failure("Secret %q not found in %q; operator should merge the Submariner peer",
				ciliumClusterMeshSecret, metav1.NamespaceSystem)

			return
		}

		status.Failure("Error reading Secret %q: %v", ciliumClusterMeshSecret, err)

		return
	}

	required := []string{
		ciliumCMRemoteName,
		ciliumCMRemoteName + ".etcd-client-ca.crt",
		ciliumCMRemoteName + ".etcd-client.crt",
		ciliumCMRemoteName + ".etcd-client.key",
	}

	for _, key := range required {
		if len(secret.Data[key]) == 0 {
			status.Failure("cilium-clustermesh is missing peer key %q", key)
		}
	}
}

func checkCiliumCMRouteAgentEnv(ctx context.Context, client kubernetes.Interface, namespace string, status reporter.Interface) {
	if namespace == "" {
		namespace = metav1.NamespaceDefault
	}

	routeAgent, err := client.AppsV1().DaemonSets(namespace).Get(ctx, names.RouteAgentComponent, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			status.Failure("route-agent DaemonSet %q not found in namespace %q",
				names.RouteAgentComponent, namespace)

			return
		}

		status.Failure("Error reading route-agent DaemonSet: %v", err)

		return
	}

	if len(routeAgent.Spec.Template.Spec.Containers) == 0 {
		status.Failure("route-agent DaemonSet has no containers")
		return
	}

	foundListen := false
	foundTLSVol := false

	for _, e := range routeAgent.Spec.Template.Spec.Containers[0].Env {
		if e.Name == ciliumCMListenURLEnv {
			foundListen = true
			break
		}
	}

	for i := range routeAgent.Spec.Template.Spec.Volumes {
		if routeAgent.Spec.Template.Spec.Volumes[i].Name == "cilium-cm-tls" {
			foundTLSVol = true
			break
		}
	}

	if !foundListen {
		status.Failure("route-agent is missing env %s (operator should set it for Cilium)",
			ciliumCMListenURLEnv)
	}

	if !foundTLSVol {
		status.Failure("route-agent is missing volume cilium-cm-tls")
	}
}
