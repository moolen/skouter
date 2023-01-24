/*
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
package e2e

import (
	"flag"
	"testing"

	// nolint
	. "github.com/onsi/ginkgo/v2"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	// nolint
	. "github.com/onsi/gomega"
)

var (
	k8s        crclient.Client
	clientSet  *kubernetes.Clientset
	restConfig *rest.Config
	debugMode  bool
)

func init() {
	flag.BoolVar(&debugMode, "debug", false, "enable test debug mode: no clean up will be run after tests to allow introspection.")
}

var _ = SynchronizedBeforeSuite(func() []byte {
	restConfig, clientSet, k8s = NewConfig()
	return nil
}, func([]byte) {
	// noop
})

func TestE2E(t *testing.T) {
	NewWithT(t)
	RegisterFailHandler(Fail)
	RunSpecs(t, "e2e suite", Label("e2e"))
}
