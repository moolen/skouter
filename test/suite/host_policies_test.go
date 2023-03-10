package e2e

import (
	// nolint
	"context"
	"time"

	"github.com/google/uuid"
	v1alpha1 "github.com/moolen/skouter/api"
	. "github.com/onsi/ginkgo/v2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	// nolint
	. "github.com/onsi/gomega"
)

const (
	testExampleCom  = "wget --no-check-certificate -T 3 -O /dev/null example.com"
	testNYTimes     = "wget --no-check-certificate -T 3 -O /dev/null nytimes.com"
	testGitHub      = "wget --no-check-certificate -T 3 -O /dev/null github.com"
	testHTTPBin     = "wget --no-check-certificate -T 3 -O /dev/null httpbin.org"
	testK8sRegistry = "wget --no-check-certificate -T 3 -O /dev/null registry.k8s.io"
	testWikiDE      = "wget --no-check-certificate -T 3 -O /dev/null de.wikipedia.org"
	testWikiEN      = "wget --no-check-certificate -T 3 -O /dev/null en.wikipedia.org"

	githubCIDR = "140.82.121.3/24"
	wikiRegexp = ".*.wikipedia.org"
)

var (
	matchTestWorkloads = map[string]string{"e2e": "test"}
)

var _ = Describe("host egress policies", Label("host"), func() {

	var uid string
	BeforeEach(func() {
		defer GinkgoRecover()
		uid = uuid.New().String()
		err := k8s.Create(context.Background(), hostEgressPolicy(uid, map[string]string{}, []string{"example.com"}, nil, nil))
		Expect(err).ToNot(HaveOccurred())
		By("creating pod under test")
		err = k8s.Create(context.Background(), testPod(uid, defaultLabels(uid), true))
		Expect(err).ToNot(HaveOccurred())
		_, err = WaitForPodsRunning(clientSet, 1, "default", metav1.ListOptions{
			LabelSelector: "name=" + uid,
		})
		Expect(err).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		var podList v1.PodList
		err := k8s.List(context.Background(), &podList, crclient.MatchingLabels(matchTestWorkloads))
		Expect(err).ToNot(HaveOccurred())
		for _, po := range podList.Items {
			err = k8s.Delete(context.Background(), &po, crclient.GracePeriodSeconds(0))
			Expect(err).ToNot(HaveOccurred())
		}

		var egressList v1alpha1.EgressList
		err = k8s.List(context.Background(), &egressList, crclient.MatchingLabels(matchTestWorkloads))
		Expect(err).ToNot(HaveOccurred())
		for _, eg := range egressList.Items {
			err = k8s.Delete(context.Background(), &eg)
			Expect(err).ToNot(HaveOccurred())
		}
	})

	It("allow host egress with match, deny egress without match", func() {
		Eventually(func() error {
			_, err := ExecCmd(clientSet, restConfig, uid, "default", testExampleCom, "", time.Second*10)
			return err
		}).WithTimeout(testTimeout).ShouldNot(HaveOccurred())

		for _, test := range []string{testNYTimes, testK8sRegistry, testHTTPBin} {
			Eventually(func() error {
				_, err := ExecCmd(clientSet, restConfig, uid, "default", test, "", time.Second*10)
				return err
			}).WithTimeout(testTimeout).Should(HaveOccurred())
		}
	})

	It("allow host egress with CIDR", func() {
		Eventually(func() error {
			_, err := ExecCmd(clientSet, restConfig, uid, "default", testGitHub, "", time.Second*10)
			return err
		}).WithTimeout(testTimeout).Should(HaveOccurred())

		err := k8s.Patch(context.Background(),
			hostEgressPolicy(
				uid, map[string]string{},
				nil,
				[]string{
					githubCIDR,
				},
				nil,
			), crclient.Apply, crclient.FieldOwner("e2e"), crclient.ForceOwnership)
		Expect(err).ToNot(HaveOccurred())

		Eventually(func() error {
			_, err := ExecCmd(clientSet, restConfig, uid, "default", testGitHub, "", time.Second*10)
			return err
		}).WithTimeout(testTimeout).ShouldNot(HaveOccurred())
	})

	It("allow host egress after egress crd has been updated", func() {
		Eventually(func() error {
			_, err := ExecCmd(clientSet, restConfig, uid, "default", testExampleCom, "", testTimeout)
			return err
		}).WithTimeout(testTimeout).ShouldNot(HaveOccurred())

		err := k8s.Patch(context.Background(),
			hostEgressPolicy(
				uid, map[string]string{},
				[]string{
					"example.com",
					"nytimes.com",
					"www.nytimes.com",
				},
				nil,
				nil,
			), crclient.Apply, crclient.FieldOwner("e2e"), crclient.ForceOwnership)
		Expect(err).ToNot(HaveOccurred())

		Eventually(func() error {
			_, err = ExecCmd(clientSet, restConfig, uid, "default", testNYTimes, "", testTimeout)
			return err
		}).WithTimeout(testTimeout).ShouldNot(HaveOccurred())
	})

	It("deny host egress after egress rule has been removed", func() {
		Eventually(func() error {
			_, err := ExecCmd(clientSet, restConfig, uid, "default", testExampleCom, "", testTimeout)
			return err
		}).WithTimeout(testTimeout).ShouldNot(HaveOccurred())

		By("removing egress rules")
		err := k8s.Patch(context.Background(),
			hostEgressPolicy(
				uid,
				map[string]string{},
				[]string{"nytimes.com", "www.nytimes.com"},
				nil,
				nil,
			), crclient.Apply, crclient.FieldOwner("e2e"), crclient.ForceOwnership)
		Expect(err).ToNot(HaveOccurred())

		Eventually(func() error {
			_, err := ExecCmd(clientSet, restConfig, uid, "default", testExampleCom, "", testTimeout)
			return err
		}).WithTimeout(testTimeout).WithPolling(time.Second).Should(HaveOccurred())
	})

	It("allow pod egress after egress cidr has been updated", func() {
		Eventually(func() error {
			_, err := ExecCmd(clientSet, restConfig, uid, "default", testExampleCom, "", testTimeout)
			return err
		}).WithTimeout(testTimeout).ShouldNot(HaveOccurred())

		Eventually(func() error {
			_, err := ExecCmd(clientSet, restConfig, uid, "default", testGitHub, "", testTimeout)
			return err
		}).WithTimeout(testTimeout).Should(HaveOccurred())

		err := k8s.Patch(context.Background(),
			hostEgressPolicy(
				uid, map[string]string{},
				nil,
				[]string{
					githubCIDR,
				},
				nil,
			), crclient.Apply, crclient.FieldOwner("e2e"), crclient.ForceOwnership)
		Expect(err).ToNot(HaveOccurred())

		Eventually(func() error {
			_, err = ExecCmd(clientSet, restConfig, uid, "default", testGitHub, "", testTimeout)
			return err
		}).WithTimeout(testTimeout).ShouldNot(HaveOccurred())
	})

	It("allow regex egress after crd has been updated", func() {
		Eventually(func() error {
			_, err := ExecCmd(clientSet, restConfig, uid, "default", testExampleCom, "", testTimeout)
			return err
		}).WithTimeout(testTimeout).ShouldNot(HaveOccurred())

		Eventually(func() error {
			_, err := ExecCmd(clientSet, restConfig, uid, "default", testWikiDE, "", testTimeout)
			return err
		}).WithTimeout(testTimeout).Should(HaveOccurred())

		err := k8s.Patch(context.Background(),
			hostEgressPolicy(
				uid, map[string]string{},
				nil,
				nil,
				[]string{wikiRegexp},
			), crclient.Apply, crclient.FieldOwner("e2e"), crclient.ForceOwnership)
		Expect(err).ToNot(HaveOccurred())

		for _, test := range []string{testWikiDE, testWikiEN} {
			Eventually(func() error {
				_, err = ExecCmd(clientSet, restConfig, uid, "default", test, "", testTimeout)
				return err
			}).WithTimeout(testTimeout).ShouldNot(HaveOccurred())
		}

		// remove rule again
		err = k8s.Patch(context.Background(),
			hostEgressPolicy(
				uid, map[string]string{},
				nil,
				nil,
				nil,
			), crclient.Apply, crclient.FieldOwner("e2e"), crclient.ForceOwnership)
		Expect(err).ToNot(HaveOccurred())

		for _, test := range []string{testWikiDE, testWikiEN} {
			Eventually(func() error {
				_, err = ExecCmd(clientSet, restConfig, uid, "default", test, "", testTimeout)
				return err
			}).WithTimeout(testTimeout).WithPolling(time.Second).Should(HaveOccurred())
		}
	})
})

func hostEgressPolicy(uid string, nodeLabels map[string]string, domains []string, cidrs []string, fqdns []string) *v1alpha1.Egress {
	return &v1alpha1.Egress{
		TypeMeta: metav1.TypeMeta{
			Kind:       v1alpha1.EgressKind,
			APIVersion: v1alpha1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      uid,
			Namespace: "default",
			Labels:    defaultLabels(uid),
		},
		Spec: v1alpha1.EgressSpec{
			NodeSelector: &v1alpha1.Selector{
				MatchLabels: nodeLabels,
			},
			Rules: []v1alpha1.EgressRule{
				{
					CIDRs:   cidrs,
					Domains: domains,
				},
				{
					Domains: []string{
						"registry-1.docker.io",
						"download.docker.com",
						"registry.k8s.io",
					},
					IPs:  controlPlaneAddrs,
					FQDN: fqdns,
				},
			},
		},
	}
}

func defaultLabels(name string) map[string]string {
	defaults := map[string]string{
		"name": name,
	}
	for k, v := range matchTestWorkloads {
		defaults[k] = v
	}
	return defaults
}

func testPod(name string, labels map[string]string, hostNetwork bool) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			Labels:    labels,
		},
		Spec: v1.PodSpec{
			HostNetwork: hostNetwork,
			Containers: []v1.Container{
				{
					Name:            "test",
					Image:           "alpine:3.16", // 3.16 needed for older openssl version to support SSL DPI
					ImagePullPolicy: v1.PullIfNotPresent,
					Command:         []string{"/bin/sleep", "3600"},
				},
			},
		},
	}
}
