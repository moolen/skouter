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

var _ = Describe("pod egress policies", Label("allow"), func() {

	var uid string
	BeforeEach(func() {
		defer GinkgoRecover()
		uid = uuid.New().String()
		err := k8s.Create(context.Background(), podEgressPolicy(uid, defaultLabels(uid), []string{"example.com"}, nil, nil))
		Expect(err).ToNot(HaveOccurred())

		err = k8s.Create(context.Background(), testPod(uid, defaultLabels(uid), false))
		Expect(err).ToNot(HaveOccurred())
		_, err = WaitForPodsRunning(clientSet, 1, "default", metav1.ListOptions{
			LabelSelector: "name=" + uid,
		})
		Expect(err).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		// do not clean up resources if we're in debug mode
		if CurrentGinkgoTestDescription().Failed && debugMode {
			return
		}
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

	It("allow pod egress with match, deny egress without match", func() {
		Eventually(func() error {
			_, err := ExecCmd(clientSet, restConfig, uid, "default", testExampleCom)
			return err
		}).WithTimeout(time.Second * 30).ShouldNot(HaveOccurred())

		Eventually(func() error {
			_, err := ExecCmd(clientSet, restConfig, uid, "default", testNYTimes)
			return err
		}).WithTimeout(time.Second * 30).Should(HaveOccurred())
	})

	It("allow pod egress after egress crd has been updated", func() {
		Eventually(func() error {
			_, err := ExecCmd(clientSet, restConfig, uid, "default", testExampleCom)
			return err
		}).WithTimeout(time.Second * 30).ShouldNot(HaveOccurred())

		err := k8s.Patch(context.Background(),
			podEgressPolicy(
				uid, defaultLabels(uid),
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
			_, err = ExecCmd(clientSet, restConfig, uid, "default", testNYTimes)
			return err
		}).WithTimeout(time.Second * 30).ShouldNot(HaveOccurred())
	})

	It("deny egress after egress rule has been removed", func() {
		Eventually(func() error {
			_, err := ExecCmd(clientSet, restConfig, uid, "default", testExampleCom)
			return err
		}).WithTimeout(time.Second * 30).ShouldNot(HaveOccurred())

		By("removing egress rules")
		err := k8s.Patch(context.Background(),
			podEgressPolicy(
				uid,
				defaultLabels(uid),
				[]string{"nytimes.com", "www.nytimes.com"},
				nil,
				nil,
			), crclient.Apply, crclient.FieldOwner("e2e"), crclient.ForceOwnership)
		Expect(err).ToNot(HaveOccurred())

		Eventually(func() string {
			out, _ := ExecCmd(clientSet, restConfig, uid, "default", testExampleCom)
			return out
		}).WithTimeout(time.Second * 30).WithPolling(time.Second).Should(ContainSubstring("download timed out"))
	})

	It("allow pod egress after egress cidr has been updated", func() {
		Eventually(func() error {
			_, err := ExecCmd(clientSet, restConfig, uid, "default", testExampleCom)
			return err
		}).WithTimeout(time.Second * 30).ShouldNot(HaveOccurred())

		Eventually(func() error {
			_, err := ExecCmd(clientSet, restConfig, uid, "default", testGitHub)
			return err
		}).WithTimeout(time.Second * 30).Should(HaveOccurred())

		err := k8s.Patch(context.Background(),
			podEgressPolicy(
				uid, defaultLabels(uid),
				nil,
				[]string{
					githubCIDR,
				},
				nil,
			), crclient.Apply, crclient.FieldOwner("e2e"), crclient.ForceOwnership)
		Expect(err).ToNot(HaveOccurred())

		Eventually(func() error {
			_, err = ExecCmd(clientSet, restConfig, uid, "default", testGitHub)
			return err
		}).WithTimeout(time.Second * 30).ShouldNot(HaveOccurred())
	})

	It("allow wildcard egress after crd has been updated", func() {
		Eventually(func() error {
			_, err := ExecCmd(clientSet, restConfig, uid, "default", testExampleCom)
			return err
		}).WithTimeout(time.Second * 30).ShouldNot(HaveOccurred())

		Eventually(func() error {
			_, err := ExecCmd(clientSet, restConfig, uid, "default", testWikiDE)
			return err
		}).WithTimeout(time.Second * 30).Should(HaveOccurred())

		err := k8s.Patch(context.Background(),
			podEgressPolicy(
				uid, defaultLabels(uid),
				nil,
				nil,
				[]string{wikiRegexp},
			), crclient.Apply, crclient.FieldOwner("e2e"), crclient.ForceOwnership)
		Expect(err).ToNot(HaveOccurred())

		for _, test := range []string{testWikiDE, testWikiEN} {
			Eventually(func() error {
				_, err = ExecCmd(clientSet, restConfig, uid, "default", test)
				return err
			}).WithTimeout(time.Second * 30).ShouldNot(HaveOccurred())
		}

		// remove rule again
		err = k8s.Patch(context.Background(),
			podEgressPolicy(
				uid, defaultLabels(uid),
				nil,
				nil,
				nil,
			), crclient.Apply, crclient.FieldOwner("e2e"), crclient.ForceOwnership)
		Expect(err).ToNot(HaveOccurred())

		for _, test := range []string{testWikiDE, testWikiEN} {
			Eventually(func() error {
				_, err = ExecCmd(clientSet, restConfig, uid, "default", test)
				return err
			}).WithTimeout(time.Second * 30).Should(HaveOccurred())
		}
	})

	It("pods with host networking must not be affected by egress policy with podSelector", func() {
		name := uid + "-hostnet"
		err := k8s.Create(context.Background(), testPod(name, defaultLabels(name), true))
		Expect(err).ToNot(HaveOccurred())
		_, err = WaitForPodsRunning(clientSet, 1, "default", metav1.ListOptions{
			LabelSelector: "name=" + name,
		})
		Expect(err).ToNot(HaveOccurred())

		for _, tc := range []string{testExampleCom, testNYTimes, testHTTPBin, testK8sRegistry} {
			_, err = ExecCmd(clientSet, restConfig, name, "default", tc)
			Expect(err).ToNot(HaveOccurred())
		}
	})
})

func podEgressPolicy(uid string, podLabels map[string]string, domains, cidrs, wildcards []string) *v1alpha1.Egress {
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
			PodSelector: &v1alpha1.Selector{
				MatchLabels: podLabels,
			},
			Rules: []v1alpha1.EgressRule{
				{
					Domains:   domains,
					CIDRs:     cidrs,
					Wildcards: wildcards,
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
