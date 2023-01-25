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

var _ = Describe("host egress policies", Label("allow"), func() {

	var uid string
	BeforeEach(func() {
		defer GinkgoRecover()
		uid = uuid.New().String()
		err := k8s.Create(context.Background(), hostEgressPolicyWithDomains(uid, defaultLabels(uid), []string{"example.com"}))
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

	FIt("allow host egress with match, deny egress without match", func() {
		Eventually(func() error {
			_, err := ExecCmd(clientSet, restConfig, uid, "default", testExampleCom)
			return err
		}).WithTimeout(time.Second * 30).ShouldNot(HaveOccurred())

		for _, test := range []string{testNYTimes, testK8sRegistry, testHTTPBin} {
			Eventually(func() error {
				_, err := ExecCmd(clientSet, restConfig, uid, "default", test)
				return err
			}).WithTimeout(time.Second * 30).Should(HaveOccurred())
		}
	})
})

func hostEgressPolicyWithDomains(uid string, nodeLabels map[string]string, domains []string) *v1alpha1.Egress {
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
					Domains: domains,
				},
				{
					Domains: []string{
						"registry-1.docker.io",
						"download.docker.com",
						"registry.k8s.io",
					},
				},
			},
		},
	}
}
