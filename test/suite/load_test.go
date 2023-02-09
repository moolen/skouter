package e2e

import (
	// nolint
	"context"
	"fmt"
	"time"

	v1alpha1 "github.com/moolen/skouter/api"
	. "github.com/onsi/ginkgo/v2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	// nolint
	. "github.com/onsi/gomega"
)

var (
	loadTestScript = `
	import http from 'k6/http';

	export default function () {
		http.get('http://httpbin01.default.svc.cluster.local/status/200');
		http.get('http://httpbin02.default.svc.cluster.local/status/200');
		http.get('http://httpbin03.default.svc.cluster.local/status/200');
		http.get('http://httpbin04.default.svc.cluster.local/status/200');
	}`
	HTTPBinBackends = []string{
		"httpbin01.default.svc.cluster.local",
		"httpbin02.default.svc.cluster.local",
		"httpbin03.default.svc.cluster.local",
		"httpbin04.default.svc.cluster.local",
	}
	loadTestDuration = time.Minute
)

var _ = Describe("load test", Label("load"), Ordered, func() {
	var podName string

	BeforeAll(func() {
		defer GinkgoRecover()
		podName = "k6-load-test"
		By("creating httpbin upstream endpoints")
		createHTTPBackend("httpbin01")
		createHTTPBackend("httpbin02")
		createHTTPBackend("httpbin03")
		createHTTPBackend("httpbin04")

		By("creating load test pod")
		err := k8s.Create(context.Background(), k6Pod(podName, defaultLabels(podName)))
		Expect(err).ToNot(HaveOccurred())
		_, err = WaitForPodsRunning(clientSet, 1, "default", metav1.ListOptions{
			LabelSelector: "name=" + podName,
		})
		Expect(err).ToNot(HaveOccurred())
	})

	AfterAll(func() {
		var podList v1.PodList
		err := k8s.List(context.Background(), &podList, crclient.MatchingLabels(matchTestWorkloads))
		Expect(err).ToNot(HaveOccurred())
		for _, po := range podList.Items {
			err = k8s.Delete(context.Background(), &po, crclient.GracePeriodSeconds(0))
			Expect(err).ToNot(HaveOccurred())
		}

		var svcList v1.ServiceList
		err = k8s.List(context.Background(), &svcList, crclient.MatchingLabels(matchTestWorkloads))
		Expect(err).ToNot(HaveOccurred())
		for _, po := range svcList.Items {
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

	AfterEach(func() {
		var egressList v1alpha1.EgressList
		err := k8s.List(context.Background(), &egressList, crclient.MatchingLabels(matchTestWorkloads))
		Expect(err).ToNot(HaveOccurred())
		for _, eg := range egressList.Items {
			err = k8s.Delete(context.Background(), &eg)
			Expect(err).ToNot(HaveOccurred())
		}
	})

	It("run load test with fixed domain", func() {
		By("creating egress policy")
		err := k8s.Create(context.Background(), hostEgressPolicy(podName, defaultLabels(podName), HTTPBinBackends, nil, nil))
		Expect(err).ToNot(HaveOccurred())

		done := make(chan struct{})
		go runLoadTest(podName, done)

		// while the test runs we want to restart the skouter pod every few seconds
		// and see that no connections drop
		for i := 0; i < 4; i++ {
			<-time.After(loadTestDuration / 4)
			var pl v1.PodList
			err = k8s.List(context.Background(), &pl, crclient.MatchingLabels(map[string]string{"app": "skouter"}))
			Expect(err).ToNot(HaveOccurred())
			By("deleting skouter pod")
			for _, po := range pl.Items {
				err = k8s.Delete(context.Background(), &po)
				Expect(err).ToNot(HaveOccurred())
			}
		}
		<-done
	})

	It("run load test with regex domain", func() {
		By("creating egress policy")
		err := k8s.Create(context.Background(), hostEgressPolicy(podName, defaultLabels(podName), nil, nil, []string{
			".*default.svc.cluster.local",
		}))
		Expect(err).ToNot(HaveOccurred())

		done := make(chan struct{})
		go runLoadTest(podName, done)

		// while the test runs we want to restart the skouter pod every few seconds
		// and see that no connections drop
		for i := 0; i < 4; i++ {
			<-time.After(loadTestDuration / 4)
			var pl v1.PodList
			err = k8s.List(context.Background(), &pl, crclient.MatchingLabels(map[string]string{"app": "skouter"}))
			Expect(err).ToNot(HaveOccurred())
			for _, po := range pl.Items {
				By("deleting skouter pod")
				err = k8s.Delete(context.Background(), &po)
				Expect(err).ToNot(HaveOccurred())
			}
		}
		<-done
	})

})

func runLoadTest(k6PodName string, done chan struct{}) {
	defer close(done)
	defer GinkgoRecover()
	By("Starting load test")
	cmd := fmt.Sprintf("k6 --vus 10 -d %s --rps 10 run -q -w --no-usage-report -", loadTestDuration)
	out, err := ExecCmd(clientSet, restConfig, k6PodName, "default", cmd, loadTestScript, loadTestDuration+time.Minute)

	Expect(err).ToNot(HaveOccurred())
	Expect(out).To(ContainSubstring("http_req_failed................: 0.00%"))
}

func createHTTPBackend(name string) {
	labels := defaultLabels(name)
	po := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			Labels:    labels,
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:            "httpbin",
					Image:           "mccutchen/go-httpbin:v2.5.4",
					ImagePullPolicy: v1.PullIfNotPresent,
				},
			},
		},
	}
	err := k8s.Create(context.Background(), po)
	Expect(err).ToNot(HaveOccurred())
	_, err = WaitForPodsRunning(clientSet, 1, "default", metav1.ListOptions{
		LabelSelector: "name=" + name,
	})
	Expect(err).ToNot(HaveOccurred())

	svc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			Labels:    labels,
		},
		Spec: v1.ServiceSpec{
			Selector: labels,
			Ports: []v1.ServicePort{
				{
					Name:       "http",
					Port:       80,
					TargetPort: intstr.FromInt(8080),
				},
			},
		},
	}
	err = k8s.Create(context.Background(), svc)
	Expect(err).ToNot(HaveOccurred())

}

func k6Pod(name string, labels map[string]string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			Labels:    labels,
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:            "k6",
					Image:           "loadimpact/k6:0.42.0",
					ImagePullPolicy: v1.PullIfNotPresent,
					Command:         []string{"/bin/sleep", "3600"},
				},
			},
		},
	}
}
