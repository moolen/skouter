package e2e

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	v1alpha1 "github.com/moolen/skouter/api"
	v1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	// nolint
	. "github.com/onsi/ginkgo/v2"
)

var Scheme = runtime.NewScheme()

func init() {
	_ = scheme.AddToScheme(Scheme)
	_ = v1alpha1.AddToScheme(Scheme)
	_ = apiextensionsv1.AddToScheme(Scheme)
}

// NewConfig loads and returns the kubernetes credentials from the environment.
// KUBECONFIG env var takes precedence and falls back to in-cluster config.
func NewConfig() (*rest.Config, *kubernetes.Clientset, crclient.Client) {
	var kubeConfig *rest.Config
	var err error
	kcPath := os.Getenv("KUBECONFIG")
	inCluster := os.Getenv("KUBERNETES_SERVICE_HOST")
	if inCluster == "" && kcPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			Fail(err.Error())
		}
		kcPath = filepath.Join(home, ".kube/config")
	}
	if kcPath != "" {
		kubeConfig, err = clientcmd.BuildConfigFromFlags("", kcPath)
		if err != nil {
			Fail(err.Error())
		}
	} else {
		kubeConfig, err = rest.InClusterConfig()
		if err != nil {
			Fail(err.Error())
		}
	}

	kubeClientSet, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		Fail(err.Error())
	}

	CRClient, err := crclient.New(kubeConfig, crclient.Options{Scheme: Scheme})
	if err != nil {
		Fail(err.Error())
	}

	return kubeConfig, kubeClientSet, CRClient
}

// WaitForPodsRunning waits for a given amount of time until a group of Pods is running in the given namespace.
func WaitForPodsRunning(kubeClientSet kubernetes.Interface, expectedReplicas int, namespace string, opts metav1.ListOptions) (*v1.PodList, error) {
	var pods *v1.PodList
	err := wait.PollImmediate(1*time.Second, time.Minute*5, func() (bool, error) {
		pl, err := kubeClientSet.CoreV1().Pods(namespace).List(context.TODO(), opts)
		if err != nil {
			return false, nil
		}

		r := 0
		for i := range pl.Items {
			if pl.Items[i].Status.Phase == v1.PodRunning {
				r++
			}
		}

		if r == expectedReplicas {
			pods = pl
			return true, nil
		}

		return false, nil
	})
	return pods, err
}

// ExecCmd exec command on specific pod and wait the command's output.
func ExecCmd(client kubernetes.Interface, config *rest.Config, podName, namespace string,
	command, stdin string, timeout time.Duration) (string, error) {
	cmd := []string{
		"sh",
		"-c",
		command,
	}

	req := client.CoreV1().RESTClient().Post().Resource("pods").Name(podName).
		Namespace(namespace).SubResource("exec")
	option := &v1.PodExecOptions{
		Command: cmd,
		Stdin:   true,
		Stdout:  true,
		Stderr:  true,
		TTY:     false,
	}
	req.VersionedParams(
		option,
		scheme.ParameterCodec,
	)
	exec, err := remotecommand.NewSPDYExecutor(config, "POST", req.URL())
	if err != nil {
		return "", err
	}
	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdin:  strings.NewReader(stdin),
		Stdout: &stdout,
		Stderr: &stderr,
		Tty:    false,
	})
	if err != nil {
		return stdout.String() + stderr.String(), fmt.Errorf("unable to exec stream: %w: \n%s\n%s", err, stdout.String(), stderr.String())
	}

	return stdout.String() + stderr.String(), nil
}
