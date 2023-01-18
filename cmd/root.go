package cmd

import (
	"fmt"
	"os"

	v1alpha1 "github.com/moolen/skouter/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/moolen/skouter/pkg/bpf"
	"github.com/moolen/skouter/pkg/egress"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	scheme = runtime.NewScheme()
	log    *logrus.Logger
)

func init() {
	_ = clientgoscheme.AddToScheme(scheme)
	_ = v1alpha1.AddToScheme(scheme)
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "skouter",
	Short: "cloud-native egress firewall",
	Long:  ``,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		log = logrus.New()
		lvl, err := logrus.ParseLevel(logLevel)
		if err != nil {
			logrus.Fatalf("unable to parse loglevel: %s", err.Error())
		}
		log.SetLevel(lvl)
	},
	Run: func(cmd *cobra.Command, args []string) {
		ctx := ctrl.SetupSignalHandler()
		log.Info("creating kubernetes client")
		var cfg *rest.Config
		var err error
		if kubeconfig != "" {
			cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		} else {
			cfg, err = rest.InClusterConfig()
		}
		if err != nil {
			log.Fatalf("unable to get in-cluster config: %s", err.Error())
		}
		mgr, err := ctrl.NewManager(cfg, manager.Options{
			Scheme: scheme,
		})
		if err != nil {
			log.Fatalf("unable to setup controller-runtime manager")
		}

		// this channel is used to indicate that the config
		// should be reloaded/changed.
		updateTicker := make(chan struct{})
		if err = egress.NewReconciler(mgr.GetClient(), log, scheme, updateTicker).
			SetupWithManager(mgr, controller.Options{}); err != nil {
			log.Fatalf("unable to setup egress reconciler")
		}
		if err != nil {
			log.Fatalf("unable to create ctrl manager")
		}

		clientSet, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			log.Fatalf("unable to create kubernetes client: %s", err.Error())
		}
		podWatch, err := clientSet.CoreV1().Pods("").Watch(ctx, metav1.ListOptions{
			FieldSelector: "spec.nodeName=" + nodeName,
		})
		if err != nil {
			log.Fatalf("unable to watch pods: %s", err.Error())
		}

		go func() {
			log.Infof("starting pod watcher")
			for {
				select {
				case ev := <-podWatch.ResultChan():
					if ev.Type == watch.Error || ev.Type == "" || ev.Object == nil {
						continue
					}
					updateTicker <- struct{}{}
				case <-ctx.Done():
					log.Infof("shutdown pod watcher")
					return
				}
			}
		}()

		log.Info("launching egress resource controller manager")
		go mgr.Start(ctx)

		bpfctrl, err := bpf.New(ctx, mgr.GetClient(), cgroupfs, bpffs, allowedDNS, userspaceDNSParser, log, updateTicker)
		if err != nil {
			log.Fatal(err)
		}
		defer bpfctrl.Close()
		log.Info("launching bpf controller")
		go bpfctrl.Run()

		<-ctx.Done()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var (
	nodeName           string
	logLevel           string
	kubeconfig         string
	cgroupfs           string
	bpffs              string
	allowedDNS         string
	userspaceDNSParser bool
)

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&logLevel, "loglevel", "INFO", "loglevel to use (debug, info, warn, error)")
	rootCmd.Flags().StringVar(&nodeName, "node-name", "", "")
	rootCmd.Flags().StringVar(&cgroupfs, "cgroupfs", "/sys/fs/cgroup/kubepods.slice", "")
	rootCmd.Flags().StringVar(&bpffs, "bpffs", "/sys/fs/bpf", "")
	rootCmd.Flags().StringVar(&allowedDNS, "allowed-dns", "10.96.0.10", "allowed dns server address")
	rootCmd.Flags().BoolVar(&userspaceDNSParser, "userspace-dns-parser", false, "parse dns packets in userspace")
	rootCmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "kubeconfig to use (out-of-cluster config)")
}

func initConfig() {
	viper.AutomaticEnv()
}
