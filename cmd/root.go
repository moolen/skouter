package cmd

import (
	"fmt"
	"net/http"
	"os"

	v1alpha1 "github.com/moolen/skouter/api"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/moolen/skouter/pkg/bpf"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	// enable profiling
	_ "net/http/pprof"
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
		cfg := kubeConfig()

		log.Info("launching egress resource controller manager")

		reg := prometheus.NewRegistry()
		bpfctrl, err := bpf.New(ctx,
			cfg,
			cgroupfs,
			bpffs,
			nodeName,
			nodeIP,
			cacheStoragePath,
			allowedDNS,
			auditMode,
			log,
			reg)
		if err != nil {
			log.Fatal(err)
		}
		defer bpfctrl.Close()
		log.Info("launching bpf controller")
		go func() {
			err := bpfctrl.Run()
			if err != nil {
				log.Fatalf("bpf controller failed to run: %s", err.Error())
			}
		}()
		http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
		go func() {
			err := http.ListenAndServe(":3000", nil)
			if err != nil {
				log.Error(err)
			}
		}()

		<-ctx.Done()
	},
}

func kubeConfig() *rest.Config {
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
	return cfg
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
	nodeName         string
	nodeIP           string
	cacheStoragePath string
	auditMode        bool
	logLevel         string
	kubeconfig       string
	cgroupfs         string
	bpffs            string
	allowedDNS       []string
)

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&logLevel, "loglevel", "INFO", "loglevel to use (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&cacheStoragePath, "cache-storage-path", "/var/run/skouter/cache", "path to the skouter cache dir.")
	rootCmd.PersistentFlags().StringVar(&bpffs, "bpffs", "/host/sys/fs/bpf", "")
	rootCmd.Flags().StringVar(&nodeName, "node-name", "", "")
	rootCmd.Flags().StringVar(&nodeIP, "node-ip", "", "ip address of this node. Used to filter egress traffic on the host namespace.")
	rootCmd.Flags().BoolVar(&auditMode, "audit-mode", false, "enable audit mode - no actual blocking will be done. This must be specified on start-up and can not be changed during runtime. Metrics `audit_blocked_addr` will contain the IPs egressing")
	rootCmd.Flags().StringVar(&cgroupfs, "cgroupfs", "/sys/fs/cgroup/kubepods.slice", "")
	rootCmd.Flags().StringArrayVar(&allowedDNS, "allowed-dns", []string{"10.96.0.10"}, "allowed dns server address")
	rootCmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "kubeconfig to use (out-of-cluster config)")
}

func initConfig() {
	viper.AutomaticEnv()
}
