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

	"github.com/moolen/skouter/pkg/controller"
	"github.com/moolen/skouter/pkg/log"
	"github.com/spf13/cobra"

	"github.com/spf13/viper"

	// enable profiling
	_ "net/http/pprof"
)

var (
	scheme = runtime.NewScheme()
	logger = log.DefaultLogger
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
		log.WithV(verbosity)
	},
	Run: func(cmd *cobra.Command, args []string) {
		ctx := ctrl.SetupSignalHandler()
		logger.Info("creating kubernetes client")
		cfg := kubeConfig()

		logger.Info("launching egress resource controller manager")

		bpfctrl, err := controller.New(ctx,
			cfg,
			cgroupfs,
			bpffs,
			nodeName,
			nodeIP,
			cacheStoragePath,
			allowedDNS,
			auditMode)
		if err != nil {
			logger.Error(err, "unable to create controller")
			panic(err)
		}
		defer bpfctrl.Close()
		logger.Info("launching bpf controller")
		go func() {
			err := bpfctrl.Run()
			if err != nil {
				logger.Error(err, "bpf controller failed to run")
				panic(err)
			}
		}()
		http.Handle("/metrics", promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{}))
		go func() {
			err := http.ListenAndServe(":3000", nil)
			if err != nil {
				logger.Error(err, "unable to listen http")
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
		logger.Error(err, "unable to get in-cluster config")
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
	verbosity        int
	kubeconfig       string
	cgroupfs         string
	bpffs            string
	allowedDNS       []string
)

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().IntVarP(&verbosity, "verbosity", "v", 0, "verbosity level to use")
	rootCmd.PersistentFlags().StringVar(&cacheStoragePath, "cache-storage-path", "/var/run/skouter/cache", "path to the skouter cache dir.")
	rootCmd.PersistentFlags().StringVar(&bpffs, "bpffs", "/host/sys/fs/bpf", "")
	rootCmd.PersistentFlags().StringVar(&nodeName, "node-name", os.Getenv("NODE_NAME"), "")
	rootCmd.PersistentFlags().StringVar(&nodeIP, "node-ip", os.Getenv("NODE_IP"), "ip address of this node. Used to filter egress traffic on the host namespace.")
	rootCmd.Flags().BoolVar(&auditMode, "audit-mode", false, "enable audit mode - no actual blocking will be done. This must be specified on start-up and can not be changed during runtime. Metrics `audit_blocked_addr` will contain the IPs egressing")
	rootCmd.Flags().StringVar(&cgroupfs, "cgroupfs", "/host/sys/fs/cgroup/kubepods.slice", "")
	rootCmd.PersistentFlags().StringArrayVar(&allowedDNS, "allowed-dns", []string{"10.96.0.10"}, "allowed dns server address")
	rootCmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "kubeconfig to use (out-of-cluster config)")
}

func initConfig() {
	viper.AutomaticEnv()
}
