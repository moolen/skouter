package log

import (
	"k8s.io/klog/v2"
)

var DefaultLogger *klog.Logger

func init() {
	log := klog.NewKlogr()
	DefaultLogger = &log
}
