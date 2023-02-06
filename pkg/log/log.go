package log

import (
	"strconv"

	"github.com/go-logr/logr"
	zzap "go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var DefaultLogger logr.Logger

type Level struct {
	l int8
}

var level = &Level{l: 0}

func (l Level) Enabled(lvl zapcore.Level) bool {
	ll := lvl.Get()
	return int(ll.(zapcore.Level)) >= int(l.l)
}

func (l Level) String() string {
	return strconv.Itoa(int(l.l))
}

func WithV(verbosity int) {
	level.l = int8(-1 * verbosity)
}

func init() {
	enc := zzap.NewProductionEncoderConfig()
	enc.LevelKey = "verbosity"
	enc.EncodeLevel = func(l zapcore.Level, pae zapcore.PrimitiveArrayEncoder) {
		pae.AppendString(strconv.Itoa(int(-1 * l)))
	}
	log := zap.New(zap.Level(level), zap.Encoder(zapcore.NewJSONEncoder(enc)))
	DefaultLogger = log
}
