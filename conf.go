package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/go-playground/validator"
	"github.com/spf13/viper"
)

type Conf struct {
	Proxy ProxyConf `mapstructure:"proxy"`
	Log   LogConf   `mapstructure:"log"`
}
type ProxyConf struct {
	Port int `mapstructure:"port" validate:"required"`
}
type LogConf struct {
	InfoPath  string `mapstructure:"info_path"`
	ErrorPath string `mapstructure:"error_path"`
}

func ReadConf() (*Conf, error) {
	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.WatchConfig()
	if err := v.ReadInConfig(); err != nil {
		return nil, err
	}
	conf := &Conf{}
	if err := v.Unmarshal(conf); err != nil {
		return nil, err
	}
	validate := validator.New()
	if err := validate.Struct(conf); err != nil {
		var sb strings.Builder
		for _, err := range err.(validator.ValidationErrors) {
			sb.WriteString(fmt.Sprintf("Field '%s' failed on '%s'\n", err.Field(), err.Tag()))
		}
		return nil, errors.New(sb.String())
	}

	return conf, nil
}
