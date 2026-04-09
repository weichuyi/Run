package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/run-proxy/run/config"
	"github.com/run-proxy/run/core"
	log "github.com/run-proxy/run/common/log"
)

// Version 当前版本号
const Version = "1.0.0"

func main() {
	var (
		configPath  = flag.String("f", "config.yaml", "配置文件路径")
		testOnly    = flag.Bool("t", false, "仅检查配置文件语法，不启动")
		showVersion = flag.Bool("v", false, "显示版本信息")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("Run v%s\n", Version)
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "配置加载失败: %v\n", err)
		os.Exit(1)
	}

	if *testOnly {
		fmt.Println("配置文件语法正确 ✓")
		return
	}

	log.SetLevel(cfg.General.LogLevel)

	engine, err := core.New(cfg)
	if err != nil {
		log.Fatalf("初始化引擎失败: %v", err)
	}

	if err := engine.Start(); err != nil {
		log.Fatalf("启动失败: %v", err)
	}

	log.Infof("Run v%s 已启动", Version)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit

	log.Infof("收到信号 %v，正在安全退出...", sig)
	engine.Stop()
	log.Info("Run 已停止")
}
