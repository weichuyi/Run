package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

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

	// 程序停止通道：操作系统信号 或 Dashboard 停止按钟
	quit := make(chan struct{})
	var once sync.Once
	engine.SetShutdown(func() {
		once.Do(func() { close(quit) })
	})

	if err := engine.Start(); err != nil {
		log.Fatalf("启动失败: %v", err)
	}

	log.Infof("Run v%s 已启动", Version)

	// 自动在默认浏览器打开控制面板
	apiAddr := cfg.General.ExternalController
	if strings.HasPrefix(apiAddr, "0.0.0.0:") {
		apiAddr = "127.0.0.1:" + strings.TrimPrefix(apiAddr, "0.0.0.0:")
	} else if strings.HasPrefix(apiAddr, ":") {
		apiAddr = "127.0.0.1" + apiAddr
	}
	if apiAddr != "" {
		dashURL := "http://" + apiAddr + "/ui"
		log.Infof("控制面板: %s", dashURL)
		go func() {
			time.Sleep(400 * time.Millisecond)
			_ = exec.Command("cmd", "/c", "start", dashURL).Start()
		}()
	}

	siCh := make(chan os.Signal, 1)
	signal.Notify(siCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-siCh:
		log.Infof("收到信号 %v，正在安全退出...", sig)
		once.Do(func() { close(quit) })
	case <-quit:
		log.Info("收到停止请求")
	}

	engine.Stop()
	log.Info("Run 已停止")
}
