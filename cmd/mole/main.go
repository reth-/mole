package main

import (
	"crypto/tls"
	"fmt"
	"github.com/calmh/mole/ansi"
	"github.com/calmh/mole/ini"
	"github.com/calmh/mole/upgrade"
	"github.com/jessevdk/go-flags"
	"io"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var (
	buildVersion string
	buildStamp   string
	buildDate    time.Time
	buildUser    string
)

var globalOpts struct {
	Home   string `short:"h" long:"home" description:"Mole home directory" default:"~/.mole" value-name:"DIR"`
	Debug  bool   `short:"d" long:"debug" description:"Show debug output"`
	NoAnsi bool   `long:"no-ansi" description:"Disable ANSI formatting sequences"`
	Remap  bool   `long:"remap-lo" description:"Use port remapping for extended lo addresses (required/default on Windows)"`
}

var serverIni struct {
	address       string
	upgrades      bool
	fingerprint   string
	ticket        string
	upgradeNotice bool
}

var globalParser = flags.NewParser(&globalOpts, flags.Default)

func main() {
	epoch, e := strconv.ParseInt(buildStamp, 10, 64)
	if e == nil {
		buildDate = time.Unix(epoch, 0)
	}

	// TIME LIMITED BETA
	// 30 days self destruct
	if !buildDate.IsZero() && time.Since(buildDate) > 30*24*time.Hour {
		fatalln("This is an expired beta version.\nPlease grab a new build from http://ps-build1.vbg.se.prnw.net/job/mole")
	}
	// TIME LIMITED BETA
	// 30 days self destruct

	if runtime.GOOS == "windows" {
		globalOpts.Remap = true
	}

	globalParser.ApplicationName = "mole"
	if _, e := globalParser.Parse(); e != nil {
		if e, ok := e.(*flags.Error); ok {
			switch e.Type {
			case flags.ErrRequired:
				fmt.Println()
				globalParser.WriteHelp(os.Stdout)
				fmt.Println()
				fallthrough
			case flags.ErrHelp:
				fmt.Printf(msgExamples)
			}
		}
		os.Exit(1)
	}

	printTotalStats()
}

var setupDone bool

func setup() {
	if setupDone {
		return
	} else {
		setupDone = true
	}

	if globalOpts.NoAnsi {
		ansi.Disable()
	}

	if globalOpts.Debug {
		printVersion()
	}

	if strings.HasPrefix(globalOpts.Home, "~/") {
		home := getHomeDir()
		globalOpts.Home = strings.Replace(globalOpts.Home, "~", home, 1)
	}
	debugln("homeDir", globalOpts.Home)

	configFile := path.Join(globalOpts.Home, "mole.ini")

	if fd, err := os.Open(configFile); err == nil {
		loadGlobalIni(fd)
		if serverIni.upgrades {
			go autoUpgrade()
		} else {
			debugln("automatic upgrades disabled")
		}
	}

	os.MkdirAll(globalOpts.Home, 0700)
}

func loadGlobalIni(fd io.Reader) {
	config := ini.Parse(fd)
	serverIni.address = config.Sections["server"]["host"] + ":" + config.Sections["server"]["port"]
	serverIni.fingerprint = strings.ToLower(strings.Replace(config.Sections["server"]["fingerprint"], ":", "", -1))
	serverIni.ticket = config.Sections["server"]["ticket"]

	serverIni.upgrades = true
	if upgSec, ok := config.Sections["upgrades"]; ok {
		upgs, ok := upgSec["automatic"]
		serverIni.upgradeNotice = !ok
		serverIni.upgrades = !ok || upgs == "yes"
	}
}

func autoUpgrade() {
	// Only do the actual upgrade once we've been running for a while
	time.Sleep(10 * time.Second)
	build, err := latestBuild()
	if err == nil {
		bd := time.Unix(int64(build.BuildStamp), 0)
		if isNewer := bd.Sub(buildDate).Seconds() > 0; isNewer {
			err = upgrade.UpgradeTo(build)
			if err == nil {
				if serverIni.upgradeNotice {
					infoln(msgAutoUpgrades)
				}
				okf(msgUpgraded, build.Version)
			}
		}
	}
}

func printVersion() {
	infof("mole (%s-%s)", runtime.GOOS, runtime.GOARCH)
	if buildVersion != "" {
		infof("  %s", buildVersion)
	}
	if !buildDate.IsZero() {
		infof("  %v by %s", buildDate, buildUser)
	}
}

func certificate() tls.Certificate {
	cert, err := tls.LoadX509KeyPair(path.Join(globalOpts.Home, "mole.crt"), path.Join(globalOpts.Home, "mole.key"))
	fatalErr(err)
	return cert
}
