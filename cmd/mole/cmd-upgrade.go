package main

import (
	"errors"
	"github.com/calmh/mole/upgrade"
	"github.com/jessevdk/go-flags"
	"time"
)

type upgradeCommand struct {
	Force bool `short:"f" long:"force" description:"Don't perform newness check, just upgrade to whatever the server has."`
}

var upgradeParser *flags.Parser

var errNoUpgradeUrl = errors.New("no upgrade URL")

func init() {
	cmd := upgradeCommand{}
	upgradeParser = globalParser.AddCommand("upgrade", msgUpgradeShort, msgUpgradeLong, &cmd)
}

func latestBuild() (build upgrade.Build, err error) {
	cl := NewClient(serverIni.address, serverIni.fingerprint)

	upgradesURL, err := cl.UpgradesURL()
	if err != nil {
		return
	}
	if upgradesURL == "" {
		err = errNoUpgradeUrl
		return
	}

	debugln("checking for upgrade at", upgradesURL)
	build, err = upgrade.Newest("mole", upgradesURL)
	debugln("got build", build)
	return
}

func (c *upgradeCommand) Execute(args []string) error {
	setup()

	build, err := latestBuild()
	fatalErr(err)

	bd := time.Unix(int64(build.BuildStamp), 0)
	isNewer := bd.Sub(buildDate).Seconds() > 0
	if c.Force || isNewer {
		infoln(msgDownloadingUpgrade)

		err = upgrade.UpgradeTo(build)
		if err != nil {
			return err
		} else {
			okf(msgUpgraded, build.Version)
		}
	} else {
		okln(msgNoUpgrades)
	}

	return nil
}
