/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Intel Corporation
 */

package distributor

import (
	"context"
	"fmt"
	"time"

	"github.com/CloudNativeDataPlane/cndp/lang/go/bindings/cne"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const (
	version    = "v0.1.0"
	numWorkers = 4
)

var (
	config  string
	verbose bool
)

func NewDistributorCommand(ctx context.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:    "distributor -c config.jsonc",
		Short:  "An example to distribute packets via lockless rings between worker threads",
		PreRun: PreRun,
		Run: func(cmd *cobra.Command, args []string) {
			run(ctx, cmd, args)
		},
	}

	flags := cmd.Flags()
	cmd.Version = version
	flags.StringVarP(&config, "config", "c", "", "path to configuration file")
	flags.BoolVarP(&verbose, "verbose", "V", false, "verbose output")

	cmd.MarkFlagRequired("config")

	return cmd
}

func PreRun(cmd *cobra.Command, args []string) {
	if verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}

	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		logrus.Debugf("FLAG: --%s=%q", f.Name, f.Value)
	})
}

func printStat(handle *cne.System, workers []*Worker) {
	// Clear console
	fmt.Print("\033[H\033[2J")

	for _, lport := range handle.LPortList() {
		ps, err := lport.LPortStats()
		if err != nil {
			return
		}

		fmt.Printf("%10s: in %d, out %d\n", lport.Name(), ps.InPackets, ps.OutPackets)
	}

	for _, worker := range workers {
		fmt.Printf("%10s: process %d\n", worker.Name, worker.Count)
	}
}

func run(ctx context.Context, cmd *cobra.Command, args []string) {
	handle, err := cne.OpenWithFile(config)
	if err != nil {
		logrus.Errorf("can't open config files: %s", err)
		return
	}
	defer handle.Close()

	lb, err := NewDefaultLoadBalancer(numWorkers)
	if err != nil {
		logrus.Errorf("failed to create default loadbalancer: %s", err)
		return
	}

	// Refresh console every 1 second
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(1 * time.Second):
				printStat(handle, lb.Workers())
			}
		}
	}()

	tx, err := NewTX(ctx, handle, lb)
	if err != nil {
		logrus.Errorf("failed to create tx: %s", err)
		return
	}
	tx.Start()
	defer tx.Stop()

	rx := NewRX(ctx, handle, lb)
	rx.Start()
	defer rx.Stop()

	lb.Run(ctx)
}
