/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Intel Corporation
 */

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/CloudNativeDataPlane/cndp/lang/go/bindings/examples/distributor/pkg/distributor"
	"github.com/sirupsen/logrus"
)

var (
	shutdownSignals      = []os.Signal{os.Interrupt, syscall.SIGTERM}
	onlyOneSignalHandler = make(chan struct{})
)

func SetupSignalHandler() context.Context {
	close(onlyOneSignalHandler)

	c := make(chan os.Signal, 2)
	ctx, cancel := context.WithCancel(context.Background())
	signal.Notify(c, shutdownSignals...)

	go func() {
		<-c
		cancel()
		<-c
		os.Exit(1)
	}()

	return ctx
}

func main() {
	logrus.SetFormatter(&logrus.TextFormatter{TimestampFormat: "2006-01-02 15:04:05", FullTimestamp: true})

	cmd := distributor.NewDistributorCommand(SetupSignalHandler())

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
