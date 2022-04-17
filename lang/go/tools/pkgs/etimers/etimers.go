// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2019-2022 Intel Corporation

package etimers

import (
	"strings"
	"sync"
	"time"

	tlog "github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/ttylog"
)

// etimers is a package to handle timers for the performance monitor tool.
// A number of timers needed to be handled in a consistant way and from a single
// go routine.

// EventTimers to process when timer expires
type EventTimers struct {
	lock     sync.Mutex
	timo     time.Duration
	maxSteps int
	step     int
	list     map[string]*EventAction
	action   chan *EventAction
	ticker   *time.Ticker
	ticks    uint64
}

// EventAction information
type EventAction struct {
	Name    string
	Action  string
	Routine func(step int, ticks uint64)
}

// New for calling tview events
// Takes New(timo time.duration, steps int)
// defaults to time.Second and 0 steps
func New(arg ...interface{}) *EventTimers {
	te := &EventTimers{}

	// Create the first map holding all event actions
	te.list = make(map[string]*EventAction, 0)

	te.maxSteps = 0
	te.timo = time.Second

	// Loop in the arg(s) to create any supplied events.
	for _, a := range arg {
		switch a.(type) {
		case time.Duration:
			te.timo = a.(time.Duration)
		case int:
			te.maxSteps = a.(int)
		}
	}

	// Create the channel and ticker instances
	te.action = make(chan *EventAction, 16)
	te.ticker = time.NewTicker(te.timo)

	tlog.DebugPrintf("New etimers: %+v\n", te)

	return te
}

// Start to handle timeouts with tview
func (te *EventTimers) Start() {

	// Create a go routine that handles all of the timer events
	go func() {

		// Loop forever until a quit message is recieved over the channel
	ForLoop:
		for {
			select {
			case event := <-te.action:
				tlog.DebugPrintf("EventAction: %s --> %s\n", event.Name, event.Action)

				// When a timer expires then execute the actions attached to the events.
				te.doAction(event)

				if strings.ToLower(event.Action) == "quit" {
					break ForLoop
				}

			// Process the timer ticks and call the timeout routine handler.
			case <-te.ticker.C:
				te.doTimeout()
			}
		}
	}()
}

func (te *EventTimers) doTimeout() {

	// Lock the timer while processing a timeout event
	te.lock.Lock()
	defer te.lock.Unlock()

	// Bump the step counter, which is passed to the action routines as a time
	// reference like value normally 0-4 or 0-8 steps. Each step is 1/4 or 1/8
	// of a second.
	te.step++
	if te.step >= te.maxSteps {
		te.step = 0
	}

	// Call all of the actions when for this timer event
	for _, a := range te.list {
		tlog.DebugPrintf("Call Action: %s\n", a.Name)
		a.Routine(te.step, te.ticks)
	}

	// bump the ticks processed as a type of tick counter.
	te.ticks++
}

// Process an action when a timer event happens
func (te *EventTimers) doAction(a *EventAction) {

	// Covert the action to a string for the switch below
	action := strings.ToLower(a.Action)

	te.lock.Lock()
	defer te.lock.Unlock()

	// Handle the action for a given event
	switch action {
	case "add":
		// Add a new action to the list atomicly
		tlog.DebugPrintf("Add Action: %s\n", a.Name)
		te.list[a.Name] = a

	case "remove":
		// Remove an action atomicly
		tlog.DebugPrintf("Remove Action: %s\n", a.Name)
		if _, ok := te.list[a.Name]; ok {
			tlog.DebugPrintf("Removed: %s\n", a.Name)
			delete(te.list, a.Name)
		}

	case "quit":
		// Quit the event timer go routine
		close(te.action)
		te.ticker.Stop()
	}
}

// Add to the list of timers
func (te *EventTimers) Add(name string, f func(step int, ticks uint64)) {

	te.lock.Lock()
	defer te.lock.Unlock()

	// Add a timer event by passing it to the timer go routine
	ea := &EventAction{Name: name, Action: "Add", Routine: f}

	te.action <- ea
}

// Remove to the list of timers
func (te *EventTimers) Remove(name string) {

	te.lock.Lock()
	defer te.lock.Unlock()

	// Remove the timer event action by sending it to the go routine
	ea := &EventAction{Name: name, Action: "Remove"}

	te.action <- ea
}

// Stop the timers
func (te *EventTimers) Stop() {

	te.lock.Lock()
	defer te.lock.Unlock()

	// Force the timer routine to quit
	ea := &EventAction{Action: "quit"}

	te.action <- ea
}
