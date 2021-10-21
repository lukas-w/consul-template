// +build !windows

package child

import (
	"github.com/hashicorp/go-gatedio"
	"syscall"
	"testing"
	"time"
)

func TestSignal(t *testing.T) {

	c := testChild(t)
	c.command = "sh"
	c.args = []string{"-c", "trap 'echo one; exit' USR1; while true; do sleep 0.2; done"}

	out := gatedio.NewByteBuffer()
	c.stdout = out

	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	defer c.Stop()

	// For some reason bash doesn't start immediately
	time.Sleep(fileWaitSleepDelay)

	if err := c.Signal(syscall.SIGUSR1); err != nil {
		t.Fatal(err)
	}

	// Give time for the file to flush
	time.Sleep(fileWaitSleepDelay)

	expected := "one\n"
	if out.String() != expected {
		t.Errorf("expected %q to be %q", out.String(), expected)
	}
}

func TestSignal_noProcess(t *testing.T) {

	c := testChild(t)
	if err := c.Signal(syscall.SIGUSR1); err != nil {
		// Just assert there is no error
		t.Fatal(err)
	}
}

func TestReload_signal(t *testing.T) {

	c := testChild(t)
	c.command = "sh"
	c.args = []string{"-c", "trap 'echo one; exit' USR1; while true; do sleep 0.2; done"}
	c.reloadSignal = syscall.SIGUSR1

	out := gatedio.NewByteBuffer()
	c.stdout = out

	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	defer c.Stop()

	// For some reason bash doesn't start immediately
	time.Sleep(fileWaitSleepDelay)

	if err := c.Reload(); err != nil {
		t.Fatal(err)
	}

	// Give time for the file to flush
	time.Sleep(fileWaitSleepDelay)

	expected := "one\n"
	if out.String() != expected {
		t.Errorf("expected %q to be %q", out.String(), expected)
	}
}

func TestReload_noProcess(t *testing.T) {

	c := testChild(t)
	c.reloadSignal = syscall.SIGUSR1
	if err := c.Reload(); err != nil {
		t.Fatal(err)
	}
}

func TestKill_signal(t *testing.T) {

	c := testChild(t)
	c.command = "sh"
	c.args = []string{"-c", "trap 'echo one; exit' USR1; while true; do sleep 0.2; done"}
	c.killSignal = syscall.SIGUSR1

	out := gatedio.NewByteBuffer()
	c.stdout = out

	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	defer c.Stop()

	// For some reason bash doesn't start immediately
	time.Sleep(fileWaitSleepDelay)

	c.Kill()

	// Give time for the file to flush
	time.Sleep(fileWaitSleepDelay)

	expected := "one\n"
	if out.String() != expected {
		t.Errorf("expected %q to be %q", out.String(), expected)
	}
}

func TestKill_noProcess(t *testing.T) {

	c := testChild(t)
	c.killSignal = syscall.SIGUSR1
	c.Kill()
}

func TestStop_noWaitForSplay(t *testing.T) {
	c := testChild(t)
	c.command = "sh"
	c.args = []string{"-c", "trap 'echo one; exit' USR1; while true; do sleep 0.2; done"}
	c.splay = 100 * time.Second
	c.reloadSignal = nil
	c.killSignal = syscall.SIGUSR1

	out := gatedio.NewByteBuffer()
	c.stdout = out

	if err := c.Start(); err != nil {
		t.Fatal(err)
	}

	// For some reason bash doesn't start immediately
	time.Sleep(fileWaitSleepDelay)

	killStartTime := time.Now()
	c.StopImmediately()
	killEndTime := time.Now()

	expected := "one\n"
	if out.String() != expected {
		t.Errorf("expected %q to be %q", out.String(), expected)
	}

	if killEndTime.Sub(killStartTime) > fileWaitSleepDelay {
		t.Error("expected not to wait for splay")
	}
}
func TestSetpgid(t *testing.T) {
	t.Run("true", func(t *testing.T) {
		c := testChild(t)
		c.command = "sh"
		c.args = []string{"-c", "while true; do sleep 0.2; done"}
		// default, but to be explicit for the test
		c.setpgid = true

		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		defer c.Stop()

		// when setpgid is true, the pid and gpid should be the same
		gpid, err := syscall.Getpgid(c.Pid())
		if err != nil {
			t.Fatal("Getpgid error:", err)
		}

		if c.Pid() != gpid {
			t.Fatal("pid and gpid should match")
		}
	})
	t.Run("false", func(t *testing.T) {
		c := testChild(t)
		c.command = "sh"
		c.args = []string{"-c", "while true; do sleep 0.2; done"}
		c.setpgid = false

		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		defer c.Stop()

		// when setpgid is true, the pid and gpid should be the same
		gpid, err := syscall.Getpgid(c.Pid())
		if err != nil {
			t.Fatal("Getpgid error:", err)
		}

		if c.Pid() == gpid {
			t.Fatal("pid and gpid should NOT match")
		}
	})
}
