package sequencer

import (
	"fmt"
	"time"

	"github.com/golang/glog"

	"github.com/n-ct/ct-certificate-authority/ca"
)

func Run(done chan bool, caInstance *ca.CA) error {
	mmdStr := fmt.Sprintf("%v", caInstance.MMD) + "s"
	mmdDur, err := time.ParseDuration(mmdStr)
	if err != nil {
		return fmt.Errorf("failed to parse mmd into duration: %v", err)
	}
	ticker := time.NewTicker(mmdDur)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			glog.Infoln("Shutting down sequencer")
			return nil
		case <-ticker.C:
			fmt.Println("New MMD")
		}
	}
}