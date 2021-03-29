package sequencer

import (
  "time"
  "github.com/golang/glog"
)

func Run(done chan bool, t *tree.MerkleTree, mmd time.Duration) error {
	ticker := time.NewTicker(mmd)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			glog.Infoln("Shutting down sequencer")
			return nil
		case <-ticker.C:
			glog.Infoln("Sequencing and signing all nodes added since last mmd")
			err := t.IntegrateQueue()
			if(err != nil) {
			return err
			}
		}
	}
}