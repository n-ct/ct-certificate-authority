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
			caInstance.UpdateMMD()
			glog.Infoln("New MMD")
			glog.Infof("DeltaRevocations: %v", caInstance.DeltaRevocations)
			// Add delta revocations to crv
			// TODO: Currently hardcoded to let's-revoke. Make modular later
			revType := "Let's-Revoke"
			glog.Infoln("Updating revocation objects")
			caInstance.UpdateRevocationObjMap(revType)	
			glog.Infoln(*caInstance.RevocationObjMap[revType])
			// Send SRD to Logger
			// Clear delta revocations
			if err = caInstance.ClearDeltaRevocations(); err != nil {
				glog.Infof("failed to clear revocations in sequencer: %v", err)
			}
			glog.Infof("Cleared deltaRevocations")

		}
	}
}