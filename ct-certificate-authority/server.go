package main 

import (
	"fmt"
	"context"
	"time"
	"flag"
	"os"
	"os/signal"
	"net/http"
	"syscall"

	"github.com/golang/glog"
	ctca "github.com/n-ct/ct-certificate-authority"
	"github.com/n-ct/ct-certificate-authority/ca"
	"github.com/n-ct/ct-certificate-authority/handler"
	"github.com/n-ct/ct-certificate-authority/sequencer"
)

var (
	caConfigName = flag.String("config", "ca/ca_config.json", "File containing CA configuration")
	caListName = flag.String("calist", "ca/ca_list.json", "File containing CAList")
	logListName = flag.String("loglist", "ca/log_list.json", "File containing LogList")
)

func main(){
	flag.Parse()
	defer glog.Flush()

	// Handle user interrupt to stop the CA 
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	// Initalize the variables of the CA
	caInstance, err := ca.NewCA(*caConfigName, *caListName, *logListName)
	if err != nil {
		fmt.Println("failed to create ca: %w", err)	// Only for testing purposes
		glog.Fatalf("Couldn't create ca: %v", err)
		glog.Flush()
		os.Exit(-1)
	}
	glog.Infoln("Starting CT-CA")

	// Test function
	//caInstance.TestLogClient()

	// Create http.Server instance for the CA
	server := serverSetup(caInstance)
	glog.Infoln("Created ca http.Server")

	// Start the Sequencer that will keep track of MMDs
	startSequencer(caInstance)

	// Handling the stop signal and closing things 
	<-stop
	glog.Infoln("Received stop signal")
	shutdownServer(server, 0)
}

// Sets up the basic ca http server
func serverSetup(c *ca.CA) *http.Server{
	serveMux := handlerSetup(c)
	glog.Infof("Serving at address: %s", c.ListenAddress)
	fmt.Printf("Serving at address: %s", c.ListenAddress)
	server := &http.Server {
		Addr: c.ListenAddress,
		Handler: serveMux,
	}

	// start up handles
	go func() {
		if err := server.ListenAndServe(); err != nil {
			glog.Flush()
			glog.Exitf("Problem serving: %v\n",err)
		}
	}()
	return server
}

// Sets up the handler and the various path handle functions
func handlerSetup(c *ca.CA) (*http.ServeMux) {
	handler := handler.NewHandler(c)
	serveMux := http.NewServeMux()
	serveMux.HandleFunc(ctca.GetRevocationStatusPath, handler.GetRevocationStatus)
	serveMux.HandleFunc(ctca.PostLogRevocationDigestPath, handler.PostLogRevocationDigest)

	// Return a 200 on the root so clients can easily check if server is up
	serveMux.HandleFunc("/", func(resp http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/" {
			resp.WriteHeader(http.StatusOK)
		} else {
			resp.WriteHeader(http.StatusNotFound)
		}
	})
	return serveMux
}

func startSequencer(caInstance *ca.CA) {
	glog.Infoln("Starting sequencer")
	seqdone := make(chan bool)
	go func() {
		if err := sequencer.Run(seqdone, caInstance); err != nil {
			glog.Exitf("failed to start sequencer: %v",err)
		}
	}()
	glog.Infoln("Sequencer started")
}

func shutdownServer(server *http.Server, returnCode int){
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	server.Shutdown(ctx)
	glog.Infoln("Shutting down Server")
	glog.Flush()
	os.Exit(returnCode)
}