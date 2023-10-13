// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/joho/godotenv"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
)

type RegistryAPIResponse struct {
	ID    string `json:"_id"`
	Links struct {
		CertificationProject struct {
			Href string `json:"href"`
		} `json:"certification_project"`
		Images struct {
			Href string `json:"href"`
		} `json:"images"`
		OperatorBundles struct {
			Href string `json:"href"`
		} `json:"operator_bundles"`
		ProductListings struct {
			Href string `json:"href"`
		} `json:"product_listings"`
		Vendor struct {
			Href string `json:"href"`
		} `json:"vendor"`
	} `json:"_links"`
	ApplicationCategories    []string `json:"application_categories"`
	AutoRebuildTags          []string `json:"auto_rebuild_tags"`
	BuildCategories          []string `json:"build_categories"`
	CanAutoReleaseCveRebuild bool     `json:"can_auto_release_cve_rebuild"`
	ContentStreamGrades      []struct {
		Grade    string `json:"grade"`
		ImageIds []struct {
			Arch string `json:"arch"`
			ID   string `json:"id"`
		} `json:"image_ids"`
		Tag string `json:"tag"`
	} `json:"content_stream_grades"`
	ContentStreamTags []string  `json:"content_stream_tags"`
	CreationDate      time.Time `json:"creation_date"`
	Description       string    `json:"description"`
	DisplayData       struct {
		LongDescription         string `json:"long_description"`
		LongDescriptionMarkdown string `json:"long_description_markdown"`
		Name                    string `json:"name"`
		OpenshiftTags           string `json:"openshift_tags"`
		ShortDescription        string `json:"short_description"`
	} `json:"display_data"`
	DocumentationLinks              []any     `json:"documentation_links"`
	EolDate                         time.Time `json:"eol_date"`
	FbcOptIn                        bool      `json:"fbc_opt_in"`
	FreshnessGradesUnknownUntilDate any       `json:"freshness_grades_unknown_until_date"`
	IncludesMultipleContentStreams  bool      `json:"includes_multiple_content_streams"`
	LastUpdateDate                  time.Time `json:"last_update_date"`
	MetadataSource                  string    `json:"metadata_source"`
	Namespace                       string    `json:"namespace"`
	NonProductionOnly               bool      `json:"non_production_only"`
	ObjectType                      string    `json:"object_type"`
	PrivilegedImagesAllowed         bool      `json:"privileged_images_allowed"`
	ProductID                       any       `json:"product_id"`
	ProductListings                 []string  `json:"product_listings"`
	ProtectedForPull                bool      `json:"protected_for_pull"`
	ProtectedForSearch              bool      `json:"protected_for_search"`
	Published                       bool      `json:"published"`
	Registry                        string    `json:"registry"`
	RegistryTarget                  string    `json:"registry_target"`
	ReleaseCategories               []string  `json:"release_categories"`
	Repository                      string    `json:"repository"`
	RequiresTerms                   bool      `json:"requires_terms"`
	TotalSizeBytes                  int       `json:"total_size_bytes"`
	TotalUncompressedSizeBytes      int64     `json:"total_uncompressed_size_bytes"`
	UseLatest                       bool      `json:"use_latest"`
	VendorLabel                     string    `json:"vendor_label"`
}

const (
	timeout                    = 1 * time.Second
	apiVersion                 = "externaldata.gatekeeper.sh/v1beta1"
	applicationName            = "rh-registry-gatekeeper-provider"
	constRegistryURL           = "https://catalog.redhat.com/api/containers/v1/repositories/registry/registry.access.redhat.com/repository/jboss-webserver-5/webserver54-openjdk8-tomcat9-openshift-rhel7"
	constRegistrymethod        = "GET"
	constEOLDateValidCheck     = "true"
	constEOLDateValidityPeriod = "525600"
	constDeprecatedValidCheck  = "true"
	constHealthgradeValidCheck = "true"
	constAllowedHealthGrades   = "A,B,C"
	constServerPort            = ":8090"
	constGatekeeperCACert      = "/gatekeeper-ca/ca.crt"
	constSSLCertFolder         = "/provider-certs"
	https_enabled              = "true"
)

var (
	//Server Port
	serverPort string

	//Gatekeeper CA location
	gatekeeperCACert string

	//SSL Cert location
	sslCertFolder string

	//Registry API to call for RedHat Data - #REGISTRY_API_URL
	registryAPIURL string

	//Registry API Method - #REGISTRY_API_METHOD
	registryAPIMethod string = "GET"

	//Check if Image is more than eolDateValidityPeriod old from EOL Data - #EOL_DATE_VALID_CHECK
	eolDateValidCheck bool

	//EOL Date Validity Period in minutes - #EOL_DATE_VALIDITY_PERIOD
	eolDateValidityPeriod float64

	//Check if Image is deprecated
	deprecatedValidCheck bool

	//Check Image Health Check Grade from API
	healthgradeValidCheck bool

	//Allowed Image Health Grades
	allowedHealthGrades []string

	//Enable HTTPS. Default is true
	httpsEnabled bool
)

func init() {
	//Read env variables
	if err := godotenv.Load(); err != nil {
		fmt.Println("No .env file found, Will use env variables")
	}
}

func getEnvSetDefault(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func main() {
	//Parse Flags
	flag.Parse()

	//Initialize logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	//Set Local Variables
	var err error
	var shouldnoterror error

	//Read env variables

	httpsEnabled, err = strconv.ParseBool(getEnvSetDefault(("HTTPS_ENABLED"), https_enabled))
	serverPort = getEnvSetDefault("SERVER_PORT", constServerPort)
	registryAPIURL = getEnvSetDefault("REGISTRY_API_URL", constRegistryURL)
	registryAPIMethod = getEnvSetDefault("REGISTRY_API_METHOD", constRegistrymethod)

	eolDateValidCheck, err = strconv.ParseBool(getEnvSetDefault(("EOL_DATE_VALID_CHECK"), constEOLDateValidCheck))
	if err != nil {
		slog.Info("EOL_DATE_VALID_CHECK not set, defaulting to True")
		eolDateValidCheck = true
	}

	eolDateValidityPeriod, err = strconv.ParseFloat(getEnvSetDefault(("EOL_DATE_VALIDITY_PERIOD"), constEOLDateValidityPeriod), 64)
	if err != nil {
		slog.Info("EOL_DATE_VALIDITY_PERIOD not set, defaulting to 525600")
		eolDateValidityPeriod = 525600
	}
	if err != nil {
		slog.Info("EOL_DATE_VALIDITY_PERIOD not set, defaulting to 525600")
		eolDateValidityPeriod, shouldnoterror = strconv.ParseFloat(constEOLDateValidityPeriod, 64)
	}

	deprecatedValidCheck, err = strconv.ParseBool(getEnvSetDefault(("DEPRECATED_VALID_CHECK"), constDeprecatedValidCheck))
	if err != nil {
		slog.Info("DEPRECATED_VALID_CHECK not set, defaulting to True")
		deprecatedValidCheck, shouldnoterror = strconv.ParseBool(constDeprecatedValidCheck)
	}

	healthgradeValidCheck, err = strconv.ParseBool(getEnvSetDefault(("HEALTHGRADE_VALID_CHECK"), constHealthgradeValidCheck))
	if err != nil {
		slog.Info("HEALTHGRADE_VALID_CHECK not set, defaulting to True")
		healthgradeValidCheck, shouldnoterror = strconv.ParseBool(constHealthgradeValidCheck)
	}

	gatekeeperCACert = getEnvSetDefault(("GATEKEEPER_CA_CERT"), constGatekeeperCACert)

	sslCertFolder = getEnvSetDefault(("SSL_CERT_FOLDER"), constSSLCertFolder)

	allowedHealthGrades = strings.Split(getEnvSetDefault(("ALLOWED_HEALTH_GRADES"), constAllowedHealthGrades), ",")

	if shouldnoterror != nil {
		logger.Error("Error parsing our constants: %s", shouldnoterror)
	}

	logger.Info("starting server...")

	if httpsEnabled {
		logger.Info("HTTPS Enabled")
		// load Gatekeeper's CA certificate
		caCert, err := os.ReadFile(gatekeeperCACert)
		if err != nil {
			panic(err)
		}

		clientCAs := x509.NewCertPool()
		clientCAs.AppendCertsFromPEM(caCert)

		mux := http.NewServeMux()
		mux.HandleFunc("/validate", processTimeout(validate, timeout))

		server := &http.Server{
			Addr:              serverPort,
			Handler:           mux,
			ReadHeaderTimeout: timeout,
			TLSConfig: &tls.Config{
				ClientAuth: tls.RequireAndVerifyClientCert,
				ClientCAs:  clientCAs,
				MinVersion: tls.VersionTLS13,
			},
		}

		if err := server.ListenAndServeTLS(fmt.Sprintf("%s/tls.crt", sslCertFolder), fmt.Sprintf("%s/tls.key", sslCertFolder)); err != nil {
			panic(err)
		}

	} else {
		logger.Info("HTTPS Disabled")
		http.HandleFunc("/validate", validate)
		srv := &http.Server{
			Addr:              serverPort,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			ReadHeaderTimeout: timeout,
		}

		if err := srv.ListenAndServe(); err != nil {
			panic(err)
		}
	}

}

// PrettyPrint to print struct in a readable way
func PrettyPrint(i interface{}) string {
	s, _ := json.MarshalIndent(i, "", "\t")
	return string(s)
}

func validate(w http.ResponseWriter, req *http.Request) {
	// only accept POST requests
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	//Allow only POST requests
	if req.Method != http.MethodPost {
		sendResponse(nil, "only POST is allowed", w)
		return
	}

	// read request body from Gatekeeper
	gkprequestBody, err := io.ReadAll(req.Body)
	if err != nil {
		errorString := fmt.Sprintf("client: could not read request from gatekeeper: %v\n", err)
		logger.Error(errorString)
		sendResponse(nil, errorString, w)
		return
	}

	// parse request body from Gatekeeper
	var providerRequest externaldata.ProviderRequest
	err = json.Unmarshal(gkprequestBody, &providerRequest)
	if err != nil {
		errorString := fmt.Sprintf("client: could not unmarshal request body from gatekeeper: %v\n", err)
		logger.Error(errorString)
		sendResponse(nil, errorString, w)
		return
	}

	// iterate over all keys
	for _, key := range providerRequest.Request.Keys {
		fmt.Println("verify signature for:", key)
		ref, err := name.ParseReference(key)
		if err != nil {
			sendResponse(nil, fmt.Sprintf("ERROR (ParseReference(%q)): %v", key, err), w)
			return
		}

		fmt.Println("ref:", ref)
		fmt.Println(ref.Context().RepositoryStr())
		fmt.Println(ref.Identifier())

	}
	// Create request to RH registry API
	apirequest, err := http.NewRequest(registryAPIMethod, registryAPIURL, nil)
	if err != nil {
		errorString := fmt.Sprintf("client: could not create request: %s\n", err)
		logger.Error(errorString)
		sendResponse(nil, errorString, w)
		return
	}

	// Set headers
	apirequest.Header.Set("accept", "application/json")

	// Make request to RH registry API
	apiresponse, err := http.DefaultClient.Do(apirequest)
	if err != nil {
		errorString := fmt.Sprintf("client: error making http request: %s\n", err)
		logger.Error(errorString)
		sendResponse(nil, errorString, w)
		return
	}

	logger.Info("client: got response from RH Registry!\n")
	if apiresponse.StatusCode != http.StatusOK {
		errorString := fmt.Sprintf("client did not got valid status code: %d\n", apiresponse.StatusCode)
		sendResponse(nil, errorString, w)
		defer apiresponse.Body.Close()
		return
	}

	apiresponseBody, err := io.ReadAll(apiresponse.Body)
	if err != nil {
		errorString := fmt.Sprintf("client: could not read response body: %s\n", err)
		sendResponse(nil, errorString, w)
		defer apiresponse.Body.Close()
		return
	}

	fmt.Printf("client: response body: %s\n", apiresponseBody)
	var parsedResponse RegistryAPIResponse
	if err := json.Unmarshal(apiresponseBody, &parsedResponse); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
		errorString := fmt.Sprintf("Can not unmarshal JSON Registry API Response JSON: %s\n", err)
		sendResponse(nil, errorString, w)
		return
	}
	fmt.Println(PrettyPrint(parsedResponse))

	results := make([]externaldata.Item, 0)

	checkresponse := activeValidChecks(parsedResponse)
	for k, v := range checkresponse {
		results = append(results, externaldata.Item{
			Key:   k,
			Value: v,
		})
	}

	sendResponse(&results, "", w)
}

// activeValidChecks checks if the image is valid based on the checks enabled
func activeValidChecks(parsedResponse RegistryAPIResponse) map[string]string {

	responseMap := make(map[string]string)

	fmt.Println("registryAPIURL: ", registryAPIURL)
	fmt.Println("eolDateValidityCheck: ", eolDateValidCheck)
	fmt.Println("eolDateValidityPeriod: ", eolDateValidityPeriod)
	fmt.Println("deperecatedValidCheck: ", deprecatedValidCheck)
	fmt.Println("healthgradeValidCheck: ", healthgradeValidCheck)

	//Check if Image is Deprecated
	if deprecatedValidCheck {
		if slices.Contains(parsedResponse.ReleaseCategories, "Deprecated") {
			responseMap["Deprecated"] = "true"
		}
	}

	//Check if Image is more than eolDateValidityPeriod old from EOL Data
	if eolDateValidCheck {
		if time.Since(parsedResponse.EolDate).Minutes() > eolDateValidityPeriod {
			responseMap["EOLDate"] = "true"
			responseMap["EOLDateValue"] = parsedResponse.EolDate.String()
		}
	}

	//Check Image Health Check Grade from API
	if healthgradeValidCheck {
		failedhealthgrade := true
		imagehealthgrade := parsedResponse.ContentStreamGrades[0].Grade
		for i := 0; i < len(allowedHealthGrades); i++ {
			if imagehealthgrade == allowedHealthGrades[i] {
				failedhealthgrade = false
			}
		}
		if failedhealthgrade {
			responseMap["HealthGrade"] = "true"
			responseMap["HealthGradeValue"] = imagehealthgrade
		}
	}

	return responseMap
}

// sendResponse sends back the response to Gatekeeper.
func sendResponse(results *[]externaldata.Item, systemErr string, w http.ResponseWriter) {
	response := externaldata.ProviderResponse{
		APIVersion: apiVersion,
		Kind:       "ProviderResponse",
	}

	if results != nil {
		response.Response.Items = *results
	} else {
		response.Response.SystemError = systemErr
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		panic(err)
	}
}

func processTimeout(h http.HandlerFunc, duration time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), duration)
		defer cancel()

		r = r.WithContext(ctx)

		processDone := make(chan bool)
		go func() {
			h(w, r)
			processDone <- true
		}()

		select {
		case <-ctx.Done():
			sendResponse(nil, "operation timed out", w)
		case <-processDone:
		}
	}
}
