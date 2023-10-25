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

//TODO: Need to Add Caching for External API Calls

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/exp/slog"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/joho/godotenv"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
)

type SkopeoResponse struct {
	Name          string    `json:"Name,omitempty"`
	Digest        string    `json:"Digest,omitempty"`
	RepoTags      []string  `json:"RepoTags,omitempty"`
	Created       time.Time `json:"Created,omitempty"`
	DockerVersion string    `json:"DockerVersion,omitempty"`
	Labels        struct {
		Architecture              string `json:"architecture,omitempty"`
		BuildDate                 string `json:"build-date,omitempty"`
		ComRedhatComponent        string `json:"com.redhat.component,omitempty"`
		ComRedhatLicenseTerms     string `json:"com.redhat.license_terms,omitempty"`
		Description               string `json:"description,omitempty"`
		DistributionScope         string `json:"distribution-scope,omitempty"`
		IoBuildahVersion          string `json:"io.buildah.version,omitempty"`
		IoK8SDescription          string `json:"io.k8s.description,omitempty"`
		IoK8SDisplayName          string `json:"io.k8s.display-name,omitempty"`
		IoOpenshiftExposeServices string `json:"io.openshift.expose-services,omitempty"`
		IoOpenshiftTags           string `json:"io.openshift.tags,omitempty"`
		Maintainer                string `json:"maintainer,omitempty"`
		Name                      string `json:"name,omitempty"`
		Release                   string `json:"release,omitempty"`
		Summary                   string `json:"summary,omitempty"`
		UpstreamRef               string `json:"upstream-ref,omitempty"`
		UpstreamURL               string `json:"upstream-url,omitempty"`
		URL                       string `json:"url,omitempty"`
		VcsRef                    string `json:"vcs-ref,omitempty"`
		VcsType                   string `json:"vcs-type,omitempty"`
		Vendor                    string `json:"vendor,omitempty"`
		Version                   string `json:"version,omitempty"`
	} `json:"Labels,omitempty"`
	Architecture string   `json:"Architecture,omitempty"`
	Os           string   `json:"Os,omitempty"`
	Layers       []string `json:"Layers,omitempty"`
	Env          []string `json:"Env,omitempty"`
}

type ImageAPIResponse struct {
	Data []struct {
		ID    string `json:"_id"`
		Links struct {
			Artifacts struct {
				Href string `json:"href"`
			} `json:"artifacts"`
			Requests struct {
				Href string `json:"href"`
			} `json:"requests"`
			RpmManifest struct {
				Href string `json:"href"`
			} `json:"rpm_manifest"`
			TestResults struct {
				Href string `json:"href"`
			} `json:"test_results"`
			Vulnerabilities struct {
				Href string `json:"href"`
			} `json:"vulnerabilities"`
		} `json:"_links"`
		Architecture string `json:"architecture"`
		Brew         struct {
			Build          string    `json:"build"`
			CompletionDate time.Time `json:"completion_date"`
			Nvra           string    `json:"nvra"`
			Package        string    `json:"package"`
		} `json:"brew,omitempty"`
		CloudService       bool      `json:"cloud_service,omitempty"`
		Certified          bool      `json:"certified,omitempty"`
		ContentSets        []string  `json:"content_sets"`
		CpeIds             []string  `json:"cpe_ids"`
		CpeIdsRHBaseImages []string  `json:"cpe_ids_rh_base_images,omitempty"`
		CreationDate       time.Time `json:"creation_date"`
		DockerImageID      string    `json:"docker_image_id"`
		FreshnessGrades    []struct {
			CreationDate time.Time `json:"creation_date,omitempty"`
			EndDate      time.Time `json:"end_date,omitempty"`
			Grade        string    `json:"grade"`
			StartDate    time.Time `json:"start_date"`
		} `json:"freshness_grades,omitempty"`
		ImageID        string    `json:"image_id"`
		LastUpdateDate time.Time `json:"last_update_date"`
		ObjectType     string    `json:"object_type"`
		ParsedData     struct {
			Architecture  string    `json:"architecture,omitempty"`
			Command       string    `json:"command,omitempty"`
			Comment       string    `json:"comment,omitempty"`
			Created       time.Time `json:"created,omitempty"`
			DockerVersion string    `json:"docker_version,omitempty"`
			Image_ID      string    `json:"image_id,omitempty"`
			EnvVariables  []string  `json:"env_variables"`
			Labels        []struct {
				Name  string `json:"name,omitempty"`
				Value string `json:"value,omitempty"`
			} `json:"labels,omitempty"`
			Layers                 []string `json:"layers"`
			Os                     string   `json:"os"`
			Size                   int      `json:"size"`
			UncompressedLayerSizes []struct {
				LayerID   string `json:"layer_id"`
				SizeBytes int    `json:"size_bytes"`
			} `json:"uncompressed_layer_sizes,omitempty"`
			UncompressedSizeBytes int    `json:"uncompressed_size_bytes"`
			User                  string `json:"user"`
		} `json:"parsed_data,omitempty"`
		RawConfig    string `json:"raw_config"`
		Repositories []struct {
			Links struct {
				ImageAdvisory struct {
					Href string `json:"href"`
				} `json:"image_advisory"`
				Repository struct {
					Href string `json:"href"`
				} `json:"repository"`
			} `json:"_links"`
			Comparison struct {
				AdvisoryRpmMapping []struct {
					AdvisoryIds []string `json:"advisory_ids"`
					Nvra        string   `json:"nvra"`
				} `json:"advisory_rpm_mapping"`
				Reason     string `json:"reason"`
				ReasonText string `json:"reason_text"`
				Rpms       struct {
					Downgrade []interface{} `json:"downgrade"`
					New       []interface{} `json:"new"`
					Remove    []interface{} `json:"remove"`
					Upgrade   []string      `json:"upgrade"`
				} `json:"rpms"`
				WithNvr string `json:"with_nvr"`
			} `json:"comparison"`
			ContentAdvisoryIds    []string  `json:"content_advisory_ids"`
			ImageAdvisoryID       string    `json:"image_advisory_id"`
			ManifestListDigest    string    `json:"manifest_list_digest"`
			ManifestSchema2Digest string    `json:"manifest_schema2_digest"`
			Published             bool      `json:"published"`
			PublishedDate         time.Time `json:"published_date"`
			PushDate              time.Time `json:"push_date"`
			Registry              string    `json:"registry"`
			Repository            string    `json:"repository"`
			Signatures            []struct {
				KeyLongID string   `json:"key_long_id"`
				Tags      []string `json:"tags"`
			} `json:"signatures"`
			Tags []struct {
				Links struct {
					TagHistory struct {
						Href string `json:"href"`
					} `json:"tag_history"`
				} `json:"_links"`
				AddedDate time.Time `json:"added_date"`
				Name      string    `json:"name"`
			} `json:"tags"`
		} `json:"repositories"`
		SumLayerSizeBytes      int64  `json:"sum_layer_size_bytes"`
		TopLayerID             string `json:"top_layer_id"`
		UncompressedTopLayerID string `json:"uncompressed_top_layer_id"`
	} `json:"data"`
	Page     int `json:"page"`
	PageSize int `json:"page_size"`
	Total    int `json:"total"`
}

type RegistryAPIResponse struct {
	ID    string `json:"_id"`
	Links struct {
		CertificationProject struct {
			Href string `json:"href,omitempty"`
		} `json:"certification_project"`
		Images struct {
			Href string `json:"href,omitempty"`
		} `json:"images"`
		OperatorBundles struct {
			Href string `json:"href,omitempty"`
		} `json:"operator_bundles"`
		ProductListings struct {
			Href string `json:"href,omitempty"`
		} `json:"product_listings"`
		Vendor struct {
			Href string `json:"href,omitempty"`
		} `json:"vendor"`
	} `json:"_links,omitempty"`
	ApplicationCategories    []string `json:"application_categories,omitempty"`
	AutoRebuildTags          []string `json:"auto_rebuild_tags,omitempty"`
	BuildCategories          []string `json:"build_categories,omitempty"`
	CanAutoReleaseCveRebuild bool     `json:"can_auto_release_cve_rebuild,omitempty"`
	ContentStreamGrades      []struct {
		Grade    string `json:"grade,omitempty"`
		ImageIds []struct {
			Arch string `json:"arch,omitempty"`
			ID   string `json:"id,omitempty"`
		} `json:"image_ids,omitempty"`
		Tag string `json:"tag,omitempty"`
	} `json:"content_stream_grades,omitempty"`
	ContentStreamTags []string  `json:"content_stream_tags,omitempty"`
	CreationDate      time.Time `json:"creation_date,omitempty"`
	Description       string    `json:"description"`
	DisplayData       struct {
		LongDescription         string `json:"long_description,omitempty"`
		LongDescriptionMarkdown string `json:"long_description_markdown,omitempty"`
		Name                    string `json:"name,omitempty"`
		OpenshiftTags           string `json:"openshift_tags,omitempty"`
		ShortDescription        string `json:"short_description,omitempty"`
	} `json:"display_data,omitempty"`
	DocumentationLinks              []any     `json:"documentation_links"`
	Deprecated                      bool      `json:"deprecated,omitempty"`
	EolDate                         time.Time `json:"eol_date,omitempty"`
	FbcOptIn                        bool      `json:"fbc_opt_in"`
	FreshnessGradesUnknownUntilDate any       `json:"freshness_grades_unknown_until_date"`
	IncludesMultipleContentStreams  bool      `json:"includes_multiple_content_streams"`
	LastUpdateDate                  time.Time `json:"last_update_date,omitempty"`
	MetadataSource                  string    `json:"metadata_source"`
	Metrics                         struct {
		LastUpdateDate time.Time `json:"last_update_date,omitempty"`
		PullCount      int       `json:"pulls_in_last_30_days,omitempty"`
	} `json:"metrics,omitempty"`
	Namespace                  string   `json:"namespace"`
	NonProductionOnly          bool     `json:"non_production_only"`
	ObjectType                 string   `json:"object_type"`
	PrivilegedImagesAllowed    bool     `json:"privileged_images_allowed"`
	ProductID                  any      `json:"product_id"`
	ProductListings            []string `json:"product_listings"`
	ProtectedForPull           bool     `json:"protected_for_pull"`
	ProtectedForSearch         bool     `json:"protected_for_search"`
	Published                  bool     `json:"published"`
	Registry                   string   `json:"registry"`
	RegistryTarget             string   `json:"registry_target"`
	ReplacedByRepository       string   `json:"replaced_by_repository_name,omitempty"`
	ReleaseCategories          []string `json:"release_categories"`
	Repository                 string   `json:"repository"`
	RequiresTerms              bool     `json:"requires_terms,omitempty"`
	SupportLevels              []string `json:"support_levels,omitempty"`
	TotalSizeBytes             int      `json:"total_size_bytes,omitempty"`
	TotalUncompressedSizeBytes int64    `json:"total_uncompressed_size_bytes,omitempty"`
	UseLatest                  bool     `json:"use_latest"`
	VendorLabel                string   `json:"vendor_label"`
}

const (
	readTimeout                = 10 * time.Second
	writeTimeout               = 10 * time.Second
	apiVersion                 = "externaldata.gatekeeper.sh/v1beta1"
	applicationName            = "rh-registry-gatekeeper-provider"
	constRegistryURL           = "https://catalog.redhat.com/api/containers/v1"
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
	//Valid Registries
	validRegistries = []string{"registry.access.redhat.com", "registry.redhat.io"}

	//global context
	logger *slog.Logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))

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
		logger.Info("No .env file found, Will use env variables")
	}

	//Set Context logging

	// logger options- TODO Implement global logging level
	//opts := slog.HandlerOptions{
	//		AddSource: false,
	//		Level:     slog.LevelDebug,
	//	}

	slog.SetDefault(logger)

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

	//Set Local Variables
	var err error
	var shouldnoterror error

	//Read env variables

	serverPort = getEnvSetDefault("SERVER_PORT", constServerPort)
	registryAPIURL = getEnvSetDefault("REGISTRY_API_URL", constRegistryURL)
	registryAPIMethod = getEnvSetDefault("REGISTRY_API_METHOD", constRegistrymethod)

	httpsEnabled, err = strconv.ParseBool(getEnvSetDefault(("HTTPS_ENABLED"), https_enabled))
	if err != nil {
		slog.Info("EOL_DATE_VALID_CHECK not set, defaulting to True")
		eolDateValidCheck = true
	}

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

		// create a cert pool and add cert to it
		clientCAs := x509.NewCertPool()
		clientCAs.AppendCertsFromPEM(caCert)

		//Add Cert to System Pool
		systemclientCA, err := x509.SystemCertPool()
		if err != nil {
			logger.Error("Error adding Gatekeeper CA to System Cert Pool: %s", err)
		} else {
			systemclientCA.AppendCertsFromPEM(caCert)
		}

		mux := http.NewServeMux()
		mux.HandleFunc("/validate", processTimeout(validate, readTimeout))
		mux.HandleFunc("/mutatetagdigest", processTimeout(mutatetagdigest, readTimeout))

		server := &http.Server{
			Addr:              serverPort,
			Handler:           mux,
			ReadHeaderTimeout: readTimeout,
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
		http.HandleFunc("/mutatetagdigest", mutatetagdigest)
		srv := &http.Server{
			Addr:              serverPort,
			ReadTimeout:       readTimeout,
			WriteTimeout:      writeTimeout,
			ReadHeaderTimeout: readTimeout,
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
	var appendregistryAPIURL string

	results := make([]externaldata.Item, 0)

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
	for idx, key := range providerRequest.Request.Keys {
		fmt.Println(idx, key)
		logger.Info(fmt.Sprintf("Validating Image: %s", key))
		var parsedRegistryResponse RegistryAPIResponse
		nestedresults := make([]externaldata.Item, 0)
		//var parsedImageResponse ImageAPIResponse
		apiqueryStrings := make(map[string]string)
		apirequestHeaders := make(map[string]string)

		//Parse Image Name
		ref, err := name.ParseReference(key)
		if err != nil {
			sendResponse(nil, fmt.Sprintf("ERROR (ParseReference(%q)): %v", key, err), w)
			return
		}

		//Supported Registry Check
		if !(validRegistriesCheck(ref.Context().RegistryStr())) {
			sendResponse(nil, fmt.Sprintf("ERROR: Registry %s is not supported by this Provider", ref.String()), w)
			return
		}

		//Set API Header
		apirequestHeaders["accept"] = "application/json"

		//Determine which API to call first depending on
		if strings.Contains(ref.Identifier(), "sha256") {
			appendregistryAPIURL = fmt.Sprintf("%s/repositories/registry/registry.access.redhat.com/repository/%s/images", registryAPIURL, ref.Context().RepositoryStr())
			apiqueryStrings["filter"] = fmt.Sprintf("repositories.published==true;repositories.manifest_list_digest==%s", ref.Identifier())
			apiqueryStrings["sort_by"] = "last_update_date[desc]"
			apiqueryStrings["page_size"] = "1"

		} else {
			appendregistryAPIURL = fmt.Sprintf("%s/repositories/registry/registry.access.redhat.com/repository/%s/tag/%s", registryAPIURL, ref.Context().RepositoryStr(), ref.Identifier())
		}

		//Make request to RH registry API
		apiresponse, err := callAPI(registryAPIMethod, appendregistryAPIURL, apirequestHeaders, apiqueryStrings)
		if err != nil {
			sendResponse(nil, fmt.Sprintf("%s", err), w)
			defer apiresponse.Body.Close()
			return
		}

		//Read response body
		apiresponseBody, err := io.ReadAll(apiresponse.Body)
		if err != nil {
			errorString := fmt.Sprintf("client: could not read response body: %s\n", err)
			sendResponse(nil, errorString, w)
			defer apiresponse.Body.Close()
			return
		}

		//Parse response body
		parsedImageResponse, err := parseImageResponse(apiresponseBody)
		if err != nil {
			errorString := fmt.Sprintf("client: could not parse response body: %s\n", err)
			sendResponse(nil, errorString, w)
			defer apiresponse.Body.Close()
			return
		}

		if eolDateValidCheck || deprecatedValidCheck {
			//Make request to RH registry API
			apiresponse, err = callAPI(registryAPIMethod, fmt.Sprintf("%s/repositories/registry/registry.access.redhat.com/repository/%s", registryAPIURL, ref.Context().RepositoryStr()), nil, nil)
			if err != nil {
				errorString := fmt.Sprintf("client: could not read response body: %s\n", err)
				sendResponse(nil, errorString, w)
				defer apiresponse.Body.Close()
				return
			}

			//Read response body
			apiresponseBody, err := io.ReadAll(apiresponse.Body)
			if err != nil {
				errorString := fmt.Sprintf("client: could not read response body: %s\n", err)
				sendResponse(nil, errorString, w)
				defer apiresponse.Body.Close()
				return
			}

			//Parse Registry response body
			parsedRegistryResponse, err = parseRegistryResponse(apiresponseBody)
			if err != nil {
				errorString := fmt.Sprintf("client: could not parse response body: %s\n", err)
				sendResponse(nil, errorString, w)
				defer apiresponse.Body.Close()
				return
			}

			//Check if Image is EOL
			if eolDateValidCheck {
				checkresponse := repoisEOLCheck(parsedRegistryResponse)
				for k, v := range checkresponse {
					nestedresults = append(nestedresults, externaldata.Item{
						Key:   k,
						Value: v,
					})
				}
			}

			//Check if Image is Deprecated
			if deprecatedValidCheck {
				checkresponse := repoisDeprecatedCheck(parsedRegistryResponse)
				for k, v := range checkresponse {
					nestedresults = append(nestedresults, externaldata.Item{
						Key:   k,
						Value: v,
					})
				}
			}
		}

		//Check if HealthGrade is Good
		if healthgradeValidCheck {
			checkresponse := imageHealthGradeCheck(parsedImageResponse)
			for k, v := range checkresponse {

				nestedresults = append(nestedresults, externaldata.Item{
					Key:   k,
					Value: v,
				})
			}
		}
		results = append(results, externaldata.Item{
			Key:   key,
			Value: nestedresults,
		})

	}
	sendResponse(&results, "", w)
}

func validRegistriesCheck(registry string) bool {
	return slices.Contains(validRegistries, registry)
}

func callAPI(httprequestMethod string, apirequestURL string, apirequestHeaders map[string]string, apiqueryStrings map[string]string) (*http.Response, error) {
	// Create request to API
	apirequest, err := http.NewRequest(httprequestMethod, apirequestURL, nil)
	if err != nil {
		errorString := fmt.Sprintf("client: could not create request: %s\n", err)
		logger.Debug(errorString)
		return nil, err
	}

	// Set headers
	for k, v := range apirequestHeaders { // Add all headers to request
		apirequest.Header.Set(k, v)
	}

	// Set query strings
	if len(apiqueryStrings) > 0 {
		apiquery := apirequest.URL.Query()
		for k, v := range apiqueryStrings { // Add all headers to request
			apiquery.Add(k, v)
		}
		apirequest.URL.RawQuery = apiquery.Encode()
	}

	//Make request to RH registry API
	apiresponse, err := http.DefaultClient.Do(apirequest)
	if err != nil {
		errorString := fmt.Sprintf("client: error making http request: %s\n", err)
		logger.Debug(errorString)
		return nil, err
	}

	//Check if we got a valid status code
	logger.Debug("client: got a response from RH Registry!\n")
	if apiresponse.StatusCode != http.StatusOK {
		errorString := fmt.Sprintf("client did not got valid status code: %d\n", apiresponse.StatusCode)
		logger.Debug(errorString)
		return nil, errors.New(errorString)
	}

	return apiresponse, nil
}

func mutatetagdigest(w http.ResponseWriter, req *http.Request) {
	results := make([]externaldata.Item, 0)

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

	for _, key := range providerRequest.Request.Keys {
		logger.Info(fmt.Sprintf("Recieved Request to Mutate Image:%s", key))

		ref, err := name.ParseReference(key)
		if err != nil {
			sendResponse(nil, fmt.Sprintf("ERROR (ParseReference(%q)): %v", key, err), w)
			return
		}

		//Parse Image Name
		parsedSkopeoResponse, error := skopeoShellCommand(ref.String())
		if error != nil {
			sendResponse(nil, fmt.Sprintf("ERROR (ParseReference(%q)): %v", key, err), w)
			return
		}
		results = append(results, externaldata.Item{
			Key:   ref.String(),
			Value: fmt.Sprintf("%s/%s@%s", ref.Context().RegistryStr(), ref.Context().RepositoryStr(), parsedSkopeoResponse.Digest),
		})

	}
	sendResponse(&results, "Enable Indempotent Flag", w)

}

// parseRegistryResponse parses the response from the RH Registry API when it returns a ContainerRegistryType
func parseRegistryResponse(apiresponseBody []byte) (RegistryAPIResponse, error) {
	var parsedResponse RegistryAPIResponse
	if err := json.Unmarshal(apiresponseBody, &parsedResponse); err != nil { // Parse []byte to go struct pointer
		logger.Error("Can not unmarshal JSON: %s", err)
		return parsedResponse, err
	}

	return parsedResponse, nil
}

// parseImageResponse parses the response from the RH Registry API when it returns a ContainerImageType
func parseImageResponse(apiresponseBody []byte) (ImageAPIResponse, error) {
	var parsedResponse ImageAPIResponse
	if err := json.Unmarshal(apiresponseBody, &parsedResponse); err != nil { // Parse []byte to go struct pointer
		logger.Error("Can not unmarshal JSON: %s", err)
		return parsedResponse, err
	}

	if parsedResponse.Total == 0 {
		return parsedResponse, errors.New("got empty result from api")
	}

	return parsedResponse, nil
}

// repoisDeprecatedCheck checks if the Registry Deprecated Flag is Set
func repoisDeprecatedCheck(parsedResponse RegistryAPIResponse) map[string]string {
	responseMap := make(map[string]string)
	if slices.Contains(parsedResponse.ReleaseCategories, "Deprecated") {
		responseMap["Deprecated"] = "true"
	} else {
		responseMap["Deprecated"] = "false"
	}
	return responseMap
}

// repoisEOLCheck checks if the image is EOL based on the EOL Date
func repoisEOLCheck(parsedResponse RegistryAPIResponse) map[string]string {
	responseMap := make(map[string]string)

	if !parsedResponse.EolDate.IsZero() {
		if time.Since(parsedResponse.EolDate).Minutes() > eolDateValidityPeriod {
			responseMap["EOLDate"] = "true"
			responseMap["EOLDateValue"] = parsedResponse.EolDate.String()
		} else {
			responseMap["EOLDate"] = "false"
		}
	} else {
		responseMap["EOLDate"] = "false"
	}

	return responseMap
}

// imageHealthGradeCheck checks if the image health grade is allowed
func imageHealthGradeCheck(parsedResponse ImageAPIResponse) map[string]string {
	responseMap := make(map[string]string)
	failedhealthgrade := true
	imagehealthgrade := parsedResponse.Data[0].FreshnessGrades[0].Grade
	for i := 0; i < len(allowedHealthGrades); i++ {
		if imagehealthgrade == allowedHealthGrades[i] {
			failedhealthgrade = false
		}
	}
	if failedhealthgrade {
		responseMap["HealthGrade"] = "true"
		responseMap["HealthGradeValue"] = imagehealthgrade
	} else {
		responseMap["HealthGrade"] = "false"
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
		//TODO: Should add another Function Paramater but dont want to refactor at this time
		if systemErr == "Enable Indempotent Flag" {
			response.Response.Idempotent = true
			response.Response.SystemError = ""
		}

	} else {
		response.Response.SystemError = systemErr
	}

	logger.Info(fmt.Sprintf("Sending Response: %s", PrettyPrint(response)))
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

func skopeoShellCommand(image string) (SkopeoResponse, error) {
	var outbuf, errbuf strings.Builder
	var parsedResponse SkopeoResponse

	cmd := exec.Command("skopeo", "inspect", fmt.Sprintf("docker://%s", image))
	cmd.Stdout = &outbuf
	cmd.Stderr = &errbuf
	err := cmd.Run()
	if err != nil {
		logger.Error("Error running skopeo command: %s", err)
		return parsedResponse, err
	}

	if err := json.Unmarshal([]byte(outbuf.String()), &parsedResponse); err != nil { // Parse []byte to go struct pointer
		logger.Error("Can not unmarshal JSON: %s", err)
		return parsedResponse, err
	}

	return parsedResponse, err

}
