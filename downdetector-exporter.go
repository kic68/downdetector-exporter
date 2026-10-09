// downdetector-exporter is a Prometheus exporter for Downdetector metrics.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/urfave/cli/v3"

	"github.com/coreos/go-systemd/daemon"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	// a token can live at most 3600 seconds before it needs to be refreshed.
	tokenGraceSeconds = 300 // Seconds before token EOL when a new token must be fetched
	// seconds before next loop is started.
	minSleepSeconds = 60
	baseURL         = "https://downdetectorapi.com/v2"
)

var (
	// version is set via ldflags during build.
	version = "dev"
	lg      = log.NewLogfmtLogger(os.Stdout)

	// fields for metrics request. If expanded, struct CompanySet needs to be expanded accordingly.
	fieldsToReturn       = []string{"id", "name", "slug", "baseline_current", "country_iso", "stats_24", "stats_60", "status"}
	fieldsToReturnSearch = []string{"id", "name", "slug", "country_iso"}

	token       Token
	credentials BasicAuth
	username    string
	password    string

	httpClient *http.Client

	// Downdetector delivers one CompanySet per given ID.
	metricsResponse []CompanySet

	// exposed holds the various metrics that are collected.
	exposed = map[string]*prometheus.GaugeVec{}
	// show last update time to see if system is working correctly.
	lastUpdate = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dd_lastUpdate",
		Help: "Last update timestamp in epoch seconds",
	},
		[]string{"scope"},
	)
)

func init() {
	// add the lastUpdate metrics to prometheus
	prometheus.MustRegister(lastUpdate)
}

// BasicAuth contains username and string after reading them in from Yaml file.
type BasicAuth struct {
	UserName string `json:"username"`
	Password string `json:"password"`
}

// Token contains token, expiration at issuing time, type and, later, the time of issuing.
type Token struct {
	// Access containing access token (type Bearer normally)
	Access string `json:"access_token"`
	// ExpiresIn usually contains 3600 (seconds)
	ExpiresIn int `json:"expires_in"`
	// Type contains the token type (Bearer)
	Type string `json:"token_type"`
	// RefreshTime must programmatically be set after a token has been successfully fetched
	RefreshTime time.Time
}

// CompanySet contains returned data per Company
// CompanySet Prefix field with Label if value is to be used as label
// CompanySet Prefix field with Ignore if value is neither a metric nor a label but you want to handle it programmatically
// CompanySet Fields without Prefix will be used as metrics value.
type CompanySet struct {
	LabelCountryISO string `json:"country_iso,omitempty"`
	LabelName       string `json:"name,omitempty"`
	LabelSlug       string `json:"slug,omitempty"`
	// IgnoreStatus contains the status name (success, warning, danger) in string form
	IgnoreStatus string `json:"status,omitempty"`
	LabelID      int    `json:"id"`
	// BaseLineCurrent is a value generated over the last 24 hours, shows the normal baseline value of a service
	BaselineCurrent int `json:"baseline_current"`
	// Stats60 is the current metrics of mentions
	Stats60 int `json:"stats_60"`
	// IgnoreStats24 is the statistics over the last 24h in 15 minute buckets.
	IgnoreStats24 []int `json:"stats_24"`
	// Stats15 is the number of reports over the last 15
	Stats15 int `json:"-"`
	// NumStatus needs to be filled in programmatically from IgnoreStatus value so it can be used as metric
	NumStatus int `json:"-"`
}

func getCredentials(credentialsFile string) {
	// given username and password takes precedence over credentialsFile
	if username != "" && password != "" {
		credentials.UserName = username
		credentials.Password = password
	} else {
		osFile, err := os.Open(credentialsFile)
		if err != nil {
			// return if we weren't successful - we have tokenGraceSeconds to retry
			_ = level.Error(lg).Log("msg", "Couldn't read credentials file: "+err.Error())
			os.Exit(2)
		}
		// fmt.Println(dat)
		err = yaml.NewDecoder(osFile).Decode(&credentials)
		if err != nil || credentials.Password == "" || credentials.UserName == "" {
			errorText := "Username/Password not set"
			_ = level.Error(lg).Log("msg", "Couldn't parse credentials file: "+errorText)
			_ = level.Error(lg).Log("msg", "YAML file needs to contain userName and password fields")
			os.Exit(2)
		}
	}
}

func main() {
	// Destination variables of command line parser
	var listenAddress string
	var credentialsFile string
	var metricsPath string
	var logLevel string
	var companyIDs string
	var searchString string

	// TODO: - value checking
	// app is a command line parser
	cli.VersionFlag = &cli.BoolFlag{
		Name:    "version",
		Aliases: []string{"V"},
		Usage:   "print version information and exit",
	}

	app := &cli.Command{
		Authors: []any{
			mail.Address{
				Name:    "Torben Frey",
				Address: "torben@torben.dev",
			},
		},
		Commands:  nil,
		ArgsUsage: " ",
		Name:      "downdetector-exporter",
		Version:   version,
		Usage:     "report metrics of downdetector api",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "company_ids",
				Aliases:     []string{"i"},
				Usage:       "comma separated list of company ids to monitor",
				Destination: &companyIDs,
				Sources:     cli.EnvVars("COMPANY_IDS"),
			},
			&cli.StringFlag{
				Name:        "credentials_file",
				Aliases:     []string{"c"},
				Usage:       "file containing credentials for downdetector. Credentials file is in YAML format and contains two fields, username and password. Alternatively give username and password, they win over credentials file.",
				Destination: &credentialsFile,
				Sources:     cli.EnvVars("CREDENTIALS_FILE"),
			},
			&cli.StringFlag{
				Name:        "username",
				Value:       "",
				Aliases:     []string{"u"},
				Usage:       "username, wins over credentials file",
				Destination: &username,
				Sources:     cli.EnvVars("DD_USERNAME"),
			},
			&cli.StringFlag{
				Name:        "password",
				Value:       "",
				Aliases:     []string{"p"},
				Usage:       "password, wins over credentials file",
				Destination: &password,
				Sources:     cli.EnvVars("DD_PASSWORD"),
			},
			&cli.StringFlag{
				Name:        "listen_address",
				Value:       ":9313",
				Aliases:     []string{"l"},
				Usage:       "[optional] address to listen on, either :port or address:port",
				Destination: &listenAddress,
				Sources:     cli.EnvVars("LISTEN_ADDRESS"),
			},
			&cli.StringFlag{
				Name:        "metrics_path",
				Value:       "/metrics",
				Aliases:     []string{"m"},
				Usage:       "[optional] URL path where metrics are exposed",
				Destination: &metricsPath,
				Sources:     cli.EnvVars("METRICS_PATH"),
			},
			&cli.StringFlag{
				Name:        "log_level",
				Value:       "ERROR",
				Aliases:     []string{"v"},
				Usage:       "[optional] log level, choose from DEBUG, INFO, WARN, ERROR",
				Destination: &logLevel,
				Sources:     cli.EnvVars("LOG_LEVEL"),
			},
			&cli.StringFlag{
				Name:        "search_string",
				Value:       "",
				Aliases:     []string{"s"},
				Usage:       "[optional] search for companies containing this text and return their IDs",
				Destination: &searchString,
			},
		},
		Action: func(context.Context, *cli.Command) error {
			if credentialsFile == "" {
				if username == "" || password == "" {
					_ = level.Error(lg).Log("msg", "Either credentials_file or username and password need to be set!")

					os.Exit(2)
				}
			}

			if companyIDs == "" && searchString == "" {
				_ = level.Error(lg).Log("msg", "Either company_ids or a search string need to be set!")
				os.Exit(2)
			}

			// Debugging output
			lg = log.NewLogfmtLogger(os.Stdout)
			lg = log.With(lg, "ts", log.DefaultTimestamp, "caller", log.DefaultCaller)
			switch logLevel {
			case "DEBUG":
				lg = level.NewFilter(lg, level.AllowDebug())
			case "INFO":
				lg = level.NewFilter(lg, level.AllowInfo())
			case "WARN":
				lg = level.NewFilter(lg, level.AllowWarn())
			default:
				lg = level.NewFilter(lg, level.AllowError())
			}

			_ = level.Debug(lg).Log("msg", "listenAddress: "+listenAddress)
			_ = level.Debug(lg).Log("msg", "credentialsFile: "+credentialsFile)
			_ = level.Debug(lg).Log("msg", "metricsPath: "+metricsPath)
			_ = level.Debug(lg).Log("msg", fmt.Sprintf("companyIDs: %v", companyIDs))

			// install promhttp handler for metricsPath (/metrics)
			http.Handle(metricsPath, promhttp.Handler())

			// show nice web page if called without metricsPath
			http.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
				if _, err := w.Write([]byte(`<html>
					<head><title>Downdetector Exporter</title></head>
					<body>
					<h1>Downdetector Exporter</h1>
					<p><a href='` + metricsPath + `'>Metrics</a></p>
					</body>
					</html>`)); err != nil {
					_ = level.Warn(lg).Log("msg", "couldn't write response: "+err.Error())
				}
			})

			// Start the http server in background, but catch error
			go func() {
				err := http.ListenAndServe(listenAddress, nil)
				_ = level.Error(lg).Log("msg", err.Error())
				os.Exit(2)
			}()

			// wait for initialization of http server before looping so the systemd alive check doesn't fail
			time.Sleep(time.Second * 3)

			// notify systemd that we're ready
			if _, err := daemon.SdNotify(false, daemon.SdNotifyReady); err != nil {
				_ = level.Warn(lg).Log("msg", "systemd notify failed: "+err.Error())
			}

			// read in credentials from Yaml file or username/password variables
			getCredentials(credentialsFile)

			// TODO: Proxy URL instead of ""
			httpClient = getHTTPClient("")

			// Working loop
			for {
				// does the individual work, so the rest of the code can be used for other exporters
				workHorse(companyIDs, searchString)

				// send aliveness to systemd
				systemAlive(listenAddress, metricsPath)

				// sleep minSleepSeconds seconds before starting next loop
				time.Sleep(time.Second * minSleepSeconds)
			}
		},
	}

	// Start the app
	err := app.Run(context.Background(), os.Args)
	if err != nil {
		_ = level.Error(lg).Log("msg", err.Error())
	}
}

func workHorse(companyIDs string, searchString string) {
	// refresh token if only tokenGraceSeconds are left before it expires
	if token.Access == "" || int(time.Since(token.RefreshTime).Seconds()) > token.ExpiresIn-tokenGraceSeconds {
		_ = level.Debug(lg).Log("msg", "refreshing token")
		initToken()
	} else {
		_ = level.Debug(lg).Log("msg", fmt.Sprintf("Seconds before a new token must be fetched: %d", (token.ExpiresIn-tokenGraceSeconds)-int(time.Since(token.RefreshTime).Seconds())))
	}

	if getMetrics(companyIDs, searchString) {
		os.Exit(2)
	}
}

func getHTTPClient(proxyURLStr string) *http.Client {
	var (
		httpRequestsTotal = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "client_api_requests_total",
				Help: "Total number of client requests made.",
			},
			[]string{"method", "code"},
		)
	)
	prometheus.MustRegister(httpRequestsTotal)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	if proxyURLStr != "" {
		proxyURL, err := url.Parse(proxyURLStr)
		if err != nil {
			_ = level.Error(lg).Log("msg", "Couldn't parse proxy url: "+err.Error())
			os.Exit(2)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	roundTripper := promhttp.InstrumentRoundTripperCounter(httpRequestsTotal, transport)

	// adding the Transport object to the http Client
	client := &http.Client{
		Transport: roundTripper,
		Timeout:   60 * time.Second,
	}
	return client
}

func initToken() {
	// create the token refresh request
	url := baseURL + "/tokens?grant_type=client_credentials"
	req, err := http.NewRequest(http.MethodPost, url, nil)
	req.SetBasicAuth(credentials.UserName, credentials.Password)
	if err != nil {
		// return if we weren't successful - we have tokenGraceSeconds to retry
		_ = level.Warn(lg).Log("msg", "Couldn't apply Basic Auth: "+err.Error())
		return
	}
	// send the token refresh request
	res, err := httpClient.Do(req)
	if err != nil {
		_ = level.Error(lg).Log("msg", "Couldn't get token: "+err.Error())
		return
	}
	if res.StatusCode != http.StatusOK {
		// return if we weren't successful - we have tokenGraceSeconds to retry
		body, _ := io.ReadAll(res.Body)
		_ = level.Warn(lg).Log("msg", fmt.Sprintf("Error response code: %d - %s", res.StatusCode, body))
		return
	}
	defer func() { _ = res.Body.Close() }()

	// read body from response
	body, err := io.ReadAll(res.Body)
	if err != nil {
		// return if we weren't successful - we have tokenGraceSeconds to retry
		_ = level.Warn(lg).Log("msg", "Couldn't read in body: "+err.Error())
		return
	}

	// unmarshal body content into token struct
	err = json.Unmarshal(body, &token)
	if err != nil {
		_ = level.Warn(lg).Log("msg", "Couldn't unmarshal json: "+err.Error())
		return
	}

	// Mark we have refreshed token right now
	token.RefreshTime = time.Now()
	_ = level.Debug(lg).Log("msg", "Token Type: "+token.Type)
	_ = level.Debug(lg).Log("msg", fmt.Sprintf("Expires in: %d", token.ExpiresIn))
	_ = level.Debug(lg).Log("msg", fmt.Sprintf("Token Refresh Time: %s", token.RefreshTime))
}

// getMetrics fetches metrics or search results and reports whether the caller should exit afterwards.
func getMetrics(companyIDs string, searchString string) bool {
	var url string
	if searchString == "" {
		// create the metrics fetching request
		url = baseURL + "/companies?fields=" + strings.Join(fieldsToReturn, "%2C") + "&ids=" + strings.ReplaceAll(companyIDs, ",", "%2C")
	} else {
		url = baseURL + "/companies/search?name=" + searchString + "&fields=" + strings.Join(fieldsToReturnSearch, "%2C")
	}
	// curl --request GET -H "Authorization: Bearer $TOKEN" --url 'https://downdetectorapi.com/v2/companies/search?name=mail.com&fields=url%2Cbaseline%2Csite_id%2Cstatus%2Ccountry_iso%2Cname%2Cslug' | jq .

	req, err := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Add("Authorization", "Bearer "+token.Access)
	if err != nil {
		_ = level.Warn(lg).Log("msg", "Couldn't apply authorization header: "+err.Error())
		return false
	}
	// send the metrics request
	res, err := httpClient.Do(req)
	if err != nil {
		_ = level.Error(lg).Log("msg", "Couldn't get metrics: "+err.Error())
		return false
	}
	if res.StatusCode != http.StatusOK {
		// return if we weren't successful
		body, _ := io.ReadAll(res.Body)
		_ = level.Warn(lg).Log("msg", fmt.Sprintf("Could not get metrics: %d - %s", res.StatusCode, body))
		return false
	}
	defer func() { _ = res.Body.Close() }()

	// read body from response
	body, err := io.ReadAll(res.Body)
	if err != nil {
		// return if we weren't successful - we have tokenGraceSeconds to retry
		_ = level.Warn(lg).Log("msg", "Couldn't read in body: "+err.Error())
		return false
	}

	// unmarshal body content into metricResponse struct
	err = json.Unmarshal(body, &metricsResponse)
	if err != nil {
		_ = level.Warn(lg).Log("msg", "Couldn't unmarshal json: "+err.Error())
		return false
	}

	// Loop through all companies in response
	for _, companySet := range metricsResponse {
		if searchString != "" {
			fmt.Printf("ID: %d - Name: %s, Slug: %s, Country: %s\n", companySet.LabelID, companySet.LabelName, companySet.LabelSlug, companySet.LabelCountryISO)
		} else {
			// convert string value (success, warning, danger) to int metrics
			switch companySet.IgnoreStatus {
			case "success":
				companySet.NumStatus = 0
			case "warning":
				companySet.NumStatus = 1
			case "danger":
				companySet.NumStatus = 2
			default:
				companySet.NumStatus = -1
			}
			// get last value from Stats24 array
			companySet.Stats15 = companySet.IgnoreStats24[len(companySet.IgnoreStats24)-1]

			// Debugging output
			_ = level.Debug(lg).Log("msg", "")
			_ = level.Debug(lg).Log("msg", "===== Labels =====")
			_ = level.Debug(lg).Log("msg", "Name:             "+companySet.LabelName)
			_ = level.Debug(lg).Log("msg", "Slug:             "+companySet.LabelSlug)
			_ = level.Debug(lg).Log("msg", "Country:          "+companySet.LabelCountryISO)
			_ = level.Debug(lg).Log("msg", fmt.Sprintf("Name:             %d", companySet.LabelID))
			_ = level.Debug(lg).Log("msg", "===== Info =====")
			_ = level.Debug(lg).Log("msg", "Status:           "+companySet.IgnoreStatus)
			_ = level.Debug(lg).Log("msg", "===== Metrics =====")
			_ = level.Debug(lg).Log("msg", fmt.Sprintf("Current Baseline: %d", companySet.BaselineCurrent))
			_ = level.Debug(lg).Log("msg", fmt.Sprintf("Stats60:          %d", companySet.Stats60))
			_ = level.Debug(lg).Log("msg", fmt.Sprintf("Stats15:          %d", companySet.Stats15))
			_ = level.Debug(lg).Log("msg", fmt.Sprintf("Status:           %d", companySet.NumStatus))

			// create empty array to hold labels
			labels := make([]string, 0)
			// create empty array to hold label values
			labelValues := make([]string, 0)

			// reflect to get members of struct
			cs := reflect.ValueOf(companySet)
			typeOfCompanySet := cs.Type()

			// Loop over all struct members and collect all fields starting with Label in array of labels
			_ = level.Debug(lg).Log("msg", "")
			_ = level.Debug(lg).Log("msg", "Looping over CompanySet")

			for i := 0; i < cs.NumField(); i++ {
				key := typeOfCompanySet.Field(i).Name
				value := cs.Field(i).Interface()
				_ = level.Debug(lg).Log("msg", fmt.Sprintf("Field: %s, Value: %v", key, value))
				if after, ok := strings.CutPrefix(key, "Label"); ok {
					// labels have lower case names
					labels = append(labels, strings.ToLower(after))
					var labelValue string
					// IDs are returned as integers, convert to string
					if cs.Field(i).Type().Name() == "string" {
						labelValue = cs.Field(i).String()
					} else {
						labelValue = strconv.FormatInt(cs.Field(i).Int(), 10)
					}
					labelValues = append(labelValues, labelValue)
				}
			}
			_ = level.Debug(lg).Log("msg", "")
			_ = level.Debug(lg).Log("msg", fmt.Sprintf("Labels: %v", labels))

			// Loop over all struct fields and set Exporter to value with list of labels if they don't
			// start with Label or Ignore
			_ = level.Debug(lg).Log("msg", "")
			for i := 0; i < cs.NumField(); i++ {
				key := typeOfCompanySet.Field(i).Name
				if !strings.HasPrefix(key, "Label") && !strings.HasPrefix(key, "Ignore") {
					value := cs.Field(i).Int()
					setPrometheusMetric(key, int(value), labels, labelValues)
				}
			}
		}
	}
	return searchString != ""
}

func setPrometheusMetric(key string, value int, labels []string, labelValues []string) {
	_ = level.Debug(lg).Log("msg", fmt.Sprintf("Key: %s, Value: %d, Labels: %v", key, value, labels))
	// Check if metric is already registered, if not, register it
	_, ok := exposed[key]
	if !ok {
		exposed[key] = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "dd_" + key,
			Help: "N/A",
		},
			labels,
		)

		prometheus.MustRegister(exposed[key])
	}

	// Now set the value
	exposed[key].WithLabelValues(labelValues...).Set(float64(value))

	// Update lastUpdate so we immediately see when no updates happen anymore
	now := time.Now()
	seconds := now.Unix()
	lastUpdate.WithLabelValues("global").Set(float64(seconds))
}

func systemAlive(listenAddress string, metricsPath string) {
	// systemd alive check
	var metricsURL string
	if !strings.HasPrefix(listenAddress, ":") {
		// User has provided address + port
		metricsURL = "http://" + listenAddress + metricsPath
	} else {
		// User has provided :port only - we need to check ourselves on 127.0.0.1
		metricsURL = "http://127.0.0.1" + listenAddress + metricsPath
	}

	// Call the metrics URL...
	res, err := http.Get(metricsURL)
	if err != nil {
		// ... do nothing if it was not ok, but log. Systemd will restart soon.
		_ = level.Warn(lg).Log("msg", "liveness check failed: "+err.Error())
		return
	}
	// ... and notify systemd that everything was ok
	if _, err := daemon.SdNotify(false, daemon.SdNotifyWatchdog); err != nil {
		_ = level.Warn(lg).Log("msg", "systemd notify failed: "+err.Error())
	}
	// Read all away or else we'll run out of sockets sooner or later
	_, _ = io.ReadAll(res.Body)
	if err := res.Body.Close(); err != nil {
		_ = level.Warn(lg).Log("msg", "couldn't close response body: "+err.Error())
	}
}
