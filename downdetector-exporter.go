package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/go-kit/kit/log"
	kitlog "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/urfave/cli/v2"

	"github.com/coreos/go-systemd/daemon"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	// a token can live at most 3600 seconds before it needs to be refreshed
	tokenGraceSeconds = 300 // Seconds before token EOL when a new token must be fetched
	// seconds before next loop is started
	minSleepSeconds = 60
	baseURL         = "https://downdetectorapi.com/v2"
)

var (
	lg = kitlog.NewLogfmtLogger(os.Stdout)

	// fields for metrics request. If expanded, struct CompanySet needs to be expanded accordingly
	fieldsToReturn       = []string{"id", "name", "slug", "baseline_current", "country_iso", "stats_60", "status"}
	fieldsToReturnSearch = []string{"id", "name", "slug", "country_iso"}

	token       Token
	credentials BasicAuth
	username    string
	password    string

	httpClient *http.Client

	// Downdetector delivers one CompanySet per given ID
	metricsResponse []CompanySet

	// exposed holds the various metrics that are collected
	exposed = map[string]*prometheus.GaugeVec{}
	// show last update time to see if system is working correctly
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

// BasicAuth contains username and string after reading them in from Yaml file
type BasicAuth struct {
	UserName string `json:"username"`
	Password string `json:"password"`
}

// Token contains token, expiration at issuing time, type and, later, the time of issuing
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
// CompanySet Fields without Prefix will be used as metrics value
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
			level.Error(lg).Log("msg", fmt.Sprintf("Couldn't read credentials file: %s", err.Error()))
			os.Exit(2)
		}
		//fmt.Println(dat)
		err = yaml.NewDecoder(osFile).Decode(&credentials)
		if err != nil || credentials.Password == "" || credentials.UserName == "" {
			errorText := "Username/Password not set"
			if err != nil {
				//errorText = err.Error()
			}
			level.Error(lg).Log("msg", fmt.Sprintf("Couldn't parse credentials file: %s", errorText))
			level.Error(lg).Log("msg", fmt.Sprintf("YAML file needs to contain userName and password fields"))
			os.Exit(2)
		}
	}
}

// trace prints out information about the current function called
func trace() string {
	pc, file, line, ok := runtime.Caller(1)
	if !ok {
		return "TRACE ERROR"
	}

	fn := runtime.FuncForPC(pc)
	return fmt.Sprintf("File: %s Line: %d Function: %s", file, line, fn.Name())
}

func main() {

	// Destination variables of command line parser
	var listenAddress string
	var credentialsFile string
	var metricsPath string
	var logLevel string
	var companyIDs string
	var searchString string

	// Override template
	cli.AppHelpTemplate = `
	NAME:
	   {{.Name}} - {{.Usage}}

	USAGE:
	   {{.HelpName}} {{if .VisibleFlags}}[global options]{{end}}{{if .Commands}} command [command options]{{end}} {{if .ArgsUsage}}{{.ArgsUsage}}{{else}}[arguments...]{{end}}
	   {{if len .Authors}}
	AUTHOR:
	   {{range .Authors}}{{ . }}{{end}}
	   {{end}}{{if .Commands}}
	COMMANDS:
	{{range .Commands}}{{if not .HideHelp}}   {{join .Names ", "}}{{ "\t"}}{{.Usage}}{{ "\n" }}{{end}}{{end}}{{end}}{{if .VisibleFlags}}
	GLOBAL OPTIONS:
	   {{range .VisibleFlags}}{{.}}
	   {{end}}{{end}}{{if .Copyright }}
	COPYRIGHT:
	   {{.Copyright}}
	   {{end}}{{if .Version}}
	VERSION:
	   {{.Version}}
	   {{end}}
  `

	// TODO: - value checking
	// app is a command line parser
	app := &cli.App{
		Authors: []*cli.Author{
			{
				Name:  "Torben Frey",
				Email: "torben@torben.dev",
			},
		},
		Commands:  nil,
		HideHelp:  true,
		ArgsUsage: " ",
		Name:      "downdetector-exporter",
		Usage:     "report metrics of downdetector api",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "company_ids",
				Aliases:     []string{"i"},
				Usage:       "comma separated list of company ids to monitor",
				Destination: &companyIDs,
				EnvVars:     []string{"COMPANY_IDS"},
			},
			&cli.StringFlag{
				Name:        "credentials_file",
				Aliases:     []string{"c"},
				Usage:       "file containing credentials for downdetector. Credentials file is in YAML format and contains two fields, username and password. Alternatively give username and password, they win over credentials file.",
				Destination: &credentialsFile,
				EnvVars:     []string{"CREDENTIALS_FILE"},
			},
			&cli.StringFlag{
				Name:        "username",
				Value:       "",
				Aliases:     []string{"u"},
				Usage:       "username, wins over credentials file",
				Destination: &username,
				EnvVars:     []string{"DD_USERNAME"},
			},
			&cli.StringFlag{
				Name:        "password",
				Value:       "",
				Aliases:     []string{"p"},
				Usage:       "password, wins over credentials file",
				Destination: &password,
				EnvVars:     []string{"DD_PASSWORD"},
			},
			&cli.StringFlag{
				Name:        "listen_address",
				Value:       ":9313",
				Aliases:     []string{"l"},
				Usage:       "[optional] address to listen on, either :port or address:port",
				Destination: &listenAddress,
				EnvVars:     []string{"LISTEN_ADDRESS"},
			},
			&cli.StringFlag{
				Name:        "metrics_path",
				Value:       "/metrics",
				Aliases:     []string{"m"},
				Usage:       "[optional] URL path where metrics are exposed",
				Destination: &metricsPath,
				EnvVars:     []string{"METRICS_PATH"},
			},
			&cli.StringFlag{
				Name:        "log_level",
				Value:       "ERROR",
				Aliases:     []string{"v"},
				Usage:       "[optional] log level, choose from DEBUG, INFO, WARN, ERROR",
				Destination: &logLevel,
				EnvVars:     []string{"LOG_LEVEL"},
			},
			&cli.StringFlag{
				Name:        "search_string",
				Value:       "",
				Aliases:     []string{"s"},
				Usage:       "[optional] search for companies containing this text and return their IDs",
				Destination: &searchString,
			},
		},
		Action: func(c *cli.Context) error {

			if credentialsFile == "" {
				if username == "" || password == "" {
					level.Error(lg).Log("msg", "Either credentials_file or username and password need to be set!")

					os.Exit(2)
				}
			}

			if companyIDs == "" && searchString == "" {
				level.Error(lg).Log("msg", "Either company_ids or a search string need to be set!")
				os.Exit(2)
			}

			// Debugging output
			lg = kitlog.NewLogfmtLogger(os.Stdout)
			lg = kitlog.With(lg, "ts", log.DefaultTimestamp, "caller", kitlog.DefaultCaller)
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

			level.Debug(lg).Log("msg", fmt.Sprintf("listenAddress: %s", listenAddress))
			level.Debug(lg).Log("msg", fmt.Sprintf("credentialsFile: %s", credentialsFile))
			level.Debug(lg).Log("msg", fmt.Sprintf("metricsPath: %s", metricsPath))
			level.Debug(lg).Log("msg", fmt.Sprintf("companyIDs: %v", companyIDs))

			// install promhttp handler for metricsPath (/metrics)
			http.Handle(metricsPath, promhttp.Handler())

			// show nice web page if called without metricsPath
			http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`<html>
					<head><title>Downdetector Exporter</title></head>
					<body>
					<h1>Downdetector Exporter</h1>
					<p><a href='` + metricsPath + `'>Metrics</a></p>
					</body>
					</html>`))
			})

			// Start the http server in background, but catch error
			go func() {
				err := http.ListenAndServe(listenAddress, nil)
				level.Error(lg).Log("msg", err.Error())
				os.Exit(2)
			}()

			// wait for initialization of http server before looping so the systemd alive check doesn't fail
			time.Sleep(time.Second * 3)

			// notify systemd that we're ready
			daemon.SdNotify(false, daemon.SdNotifyReady)

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
	err := app.Run(os.Args)
	level.Error(lg).Log("msg", err.Error())
}

func workHorse(companyIDs string, searchString string) {

	// refresh token if only tokenGraceSeconds are left before it expires
	if token.Access == "" || int(time.Now().Sub(token.RefreshTime).Seconds()) > token.ExpiresIn-tokenGraceSeconds {
		level.Debug(lg).Log("msg", "refreshing token")
		initToken()
	} else {
		level.Debug(lg).Log("msg", fmt.Sprintf("Seconds before a new token must be fetched: %d", (token.ExpiresIn-tokenGraceSeconds)-int(time.Now().Sub(token.RefreshTime).Seconds())))
	}

	getMetrics(companyIDs, searchString)
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
			level.Error(lg).Log("msg", fmt.Sprintf("Couldn't parse proxy url: %s", err.Error()))
			os.Exit(2)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	roundTripper := promhttp.InstrumentRoundTripperCounter(httpRequestsTotal, transport)

	//adding the Transport object to the http Client
	client := &http.Client{
		Transport: roundTripper,
		Timeout:   60 * time.Second,
	}
	return client
}

func initToken() {

	// create the token refresh request
	url := baseURL + "/tokens?grant_type=client_credentials"
	req, err := http.NewRequest("POST", url, nil)
	req.SetBasicAuth(credentials.UserName, credentials.Password)
	if err != nil {
		// return if we weren't successful - we have tokenGraceSeconds to retry
		level.Warn(lg).Log("msg", fmt.Sprintf("Couldn't apply Basic Auth: %s", err.Error()))
		return
	}
	// send the token refresh request
	res, err := httpClient.Do(req)
	if res.StatusCode != 200 {
		// return if we weren't successful - we have tokenGraceSeconds to retry
		body, _ := ioutil.ReadAll(res.Body)
		level.Warn(lg).Log("msg", fmt.Sprintf("Error response code: %d - %s", res.StatusCode, body))
		return
	}
	defer res.Body.Close()

	// read body from response
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		// return if we weren't successful - we have tokenGraceSeconds to retry
		level.Warn(lg).Log("msg", fmt.Sprintf("Couldn't read in body: %s", err.Error()))
		return
	}

	// unmarshal body content into token struct
	err = json.Unmarshal(body, &token)
	if err != nil {
		level.Warn(lg).Log("msg", fmt.Sprintf("Couldn't unmarshal json: %s", err.Error()))
		return
	}

	// Mark we have refreshed token right now
	token.RefreshTime = time.Now()
	level.Debug(lg).Log("msg", fmt.Sprintf("Token Type: %s", token.Type))
	level.Debug(lg).Log("msg", fmt.Sprintf("Expires in: %d", token.ExpiresIn))
	level.Debug(lg).Log("msg", fmt.Sprintf("Token Refresh Time: %s", token.RefreshTime))

}

func getMetrics(companyIDs string, searchString string) {

	var url string
	if searchString == "" {
		// create the metrics fetching request
		url = baseURL + "/companies?fields=" + strings.Join(fieldsToReturn[:], "%2C") + "&ids=" + strings.ReplaceAll(companyIDs, ",", "%2C")
	} else {
		url = baseURL + "/companies/search?name=" + searchString + "&fields=" + strings.Join(fieldsToReturnSearch[:], "%2C")
	}
	// curl --request GET -H "Authorization: Bearer $TOKEN" --url 'https://downdetectorapi.com/v2/companies/search?name=mail.com&fields=url%2Cbaseline%2Csite_id%2Cstatus%2Ccountry_iso%2Cname%2Cslug' | jq .

	req, err := http.NewRequest("GET", url, nil)
	req.Header.Add("Authorization", "Bearer "+token.Access)
	if err != nil {
		level.Warn(lg).Log("msg", fmt.Sprintf("Couldn't apply authorization header: %s", err.Error()))
		return
	}
	// send the metrics request
	res, err := httpClient.Do(req)
	if res.StatusCode != 200 {
		// return if we weren't successful
		body, _ := ioutil.ReadAll(res.Body)
		level.Warn(lg).Log("msg", fmt.Sprintf("Could not get metrics: %d - %s", res.StatusCode, body))
		return
	}
	defer res.Body.Close()

	// read body from response
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		// return if we weren't successful - we have tokenGraceSeconds to retry
		level.Warn(lg).Log("msg", fmt.Sprintf("Couldn't read in body: %s", err.Error()))
		return
	}

	// unmarshal body content into metricResponse struct
	err = json.Unmarshal(body, &metricsResponse)
	if err != nil {
		level.Warn(lg).Log("msg", fmt.Sprintf("Couldn't unmarshal json: %s", err.Error()))
		return
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

			// Debugging output
			level.Debug(lg).Log("msg", fmt.Sprintf(""))
			level.Debug(lg).Log("msg", fmt.Sprintf("===== Labels ====="))
			level.Debug(lg).Log("msg", fmt.Sprintf("Name:             %s", companySet.LabelName))
			level.Debug(lg).Log("msg", fmt.Sprintf("Slug:             %s", companySet.LabelSlug))
			level.Debug(lg).Log("msg", fmt.Sprintf("Country:          %s", companySet.LabelCountryISO))
			level.Debug(lg).Log("msg", fmt.Sprintf("Name:             %d", companySet.LabelID))
			level.Debug(lg).Log("msg", fmt.Sprintf("===== Info ====="))
			level.Debug(lg).Log("msg", fmt.Sprintf("Status:           %s", companySet.IgnoreStatus))
			level.Debug(lg).Log("msg", fmt.Sprintf("===== Metrics ====="))
			level.Debug(lg).Log("msg", fmt.Sprintf("Current Baseline: %d", companySet.BaselineCurrent))
			level.Debug(lg).Log("msg", fmt.Sprintf("Stats60:          %d", companySet.Stats60))
			level.Debug(lg).Log("msg", fmt.Sprintf("Status:           %d", companySet.NumStatus))

			// create empty array to hold labels
			labels := make([]string, 0)
			// create empty array to hold label values
			labelValues := make([]string, 0)

			// reflect to get members of struct
			cs := reflect.ValueOf(companySet)
			typeOfCompanySet := cs.Type()

			// Loop over all struct members and collect all fields starting with Label in array of labels
			level.Debug(lg).Log("msg", fmt.Sprintf(""))
			level.Debug(lg).Log("msg", fmt.Sprintf("Looping over CompanySet"))

			for i := 0; i < cs.NumField(); i++ {
				key := typeOfCompanySet.Field(i).Name
				value := cs.Field(i).Interface()
				level.Debug(lg).Log("msg", fmt.Sprintf("Field: %s, Value: %v", key, value))
				if strings.HasPrefix(key, "Label") {
					// labels have lower case names
					labels = append(labels, strings.ToLower(strings.TrimPrefix(key, "Label")))
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
			level.Debug(lg).Log("msg", fmt.Sprintf(""))
			level.Debug(lg).Log("msg", fmt.Sprintf("Labels: %v", labels))

			// Loop over all struct fields and set Exporter to value with list of labels if they don't
			// start with Label or Ignore
			level.Debug(lg).Log("msg", fmt.Sprintf(""))
			for i := 0; i < cs.NumField(); i++ {
				key := typeOfCompanySet.Field(i).Name
				if !(strings.HasPrefix(key, "Label") || strings.HasPrefix(key, "Ignore")) {
					value := cs.Field(i).Int()
					setPrometheusMetric(key, int(value), labels, labelValues)
				}
			}
		}
	}
	if searchString != "" {
		os.Exit(2)
	}
}

func setPrometheusMetric(key string, value int, labels []string, labelValues []string) {
	level.Debug(lg).Log("msg", fmt.Sprintf("Key: %s, Value: %d, Labels: %v", key, value, labels))
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
	if err == nil {
		// ... and notify systemd that everything was ok
		daemon.SdNotify(false, daemon.SdNotifyWatchdog)
	} else {
		// ... do nothing if it was not ok, but log. Systemd will restart soon.
		level.Warn(lg).Log("msg", fmt.Sprintf("liveness check failed: %s", err.Error()))
	}
	// Read all away or else we'll run out of sockets sooner or later
	_, _ = ioutil.ReadAll(res.Body)
	defer res.Body.Close()
}
