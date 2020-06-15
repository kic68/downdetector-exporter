# Downdetector Exporter

## Usage

### Help message

```
./downdetector-exporter --help
Incorrect Usage. flag: help requested


  NAME:
     downdetector-exporter - report metrics of downdetector api

  USAGE:
     downdetector-exporter [global options]

  AUTHOR:
     Torben Frey <torben@torben.dev>

  GLOBAL OPTIONS:
     --company_ids value, -i value       comma separated list of company ids to monitor [$COMPANY_IDS]
     --credentials_file value, -c value  file containing credentials for downdetector. Credentials file is in YAML format and contains two fields, username and password. Alternatively give username and password, they win over credentials file. [$CREDENTIALS_FILE]
     --username value, -u value          username, wins over credentials file [$DD_USERNAME]
     --password value, -p value          password, wins over credentials file [$DD_PASSWORD]
     --listen_address value, -l value    [optional] address to listen on, either :port or address:port (default: ":9313") [$LISTEN_ADDRESS]
     --metrics_path value, -m value      [optional] URL path where metrics are exposed (default: "/metrics") [$METRICS_PATH]
     --log_level value, -v value         [optional] log level, choose from DEBUG, INFO, WARN, ERROR (default: "ERROR") [$LOG_LEVEL]
     --search_string value, -s value     [optional] search for companies containing this text and return their IDs

  level=error msg="flag: help requested"
```

#### Prerequisites

Either provide a credentials file using the --credentials_file parameter. The file needs to be in YAML format like this:

```
---
username: adjshkajsdhakjsd
password: djhfksjdfhksjfhksjdhf

```
Alternatively you can provide username and password parameters, they will win over the credentials file.

### How to execute

There are two modes - either you already know your company's IDs, then provide them in a comma separated list:

`downdetector-exporter -c downdetector-credentials.yaml -i 23456,12345,34567`

This will startup the exporter in production mode. Check on port 9313.

The other mode is if you not yet know IDs of your company. In this case just pass a search_string parameter which will be searched for case insensitively:

`downdetector-exporter -c downdetector-credentials.yaml -s microsoft`

This will render a list of IDs you can chose yours from:

```
ID: 37466 - Name: Microsoft Azure, Slug: windows-azure, Country: MX
ID: 37467 - Name: Microsoft Azure, Slug: windows-azure, Country: AR
ID: 38018 - Name: Microsoft Teams, Slug: teams, Country: US
ID: 38184 - Name: Microsoft Teams, Slug: teams, Country: GB
ID: 38185 - Name: Microsoft Teams, Slug: teams, Country: DE
ID: 38186 - Name: Microsoft Teams, Slug: teams, Country: NL
ID: 38187 - Name: Microsoft VLSC, Slug: vlsc, Country: US
ID: 38694 - Name: Microsoft Teams, Slug: teams, Country: AU
ID: 39143 - Name: Microsoft Azure, Slug: windows-azure, Country: NZ
ID: 39144 - Name: Microsoft Teams, Slug: teams, Country: NZ
ID: 39145 - Name: Microsoft Teams, Slug: teams, Country: JP
ID: 39146 - Name: Microsoft Teams, Slug: teams, Country: CA
ID: 39302 - Name: Microsoft Teams, Slug: teams, Country: SE
ID: 39317 - Name: Microsoft Azure, Slug: windows-azure, Country: SE
ID: 39318 - Name: Microsoft Azure, Slug: windows-azure, Country: FI
```

### Systemd notifications

The exporter will send readyness and alive messages to systemd. Systemd will restart the exporter once these alive messages stop if you provide a unit file such as

```
[Unit]
Description=Prometheus Downdetector Exporter
After=network.target
AssertPathExists=/home/username/go/bin

[Service]
Type=notify
ExecStart=/home/username/go/bin/downdetector-exporter -c downdetector-credentials.yaml -i 23456,12345,34567
User=username
WatchdogSec=180s
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

### Configure via environment variables

To make the system more compatible with docker and kubernetes, all parameters (except the search string) can be set via environment variables:

```
COMPANY_IDS
CREDENTIALS_FILE
DD_USERNAME
DD_PASSWORD
LISTEN_ADDRESS
METRICS_PATH
LOG_LEVEL
```

### Grafana dashboard

There's a grafana_dashboard.json file in the repository which can be imported to Grafana.
