package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type config struct {
	stsURL   string
	mockURL  string
	rate     int
	workers  int
	duration time.Duration
	flow     string
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
}

type requestForms struct {
	clientCredentials url.Values
	tokenExchange     url.Values
}

type counters struct {
	started   time.Time
	requests  atomic.Int64
	errors    atomic.Int64
	latencyNS atomic.Int64
	maxNS     atomic.Int64
}

func main() {
	cfg := parseFlags()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if cfg.duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.duration)
		defer cancel()
	}
	if err := run(ctx, cfg); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		log.Fatal(err)
	}
}

func parseFlags() config {
	cfg := config{}
	flag.StringVar(&cfg.stsURL, "sts-url", "http://localhost:8080", "STS base URL")
	flag.StringVar(&cfg.mockURL, "mock-url", "http://localhost:3004", "mock OAuth2 server base URL")
	flag.IntVar(&cfg.rate, "rate", 100, "target requests/second; 0 means unlimited")
	flag.IntVar(&cfg.workers, "workers", 8, "maximum concurrent workers")
	flag.DurationVar(&cfg.duration, "duration", 0, "run duration; 0 runs until Ctrl-C")
	flag.StringVar(&cfg.flow, "flow", "mixed", "traffic flow: mixed, client_credentials, or token_exchange")
	flag.Parse()
	if cfg.rate < 0 || cfg.workers < 1 {
		log.Fatal("rate must be >= 0 and workers must be >= 1")
	}
	switch cfg.flow {
	case "mixed", "client_credentials", "token_exchange":
	default:
		log.Fatal("flow must be mixed, client_credentials, or token_exchange")
	}
	return cfg
}

func run(ctx context.Context, cfg config) error {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        cfg.workers * 2,
			MaxIdleConnsPerHost: cfg.workers,
			IdleConnTimeout:     90 * time.Second,
		},
	}
	forms, err := prepareForms(ctx, client, cfg)
	if err != nil {
		return fmt.Errorf("prepare local tokens: %w", err)
	}
	var currentForms atomic.Pointer[requestForms]
	currentForms.Store(forms)

	stats := &counters{started: time.Now()}
	jobs := make(chan string, cfg.workers)
	var workers sync.WaitGroup
	for range cfg.workers {
		workers.Go(func() {
			for flow := range jobs {
				sendRequest(ctx, client, cfg.stsURL+"/token", flow, currentForms.Load(), stats)
			}
		})
	}

	go refreshForms(ctx, client, cfg, &currentForms)
	go printStats(ctx, stats)
	log.Printf("generating %s traffic: rate=%s workers=%d; press Ctrl-C to stop", cfg.flow, formatRate(cfg.rate), cfg.workers)

	err = produce(ctx, cfg, jobs)
	close(jobs)
	workers.Wait()
	printSnapshot(stats)
	return err
}

func produce(ctx context.Context, cfg config, jobs chan<- string) error {
	var sequence uint64
	nextFlow := func() string {
		if cfg.flow != "mixed" {
			return cfg.flow
		}
		sequence++
		if sequence%2 == 0 {
			return "token_exchange"
		}
		return "client_credentials"
	}

	if cfg.rate == 0 {
		for {
			select {
			case jobs <- nextFlow():
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	interval := time.Second / time.Duration(cfg.rate)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			select {
			case jobs <- nextFlow():
			default: // Do not accumulate an unbounded backlog if STS cannot keep up.
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func sendRequest(ctx context.Context, client *http.Client, endpoint, flow string, forms *requestForms, stats *counters) {
	form := forms.clientCredentials
	if flow == "token_exchange" {
		form = forms.tokenExchange
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		stats.errors.Add(1)
		return
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	start := time.Now()
	response, err := client.Do(request)
	elapsed := time.Since(start).Nanoseconds()
	stats.requests.Add(1)
	stats.latencyNS.Add(elapsed)
	updateMax(&stats.maxNS, elapsed)
	if err != nil {
		stats.errors.Add(1)
		return
	}
	_, copyErr := io.Copy(io.Discard, response.Body)
	closeErr := response.Body.Close()
	if response.StatusCode != http.StatusOK || copyErr != nil || closeErr != nil {
		stats.errors.Add(1)
	}
}

func updateMax(value *atomic.Int64, candidate int64) {
	for current := value.Load(); candidate > current; current = value.Load() {
		if value.CompareAndSwap(current, candidate) {
			return
		}
	}
}

func prepareForms(ctx context.Context, client *http.Client, cfg config) (*requestForms, error) {
	clientAssertion, err := postToken(ctx, client, cfg.mockURL+"/env1/token", url.Values{
		"grant_type": {"client_credentials"}, "client_id": {"default_client"}, "client_secret": {"yolo"},
		"ns": {"namespace1"}, "workload": {"workload1"},
	})
	if err != nil {
		return nil, err
	}
	subjectToken, err := subjectToken(ctx, client, cfg.mockURL)
	if err != nil {
		return nil, err
	}
	return &requestForms{
		clientCredentials: url.Values{
			"grant_type": {string(oidc.GrantTypeClientCredentials)}, "client_assertion_type": {oidc.ClientAssertionTypeJWTAssertion},
			"client_assertion": {clientAssertion}, "scope": {"env1:namespace1:workload2"},
		},
		tokenExchange: url.Values{
			"grant_type": {string(oidc.GrantTypeTokenExchange)}, "client_assertion_type": {oidc.ClientAssertionTypeJWTAssertion},
			"client_assertion": {clientAssertion}, "audience": {"env1:namespace1:workload2"},
			"subject_token": {subjectToken}, "subject_token_type": {string(oidc.JWTTokenType)},
			"requested_token_type": {string(oidc.AccessTokenType)},
		},
	}, nil
}

func subjectToken(ctx context.Context, client *http.Client, mockURL string) (string, error) {
	redirectURI := "https://unused.example/callback"
	authorize, err := url.Parse(mockURL + "/subject1/authorize")
	if err != nil {
		return "", err
	}
	authorize.RawQuery = url.Values{
		"client_id": {"default_client"}, "scope": {"openid somescope"}, "response_type": {"code"},
		"redirect_uri": {redirectURI},
	}.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, authorize.String(), nil)
	if err != nil {
		return "", err
	}
	noRedirect := *client
	noRedirect.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	response, err := noRedirect.Do(request)
	if err != nil {
		return "", err
	}
	_ = response.Body.Close()
	location, err := response.Location()
	if err != nil {
		return "", err
	}
	code := location.Query().Get("code")
	if code == "" {
		return "", errors.New("mock authorization response did not contain a code")
	}
	return postToken(ctx, client, mockURL+"/subject1/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_secret": {"yolo"},
		"client_id": {"default_client"}, "redirect_uri": {redirectURI},
	})
}

func postToken(ctx context.Context, client *http.Client, endpoint string, form url.Values) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return "", fmt.Errorf("%s returned %s: %s", endpoint, response.Status, strings.TrimSpace(string(body)))
	}
	var token tokenResponse
	if err := json.NewDecoder(response.Body).Decode(&token); err != nil {
		return "", err
	}
	if token.AccessToken == "" {
		return "", fmt.Errorf("%s returned an empty access token", endpoint)
	}
	return token.AccessToken, nil
}

func refreshForms(ctx context.Context, client *http.Client, cfg config, forms *atomic.Pointer[requestForms]) {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			refreshed, err := prepareForms(ctx, client, cfg)
			if err != nil {
				log.Printf("token refresh failed; retaining current tokens: %v", err)
				continue
			}
			forms.Store(refreshed)
			log.Print("refreshed local fixture tokens")
		case <-ctx.Done():
			return
		}
	}
}

func printStats(ctx context.Context, stats *counters) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			printSnapshot(stats)
		case <-ctx.Done():
			return
		}
	}
}

func printSnapshot(stats *counters) {
	requests := stats.requests.Load()
	if requests == 0 {
		return
	}
	elapsed := time.Since(stats.started).Seconds()
	average := time.Duration(stats.latencyNS.Load() / requests)
	log.Printf("requests=%d rate=%.1f/s errors=%d average=%s max=%s", requests, float64(requests)/elapsed, stats.errors.Load(), average.Round(time.Microsecond), time.Duration(stats.maxNS.Load()).Round(time.Microsecond))
}

func formatRate(rate int) string {
	if rate == 0 {
		return "unlimited"
	}
	return fmt.Sprintf("%d/s", rate)
}
