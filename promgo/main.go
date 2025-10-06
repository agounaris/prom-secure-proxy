package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// Configuration with defaults
var (
	PrometheusURL string
	ProxyUsername string
	ProxyPassword string
	ProxyPort     string
)

// Initialize configuration from environment variables
func initConfig() {
	PrometheusURL = getEnv("PROMETHEUS_URL", "http://localhost:9090")
	ProxyUsername = getEnv("PROXY_USERNAME", "admin")
	ProxyPassword = getEnv("PROXY_PASSWORD", "admin")
	ProxyPort = getEnv("PROXY_PORT", "8082")

	// Ensure port has colon prefix
	if !strings.HasPrefix(ProxyPort, ":") {
		ProxyPort = ":" + ProxyPort
	}
}

// Helper function to get environment variable with default value
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// Middleware for basic authentication
func basicAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()

		// Use constant-time comparison to prevent timing attacks
		usernameMatch := subtle.ConstantTimeCompare([]byte(username), []byte(ProxyUsername)) == 1
		passwordMatch := subtle.ConstantTimeCompare([]byte(password), []byte(ProxyPassword)) == 1

		if !ok || !usernameMatch || !passwordMatch {
			w.Header().Set("WWW-Authenticate", `Basic realm="Prometheus Proxy"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Store username in context
		ctx := context.WithValue(r.Context(), "username", username)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Inject tenant_id label into PromQL query
// Inject tenant_id label into PromQL query
func injectLabelIntoQuery(query, tenantID string) string {
	if query == "" || tenantID == "" {
		return query
	}

	// Keywords to exclude from label injection
	keywords := map[string]bool{
		// Aggregation operators
		"sum": true, "avg": true, "min": true, "max": true,
		"count": true, "count_values": true, "bottomk": true, "topk": true,
		"quantile": true, "stddev": true, "stdvar": true, "group": true,
		"limitk": true, "limit_ratio": true,

		// Vector matching keywords
		"by": true, "without": true, "on": true, "ignoring": true,
		"group_left": true, "group_right": true,

		// Logical/set operators
		"and": true, "or": true, "unless": true,

		// Comparison modifier
		"bool": true,

		// Time modifier
		"offset": true,

		// Math functions
		"abs": true, "ceil": true, "floor": true, "round": true,
		"exp": true, "ln": true, "log2": true, "log10": true,
		"sqrt": true, "sgn": true,

		// Trigonometric functions (binary operator)
		"atan2": true,

		// Rate/increase functions
		"rate": true, "irate": true, "increase": true,
		"delta": true, "idelta": true, "deriv": true,
		"predict_linear": true, "double_exponential_smoothing": true,

		// Range vector functions (_over_time)
		"avg_over_time": true, "min_over_time": true, "max_over_time": true,
		"sum_over_time": true, "count_over_time": true, "quantile_over_time": true,
		"stddev_over_time": true, "stdvar_over_time": true,
		"last_over_time": true, "present_over_time": true,
		"mad_over_time": true, "ts_of_min_over_time": true,
		"ts_of_max_over_time": true, "ts_of_last_over_time": true,

		// Histogram functions
		"histogram_quantile": true, "histogram_sum": true, "histogram_count": true,
		"histogram_fraction": true, "histogram_avg": true,
		"histogram_stddev": true, "histogram_stdvar": true,

		// Counter functions
		"resets": true, "changes": true,

		// Label manipulation
		"label_replace": true, "label_join": true,

		// Time/date functions
		"time": true, "timestamp": true, "minute": true, "hour": true,
		"day_of_month": true, "day_of_week": true, "day_of_year": true,
		"days_in_month": true, "month": true, "year": true,

		// Clamping functions
		"clamp": true, "clamp_max": true, "clamp_min": true,

		// Absence functions
		"absent": true, "absent_over_time": true,

		// Sorting functions
		"sort": true, "sort_desc": true,
		"sort_by_label": true, "sort_by_label_desc": true,

		// Type conversion/utility
		"scalar": true, "vector": true,

		// Experimental functions
		"info": true,
	}

	// Pattern that matches metric names but NOT when they appear in:
	// 1. After 'by', 'without', 'on', 'ignoring' keywords
	// 2. Inside parentheses of grouping clauses
	pattern := regexp.MustCompile(`\b([a-zA-Z_:][a-zA-Z0-9_:]*)\s*(\{[^}]*\})?`)

	tenantLabel := fmt.Sprintf(`tenant_id=~"%s|default-tenant|"`, tenantID)

	// First, protect grouping clauses by replacing them temporarily
	groupingPattern := regexp.MustCompile(`\b(by|without|on|ignoring)\s*\([^)]+\)`)
	groupingClauses := []string{}
	placeholder := "___GROUPING_CLAUSE_%d___"

	modifiedQuery := groupingPattern.ReplaceAllStringFunc(query, func(match string) string {
		index := len(groupingClauses)
		groupingClauses = append(groupingClauses, match)
		return fmt.Sprintf(placeholder, index)
	})

	// Now inject labels into metrics in the modified query
	result := pattern.ReplaceAllStringFunc(modifiedQuery, func(match string) string {
		submatches := pattern.FindStringSubmatch(match)
		metricName := submatches[1]
		labels := ""
		if len(submatches) > 2 {
			labels = submatches[2]
		}

		// Skip keywords
		if keywords[strings.ToLower(metricName)] {
			return match
		}

		// Skip placeholders
		if strings.HasPrefix(metricName, "___GROUPING_CLAUSE_") {
			return match
		}

		// Inject tenant_id label
		if labels != "" {
			// Insert tenant_id as first label
			labels = strings.Replace(labels, "{", "{"+tenantLabel+",", 1)
			return metricName + labels
		}

		return fmt.Sprintf("%s{%s}", metricName, tenantLabel)
	})

	// Restore grouping clauses
	for i, clause := range groupingClauses {
		result = strings.Replace(result, fmt.Sprintf(placeholder, i), clause, 1)
	}

	return result
}

// Create reverse proxy handler
func createProxyHandler() http.Handler {
	targetURL, err := url.Parse(PrometheusURL)
	if err != nil {
		log.Fatalf("Failed to parse Prometheus URL: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// Customize the Director to modify the request before forwarding
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)

		tenantID := req.Header.Get("X-Scope-OrgID")

		// Forward X-Scope-OrgID header if present
		if tenantID != "" {
			req.Header.Set("X-Scope-OrgID", tenantID)
		}

		// Handle query parameter injection for GET requests
		if req.Method == "GET" {
			query := req.URL.Query()
			if tenantID != "" && query.Get("query") != "" {
				modifiedQuery := injectLabelIntoQuery(query.Get("query"), tenantID)
				query.Set("query", modifiedQuery)
				req.URL.RawQuery = query.Encode()
			}
		}

		// Handle form-encoded POST requests
		if req.Method == "POST" && strings.Contains(req.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			// Read body
			bodyBytes, err := io.ReadAll(req.Body)
			if err == nil {
				req.Body.Close()

				// Parse form data
				values, err := url.ParseQuery(string(bodyBytes))
				if err == nil && tenantID != "" && values.Get("query") != "" {
					modifiedQuery := injectLabelIntoQuery(values.Get("query"), tenantID)
					values.Set("query", modifiedQuery)

					// Recreate body with modified query
					newBody := values.Encode()
					req.Body = io.NopCloser(bytes.NewBufferString(newBody))
					req.ContentLength = int64(len(newBody))
				} else {
					// Restore original body if parsing fails
					req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
				}
			}
		}

		// Remove sensitive headers
		req.Header.Del("Authorization")
	}

	// Error handler for proxy errors
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("Proxy error: %v", err)
		http.Error(w, fmt.Sprintf("Error connecting to Prometheus: %v", err), http.StatusBadGateway)
	}

	return proxy
}

// Health check handler
func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		// Forward to proxy for non-root paths
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"ok","message":"Prometheus proxy is running"}`)
}

func main() {
	// Initialize configuration from environment variables
	initConfig()

	// Log configuration (don't log password in production)
	log.Printf("Starting Prometheus proxy with configuration:")
	log.Printf("  Prometheus URL: %s", PrometheusURL)
	log.Printf("  Proxy Port: %s", ProxyPort)
	log.Printf("  Username: %s", ProxyUsername)

	// Create proxy handler
	proxyHandler := createProxyHandler()

	// Create a mux to handle routing
	mux := http.NewServeMux()

	// Root path for health check
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && r.Method == "GET" {
			healthCheckHandler(w, r)
		} else {
			proxyHandler.ServeHTTP(w, r)
		}
	})

	// Wrap with basic auth middleware
	handler := basicAuthMiddleware(mux)

	// Create server with timeout configuration
	server := &http.Server{
		Addr:         ProxyPort,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("Listening on %s", ProxyPort)
	log.Fatal(server.ListenAndServe())
}
