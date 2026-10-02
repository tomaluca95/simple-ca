package webserver

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tomaluca95/simple-ca/internal/types"
)

const (
	// maxRequestIdLength is the most characters a request id can have: a UUID
	// is 36 characters and a ULID 26, so nothing longer can name a request.
	// Without this bound the client decides how big a log line gets, and every
	// record of the request repeats the header verbatim.
	maxRequestIdLength = 36
)

// requestLoggerMiddleware tags the request context with a request id, so that
// every log record of this request (access log, CA operations, authorization
// decisions) carries the same request_id, and logs the request outcome. A
// client picks an id by sending an alphanumeric X-Request-ID of up to
// maxRequestIdLength characters; a longer id is refused outright, and a
// missing or non-alphanumeric one is replaced by a freshly generated UUID. The
// id that was used is returned in the X-Request-ID response header, so the
// client can correlate its logs with the CA's.
func requestLoggerMiddleware(logger types.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		requestId := c.GetHeader("X-Request-ID")
		tooLong := false
		if len(requestId) > maxRequestIdLength {
			// The guard runs before anything is processed or logged with the
			// header: a request id too long to exist is refused, so the
			// client-controlled value never reaches a log record. The rejected
			// request is logged, if at all, under a generated id.
			requestId = newRequestId()
			tooLong = true
		} else if !isAlphanumeric(requestId) {
			requestId = newRequestId()
		}
		c.Header("X-Request-ID", requestId)
		if tooLong {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "X-Request-ID too long"})
		}
		startedAt := time.Now()

		c.Request = c.Request.WithContext(types.WithRequestId(c.Request.Context(), requestId))

		c.Next()

		logger.InfoContext(c.Request.Context(), "http request",
			"method", c.Request.Method,
			"remote_addr", c.Request.RemoteAddr,
			"path", c.Request.URL.Path,
			"status", c.Writer.Status(),
			"duration", time.Since(startedAt),
		)
	}
}

// newRequestId returns a UUID (version 4, RFC 4122 variant) as the id to use
// for a request that did not bring an acceptable one.
func newRequestId() string {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	randomBytes[6] = (randomBytes[6] & 0x0f) | 0x40 // version 4
	randomBytes[8] = (randomBytes[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		randomBytes[0:4], randomBytes[4:6], randomBytes[6:8], randomBytes[8:10], randomBytes[10:16])
}

// isAlphanumeric reports whether s is a non-empty run of letters and digits.
// No shape beyond that is enforced: the id only has to name a request for
// correlation.
func isAlphanumeric(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= '0' && s[i] <= '9')) {
			return false
		}
	}
	return true
}
