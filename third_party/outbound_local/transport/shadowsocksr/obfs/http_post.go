package obfs

import (
	rand "github.com/daeuniverse/outbound/pkg/fastrand"
)

func init() {
	register("http_post", &constructor{
		New:      newHttpPost,
		Overhead: 0,
	})
}

// newHttpPost create a http_post object
func newHttpPost() IObfs {
	// newHttpSimple create a http_simple object

	t := &httpSimplePost{
		userAgentIndex: rand.Intn(len(requestUserAgent)),
		methodGet:      false,
	}
	return t
}
