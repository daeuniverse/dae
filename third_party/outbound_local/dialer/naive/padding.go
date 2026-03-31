package naive

import (
	"crypto/rand"
	"encoding/binary"
	"io"
)

const (
	// kFirstPaddings is the number of initial read/write operations
	// that are padded to flatten packet length distribution.
	kFirstPaddings = 8

	// kMaxPaddingSize is the maximum random padding size in bytes.
	kMaxPaddingSize = 255

	// kMinPaddingHeaderLen is the minimum padding header length for CONNECT requests.
	kMinPaddingHeaderLen = 16

	// kMaxPaddingHeaderLen is the maximum padding header length for CONNECT requests.
	kMaxPaddingHeaderLen = 32

	// kMinPaddingHeaderLenResp is the minimum padding header length for CONNECT responses.
	kMinPaddingHeaderLenResp = 30

	// kMaxPaddingHeaderLenResp is the maximum padding header length for CONNECT responses.
	kMaxPaddingHeaderLenResp = 62

	// paddingHeaderKey is the HTTP header key used for naiveproxy padding.
	paddingHeaderKey = "padding"
)

// paddingChars are characters that are not Huffman coded in HPACK
// and are pseudo-random enough to avoid being indexed.
var paddingChars = []byte{
	'!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=',
	'>', '?', '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',
	'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
	'Z', '[', '\\', ']', '^', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
	'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
	'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~',
}

// generatePaddingHeader generates a padding header value of random length
// between minLen and maxLen using non-Huffman-coded characters.
func generatePaddingHeader(minLen, maxLen int) string {
	n := minLen + randInt(maxLen-minLen+1)
	b := make([]byte, n)
	for i := range b {
		b[i] = paddingChars[randInt(len(paddingChars))]
	}
	return string(b)
}

// GeneratePaddingHeaderRequest generates padding for a CONNECT request header.
func GeneratePaddingHeaderRequest() string {
	return generatePaddingHeader(kMinPaddingHeaderLen, kMaxPaddingHeaderLen)
}

// GeneratePaddingHeaderResponse generates padding for a CONNECT response header.
func GeneratePaddingHeaderResponse() string {
	return generatePaddingHeader(kMinPaddingHeaderLenResp, kMaxPaddingHeaderLenResp)
}

// randInt returns a random non-negative integer in [0, max).
func randInt(max int) int {
	var buf [4]byte
	_, _ = io.ReadFull(rand.Reader, buf[:])
	return int(binary.BigEndian.Uint32(buf[:])) % max
}

// paddedWriter wraps an io.Writer and applies naiveproxy payload padding
// for the first kFirstPaddings write operations.
type paddedWriter struct {
	w       io.Writer
	padded  int
	enabled bool // padding is only enabled if the server supports it
}

func newPaddedWriter(w io.Writer, enabled bool) *paddedWriter {
	return &paddedWriter{w: w, enabled: enabled}
}

func (pw *paddedWriter) Write(b []byte) (n int, err error) {
	if !pw.enabled || pw.padded >= kFirstPaddings {
		return pw.w.Write(b)
	}
	// Split data into chunks of max 65535 bytes (max original_data_size).
	for len(b) > 0 {
		chunkSize := len(b)
		if chunkSize > 65535 {
			chunkSize = 65535
		}
		if err := writePadded(pw.w, b[:chunkSize]); err != nil {
			return n, err
		}
		n += chunkSize
		b = b[chunkSize:]
		pw.padded++
		if pw.padded >= kFirstPaddings {
			// Remaining data goes unpadded.
			if len(b) > 0 {
				var rn int
				rn, err = pw.w.Write(b)
				n += rn
			}
			return n, err
		}
	}
	return n, nil
}

// writePadded writes a single padded data frame:
//
//	struct PaddedData {
//	    uint8_t original_data_size_high;  // original_data_size / 256
//	    uint8_t original_data_size_low;   // original_data_size % 256
//	    uint8_t padding_size;
//	    uint8_t original_data[original_data_size];
//	    uint8_t zeros[padding_size];
//	};
func writePadded(w io.Writer, data []byte) error {
	paddingSize := randInt(kMaxPaddingSize + 1)
	header := [3]byte{
		byte(len(data) >> 8),
		byte(len(data) & 0xff),
		byte(paddingSize),
	}
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	if paddingSize > 0 {
		_, err := w.Write(make([]byte, paddingSize))
		return err
	}
	return nil
}

// paddedReader wraps an io.Reader and strips naiveproxy payload padding
// for the first kFirstPaddings read operations.
type paddedReader struct {
	r       io.Reader
	padded  int
	enabled bool
	pending []byte
}

func newPaddedReader(r io.Reader, enabled bool) *paddedReader {
	return &paddedReader{r: r, enabled: enabled}
}

func (pr *paddedReader) Read(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}
	if len(pr.pending) > 0 {
		n = copy(b, pr.pending)
		pr.pending = pr.pending[n:]
		return n, nil
	}
	if !pr.enabled || pr.padded >= kFirstPaddings {
		return pr.r.Read(b)
	}

	// Read the 3-byte padding header.
	var hdr [3]byte
	if _, err = io.ReadFull(pr.r, hdr[:]); err != nil {
		return 0, err
	}
	origSize := int(hdr[0])<<8 | int(hdr[1])
	padSize := int(hdr[2])

	var payload []byte
	if origSize > len(b) {
		payload = make([]byte, origSize)
	} else {
		payload = b[:origSize]
	}
	if _, err = io.ReadFull(pr.r, payload); err != nil {
		return 0, err
	}

	// Discard padding zeros.
	if padSize > 0 {
		if _, err = io.CopyN(io.Discard, pr.r, int64(padSize)); err != nil {
			return 0, err
		}
	}

	pr.padded++
	if origSize <= len(b) {
		return origSize, nil
	}

	n = copy(b, payload)
	pr.pending = payload[n:]
	return n, nil
}
