package proto

import "errors"

const ObfsHMACSHA1Len = 10

var (
	ErrAuthSHA1v4CRC32Error                = errors.New("auth_sha1_v4 post decrypt data crc32 error")
	ErrAuthSHA1v4DataLengthError           = errors.New("auth_sha1_v4 post decrypt data length error")
	ErrAuthSHA1v4IncorrectChecksum         = errors.New("auth_sha1_v4 post decrypt incorrect checksum")
	ErrAuthAES128IncorrectHMAC             = errors.New("auth_aes128_* post decrypt incorrect hmac")
	ErrAuthAES128DataLengthError           = errors.New("auth_aes128_* post decrypt length mismatch")
	ErrAuthChainDataLengthError            = errors.New("auth_chain_* post decrypt length mismatch")
	ErrAuthChainIncorrectHMAC              = errors.New("auth_chain_* post decrypt incorrect hmac")
	ErrAuthAES128IncorrectChecksum         = errors.New("auth_aes128_* post decrypt incorrect checksum")
	ErrAuthAES128PosOutOfRange             = errors.New("auth_aes128_* post decrypt pos out of range")
	ErrTLS12TicketAuthTooShortData         = errors.New("tls1.2_ticket_auth too short data")
	ErrTLS12TicketAuthHMACError            = errors.New("tls1.2_ticket_auth hmac verifying failed")
	ErrTLS12TicketAuthIncorrectMagicNumber = errors.New("tls1.2_ticket_auth incorrect magic number")
)
