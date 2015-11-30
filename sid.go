package sid

import (
	"crypto/sha1"
	"encoding/base64"
	"os"
	"sync"
	"time"

	"github.com/chanxuehong/internal"
	"github.com/chanxuehong/rand"
)

//   56bits unix100ns + 12bits pid + 12bits sequence + 48bits node + 64bits hashsum
//
//   +------ 0 ------+------ 1 ------+------ 2 ------+------ 3 ------+
//   +0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1+
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                          time_low                             |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |       time_mid                |        time_hi_and_pid_low    |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |clk_seq_hi_pid |  clk_seq_low  |         node (0-1)            |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                         node (2-5)                            |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                         hash (0-3)                            |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                         hash (4-7)                            |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

var pid = hash(uint64(os.Getpid())) // 12-bit hash of os.Getpid(), read only

// hash uint64 to a 12-bit integer value.
func hash(x uint64) uint64 {
	return (x ^ x>>12 ^ x>>24 ^ x>>36 ^ x>>48 ^ x>>60) & 0xfff
}

var node = internal.MAC[:] // read only

const (
	sequenceMask       = 0xfff // 12bits
	saltLen            = 43    // see New(), 8+4+43==55<56, Best performance for sha1.
	saltUpdateInterval = 3600  // seconds
)

var (
	gSalt = make([]byte, saltLen)

	gMutex sync.Mutex // protect following

	gSequenceStart uint32 = rand.Uint32() & sequenceMask
	gLastTimestamp int64  = -1
	gLastSequence  uint32 = gSequenceStart

	gSaltLastUpdateTimestamp int64  = -saltUpdateInterval
	gSaltSequence            uint32 = rand.Uint32()
)

func New() (id []byte) {
	var (
		timeNow          = time.Now()
		timeNowUnix      = timeNow.Unix()
		saltShouldUpdate = false
		sidTimestamp     = unix100nano(timeNow)
		sidSequence      = gSequenceStart
	)

	gMutex.Lock() // Lock
	switch {
	case sidTimestamp > gLastTimestamp:
		gLastTimestamp = sidTimestamp
		gLastSequence = sidSequence
	case sidTimestamp == gLastTimestamp:
		sidSequence = (gLastSequence + 1) & sequenceMask
		if sidSequence == gSequenceStart {
			sidTimestamp = tillNext100nano(sidTimestamp)
			gLastTimestamp = sidTimestamp
		}
		gLastSequence = sidSequence
	default:
		gSequenceStart = rand.Uint32() & sequenceMask // NOTE
		sidSequence = gSequenceStart
		gLastTimestamp = sidTimestamp
		gLastSequence = sidSequence
	}
	if timeNowUnix >= gSaltLastUpdateTimestamp+saltUpdateInterval {
		saltShouldUpdate = true
		gSaltLastUpdateTimestamp = timeNowUnix
	}
	gSaltSequence++
	gMutex.Unlock() // Unlock

	// 56bits unix100ns + 12bits pid + 12bits sequence + 48bits node + 64bits hashsum
	var idx [24]byte

	// time_low
	idx[0] = byte(sidTimestamp >> 24)
	idx[1] = byte(sidTimestamp >> 16)
	idx[2] = byte(sidTimestamp >> 8)
	idx[3] = byte(sidTimestamp)

	// time_mid
	idx[4] = byte(sidTimestamp >> 40)
	idx[5] = byte(sidTimestamp >> 32)

	// time_hi_and_pid_low
	idx[6] = byte(sidTimestamp >> 48)
	idx[7] = byte(pid)

	// clk_seq_hi_pid
	idx[8] = byte(sidSequence>>8) & 0x0f
	idx[8] |= byte(pid>>8) << 4

	// clk_seq_low
	idx[9] = byte(sidSequence)

	// node
	copy(idx[10:], node)

	// hashsum
	if saltShouldUpdate {
		rand.Read(gSalt)
		copy(idx[16:], gSalt)
	} else {
		var src [8 + 4 + saltLen]byte // 8+4+43==55

		src[0] = byte(sidTimestamp >> 56)
		src[1] = byte(sidTimestamp >> 48)
		src[2] = byte(sidTimestamp >> 40)
		src[3] = byte(sidTimestamp >> 32)
		src[4] = byte(sidTimestamp >> 24)
		src[5] = byte(sidTimestamp >> 16)
		src[6] = byte(sidTimestamp >> 8)
		src[7] = byte(sidTimestamp)
		src[8] = byte(gSaltSequence >> 24)
		src[9] = byte(gSaltSequence >> 16)
		src[10] = byte(gSaltSequence >> 8)
		src[11] = byte(gSaltSequence)
		copy(src[12:], gSalt)

		hashsum := sha1.Sum(src[:])
		copy(idx[16:], hashsum[:])
	}

	id = make([]byte, 32)
	base64.URLEncoding.Encode(id, idx[:])
	return
}
