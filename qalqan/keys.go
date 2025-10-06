/*__________________________________________________________________________
					center.bin files structure
* [32] byte - Kikey;
* [100][32] byte - Circle key;
* [1000][32] byte - Session keys <in> * users count;
* [1000][32] byte - Session keys <out> * users count;
* [16] byte - imit.
/*__________________________________________________________________________
					abc.bin files structure
* [16] byte:
	[0] - 0 - user num
	[1] - high 4 bits of session in keys
	[2] - low 4 bits of session in keys
	[3] - high 4 bits of session out keys
	[4] - low 4 bits of session out keys
	[5..15] - half imit circle key
* [32] byte - Kikey;
* [100][32] byte - Circle key;
* [1000][32] byte - Session keys <in>;
* [1000][32] byte - Session keys <out>;
* [16] byte - imit.
----------------------------------------------------------------------------
				16 byte metadata on files encrypted/decrypted
[0] - 0;
[1] - user owner, 0x33 - center user;
[2] - 0x04;
[3] - 0x20;
[4] - 0x00 - file,
	  0x77 - video,
	  0x88 - photo,
	  0x66 - text (message),
	  0x55 - audio.
[5] - key type circle or session key:
	  0x00 = circle
      0x01 = session_out
      0x02 = session_in
[6]   = circle_index (0..99)
[7]   = session_index low8 (lower 8 bits of index 0..999)
[8]   = session_index_hi2 (2 most significant bits of the index: bits 0..1)
[9..[15] = 0x00 (reserved)
____________________________________________________________________________
*/

package qalqan

import (
	"bytes"
	"crypto/sha512"
	"fmt"
)

type SessionKeySet struct {
	In  [1000][DEFAULT_KEY_LEN]byte
	Out [1000][DEFAULT_KEY_LEN]byte
}

func Hash512(value string) [32]byte {
	hash := []byte(value)
	for i := 0; i < 1000; i++ {
		sum := sha512.Sum512(hash)
		hash = sum[:]
	}
	var hash32 [32]byte
	copy(hash32[:], hash[:32])
	return hash32
}

func LoadSessionKeys(data []byte, ostream *bytes.Buffer, rKey []byte, session_keys *[]SessionKeySet) {
	const perDir = 1000 * DEFAULT_KEY_LEN
	const perUser = 2 * perDir // IN + OUT

	rem := ostream.Len()
	if rem < BLOCKLEN {
		fmt.Println("LoadSessionKeys: not enough data (no room for IMIT)")
		return
	}

	sessBytes := rem - BLOCKLEN

	hasFooter := false
	if len(data) >= 2*BLOCKLEN {
		off := len(data) - 2*BLOCKLEN
		if off >= 0 && bytes.Equal(data[off:off+4], []byte{'Q', 'P', 'W', 'D'}) {
			hasFooter = true
		}
	}
	if hasFooter {
		if sessBytes < BLOCKLEN {
			fmt.Println("LoadSessionKeys: malformed length (footer but too short)")
			return
		}
		sessBytes -= BLOCKLEN
	}

	if sessBytes%perUser != 0 {
		fmt.Printf("LoadSessionKeys: malformed length: %d is not multiple of %d\n", sessBytes, perUser)
		return
	}
	usr_cnt := sessBytes / perUser
	if usr_cnt <= 0 || usr_cnt > 255 {
		fmt.Printf("LoadSessionKeys: suspicious user count: %d\n", usr_cnt)
		return
	}

	*session_keys = make([]SessionKeySet, usr_cnt)

	readKey := make([]byte, DEFAULT_KEY_LEN)

	for u := 0; u < usr_cnt; u++ {
		// IN
		for i := 0; i < 1000; i++ {
			n, err := ostream.Read(readKey[:DEFAULT_KEY_LEN])
			if err != nil || n != DEFAULT_KEY_LEN {
				fmt.Println("LoadSessionKeys: error reading session IN key:", err)
				return
			}
			for j := 0; j < DEFAULT_KEY_LEN; j += BLOCKLEN {
				DecryptOFB(readKey[j:j+BLOCKLEN], rKey, DEFAULT_KEY_LEN, BLOCKLEN, readKey[j:j+BLOCKLEN])
			}
			copy((*session_keys)[u].In[i][:], readKey[:])
		}
		// OUT
		for i := 0; i < 1000; i++ {
			n, err := ostream.Read(readKey[:DEFAULT_KEY_LEN])
			if err != nil || n != DEFAULT_KEY_LEN {
				fmt.Println("LoadSessionKeys: error reading session OUT key:", err)
				return
			}
			for j := 0; j < DEFAULT_KEY_LEN; j += BLOCKLEN {
				DecryptOFB(readKey[j:j+BLOCKLEN], rKey, DEFAULT_KEY_LEN, BLOCKLEN, readKey[j:j+BLOCKLEN])
			}
			copy((*session_keys)[u].Out[i][:], readKey[:])
		}
	}
}

func LoadCircleKeys(data []byte, ostream *bytes.Buffer, rKey []byte, circle_keys *[100][32]byte) {
	*circle_keys = [100][32]byte{}

	if ostream.Len() < 100*DEFAULT_KEY_LEN {
		fmt.Printf("LoadCircleKeys: not enough data for 100 circle keys (have %d)\n", ostream.Len())
		return
	}

	readCircleKey := make([]byte, DEFAULT_KEY_LEN)
	for i := 0; i < 100; i++ {
		n, err := ostream.Read(readCircleKey[:DEFAULT_KEY_LEN])
		if err != nil {
			fmt.Printf("LoadCircleKeys: failed to read circle key %d: %v\n", i, err)
			return
		}
		if n != DEFAULT_KEY_LEN {
			fmt.Printf("LoadCircleKeys: unexpected EOF while reading circle key %d\n", i)
			return
		}
		for j := 0; j < DEFAULT_KEY_LEN; j += BLOCKLEN {
			DecryptOFB(readCircleKey[j:j+BLOCKLEN], rKey, DEFAULT_KEY_LEN, BLOCKLEN, readCircleKey[j:j+BLOCKLEN])
		}
		copy((*circle_keys)[i][:], readCircleKey[:])
	}
}
