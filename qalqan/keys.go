/*_________________________________________________________________________________________________
					center.bin files structure
* [16] byte:
	[0] - date of use keys high 1 bit
	[1] - date of use keys low 1 bit
	[2] - date of use key high 1 bit
	[3] - date of use key low 1 bit
	[4] - count IN keys in file (BE16)
	[5] - count OUT keys in file (BE16)
	[6..15] - trash data

* [32] byte - Kikey;
* [100][32] byte - Circle key;
* [2000][32] byte - Session keys <out> * users count, used sessions keys <out> delete in file center.bin;
* [2000][32] byte - Session keys <in> * users count, used sessions keys <in> delete in file center.bin;
* [16] byte - imit.
/*_________________________________________________________________________________________________
					abc.bin files structure
* [16] byte:
	[0] - 0 - user num
	[1] - high 4 bits of session in keys
	[2] - low 4 bits of session in keys
	[3] - high 4 bits of session out keys
	[4] - low 4 bits of session out keys
	[5] - date of use keys high 1 bit
	[6] - date of use keys low 1 bit
	[7] - date of use key high 1 bit
	[8] - date of use key low 1 bit
	[9..15] - trash data
* [32] byte - Kikey;
* [100][32] byte - Circle key;
* [2000][32] byte - Session keys <in> * users count, used sessions keys <in> delete in file abc.bin;
* [2000][32] byte - Session keys <out> * users count, used sessions keys <out> delete in file abc.bin;
* [16] byte - imit.
_________________________________________________________________________________________________
				16 byte metadata on files encrypted/decrypted
[0] - 0;
[1] - user owner, 0x33 - center user;
[2] - 0x04;
[3] - 0x20;
[4] - 0x00 - file,
	  0x77 - video,
	  0x88 - photo,
	  0x00 - text (message),
	  0x55 - audio.
[5] - key type circle or session key:
	  0x00 = circle
      0x01 = session out keys for encrypt, session in key for decrypt
[6]   = circle_index (0..99)
[7]   = session_index low8 (lower 8 bits of index 0..999)
[8]   = session_index_hi2 (2 most significant bits of the index: bits 0..1)
[9..[15] = reserved/trash
_________________________________________________________________________________________________
*/

package qalqan

import (
	"bytes"
	"crypto/sha512"
	"fmt"
	"io"
)

type SessionKeySet struct {
	In  [][DEFAULT_KEY_LEN]byte
	Out [][DEFAULT_KEY_LEN]byte
}

func LoadSessionKeysOutThenIn(
    ostream *bytes.Buffer,
    rKey []byte,
    sessionKeys *[]SessionKeySet,
    inCnt, outCnt, users int,
) error {
    const k32 = DEFAULT_KEY_LEN
    *sessionKeys = make([]SessionKeySet, users)
    readKey := make([]byte, k32)

    for u := 0; u < users; u++ {
        // OUT
        (*sessionKeys)[u].Out = make([][DEFAULT_KEY_LEN]byte, outCnt)
        for i := 0; i < outCnt; i++ {
            if _, err := io.ReadFull(ostream, readKey[:k32]); err != nil {
                return fmt.Errorf("LoadSessionKeysOutThenIn: read OUT u=%d i=%d: %w", u, i, err)
            }
            for j := 0; j < k32; j += BLOCKLEN {
                DecryptOFB(readKey[j:j+BLOCKLEN], rKey, k32, BLOCKLEN, readKey[j:j+BLOCKLEN])
            }
            copy((*sessionKeys)[u].Out[i][:], readKey[:])
        }
        // IN
        (*sessionKeys)[u].In = make([][DEFAULT_KEY_LEN]byte, inCnt)
        for i := 0; i < inCnt; i++ {
            if _, err := io.ReadFull(ostream, readKey[:k32]); err != nil {
                return fmt.Errorf("LoadSessionKeysOutThenIn: read IN u=%d i=%d: %w", u, i, err)
            }
            for j := 0; j < k32; j += BLOCKLEN {
                DecryptOFB(readKey[j:j+BLOCKLEN], rKey, k32, BLOCKLEN, readKey[j:j+BLOCKLEN])
            }
            copy((*sessionKeys)[u].In[i][:], readKey[:])
        }
    }
    return nil
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

func LoadCircleKeys(
	ostream *bytes.Buffer,
	rKey []byte,
	dst *[][DEFAULT_KEY_LEN]byte,
	count int,
) error {
	*dst = make([][DEFAULT_KEY_LEN]byte, count)

	readCircleKey := make([]byte, DEFAULT_KEY_LEN)
	for i := 0; i < count; i++ {
		n, err := ostream.Read(readCircleKey[:DEFAULT_KEY_LEN])
		if err != nil || n != DEFAULT_KEY_LEN {
			return fmt.Errorf("LoadCircleKeys: read circle %d: %v", i, err)
		}
		for j := 0; j < DEFAULT_KEY_LEN; j += BLOCKLEN {
			DecryptOFB(readCircleKey[j:j+BLOCKLEN], rKey, DEFAULT_KEY_LEN, BLOCKLEN, readCircleKey[j:j+BLOCKLEN])
		}
		copy((*dst)[i][:], readCircleKey[:])
	}
	return nil
}

func LoadSessionKeysDynamic(
	ostream *bytes.Buffer,
	rKey []byte,
	sessionKeys *[]SessionKeySet,
	inCnt, outCnt, users int,
) error {
	const k32 = DEFAULT_KEY_LEN

	*sessionKeys = make([]SessionKeySet, users)
	readKey := make([]byte, k32)

	for u := 0; u < users; u++ {
		(*sessionKeys)[u].In = make([][DEFAULT_KEY_LEN]byte, inCnt)
		for i := 0; i < inCnt; i++ {
			if _, err := io.ReadFull(ostream, readKey[:k32]); err != nil {
				return fmt.Errorf("LoadSessionKeysDynamic User: read IN u=%d i=%d: %w", u, i, err)
			}
			for j := 0; j < k32; j += BLOCKLEN {
				DecryptOFB(readKey[j:j+BLOCKLEN], rKey, k32, BLOCKLEN, readKey[j:j+BLOCKLEN])
			}
			copy((*sessionKeys)[u].In[i][:], readKey[:])
		}
		(*sessionKeys)[u].Out = make([][DEFAULT_KEY_LEN]byte, outCnt)
		for i := 0; i < outCnt; i++ {
			if _, err := io.ReadFull(ostream, readKey[:k32]); err != nil {
				return fmt.Errorf("LoadSessionKeysDynamic User: read OUT u=%d i=%d: %w", u, i, err)
			}
			for j := 0; j < k32; j += BLOCKLEN {
				DecryptOFB(readKey[j:j+BLOCKLEN], rKey, k32, BLOCKLEN, readKey[j:j+BLOCKLEN])
			}
			copy((*sessionKeys)[u].Out[i][:], readKey[:])
		}
	}

	return nil
}
