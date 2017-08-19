package giota

import (
	"fmt"
	"math"

	multihash "github.com/multiformats/go-multihash"
)

const BIT_HASH_LENGTH = 384

type Kerl struct {
	state Trits
	h     multihash.Multihash
}

func NewKerl() *Kerl {
	k := &Kerl{
		state: make(Trits, stateSize),
	}
	return k
}

//Squeeze do Squeeze in sponge func.
func (k *Kerl) Squeeze() Trytes {
	offset := 0
	length := HashSize
	trits := make(Trits, HashSize*3)

	for offset < length {
		unsigned_hash := Trytes(k.h.HexString())
		//trits_from_hash := unsigned_hash.Trits()
		//	trits_from_hash[HashSize-1] = 0
		//
		//	stop := HashSize
		//	if length < HashSize {
		//		stop = length
		//	}
		//	trits[offset:stop] = trits_from_hash[0:stop]
		//
		//	flipped_bytes := []byte("")
		//	for _, b := range unsigned_hash {
		//		flipped_bytes = append(flipped_bytes, byte(strconv.Itoa(int(b))))
		//	}
		//
		//	// Reset internal state before feeding back in
		//	m, _ := multihash.Sum(flipped_bytes, multihash.KECCAK_384, BIT_HASH_LENGTH)
		//	k.h = m
		//
		offset += HashSize
	}
	return trits.Trytes()
}

const INT_LENGTH = 12
const RADIX = 3

/// hex representation of (3^242)/2
var HALF_3 = []uint32{
	0xa5ce8964,
	0x9f007669,
	0x1484504f,
	0x3ade00d9,
	0x0c24486e,
	0x50979d57,
	0x79a4c702,
	0x48bbae36,
	0xa9f6808b,
	0xaa06a805,
	0xa87fabdf,
	0x5e69ebef,
}

/// rshift that works with up to 53
/// JS's shift operators only work on 32 bit integers
/// ours is up to 33 or 34 bits though, so
/// we need to implement shifting manually
func rshift(number, shift uint64) uint64 {
	return uint64(float64(number)/math.Pow(2, float64(shift))) >> 0
}

/// add with carry
func full_add(lh, rh uint64, carry bool) (uint32, bool) {
	v := lh + rh
	l := (rshift(v, 32)) & 0xFFFFFFFF
	r := (v & 0xFFFFFFFF) >> 0
	carry1 := l != 0

	if carry {
		v = r + 1
	}
	l = (rshift(v, 32)) & 0xFFFFFFFF
	r = (v & 0xFFFFFFFF) >> 0
	carry2 := l != 0

	return uint32(r), carry1 || carry2
}

/// adds a small (i.e. <32bit) number to base
func bigint_add_small(base []uint32, other uint64) int {
	a, b := full_add(uint64(base[0]), other, false)
	base[0] = a
	carry := b

	i := 1
	for carry && i < len(base) {
		a, b := full_add(uint64(base[i]), 0, carry)
		base[i] = a
		carry = b
		i += 1
	}

	return i
}

func trits_to_words(trits Trits) []uint32 {
	if len(trits) != 243 {
		//throw "Invalid trits length";
	}

	base := make([]uint32, INT_LENGTH)

	size := 1
	for i := len(trits) - 2; i > -1; i-- {
		trit := trits[i] + 1

		//multiply by radix
		{
			sz := size
			var carry uint64 = 0

			for j := 0; j < sz; j++ {
				v := uint64(base[j])*uint64(RADIX) + uint64(carry)
				carry = rshift(v, 32)
				base[j] = uint32(v&0xFFFFFFFF) >> 0
			}

			if carry > 0 {
				base[sz] = uint32(carry)
				size += 1
			}
		}

		//addition
		{
			var sz = bigint_add_small(base, uint64(trit))
			if sz > size {
				size = sz
			}
		}
	}
	if base != nil {
		if bigint_cmp(HALF_3, base) <= 0 {
			// base >= HALF_3
			// just do base - HALF_3
			bigint_sub(base, HALF_3)
		} else {
			// base < HALF_3
			// so we need to transform it to a two's complement representation
			// of (base - HALF_3).
			// as we don't have a wrapping (-), we need to use some bit magic
			tmp := HALF_3[:]
			bigint_sub(tmp, base)
			bigint_not(tmp)
			bigint_add_small(tmp, 1)
			base = tmp
		}
	}

	//base.reverse()
	last := len(base) - 1
	for i := 0; i < len(base)/2; i++ {
		base[i], base[last-i] = base[last-i], base[i]
	}

	for i := 0; i < len(base); i++ {
		base[i] = swap32(base[i])
	}

	return base
}

/// subtracts rh from base
func bigint_sub(base, rh []uint32) {
	var noborrow = true

	for i := 0; i < len(base); i++ {
		a, b := full_add(uint64(base[i]), uint64(^rh[i]>>0), noborrow)
		base[i] = a
		noborrow = b
	}

	if !noborrow {
		//throw "noborrow";
	}
}

/// swaps endianness
func swap32(val uint32) uint32 {
	return ((val & 0xFF) << 24) |
		((val & 0xFF00) << 8) |
		((val >> 8) & 0xFF00) |
		((val >> 24) & 0xFF)
}

/// compares two (unsigned) big integers
func bigint_cmp(lh, rh []uint32) int {
	for i := len(lh) - 1; i > -1; i-- {
		a := lh[i] >> 0
		b := rh[i] >> 0
		if a < b {
			return -1
		} else if a > b {
			return 1
		}
	}
	return 0
}

/// negates the (unsigned) input array
func bigint_not(arr []uint32) {
	for i := 0; i < len(arr); i++ {
		arr[i] = (^arr[i]) >> 0
	}
}

// Absorb fills the internal state of the sponge with the given trits.
func (k *Kerl) Absorb(inn Trytes) {
	in := inn.Trits()
	offset := 0
	length := len(in)
	for offset < length {
		stop := int(math.Min(float64(offset+HashSize), float64(length)))

		// If we're copying over a full chunk, zero last trit
		if stop-offset == HashSize {
			in[stop-1] = 0
		}

		signed_nums := in[offset:stop]
		wordsToAbsorb := trits_to_words(signed_nums)
		fmt.Println("Up to here, wordsToAbsorb is good", wordsToAbsorb)

		m, _ := multihash.Sum([]byte(""), multihash.KECCAK_384, -1)
		k.h = m

		offset += HashSize
	}
}

// Reset the internal state of the Curl sponge by filling it with all
// 0's.
func (k *Kerl) Reset() {
	for i := range k.state {
		k.state[i] = 0
	}
}

//Hash returns hash of t.
func (t Trytes) Hash1() Trytes {
	c := NewKerl()
	c.Absorb(t)
	return c.Squeeze()
}
