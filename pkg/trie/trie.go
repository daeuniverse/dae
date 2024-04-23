/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

// Package trie is modified from https://github.com/openacid/succinct/blob/loc100/sskv.go.
// Slower than about 30% but more than 40% memory saving.

package trie

import (
	"fmt"
	"math/bits"
	"net/netip"
	"sort"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/bitlist"
	"github.com/daeuniverse/outbound/pool"
)

var ValidCidrChars = NewValidChars([]byte{'0', '1'})

type ValidChars struct {
	table    [256]byte
	n        uint16
	zeroChar byte
}

func NewValidChars(validChars []byte) (v *ValidChars) {
	v = new(ValidChars)
	for _, c := range validChars {
		if v.n == 0 {
			v.zeroChar = c
		}
		v.table[c] = byte(v.n)
		v.n++
	}
	return v
}

func (v *ValidChars) Size() int {
	return int(v.n)
}

func (v *ValidChars) IsValidChar(c byte) bool {
	return v.table[c] > 0 || c == v.zeroChar
}

// Trie is a succinct, sorted and static string set impl with compacted trie as
// storage. The space cost is about half lower than the original data.
//
// # Implementation
//
// It stores sorted strings in a compacted trie(AKA prefix tree).
// A trie node has at most 256 outgoing labels.
// A label is just a single byte.
// E.g., [ab, abc, abcd, axy, buv] is represented with a trie like the following:
// (Numbers are node id)
//
//	^ -a-> 1 -b-> 3 $
//	  |      |      `c-> 6 $
//	  |      |             `d-> 9 $
//	  |      `x-> 4 -y-> 7 $
//	  `b-> 2 -u-> 5 -v-> 8 $
//
// Internally it uses a packed []byte and a bitmap with `len([]byte)` bits to
// describe the outgoing labels of a node,:
//
//	^: ab  00
//	1: bx  00
//	2: u   0
//	3: c   0
//	4: y   0
//	5: v   0
//	6: d   0
//	7: ø
//	8: ø
//	9: ø
//
// In storage it packs labels together and bitmaps joined with separator `1`:
//
//	labels(ignore space): "ab bx u c y v d"
//	label bitmap:          0010010101010101111
//
// Finally leaf nodes are indicated by another bitmap `leaves`, in which a `1`
// at i-th bit indicates the i-th node is a leaf:
//
//	leaves: 0001001111
type Trie struct {
	leaves, labelBitmap []uint64
	ranks, selects      []int32
	labels              *bitlist.CompactBitList
	ranksBL, selectsBL  *bitlist.CompactBitList

	chars *ValidChars
}

func Prefix2bin128(prefix netip.Prefix) (bin128 string) {
	n := prefix.Bits()
	if n == -1 {
		panic("! BadPrefix: " + prefix.String())
	}
	if prefix.Addr().Is4() {
		n += 96
	}
	ip := prefix.Addr().As16()
	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)
loop:
	for i := 0; i < len(ip); i++ {
		for j := 7; j >= 0; j-- {
			if (ip[i]>>j)&1 == 1 {
				_ = buf.WriteByte('1')
			} else {
				_ = buf.WriteByte('0')
			}
			n--
			if n == 0 {
				break loop
			}
		}
	}
	return buf.String()
}

func NewTrieFromPrefixes(cidrs []netip.Prefix) (*Trie, error) {
	var keys []string
	// Convert netip.Prefix -> '0' '1' string
	for _, prefix := range cidrs {
		keys = append(keys, Prefix2bin128(prefix))
	}
	t, err := NewTrie(keys, ValidCidrChars)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// NewTrie creates a new *Trie struct, from a slice of sorted strings.
func NewTrie(keys []string, chars *ValidChars) (*Trie, error) {
	// Check chars.
	keys = common.Deduplicate(keys)
	sort.Strings(keys)
	for _, key := range keys {
		for _, c := range []byte(key) {
			if !chars.IsValidChar(c) {
				return nil, fmt.Errorf("char out of range: %c", c)
			}
		}
	}

	ss := &Trie{
		chars:  chars,
		labels: bitlist.NewCompactBitList(bits.Len(uint(chars.Size()))),
	}
	lIdx := 0

	type qElt struct{ s, e, col int }

	queue := []qElt{{0, len(keys), 0}}

	for i := 0; i < len(queue); i++ {
		elt := queue[i]

		if elt.col == len(keys[elt.s]) {
			// a leaf node
			elt.s++
			setBit(&ss.leaves, i, 1)
		}

		for j := elt.s; j < elt.e; {

			frm := j

			for ; j < elt.e && keys[j][elt.col] == keys[frm][elt.col]; j++ {
			}

			queue = append(queue, qElt{frm, j, elt.col + 1})
			ss.labels.Append(uint64(chars.table[keys[frm][elt.col]]))
			setBit(&ss.labelBitmap, lIdx, 0)
			lIdx++
		}

		setBit(&ss.labelBitmap, lIdx, 1)
		lIdx++
	}

	ss.init()

	// Tighten.
	ss.labels.Tighten()

	leaves := make([]uint64, len(ss.leaves))
	copy(leaves, ss.leaves)
	ss.leaves = leaves

	labelBitmap := make([]uint64, len(ss.labelBitmap))
	copy(labelBitmap, ss.labelBitmap)
	ss.labelBitmap = labelBitmap

	ss.ranksBL = bitlist.NewCompactBitList(bits.Len64(uint64(ss.ranks[len(ss.ranks)-1])))
	ss.selectsBL = bitlist.NewCompactBitList(bits.Len64(uint64(ss.selects[len(ss.selects)-1])))
	for _, v := range ss.ranks {
		ss.ranksBL.Append(uint64(v))
	}
	for _, v := range ss.selects {
		ss.selectsBL.Append(uint64(v))
	}
	ss.ranksBL.Tighten()
	ss.selectsBL.Tighten()
	ss.ranks = nil
	ss.selects = nil

	return ss, nil
}

// HasPrefix query for a word and return whether a prefix of the word is in the Trie.
func (ss *Trie) HasPrefix(word string) bool {

	nodeId, bmIdx := 0, 0

	for i := 0; i < len(word); i++ {
		if getBit(ss.leaves, nodeId) != 0 {
			return true
		}
		c := word[i]
		if !ss.chars.IsValidChar(c) {
			return false
		}
		for ; ; bmIdx++ {
			if getBit(ss.labelBitmap, bmIdx) != 0 {
				// no more labels in this node
				return false
			}

			if byte(ss.labels.Get(bmIdx-nodeId)) == ss.chars.table[c] {
				break
			}
		}

		// go to next level

		nodeId = countZeros(ss.labelBitmap, ss.ranksBL, bmIdx+1)
		bmIdx = selectIthOne(ss.labelBitmap, ss.ranksBL, ss.selectsBL, nodeId-1) + 1
	}

	return getBit(ss.leaves, nodeId) != 0
}

func setBit(bm *[]uint64, i int, v int) {
	for i>>6 >= len(*bm) {
		*bm = append(*bm, 0)
	}
	(*bm)[i>>6] |= uint64(v) << uint(i&63)
}

func getBit(bm []uint64, i int) uint64 {
	return bm[i>>6] & (1 << uint(i&63))
}

// init builds pre-calculated cache to speed up rank() and select()
func (ss *Trie) init() {
	ss.ranks = []int32{0}
	for i := 0; i < len(ss.labelBitmap); i++ {
		n := bits.OnesCount64(ss.labelBitmap[i])
		ss.ranks = append(ss.ranks, ss.ranks[len(ss.ranks)-1]+int32(n))
	}

	ss.selects = []int32{}
	n := 0
	for i := 0; i < len(ss.labelBitmap)<<6; i++ {
		z := int(ss.labelBitmap[i>>6]>>uint(i&63)) & 1
		if z == 1 && n&63 == 0 {
			ss.selects = append(ss.selects, int32(i))
		}
		n += z
	}
}

// countZeros counts the number of "0" in a bitmap before the i-th bit(excluding
// the i-th bit) on behalf of rank index.
// E.g.:
//
//	countZeros("010010", 4) == 3
//	//          012345
func countZeros(bm []uint64, ranks *bitlist.CompactBitList, i int) int {
	return i - int(ranks.Get(i>>6)) - bits.OnesCount64(bm[i>>6]&(1<<uint(i&63)-1))
}

// selectIthOne returns the index of the i-th "1" in a bitmap, on behalf of rank
// and select indexes.
// E.g.:
//
//	selectIthOne("010010", 1) == 4
//	//            012345
func selectIthOne(bm []uint64, ranks, selects *bitlist.CompactBitList, i int) int {
	base := int(selects.Get(i>>6)) & ^63
	findIthOne := i - int(ranks.Get(base>>6))

	for i := base >> 6; i < len(bm); i++ {
		bitIdx := 0
		for w := bm[i]; w > 0; {
			findIthOne -= int(w & 1)
			if findIthOne < 0 {
				return i<<6 + bitIdx
			}
			t0 := bits.TrailingZeros64(w &^ 1)
			w >>= uint(t0)
			bitIdx += t0
		}
	}
	panic("no more ones")
}
