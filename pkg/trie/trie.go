// Package succinct is modified from https://github.com/openacid/succinct/blob/loc100/sskv.go.
package trie

import "math/bits"

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
	labels              []byte
	ranks, selects      []int32
}

// NewTrie creates a new *Trie struct, from a slice of sorted strings.
func NewTrie(keys []string) *Trie {

	ss := &Trie{}
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
			ss.labels = append(ss.labels, keys[frm][elt.col])
			setBit(&ss.labelBitmap, lIdx, 0)
			lIdx++
		}

		setBit(&ss.labelBitmap, lIdx, 1)
		lIdx++
	}

	ss.init()
	return ss
}

// HasPrefix query for a word and return whether a prefix of the word is in the Trie.
func (ss *Trie) HasPrefix(word string) bool {

	nodeId, bmIdx := 0, 0

	for i := 0; i < len(word); i++ {
		c := word[i]
		for ; ; bmIdx++ {
			if getBit(ss.labelBitmap, bmIdx) != 0 {
				// no more labels in this node
				return false
			}

			if ss.labels[bmIdx-nodeId] == c {
				break
			}
		}

		// go to next level

		nodeId = countZeros(ss.labelBitmap, ss.ranks, bmIdx+1)
		if getBit(ss.leaves, nodeId) != 0 {
			return true
		}
		bmIdx = selectIthOne(ss.labelBitmap, ss.ranks, ss.selects, nodeId-1) + 1
	}

	return false
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
func countZeros(bm []uint64, ranks []int32, i int) int {
	return i - int(ranks[i>>6]) - bits.OnesCount64(bm[i>>6]&(1<<uint(i&63)-1))
}

// selectIthOne returns the index of the i-th "1" in a bitmap, on behalf of rank
// and select indexes.
// E.g.:
//
//	selectIthOne("010010", 1) == 4
//	//            012345
func selectIthOne(bm []uint64, ranks, selects []int32, i int) int {
	base := int(selects[i>>6] & ^63)
	findIthOne := i - int(ranks[base>>6])

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
