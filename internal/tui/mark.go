package tui

import (
	"math"
	"sync"
)

// This file is a Go port of assets/brand/term-mark.py: the QBit Vault mark
// (assets/brand/qbit-vault-mark.svg geometry) rasterized for a terminal with
// half blocks. Keep the two in step; the tests pin pixels from the script.

type rgb = [3]uint8

type fcolor [3]float64

var (
	markBG  = fcolor{0x02, 0x08, 0x0D} // terminal background
	markQA  = fcolor{0x7F, 0xD0, 0xEC} // mark gradient
	markQB  = fcolor{0x91, 0xEC, 0xC5}
	orbitA  = fcolor{0x2E, 0x9B, 0xE0} // orbit gradient
	orbitB  = fcolor{0x2F, 0xBF, 0x78}
	markEnd = [2]struct {
		x, y, r float64
		c       fcolor
	}{{334, 110, 8, markQB}, {52, 104, 7, markQA}}
)

func lerp(a, b fcolor, t float64) fcolor {
	var c fcolor
	for i := range c {
		c[i] = a[i] + (b[i]-a[i])*t
	}
	return c
}

func clamp01(v float64) float64 { return math.Max(0, math.Min(1, v)) }

func segDist(px, py, ax, ay, bx, by float64) float64 {
	dx, dy := bx-ax, by-ay
	t := clamp01(((px-ax)*dx + (py-ay)*dy) / (dx*dx + dy*dy))
	return math.Hypot(px-ax-t*dx, py-ay-t*dy)
}

// rrectDist is the signed distance to a rounded rectangle (negative inside).
func rrectDist(px, py, x, y, w, h, r float64) float64 {
	cx, cy := x+w/2, y+h/2
	qx, qy := math.Abs(px-cx)-(w/2-r), math.Abs(py-cy)-(h/2-r)
	return math.Hypot(math.Max(qx, 0), math.Max(qy, 0)) + math.Min(math.Max(qx, qy), 0) - r
}

// inTrap is the keyhole body: (181,180) (174,214) (206,214) (199,180).
func inTrap(px, py float64) bool {
	if py < 180 || py > 214 {
		return false
	}
	t := (py - 180) / 34
	return 181-7*t <= px && px <= 199+7*t
}

// keyhole is the keyhole scaled by k around its center (optical size correction).
func keyhole(px, py, k float64) bool {
	kx, ky := 190+(px-190)/k, 191+(py-191)/k
	return math.Hypot(kx-190, ky-168) <= 18 || inTrap(kx, ky)
}

// ellipseDist approximates the distance to an orbit (rx 170, ry 58, rotated rot degrees).
func ellipseDist(px, py, rot float64) float64 {
	a := -rot * math.Pi / 180
	x, y := px-190, py-190
	u := x*math.Cos(a) - y*math.Sin(a)
	v := x*math.Sin(a) + y*math.Cos(a)
	f := math.Pow(u/170, 2) + math.Pow(v/58, 2) - 1
	gx, gy := 2*u/(170*170), 2*v/(58*58)
	return math.Abs(f) / math.Max(1e-9, math.Hypot(gx, gy))
}

// sample returns the color and coverage weight of one sub-sample, in viewBox units.
func sample(px, py float64, orbits bool, k float64) (fcolor, float64) {
	t := clamp01((px + py - 200) / 360)
	q := lerp(markQA, markQB, t)
	ring := rrectDist(px, py, 104, 96, 172, 172, 58)
	if math.Abs(ring) <= 10 || segDist(px, py, 232, 226, 282, 282) <= 10 || keyhole(px, py, k) {
		return q, 1.0
	}
	if ring < 0 || !orbits {
		return markBG, 0.0 // the orbits pass behind the Q: its counter stays clean
	}
	for _, e := range markEnd {
		if math.Hypot(px-e.x, py-e.y) <= e.r {
			return e.c, 1.0
		}
	}
	for _, rot := range [2]float64{-28, 32} {
		if ellipseDist(px, py, rot) <= 3.5 {
			return lerp(orbitA, orbitB, px/380), 0.8
		}
	}
	return markBG, 0.0
}

const supersample = 4

var (
	rasterMu    sync.Mutex
	rasterCache = map[[2]int][][]rgb{}
)

// RasterMark rasterizes the mark into size columns of square pixels. With
// orbits it covers the whole viewBox; without them, the Q and its tail. Empty
// pixel-row pairs at the top and bottom are trimmed, so the result has an
// even number of rows: terminal cell r is pix[2r] (top) over pix[2r+1].
func RasterMark(size int, orbits bool) [][]rgb {
	key := [2]int{size, 0}
	if orbits {
		key[1] = 1
	}
	rasterMu.Lock()
	defer rasterMu.Unlock()
	if p, ok := rasterCache[key]; ok {
		return p
	}
	p := rasterize(size, orbits)
	rasterCache[key] = p
	return p
}

func rasterize(size int, orbits bool) [][]rgb {
	x0, y0, span := 0.0, 0.0, 380.0
	if !orbits {
		x0, y0, span = 88, 80, 212
	}
	// Small marks enlarge the keyhole so it still reads as one.
	qPx := float64(size) * 172 / span
	k := 1.0
	if qPx < 22 {
		k = math.Min(1.6, 22/qPx)
	}
	ss := float64(supersample)
	pix := make([][]rgb, size)
	for j := range pix {
		row := make([]rgb, size)
		for i := range row {
			var acc fcolor
			for sj := 0; sj < supersample; sj++ {
				for si := 0; si < supersample; si++ {
					px := x0 + (float64(i)+(float64(si)+0.5)/ss)*span/float64(size)
					py := y0 + (float64(j)+(float64(sj)+0.5)/ss)*span/float64(size)
					c, w := sample(px, py, orbits, k)
					for n := range acc {
						acc[n] += c[n]*w + markBG[n]*(1-w)
					}
				}
			}
			for n := range acc {
				row[i][n] = uint8(math.RoundToEven(acc[n] / (ss * ss)))
			}
		}
		pix[j] = row
	}
	return trim(pix)
}

// trim drops empty pixel-row pairs at the top and bottom.
func trim(pix [][]rgb) [][]rgb {
	bg := rgb{uint8(markBG[0]), uint8(markBG[1]), uint8(markBG[2])}
	empty := func(r []rgb) bool {
		for _, c := range r {
			if c != bg {
				return false
			}
		}
		return true
	}
	for len(pix) > 2 && empty(pix[0]) && empty(pix[1]) {
		pix = pix[2:]
	}
	for len(pix) > 2 && empty(pix[len(pix)-1]) && empty(pix[len(pix)-2]) {
		pix = pix[:len(pix)-2]
	}
	return pix
}
