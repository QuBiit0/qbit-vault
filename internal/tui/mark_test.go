package tui_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/tui"
)

// Expectations below were generated once with the reference rasterizer:
//
//	python -I assets/brand/term-mark.py 16 ansi --no-orbits
//	python -I assets/brand/term-mark.py 40 ansi
//
// Each row is a terminal cell: top pixel (foreground) and bottom pixel
// (background) of the half block.
type pinnedCell struct {
	row, col int
	top, bot [3]uint8
}

var pinned16 = []pinnedCell{
	{0, 5, [3]uint8{66, 110, 122}, [3]uint8{130, 213, 229}},
	{1, 8, [3]uint8{2, 8, 13}, [3]uint8{51, 87, 91}},
	{2, 3, [3]uint8{2, 8, 13}, [3]uint8{2, 8, 13}},
	{3, 8, [3]uint8{135, 221, 218}, [3]uint8{136, 222, 216}},
	{4, 8, [3]uint8{137, 223, 215}, [3]uint8{137, 224, 214}},
	{5, 2, [3]uint8{2, 8, 13}, [3]uint8{52, 87, 91}},
	{6, 12, [3]uint8{142, 231, 204}, [3]uint8{143, 232, 202}},
	{7, 12, [3]uint8{46, 78, 72}, [3]uint8{2, 8, 13}},
	{7, 6, [3]uint8{139, 227, 209}, [3]uint8{2, 8, 13}},
}

var pinned40 = []pinnedCell{
	{0, 20, [3]uint8{2, 8, 13}, [3]uint8{131, 215, 227}},
	{1, 20, [3]uint8{132, 215, 226}, [3]uint8{35, 60, 66}},
	{3, 6, [3]uint8{2, 8, 13}, [3]uint8{13, 46, 62}},
	{4, 33, [3]uint8{9, 35, 31}, [3]uint8{29, 114, 87}},
	{5, 20, [3]uint8{136, 221, 218}, [3]uint8{136, 222, 217}},
	{6, 10, [3]uint8{132, 215, 226}, [3]uint8{132, 216, 225}},
	{7, 20, [3]uint8{137, 224, 213}, [3]uint8{2, 8, 13}},
	{9, 25, [3]uint8{124, 203, 180}, [3]uint8{142, 232, 203}},
	{10, 20, [3]uint8{140, 229, 207}, [3]uint8{37, 63, 61}},
	{0, 30, [3]uint8{2, 8, 13}, [3]uint8{11, 43, 39}},
	{2, 36, [3]uint8{20, 80, 60}, [3]uint8{13, 53, 42}},
	{11, 20, [3]uint8{2, 8, 13}, [3]uint8{2, 8, 13}},
}

func near(a, b [3]uint8) bool {
	for i := range a {
		d := int(a[i]) - int(b[i])
		if d < -2 || d > 2 {
			return false
		}
	}
	return true
}

func checkPinned(t *testing.T, pix [][][3]uint8, cells []pinnedCell) {
	t.Helper()
	for _, c := range cells {
		top, bot := pix[2*c.row][c.col], pix[2*c.row+1][c.col]
		if !near(top, c.top) || !near(bot, c.bot) {
			t.Errorf("cell (%d,%d): got top %v bottom %v, want %v %v (±2)", c.row, c.col, top, bot, c.top, c.bot)
		}
	}
}

func TestRasterMarkDimensionsAfterTrim(t *testing.T) {
	tests := []struct {
		name         string
		size         int
		orbits       bool
		wantPixRows  int
		wantPixWidth int
	}{
		{"header mark, no orbits", 16, false, 16, 16},
		{"splash mark with orbits is trimmed", 40, true, 24, 40},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pix := tui.RasterMark(tt.size, tt.orbits)
			if len(pix) != tt.wantPixRows {
				t.Fatalf("pixel rows = %d, want %d", len(pix), tt.wantPixRows)
			}
			for j, row := range pix {
				if len(row) != tt.wantPixWidth {
					t.Fatalf("row %d has %d pixels, want %d", j, len(row), tt.wantPixWidth)
				}
			}
		})
	}
}

func TestRasterMarkMatchesReferencePixels(t *testing.T) {
	t.Run("16 columns, no orbits", func(t *testing.T) {
		checkPinned(t, tui.RasterMark(16, false), pinned16)
	})
	t.Run("40 columns, orbits", func(t *testing.T) {
		checkPinned(t, tui.RasterMark(40, true), pinned40)
	})
}

var sgrRE = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func TestRenderMarkTruecolorHalfBlocks(t *testing.T) {
	th := tui.NewTheme(tui.Profile{Color: true, TrueColor: true})
	got := th.Mark(16, false)
	lines := strings.Split(got, "\n")
	if len(lines) != 8 {
		t.Fatalf("16-column mark has %d rows, want 8", len(lines))
	}
	for i, l := range lines {
		plain := sgrRE.ReplaceAllString(l, "")
		if n := len([]rune(plain)); n != 16 || strings.Trim(plain, "▀") != "" {
			t.Fatalf("row %d is %q after stripping colors, want 16 half blocks", i, plain)
		}
	}
	// Cell (0,5): the top pixel is the foreground, the bottom pixel the background.
	pix := tui.RasterMark(16, false)
	top, bot := pix[0][5], pix[1][5]
	wantFG := fmt.Sprintf("38;2;%d;%d;%d", top[0], top[1], top[2])
	wantBG := fmt.Sprintf("48;2;%d;%d;%d", bot[0], bot[1], bot[2])
	if !strings.Contains(lines[0], wantFG) || !strings.Contains(lines[0], wantBG) {
		t.Errorf("row 0 lacks %s / %s: %q", wantFG, wantBG, lines[0])
	}
}

func TestRenderMarkDegradesToWordmarkWithoutColor(t *testing.T) {
	th := tui.NewTheme(tui.Profile{Color: false})
	for _, size := range []int{16, 40} {
		got := th.Mark(size, size == 40)
		if got != "qbit vault" {
			t.Errorf("Mark(%d) without color = %q, want the plain wordmark", size, got)
		}
	}
}
