package helper

import "time"

// clickGuard decides whether a click answers a button of the consent prompt
// or the indicator. A button acts only on a press and a release on that same
// button. With `strict` (the consent prompt) both must also come from a real
// pointing device (not SendInput, PostMessage or SendMessage, whose messages
// any process of the user could fake), and presses during the first
// `settle` after the prompt appeared are ignored, so a click already on its
// way when the prompt pops up does not allow anything.
//
// The indicator's End session is not strict: ending must stay easy (also with
// assistive tools that inject input), and a forged End only ends the session.
type clickGuard struct {
	strict  bool
	settle  time.Duration
	shownAt time.Time
	pressed string // the button pressed and not released yet ("" none)
}

// show re-arms the guard when its window appears.
func (g *clickGuard) show(now time.Time) {
	g.shownAt, g.pressed = now, ""
}

// down records a press on `button` ("" when outside every button).
func (g *clickGuard) down(button string, hardware bool, now time.Time) {
	g.pressed = ""
	if button == "" || (g.strict && (!hardware || now.Sub(g.shownAt) < g.settle)) {
		return
	}
	g.pressed = button
}

// up returns the button that was clicked, or "".
func (g *clickGuard) up(button string, hardware bool) string {
	pressed := g.pressed
	g.pressed = ""
	if button == "" || button != pressed || (g.strict && !hardware) {
		return ""
	}
	return button
}
