package winui

import (
	"sync"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/app"
)

// viewBox holds the app's latest view. The app may send a view before the
// window exists (it starts first), so the view is kept here rather than in
// the window, and the window is told about it once it is attached.
type viewBox struct {
	mu     sync.Mutex
	view   app.View
	notify func() // set once the window exists; called outside the lock
}

func newViewBox() *viewBox { return &viewBox{view: app.View{Screen: app.ScreenLoading}} }

func (b *viewBox) set(v app.View) {
	b.mu.Lock()
	b.view = v
	n := b.notify
	b.mu.Unlock()
	if n != nil {
		n()
	}
}

func (b *viewBox) get() app.View {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.view
}

// attach starts telling the window about new views, and tells it once now
// in case a view came before the window.
func (b *viewBox) attach(notify func()) {
	b.mu.Lock()
	b.notify = notify
	b.mu.Unlock()
	notify()
}
