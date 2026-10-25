//go:build !windows

package preflight

import (
    "sync"
    "errors"
)

type dummyLsa struct {
    mu    sync.Mutex
    store map[string]map[string]bool // username -> right -> present
}

func newDummyLsa() *dummyLsa {
    return &dummyLsa{store: make(map[string]map[string]bool)}
}

func (d *dummyLsa) ensureUser(username string) map[string]bool {
    if d.store[username] == nil {
        d.store[username] = make(map[string]bool)
    }
    return d.store[username]
}

func (d *dummyLsa) EnumerateAccountRights(username string) ([]string, error) {
    d.mu.Lock()
    defer d.mu.Unlock()
    rightsMap := d.ensureUser(username)
    var rights []string
    for r := range rightsMap {
        rights = append(rights, r)
    }
    return rights, nil
}

func (d *dummyLsa) AddAccountRights(username string, rights []string) error {
    d.mu.Lock()
    defer d.mu.Unlock()
    if username == "" {
        return errors.New("username cannot be empty")
    }
    um := d.ensureUser(username)
    for _, r := range rights {
        um[r] = true
    }
    return nil
}

func (d *dummyLsa) RemoveAccountRights(username string, rights []string) error {
    d.mu.Lock()
    defer d.mu.Unlock()
    if username == "" {
        return errors.New("username cannot be empty")
    }
    um := d.ensureUser(username)
    for _, r := range rights {
        delete(um, r)
    }
    return nil
}
