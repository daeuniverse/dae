package control

import (
	"os"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
)

const SysctlPrefixPath = "/proc/sys/"

var sysctl *SysctlManager

type SysctlManager struct {
	log          *logrus.Logger
	mux          sync.Mutex
	watcher      *fsnotify.Watcher
	expectations map[string]string
}

func InitSysctlManager(log *logrus.Logger) (err error) {
	sysctl, err = NewSysctlManager(log)
	return err
}

func NewSysctlManager(log *logrus.Logger) (*SysctlManager, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	manager := &SysctlManager{
		log:          log,
		mux:          sync.Mutex{},
		watcher:      watcher,
		expectations: map[string]string{},
	}
	go manager.startWatch()
	return manager, nil
}

func (s *SysctlManager) startWatch() {
	for {
		select {
		case event, ok := <-s.watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) {
				s.log.Tracef("sysctl write event: %+v", event)
				s.mux.Lock()
				expected, ok := s.expectations[event.Name]
				s.mux.Unlock()
				if ok {
					raw, err := os.ReadFile(event.Name)
					if err != nil {
						s.log.Errorf("failed to read sysctl file %s: %v", event.Name, err)
					}
					value := strings.TrimSpace(string(raw))
					if value != expected {
						s.log.Infof("sysctl %s has unexpected value %s, expected %s", event.Name, value, expected)
						if err := os.WriteFile(event.Name, []byte(expected), 0644); err != nil {
							s.log.Errorf("failed to write sysctl file %s: %v", event.Name, err)
						}
					}
				}
			}
		case err, ok := <-s.watcher.Errors:
			if !ok {
				return
			}
			s.log.Errorf("sysctl watcher error: %v", err)
		}
	}
}

func (s *SysctlManager) Get(key string) (value string, err error) {
	path := SysctlPrefixPath + strings.Replace(key, ".", "/", -1)
	val, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(val)), nil
}

func (s *SysctlManager) Set(key string, value string, watch bool) (err error) {
	path := SysctlPrefixPath + strings.Replace(key, ".", "/", -1)
	if watch {
		s.mux.Lock()
		s.expectations[path] = value
		s.mux.Unlock()
		if err = s.watcher.Add(path); err != nil {
			return
		}
	}
	return os.WriteFile(path, []byte(value), 0644)
}
