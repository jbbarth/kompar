package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"fmt"
	"github.com/rakyll/magicmime"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

func processPath(path string, info os.FileInfo, err error) error {
	//buffer to build string
	var buffer bytes.Buffer
	//file properties
	stat, err := os.Stat(path)
	if err != nil {
		log.Printf("Unable to stat %s: %s", path, err)
	}
	//permissions
	perms := stat.Mode()
	buffer.WriteString(fmt.Sprintf("%s ", perms))
	//size
	size := stat.Size()
	buffer.WriteString(fmt.Sprintf("%d ", size))
	//uid/gid
	uid := info.Sys().(*syscall.Stat_t).Uid
	gid := info.Sys().(*syscall.Stat_t).Gid
	user := getUserFromUid(int(uid))
	group := getGroupFromGid(int(gid))
	buffer.WriteString(fmt.Sprintf("%s ", user))
	buffer.WriteString(fmt.Sprintf("%s ", group))
	if stat.IsDir() {
		//directory
		buffer.WriteString(fmt.Sprintf("%s", path))
	} else {
		//mimetype detection
		mm, err := magicmime.New(magicmime.MAGIC_MIME_TYPE | magicmime.MAGIC_SYMLINK | magicmime.MAGIC_ERROR)
		if err != nil {
			log.Panicf("Problem evaluating libmagic detection: %s", err)
		}
		mimetype, err := mm.TypeByFile(path)
		if err != nil {
			log.Printf("Unable to determine file mimetype: %s", err)
			return nil
		}
		//read file content
		contents, err := ioutil.ReadFile(path)
		if err != nil {
			log.Printf("Unable to read %s: %s", path, err)
		}
		//process
		data := []byte(contents)
		if mimetype != "application/octet-stream" {
			//standard file
			buffer.WriteString(fmt.Sprintf("%s md5=%x", path, md5.Sum(data)))
		} else {
			//binary file
			//computing the md5sum for a binary file is irrelevant, as there might
			//be different pre-linking between machines, hence different sum for
			//the same binary
			buffer.WriteString(fmt.Sprintf("%s", path))
		}
	}
	fmt.Println(buffer.String())
	return nil
}

//adapted from https://code.google.com/r/splade2009-camlistore/source/browse/lib/go/schema/schema.go?spec=svn046092d62d7912f756970a2828e47de0c641d30c&r=046092d62d7912f756970a2828e47de0c641d30c
func populateMap(m map[int]string, file string) {
	f, err := os.OpenFile(file, os.O_RDONLY, 0)
	if err != nil {
		return
	}
	bufr := bufio.NewReader(f)
	for {
		line, err := bufr.ReadString('\n')
		if err != nil {
			return
		}
		parts := strings.Split(line, ":")
		if len(parts) >= 3 {
			idstr := parts[2]
			id, err := strconv.Atoi(idstr)
			if err == nil {
				m[id] = parts[0]
			}
		}
	}
}

var uidToUsernameMap map[int]string
var getUserFromUidOnce sync.Once

func getUserFromUid(uid int) string {
	getUserFromUidOnce.Do(func() {
		uidToUsernameMap = make(map[int]string)
		populateMap(uidToUsernameMap, "/etc/passwd")
	})
	return uidToUsernameMap[uid]
}

var gidToUsernameMap map[int]string
var getGroupFromGidOnce sync.Once

func getGroupFromGid(uid int) string {
	getGroupFromGidOnce.Do(func() {
		gidToUsernameMap = make(map[int]string)
		populateMap(gidToUsernameMap, "/etc/group")
	})
	return gidToUsernameMap[uid]
}

func main() {
	for _, path := range os.Args[1:] {
		err := filepath.Walk(path, processPath)
		if err != nil {
			log.Printf("Unable to walk path %s: %s", path, err)
		}
	}
}
