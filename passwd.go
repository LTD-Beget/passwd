package passwd

// #cgo CFLAGS: -D_POSIX_SOURCE=1
// #include <sys/types.h>
// #include <pwd.h>
// #include <stdlib.h>
// size_t size_of_passwd() { return sizeof(struct passwd); }
import "C"
import "unsafe"
import "fmt"

type Passwd struct {
    Name    string
    Passwd  string
    Uid     uint32
    Gid     uint32
    Gecos   string
    Dir     string
    Shell   string
}

func Getpwnam(name string) (*Passwd, error) {
    cname := C.CString(name)
    cpwd := (*C.struct_passwd)(C.malloc(C.size_of_passwd()))
    buf := (*C.char)(C.malloc(1024))
    _, err := C.getpwnam_r(cname, cpwd, buf, 1024, &cpwd)

    if unsafe.Pointer(cpwd) == unsafe.Pointer(uintptr(0)) {
        C.free(unsafe.Pointer(cname))
        if err == nil {
            err = fmt.Errorf("User %s not found", name)
        }
        return nil, err
    }

    p := Passwd {
        Name:   C.GoString(cpwd.pw_name),
        Passwd: C.GoString(cpwd.pw_passwd),
        Uid:    uint32(cpwd.pw_uid),
        Gid:    uint32(cpwd.pw_gid),
        Gecos:  C.GoString(cpwd.pw_gecos),
        Dir:    C.GoString(cpwd.pw_dir),
        Shell:  C.GoString(cpwd.pw_shell),
    }
    C.free(unsafe.Pointer(cname))
    C.free(unsafe.Pointer(cpwd))
    C.free(unsafe.Pointer(buf))
    return &p, nil
}
