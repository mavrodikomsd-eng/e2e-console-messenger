package main

import (
	"net"
	"testing"
)

func TestFrameRoundtrip(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	payload := []byte("привет, Go!")
	go func() {
		_ = sendFrame(a, typeMessage, payload)
	}()

	ftype, got, err := recvFrame(b)
	if err != nil {
		t.Fatalf("recvFrame: %v", err)
	}
	if ftype != typeMessage {
		t.Fatalf("тип кадра = %c, ожидался %c", ftype, typeMessage)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload искажён")
	}
}

func TestOversizeFrameRejected(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	big := make([]byte, maxMessageSize+1)
	if err := sendFrame(c1, typeMessage, big); err == nil {
		t.Fatal("ожидали ошибку при превышении maxMessageSize")
	}
}

func TestGcmRoundtrip(t *testing.T) {
	encryptKey = make([]byte, keySize)
	for i := range encryptKey {
		encryptKey[i] = byte(i)
	}

	enc := encryptMessage("секретное сообщение")
	dec, err := decryptMessage(enc)
	if err != nil {
		t.Fatalf("decryptMessage: %v", err)
	}
	if dec != "секретное сообщение" {
		t.Fatalf("получили %q", dec)
	}
}

func TestDecryptGarbageFails(t *testing.T) {
	encryptKey = make([]byte, keySize)
	if _, err := decryptMessage("не-base64-мусор!!!"); err == nil {
		t.Fatal("ожидали ошибку расшифровки мусора")
	}
}

func TestValidUsername(t *testing.T) {
	cases := map[string]bool{
		"alice":    true,
		"":         false,
		"a;b":      false,
		":x":       false,
		"a\x00b":   false,
	}
	for name, want := range cases {
		if got := validUsername(name); got != want {
			t.Errorf("validUsername(%q) = %v, ожидалось %v", name, got, want)
		}
	}
	long := ""
	for i := 0; i < 33; i++ {
		long += "a"
	}
	if validUsername(long) {
		t.Error("ник длиннее 32 символов должен отклоняться")
	}
}

func TestPasswordHashRoundtrip(t *testing.T) {
	h := hashPassword("пароль")
	if h != hashPassword("пароль") {
		t.Fatal("хэш детерминирован для одинакового входа")
	}
	if h == hashPassword("другой") {
		t.Fatal("разные пароли не должны давать один хэш")
	}
}
