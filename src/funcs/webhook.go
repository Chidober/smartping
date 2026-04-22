package funcs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/cihub/seelog"
	"github.com/smartping/smartping/src/g"
	"github.com/smartping/smartping/src/nettools"
	"io"
	"net/http"
	"strings"
	"time"
)

// AlertWebhookPayload is the JSON body for both live alerts and webhook tests.
type AlertWebhookPayload struct {
	Event         string   `json:"event"`
	Source        string   `json:"source"`
	FromName      string   `json:"from_name"`
	FromIP        string   `json:"from_ip"`
	TargetName    string   `json:"target_name"`
	TargetIP      string   `json:"target_ip"`
	DetectedAt    string   `json:"detected_at"`
	Severity      string   `json:"severity"`
	Reason        string   `json:"reason"`
	CorrelationID string   `json:"correlation_id"`
	Thresholds    []string `json:"thresholds"`
	Trace         string   `json:"trace"`
}

// BuildAlertWebhookPayload builds the same JSON shape for real alerts and tests.
func BuildAlertWebhookPayload(t g.AlertLog, topoRule map[string]string) AlertWebhookPayload {
	reason := "packet loss or latency exceeded threshold"
	if topoRule["Name"] != "" {
		reason = topoRule["Name"] + " packet loss or latency exceeded threshold"
	}
	thresholds := []string{}
	if topoRule["Thdchecksec"] != "" {
		thresholds = append(thresholds, "window_sec<="+topoRule["Thdchecksec"])
	}
	if topoRule["Thdoccnum"] != "" {
		thresholds = append(thresholds, "occurrence>"+topoRule["Thdoccnum"])
	}
	if topoRule["Thdavgdelay"] != "" {
		thresholds = append(thresholds, "avgdelay_ms>"+topoRule["Thdavgdelay"])
	}
	if topoRule["Thdloss"] != "" {
		thresholds = append(thresholds, "loss_percent>"+topoRule["Thdloss"])
	}
	return AlertWebhookPayload{
		Event:         "tunnel_down",
		Source:        "smartping",
		FromName:      t.Fromname,
		FromIP:        t.Fromip,
		TargetName:    t.Targetname,
		TargetIP:      t.Targetip,
		DetectedAt:    time.Now().UTC().Format(time.RFC3339),
		Severity:      "critical",
		Reason:        reason,
		CorrelationID: fmt.Sprintf("sp-%d-%s", time.Now().Unix(), strings.ReplaceAll(t.Targetip, ".", "-")),
		Thresholds:    thresholds,
		Trace:         t.Tracert,
	}
}

// mockMtrTraceJSON returns a JSON array string identical to json.Marshal([]nettools.Mtr) from a live alert.
func mockMtrTraceJSON() string {
	h := []nettools.Mtr{
		{Host: "10.0.0.1", Send: 10, Loss: 0, Last: 2 * time.Millisecond, Avg: 2 * time.Millisecond, Best: 1 * time.Millisecond, Wrst: 4 * time.Millisecond, StDev: 0.5},
		{Host: "10.0.1.2", Send: 10, Loss: 2, Last: 25 * time.Millisecond, Avg: 30 * time.Millisecond, Best: 20 * time.Millisecond, Wrst: 80 * time.Millisecond, StDev: 12.3},
	}
	b, err := json.Marshal(h)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// MockWebhookAlertPair returns an AlertLog + topology rule matching a real alert webhook test scenario.
func MockWebhookAlertPair() (g.AlertLog, map[string]string) {
	log := g.AlertLog{
		Fromname: g.SelfCfg.Name,
		Fromip:   g.SelfCfg.Addr,
		Logtime:  time.Unix(time.Now().Unix(), 0).Format("2006-01-02 15:04"),
		Tracert:  mockMtrTraceJSON(),
	}
	var rule map[string]string
	for _, v := range g.SelfCfg.Topology {
		if v["Addr"] != "" && v["Addr"] != g.SelfCfg.Addr {
			log.Targetname = v["Name"]
			log.Targetip = v["Addr"]
			rule = map[string]string{
				"Name":        v["Name"],
				"Addr":        v["Addr"],
				"Thdchecksec": v["Thdchecksec"],
				"Thdoccnum":   v["Thdoccnum"],
				"Thdavgdelay": v["Thdavgdelay"],
				"Thdloss":     v["Thdloss"],
			}
			break
		}
	}
	if rule == nil {
		log.Targetname = "MockPeer"
		log.Targetip = "10.255.255.1"
		rule = map[string]string{
			"Name":        "MockPeer",
			"Addr":        "10.255.255.1",
			"Thdchecksec": "900",
			"Thdoccnum":   "3",
			"Thdavgdelay": "200",
			"Thdloss":     "30",
		}
	}
	return log, rule
}

func AlertSendWebhook(t g.AlertLog, topoRule map[string]string) {
	payload := BuildAlertWebhookPayload(t, topoRule)
	err := SendWebhook(g.Cfg.Alert["WebhookURL"], g.Cfg.Alert["WebhookSecret"], payload)
	if err != nil {
		seelog.Error("[func:AlertSendWebhook] SendWebhook Error ", err)
	}
}

func SendWebhook(url string, secret string, payload interface{}) error {
	bs, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	timeout := time.Duration(time.Duration(g.Cfg.Base["Timeout"]) * time.Second)
	client := http.Client{Timeout: timeout}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bs))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "SmartPing-Webhook/1.0")
	if strings.TrimSpace(secret) != "" {
		s := strings.TrimSpace(secret)
		// OpenClaw gateway hooks accept Authorization: Bearer <hooks.token> or x-openclaw-token (see extractHookToken).
		req.Header.Set("Authorization", "Bearer "+s)
		req.Header.Set("X-Openclaw-Token", s)
		// Legacy / custom receivers
		req.Header.Set("X-SmartPing-Webhook-Secret", s)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook response status=%d body=%s", resp.StatusCode, string(body))
	}
	return nil
}
