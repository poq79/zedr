// evtlog_test.go：事件日志读取层测试。
//
// 两部分：
//  1. ParseEvtXML 纯函数测试（不碰 Win32，核心测试）——样例 XML 按
//     2026-11 本机 wevtutil 实抓的真实形状构造（7036/7045 同骨架、
//     Qualifiers 属性、7 位小数秒 SystemTime、1149 的 UserData/EventXML
//     嵌套），事件内容全部为自造中性样本；
//  2. 真机通道冒烟（管理员权限下 System 通道可读，AGENTS.md 环境实锤）。
package winapi

import (
	"reflect"
	"testing"
	"time"
)

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("测试用例自身的时间常量非法 %q: %v", s, err)
	}
	return v
}

// 样例①：System 通道 7045（服务安装）——EventData 无名 Data×5，EventID 带
// Qualifiers 属性（必须被剥离，只取元素文本 7045）。SystemTime 为 Windows
// 实际的 7 位小数秒形态。
const evtXMLSystem7045 = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Service Control Manager' Guid='{555908d1-a6d7-4695-8e1e-26931d2012f4}' EventSourceName='Service Control Manager'/>
    <EventID Qualifiers='16384'>7045</EventID>
    <Version>0</Version>
    <Level>4</Level>
    <Task>0</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8080000000000000</Keywords>
    <TimeCreated SystemTime='2026-11-04T09:35:12.4812503Z'/>
    <EventRecordID>193456</EventRecordID>
    <Correlation/>
    <Execution ProcessID='1028' ThreadID='6040'/>
    <Channel>System</Channel>
    <Computer>ZEDR-HOST</Computer>
    <Security/>
  </System>
  <EventData>
    <Data>zedr-fake-svc</Data>
    <Data>C:\Windows\System32\zedr-test-svc.exe</Data>
    <Data>own process</Data>
    <Data>auto start</Data>
    <Data>LocalSystem</Data>
  </EventData>
</Event>`

// 样例②：Security 通道 4625（登录失败）——EventData 全 Name 属性型，键
// 必须小写化。Status=0xc0000064 是标准 NTSTATUS 常量（用户不存在）。
const evtXMLSecurity4625 = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>
    <EventID>4625</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8010000000000000</Keywords>
    <TimeCreated SystemTime='2026-11-04T09:36:00.1234567Z'/>
    <EventRecordID>2456789</EventRecordID>
    <Correlation/>
    <Execution ProcessID='1028' ThreadID='6040'/>
    <Channel>Security</Channel>
    <Computer>ZEDR-HOST</Computer>
    <Security/>
  </System>
  <EventData>
    <Data Name='SubjectUserSid'>S-1-5-18</Data>
    <Data Name='SubjectUserName'>ZEDR-HOST$</Data>
    <Data Name='TargetUserName'>zedr-admin</Data>
    <Data Name='WorkstationName'>ZEDR-WS</Data>
    <Data Name='IpAddress'>10.20.30.40</Data>
    <Data Name='Status'>0xc0000064</Data>
    <Data Name='LogonType'>10</Data>
  </EventData>
</Event>`

// 样例③：TSLSM 1149（RDP 会话连接）——Data 在 UserData 下、包一层带默认
// 命名空间的 <EventXML>，子元素直接命名（无 Name 属性、非 Data 元素）。
const evtXMLTSLSM1149 = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-TerminalServices-LocalSessionManager' Guid='{9d55f282-9f23-4a4d-a364-6a60e7b6cdb9}'/>
    <EventID>1149</EventID>
    <Version>0</Version>
    <Level>4</Level>
    <Task>114</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime='2026-11-04T09:40:00.0000000Z'/>
    <EventRecordID>321</EventRecordID>
    <Correlation/>
    <Execution ProcessID='820' ThreadID='1808'/>
    <Channel>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</Channel>
    <Computer>ZEDR-HOST</Computer>
    <Security UserID='S-1-5-20'/>
  </System>
  <UserData>
    <EventXML xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
      <User>zedr-user</User>
      <Domain>ZEDRDOM</Domain>
      <Address>192.0.2.55</Address>
      <SessionID>2</SessionID>
    </EventXML>
  </UserData>
</Event>`

func TestParseEvtXMLSystem7045(t *testing.T) {
	ev, err := ParseEvtXML("System", evtXMLSystem7045)
	if err != nil {
		t.Fatalf("ParseEvtXML 报错: %v", err)
	}
	if ev.Channel != "System" {
		t.Errorf("Channel = %q, want System", ev.Channel)
	}
	if ev.EventID != 7045 {
		t.Errorf("EventID = %d, want 7045（Qualifiers='16384' 必须被剥离）", ev.EventID)
	}
	if ev.RecordID != 193456 {
		t.Errorf("RecordID = %d, want 193456", ev.RecordID)
	}
	if ev.Level != 4 {
		t.Errorf("Level = %d, want 4", ev.Level)
	}
	if want := mustTime(t, "2026-11-04T09:35:12.4812503Z"); !ev.TimeCreated.Equal(want) {
		t.Errorf("TimeCreated = %v, want %v（7 位小数秒须兼容）", ev.TimeCreated, want)
	}
	wantData := map[string]string{
		"data[0]": "zedr-fake-svc",
		"data[1]": `C:\Windows\System32\zedr-test-svc.exe`,
		"data[2]": "own process",
		"data[3]": "auto start",
		"data[4]": "LocalSystem",
	}
	if !reflect.DeepEqual(ev.Data, wantData) {
		t.Errorf("Data = %#v, want %#v（无名 Data 键为 data[i]）", ev.Data, wantData)
	}
}

func TestParseEvtXMLSecurity4625(t *testing.T) {
	ev, err := ParseEvtXML("Security", evtXMLSecurity4625)
	if err != nil {
		t.Fatalf("ParseEvtXML 报错: %v", err)
	}
	if ev.EventID != 4625 {
		t.Errorf("EventID = %d, want 4625", ev.EventID)
	}
	if ev.RecordID != 2456789 {
		t.Errorf("RecordID = %d, want 2456789", ev.RecordID)
	}
	if ev.Level != 0 {
		t.Errorf("Level = %d, want 0（审计事件 Level 恒 0）", ev.Level)
	}
	if want := mustTime(t, "2026-11-04T09:36:00.1234567Z"); !ev.TimeCreated.Equal(want) {
		t.Errorf("TimeCreated = %v, want %v", ev.TimeCreated, want)
	}
	wantData := map[string]string{
		"subjectusersid":  "S-1-5-18",
		"subjectusername": "ZEDR-HOST$",
		"targetusername":  "zedr-admin",
		"workstationname": "ZEDR-WS",
		"ipaddress":       "10.20.30.40",
		"status":          "0xc0000064",
		"logontype":       "10",
	}
	if !reflect.DeepEqual(ev.Data, wantData) {
		t.Errorf("Data = %#v, want %#v（Name 属性键必须小写化）", ev.Data, wantData)
	}
}

func TestParseEvtXMLTSLSM1149(t *testing.T) {
	ev, err := ParseEvtXML("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", evtXMLTSLSM1149)
	if err != nil {
		t.Fatalf("ParseEvtXML 报错: %v", err)
	}
	if ev.EventID != 1149 {
		t.Errorf("EventID = %d, want 1149", ev.EventID)
	}
	if ev.RecordID != 321 {
		t.Errorf("RecordID = %d, want 321", ev.RecordID)
	}
	if want := mustTime(t, "2026-11-04T09:40:00.0000000Z"); !ev.TimeCreated.Equal(want) {
		t.Errorf("TimeCreated = %v, want %v（全零小数秒须兼容）", ev.TimeCreated, want)
	}
	wantData := map[string]string{
		// 键小写化、值保持原文（Domain 原文是大写 ZEDRDOM，不得被改写）。
		"user":      "zedr-user",
		"domain":    "ZEDRDOM",
		"address":   "192.0.2.55",
		"sessionid": "2",
	}
	if !reflect.DeepEqual(ev.Data, wantData) {
		t.Errorf("Data = %#v, want %#v（UserData/EventXML 嵌套须下钻，键为元素名小写）",
			ev.Data, wantData)
	}
}

func TestParseEvtXMLDataCounterMixed(t *testing.T) {
	// 无名 Data 计数器跨"命名 Data"连续递增：锁定 data[i] 只数无名项的口径
	// （全无名 System 事件两种口径等价，混排时才见分晓）。
	xmlText := `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System><EventID>1</EventID><EventRecordID>9</EventRecordID></System>
  <EventData>
    <Data>alpha</Data>
    <Data Name='Named1'>beta</Data>
    <Data>gamma</Data>
  </EventData>
</Event>`
	ev, err := ParseEvtXML("System", xmlText)
	if err != nil {
		t.Fatalf("ParseEvtXML 报错: %v", err)
	}
	wantData := map[string]string{
		"data[0]": "alpha",
		"named1":  "beta",
		"data[1]": "gamma",
	}
	if !reflect.DeepEqual(ev.Data, wantData) {
		t.Errorf("Data = %#v, want %#v", ev.Data, wantData)
	}
}

func TestParseEvtXMLEdgeCases(t *testing.T) {
	t.Run("缺EventRecordID必须报错", func(t *testing.T) {
		if _, err := ParseEvtXML("System",
			`<Event><System><EventID>7045</EventID></System></Event>`); err == nil {
			t.Fatal("缺 EventRecordID 应返回错误（结构性字段）")
		}
	})
	t.Run("EventID非法必须报错", func(t *testing.T) {
		_, err := ParseEvtXML("System",
			`<Event><System><EventID>abc</EventID><EventRecordID>1</EventRecordID></System></Event>`)
		if err == nil {
			t.Fatal("EventID 非数字应返回错误")
		}
	})
	t.Run("SystemTime非法给零值不报错", func(t *testing.T) {
		ev, err := ParseEvtXML("System",
			`<Event><System><EventID>104</EventID><EventRecordID>2</EventRecordID>`+
				`<TimeCreated SystemTime='not-a-time'/></System></Event>`)
		if err != nil {
			t.Fatalf("TimeCreated 非法不应报错: %v", err)
		}
		if !ev.TimeCreated.IsZero() {
			t.Errorf("TimeCreated = %v, want 零值", ev.TimeCreated)
		}
	})
	t.Run("无EventData时Data非nil空map", func(t *testing.T) {
		ev, err := ParseEvtXML("System",
			`<Event><System><EventID>104</EventID><EventRecordID>3</EventRecordID></System></Event>`)
		if err != nil {
			t.Fatalf("报错: %v", err)
		}
		if ev.Data == nil {
			t.Fatal("Data 必须非 nil（调用方可直接 range）")
		}
		if len(ev.Data) != 0 {
			t.Errorf("Data = %#v, want 空", ev.Data)
		}
	})
	t.Run("空值Data元素保留键", func(t *testing.T) {
		ev, err := ParseEvtXML("Security",
			`<Event><System><EventID>4624</EventID><EventRecordID>4</EventRecordID></System>`+
				`<EventData><Data Name='TargetUserName'></Data></EventData></Event>`)
		if err != nil {
			t.Fatalf("报错: %v", err)
		}
		v, ok := ev.Data["targetusername"]
		if !ok {
			t.Fatal("空值 Data 也应产生键（空值与缺失语义不同）")
		}
		if v != "" {
			t.Errorf("值 = %q, want 空", v)
		}
	})
}

// ---- 真机冒烟（管理员权限下应通过） ----

func TestEvtLogLiveSystemChannel(t *testing.T) {
	// 精选事件查询：结果可空，非空则必须升序、游标=批内最大。
	events, cursor, err := EvtReadBatch("System", "*[System[(EventID=7045)]]", 0, 100)
	if err != nil {
		t.Fatalf("EvtReadBatch(7045) 报错: %v", err)
	}
	var maxSeen uint64
	for i := 1; i < len(events); i++ {
		if events[i-1].RecordID >= events[i].RecordID {
			t.Errorf("升序被破坏: events[%d].RecordID=%d >= events[%d].RecordID=%d",
				i-1, events[i-1].RecordID, i, events[i].RecordID)
		}
	}
	for _, ev := range events {
		if ev.RecordID > maxSeen {
			maxSeen = ev.RecordID
		}
	}
	if maxSeen > cursor {
		t.Errorf("游标 %d 小于批内最大 RecordID %d", cursor, maxSeen)
	}
	t.Logf("7045 查询：%d 条，游标推进到 %d", len(events), cursor)

	// 全事件小批量读（xpath 空 = 不过滤）：验证升序、Data 非 nil、
	// OldestRecordID 与首条的关系。
	events2, cursor2, err := EvtReadBatch("System", "", 0, 10)
	if err != nil {
		t.Fatalf("EvtReadBatch(全事件) 报错: %v", err)
	}
	for i := 1; i < len(events2); i++ {
		if events2[i-1].RecordID >= events2[i].RecordID {
			t.Errorf("升序被破坏: %d >= %d", events2[i-1].RecordID, events2[i].RecordID)
		}
	}
	for i, ev := range events2 {
		if ev.Data == nil {
			t.Errorf("events2[%d].Data 必须非 nil", i)
		}
		if ev.Channel != "System" {
			t.Errorf("events2[%d].Channel = %q, want System", i, ev.Channel)
		}
	}
	if len(events2) > 0 {
		oldest, err := EvtChannelOldestRecordID("System")
		if err != nil {
			t.Fatalf("EvtChannelOldestRecordID(System) 报错: %v", err)
		}
		if oldest == 0 {
			t.Error("非空通道的最旧 RecordID 应 > 0")
		}
		if oldest > events2[0].RecordID {
			t.Errorf("最旧记录 %d 不应晚于正序首条 %d", oldest, events2[0].RecordID)
		}
		t.Logf("System 全事件批：%d 条（首条 RecordID=%d），通道最旧=%d",
			len(events2), events2[0].RecordID, oldest)
	}

	// 游标过滤：以 cursor2 为界再读，任何返回事件必须严格大于游标。
	events3, cursor3, err := EvtReadBatch("System", "", cursor2, 10)
	if err != nil {
		t.Fatalf("EvtReadBatch(cursor=%d) 报错: %v", cursor2, err)
	}
	for _, ev := range events3 {
		if ev.RecordID <= cursor2 {
			t.Errorf("游标过滤失效: RecordID=%d <= sinceID=%d", ev.RecordID, cursor2)
		}
	}
	if cursor3 < cursor2 {
		t.Errorf("游标不应回退: %d < %d", cursor3, cursor2)
	}
}

func TestEvtLogLiveFakeChannel(t *testing.T) {
	// 不存在的通道必须返回可判错误（调用方降级的依据）。
	if _, _, err := EvtReadBatch("ZedrFakeChannel", "*", 0, 10); err == nil {
		t.Fatal("不存在的通道 EvtReadBatch 必须报错")
	}
	if _, err := EvtChannelOldestRecordID("ZedrFakeChannel"); err == nil {
		t.Fatal("不存在的通道 EvtChannelOldestRecordID 必须报错")
	}
}

func TestEvtLogLiveTSLSM(t *testing.T) {
	// 真机验证 UserData/EventXML 解析链路。通道不可读允许降级（skip）——
	// 该通道部分系统未启用，不是本层缺陷。
	const ch = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
	events, cursor, err := EvtReadBatch(ch, "*[System[(EventID=1149)]]", 0, 10)
	if err != nil {
		t.Skipf("TSLSM 通道不可读（允许降级）: %v", err)
	}
	for i, ev := range events {
		if ev.Data == nil {
			t.Errorf("events[%d].Data 必须非 nil", i)
		}
		if _, ok := ev.Data["address"]; ok && ev.Data["address"] == "" {
			t.Errorf("events[%d] 有 address 键但值为空", i)
		}
	}
	if len(events) > 0 {
		t.Logf("TSLSM 1149：%d 条，首条 Data=%#v（游标 %d）", len(events), events[0].Data, cursor)
	}
}
