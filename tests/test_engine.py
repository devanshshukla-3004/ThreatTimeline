import unittest
from threattimeline.engine import analyze, normalize

def event(ts, kind, ip="203.0.113.10", user="alice", eid=None):
    e={"timestamp":ts,"event_type":kind,"source":"linux-auth","source_ip":ip,"username":user,"host":"lab-01"}
    if eid: e["event_id"]=eid
    return e

class ThreatTimelineTests(unittest.TestCase):
    def test_timeline_sorted_chronologically(self):
        data=[event("2026-10-18T10:02:00Z","failed_login"),event("2026-10-18T10:00:00Z","failed_login")]
        self.assertTrue(normalize(data)[0]["timestamp"] < normalize(data)[1]["timestamp"])
    def test_failures_then_success_detected(self):
        data=[event(f"2026-10-18T10:00:0{i}Z","failed_login") for i in range(3)]
        data.append(event("2026-10-18T10:01:00Z","successful_login"))
        self.assertIn("TT-001",[f["rule_id"] for f in analyze(data)["findings"]])
    def test_password_spraying_detected(self):
        data=[event(f"2026-10-18T10:00:0{i}Z","failed_login",user=u) for i,u in enumerate(["a","b","c"])]
        self.assertIn("TT-002",[f["rule_id"] for f in analyze(data)["findings"]])
    def test_log_clear_detected(self):
        data=[event("2026-10-18T10:00:00Z","security_log_cleared")]
        self.assertIn("TT-003",[f["rule_id"] for f in analyze(data)["findings"]])
    def test_shared_ip_correlation_group(self):
        data=[event("2026-10-18T10:00:00Z","failed_login"),event("2026-10-18T10:01:00Z","successful_login")]
        self.assertEqual(analyze(data)["summary"]["correlation_groups"],1)
    def test_invalid_timestamp_rejected(self):
        with self.assertRaises(ValueError): analyze([event("not-a-date","failed_login")])
    def test_non_list_rejected(self):
        with self.assertRaises(TypeError): analyze({})
    def test_empty_events(self):
        self.assertEqual(analyze([])["summary"]["events"],0)
if __name__=="__main__": unittest.main()
