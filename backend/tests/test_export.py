import unittest
import sys
import os
from urllib.parse import unquote

# Ensure backend can be imported
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.app import app, REPORTS, HISTORY

class TestPDFExport(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.report_id = "test_utf8_report"
        
        # Mock data with Chinese characters
        REPORTS[self.report_id] = {
            "id": self.report_id,
            "filename": "测试邮件_2024.eml",
            "risk": 90,
            "confidence": "高",
            "level": "危急", 
            "features": {
                "rules": {"keyword": 1, "url": 1},
                "llm": {"style_anomaly": 0.9}
            },
            "summary": "这是一份测试报告的摘要，包含中文字符。",
            "meta": {},
            "threats": [
                {
                    "name": "钓鱼链接", 
                    "severity": "高", 
                    "vector": "URL",
                    "affected": ["用户凭证"],
                    "impact": "账户被盗",
                    "evidence": ["http://fake-login.com"]
                }
            ],
            "chain": ["初始访问", "执行", "凭证窃取"]
        }
        
        HISTORY.append({
            "id": self.report_id,
            "level": "危急",
            "score": 90,
            "filename": "测试邮件_2024.eml",
            "ts": "2024-12-12T10:00:00"
        })

    def tearDown(self):
        if self.report_id in REPORTS:
            del REPORTS[self.report_id]
        # Clean up history if needed, but for tests it's fine

    def test_export_pdf_encoding(self):
        """Test PDF export with Chinese characters in filename and content"""
        response = self.app.get(f'/api/v1/report/export?id={self.report_id}&format=pdf')
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, 'application/pdf')
        
        # Verify Header Encoding (RFC 5987)
        cd = response.headers.get('Content-Disposition', '')
        self.assertIn("filename*=UTF-8''", cd)
        
        # Decode filename to verify it matches
        # Format: attachment; filename*=UTF-8''encoded_string
        if "filename*=UTF-8''" in cd:
            encoded_part = cd.split("filename*=UTF-8''")[1].split(';')[0]
            decoded_filename = unquote(encoded_part)
            self.assertIn("危急", decoded_filename)
            print(f"Verified filename: {decoded_filename}")

    def test_export_json_encoding(self):
        """Test JSON export with Chinese characters"""
        response = self.app.get(f'/api/v1/report/export?id={self.report_id}&format=json')
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, 'application/json')
        
        cd = response.headers.get('Content-Disposition', '')
        self.assertIn("filename*=UTF-8''", cd)
        
        if "filename*=UTF-8''" in cd:
            encoded_part = cd.split("filename*=UTF-8''")[1].split(';')[0]
            decoded_filename = unquote(encoded_part)
            self.assertIn("危急", decoded_filename)

if __name__ == '__main__':
    unittest.main()
