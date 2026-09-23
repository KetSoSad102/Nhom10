# Fill the Python code in this file

import unittest
from recursive_json_search import *
from test_data import *

class json_search_test(unittest.TestCase):
    '''test module to test search function in `recursive_json_search.py`'''

    # ===== Functional tests =====
    def test_search_found(self):
        '''key should be found, return list should not be empty'''
        self.assertTrue([] != json_search(key1, data, role="admin"))

    def test_search_not_found(self):
        '''key should not be found, should return an empty list'''
        self.assertTrue([] == json_search(key2, data, role="admin"))

    def test_is_a_list(self):
        '''Should return a list'''
        self.assertIsInstance(json_search(key1, data, role="admin"), list)

    # ===== Security tests =====
    def test_wrong_role_cannot_read_secret(self):
        '''SR-1: viewer không được phép đọc apiKey'''
        result = json_search("apiKey", data, role="viewer")
        self.assertEqual([], result)

    def test_admin_can_read_secret(self):
        '''SR-1: admin được phép đọc apiKey'''
        result = json_search("apiKey", data, role="admin")
        self.assertNotEqual([], result)

    def test_viewer_cannot_read_management_ip(self):
        '''SR-2: viewer không được phép đọc managementIpAddress'''
        result = json_search("managementIpAddress", data, role="viewer")
        self.assertEqual([], result)

    def test_operator_can_read_management_ip(self):
        '''SR-2: operator được phép đọc managementIpAddress'''
        result = json_search("managementIpAddress", data, role="operator")
        self.assertNotEqual([], result)

    def test_viewer_can_read_issue_summary(self):
        '''SR-3: viewer được phép đọc issueSummary'''
        result = json_search("issueSummary", data, role="viewer")
        self.assertNotEqual([], result)

    def test_missing_or_unknown_role_is_denied(self):
        '''SR-4: role None hoặc không tồn tại không được đọc dữ liệu'''
        for role in [None, "", "hacker", "Admin"]:
            with self.subTest(role=role):
                self.assertEqual([], json_search("issueSummary", data, role=role))

if __name__ == '__main__':
    unittest.main()



