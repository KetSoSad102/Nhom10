import copy
import unittest

from recursive_json_search import *
from test_data import *

API_KEY_VALUE = "SNMP-COMMUNITY-STRING-7f3a9c"
MGMT_IP_VALUE = "10.10.20.21"


def contains_key(obj, key):
    '''True if key appears anywhere in obj (any depth).'''
    if isinstance(obj, dict):
        return any(k == key or contains_key(v, key) for k, v in obj.items())
    if isinstance(obj, list):
        return any(contains_key(v, key) for v in obj)
    return False


class json_search_test(unittest.TestCase):
    '''test module to test search function in `recursive_json_search.py`'''

    def test_search_found(self):
        '''key should be found, return list should not be empty'''
        self.assertTrue([] != json_search(key1, data, role="viewer"))

    def test_search_not_found(self):
        '''key should not be found, should return an empty list'''
        self.assertTrue([] == json_search(key2, data, role="viewer"))

    def test_is_a_list(self):
        '''Should return a list'''
        self.assertIsInstance(json_search(key1, data, role="viewer"), list)


class json_search_security_test(unittest.TestCase):
    '''security tests for role-based access control in json_search()'''

    # --- SR-1: apiKey is admin-only ---------------------------------------

    def test_viewer_cannot_read_apiKey(self):
        '''SR-1: viewer must not read apiKey (SNMP community string)'''
        self.assertEqual([], json_search("apiKey", data, role="viewer"))

    def test_operator_cannot_read_apiKey(self):
        '''SR-1: operator must not read apiKey'''
        self.assertEqual([], json_search("apiKey", data, role="operator"))

    def test_admin_can_read_apiKey(self):
        '''SR-1: admin can read apiKey (no over-blocking)'''
        self.assertEqual([{"apiKey": API_KEY_VALUE}],
                         json_search("apiKey", data, role="admin"))

    # --- SR-2: managementIpAddress is admin/operator ----------------------

    def test_viewer_cannot_read_managementIpAddress(self):
        '''SR-2: viewer must not read managementIpAddress'''
        self.assertEqual([], json_search("managementIpAddress", data, role="viewer"))

    def test_admin_and_operator_can_read_managementIpAddress(self):
        '''SR-2: admin and operator can read managementIpAddress (no over-blocking)'''
        for role in ("admin", "operator"):
            with self.subTest(role=role):
                self.assertEqual([{"managementIpAddress": MGMT_IP_VALUE}],
                                 json_search("managementIpAddress", data, role=role))

    # --- SR-3: issueSummary is readable by all three roles ----------------

    def test_all_roles_can_read_issueSummary(self):
        '''SR-3: admin, operator and viewer can all read issueSummary'''
        expected = [{"issueSummary":
                     "Network Device 10.10.20.82 Is Unreachable From Controller"}]
        for role in ("admin", "operator", "viewer"):
            with self.subTest(role=role):
                self.assertEqual(expected, json_search("issueSummary", data, role=role))

    def test_unrestricted_key_unchanged_for_valid_role(self):
        '''SR-4 (complement): keys not in POLICY are still returned to any valid role'''
        self.assertEqual([{"hostname": "leaf2.abc.inc"}],
                         json_search("hostname", data, role="viewer"))

    # --- SR-4: missing / unknown role gets nothing ------------------------

    def test_no_role_returns_empty(self):
        '''SR-4: role=None (not provided) returns [] for restricted and unrestricted keys'''
        for key in ("apiKey", "managementIpAddress", "issueSummary", "hostname"):
            with self.subTest(key=key):
                self.assertEqual([], json_search(key, data))
                self.assertEqual([], json_search(key, data, role=None))

    def test_unknown_role_returns_empty(self):
        '''SR-4: a role not in the policy returns []'''
        for role in ("guest", "root", "superuser", ""):
            with self.subTest(role=role):
                self.assertEqual([], json_search("apiKey", data, role=role))
                self.assertEqual([], json_search("issueSummary", data, role=role))
                self.assertEqual([], json_search("hostname", data, role=role))

    def test_case_variant_role_returns_empty(self):
        '''SR-4: case/whitespace variants of a valid role are unknown roles'''
        for role in ("Admin", "ADMIN", " admin", "admin ", "Viewer"):
            with self.subTest(role=role):
                self.assertEqual([], json_search("apiKey", data, role=role))
                self.assertEqual([], json_search("issueSummary", data, role=role))
                self.assertEqual([], json_search("hostname", data, role=role))

    def test_wrong_type_role_returns_empty(self):
        '''SR-4: non-string roles are denied without raising'''
        for role in (["admin"], ("admin",), {"admin"}, {"role": "admin"}, 1, True, b"admin"):
            with self.subTest(role=role):
                self.assertEqual([], json_search("apiKey", data, role=role))
                self.assertEqual([], json_search("hostname", data, role=role))

    # --- SR-5: enforcement at any depth, no leaks via parents -------------

    def test_deeply_nested_restricted_field_protected(self):
        '''SR-5: apiKey nested deep inside lists and dicts (top-level list) is still protected'''
        nested = [{"a": [{"b": {"c": [[{"d": {"apiKey": "DEEP-SECRET"}}]]}}]}, "x", 3]
        self.assertEqual([], json_search("apiKey", nested, role="viewer"))
        self.assertEqual([], json_search("apiKey", nested, role="operator"))
        self.assertEqual([{"apiKey": "DEEP-SECRET"}],
                         json_search("apiKey", nested, role="admin"))

    def test_no_leak_via_parent_key_viewer(self):
        '''SR-1, SR-2, SR-5: viewer searching parent deviceDetails gets it with apiKey and managementIpAddress redacted'''
        result = json_search("deviceDetails", data, role="viewer")
        self.assertEqual(1, len(result))
        self.assertFalse(contains_key(result, "apiKey"))
        self.assertFalse(contains_key(result, "managementIpAddress"))
        self.assertNotIn(API_KEY_VALUE, repr(result))
        self.assertNotIn(MGMT_IP_VALUE, repr(result))
        # non-restricted siblings are kept (no over-blocking)
        self.assertEqual("leaf2.abc.inc", result[0]["deviceDetails"]["hostname"])

    def test_no_leak_via_parent_key_operator(self):
        '''SR-1, SR-2, SR-5: operator searching deviceDetails sees managementIpAddress but not apiKey'''
        result = json_search("deviceDetails", data, role="operator")
        self.assertFalse(contains_key(result, "apiKey"))
        self.assertNotIn(API_KEY_VALUE, repr(result))
        self.assertEqual(MGMT_IP_VALUE, result[0]["deviceDetails"]["managementIpAddress"])

    def test_parent_key_admin_sees_everything(self):
        '''SR-1, SR-2: admin searching deviceDetails sees both restricted fields (no over-blocking)'''
        result = json_search("deviceDetails", data, role="admin")
        self.assertEqual(API_KEY_VALUE, result[0]["deviceDetails"]["apiKey"])
        self.assertEqual(MGMT_IP_VALUE, result[0]["deviceDetails"]["managementIpAddress"])

    def test_no_leak_via_distant_ancestor(self):
        '''SR-5: viewer searching top-level ancestor enrichmentInfo gets no restricted values'''
        result = json_search("enrichmentInfo", data, role="viewer")
        self.assertEqual(1, len(result))
        self.assertNotIn(API_KEY_VALUE, repr(result))
        self.assertNotIn(MGMT_IP_VALUE, repr(result))

    def test_no_leak_from_inside_restricted_value(self):
        '''SR-1, SR-5: keys nested under a denied restricted key are not reachable'''
        crafted = {"apiKey": {"hostname": "inner-secret", "issueSummary": "inner-summary"}}
        self.assertEqual([], json_search("hostname", crafted, role="viewer"))
        self.assertEqual([], json_search("issueSummary", crafted, role="viewer"))
        self.assertEqual([{"hostname": "inner-secret"}],
                         json_search("hostname", crafted, role="admin"))

    def test_search_does_not_mutate_input(self):
        '''SR-1, SR-2 (integrity): redaction does not alter data, and results do not alias it'''
        before = copy.deepcopy(data)
        result = json_search("deviceDetails", data, role="viewer")
        self.assertEqual(before, data)
        result[0]["deviceDetails"]["hostname"] = "tampered"
        self.assertEqual(before, data)


if __name__ == '__main__':
    unittest.main()
