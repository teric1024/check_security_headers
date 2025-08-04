import unittest
import utils

class TestEvalSTS(unittest.TestCase):
    # did not check if the function could parse the values no matter what the order of directives is
    def test_whole(self):
        # ref: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security#examples
        self.assertTupleEqual(utils.eval_sts("max-age=63072000; includeSubDomains; preload"),
                          (utils.EVAL_OK, []),
                          "Should be OK")
        
    def test_subdomain(self):
        self.assertTupleEqual(utils.eval_sts("max-age=63072000; includeSubDomains"),
                          (utils.EVAL_OK, []),
                          "Should be OK")
        
    def test_max_age(self):
        self.assertTupleEqual(utils.eval_sts("max-age=63072000"),
                          (utils.EVAL_OK, []),
                          "Should be OK")
    
    def test_preload_without_includeSubDomains(self):
        self.assertEqual(utils.eval_sts("max-age=63072000; preload")[0], utils.EVAL_WARN,
                         "the includeSubDomains directive must be present when preload exists")

    def test_preload_age(self):
        self.assertEqual(utils.eval_sts("max-age=30; includeSubDomains; preload")[0],
                          utils.EVAL_WARN,
                          "Preload is not valid when max-age < 31536000")
        
    def testno_maxage(self):
        self.assertEqual(utils.eval_sts("preload")[0], utils.EVAL_WARN,
                         "no max-age, should alert")

    def test_small_maxage(self):
        self.assertEqual(utils.eval_sts("max-age=20")[0], utils.EVAL_WARN,
                         "max-age should be greater, should alert")

class TestEvalPermissionsPolicy(unittest.TestCase):
    def test_eval_permission_policy(self):
        self.assertEqual(utils.eval_permissions_policy("geolocation=()")[0], utils.EVAL_OK,
                         "Should be OK")

if __name__ == "__main__":
    unittest.main()