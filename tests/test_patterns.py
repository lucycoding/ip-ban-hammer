"""
Tests for attack pattern detection.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))

import unittest
from ipban_core.patterns import detect_attack


class TestXSSDetection(unittest.TestCase):

    def test_javascript_protocol(self):
        self.assertEqual(detect_attack('GET /?q=javascript:alert(1) HTTP/1.1'), 'XSS Attack')

    def test_script_tag(self):
        self.assertEqual(detect_attack('GET /?<script>alert(1)</script> HTTP/1.1'), 'XSS Attack')

    def test_iframe_tag(self):
        self.assertEqual(detect_attack('GET /?<iframe src="evil"> HTTP/1.1'), 'XSS Attack')

    def test_onerror_javascript(self):
        self.assertEqual(detect_attack('GET /?x=onerror="javascript:alert(1)" HTTP/1.1'), 'XSS Attack')

    def test_onload_javascript(self):
        self.assertEqual(detect_attack("GET /?x=onload='javascript:document.cookie' HTTP/1.1"), 'XSS Attack')

    def test_onmouseover_javascript(self):
        self.assertEqual(detect_attack('GET /?x=onmouseover="javascript:void(0)" HTTP/1.1'), 'XSS Attack')

    def test_onclick_javascript(self):
        self.assertEqual(detect_attack('GET /?x=onclick="javascript:alert(1)" HTTP/1.1'), 'XSS Attack')

    def test_onfocus_javascript(self):
        self.assertEqual(detect_attack("GET /?x=onfocus='javascript:alert(1)' HTTP/1.1"), 'XSS Attack')

    def test_onerror_vbscript(self):
        self.assertEqual(detect_attack('GET /?x=onerror="vbscript:msgbox" HTTP/1.1'), 'XSS Attack')

    def test_onerror_data_uri(self):
        self.assertEqual(detect_attack('GET /?x=onerror="data:text/html,<script>alert(1)</script>" HTTP/1.1'), 'XSS Attack')

    def test_context_view_not_xss(self):
        self.assertIsNone(detect_attack('GET /wp-json/wp/v2/posts?context=view HTTP/1.1'))

    def test_context_edit_not_xss(self):
        self.assertIsNone(detect_attack('GET /wp-json/wp/v2/posts?context=edit&_locale=user HTTP/1.1'))

    def test_nonce_not_xss(self):
        self.assertIsNone(detect_attack('POST /wp-admin/post.php?meta-box-loader-nonce=041caf0b7f HTTP/1.1'))

    def test_onerror_plain_value_not_xss(self):
        self.assertIsNone(detect_attack('GET /?x=onerror=handlerFunc HTTP/1.1'))

    def test_onclick_plain_value_not_xss(self):
        self.assertIsNone(detect_attack('GET /?x=onclick=doSomething HTTP/1.1'))


class TestSQLInjectionDetection(unittest.TestCase):

    def test_union_select(self):
        self.assertEqual(detect_attack('GET /?id=1 UNION SELECT 1,2,3 HTTP/1.1'), 'SQL Injection')

    def test_sleep(self):
        self.assertEqual(detect_attack('GET /?id=1 AND SLEEP(5) HTTP/1.1'), 'SQL Injection')

    def test_drop_table(self):
        self.assertEqual(detect_attack('GET /?q=DROP TABLE users HTTP/1.1'), 'SQL Injection')

    def test_normal_query_not_sql(self):
        self.assertIsNone(detect_attack('GET /wp-json/wp/v2/posts?context=view HTTP/1.1'))


class TestPathTraversalDetection(unittest.TestCase):

    def test_dot_dot_slash(self):
        self.assertEqual(detect_attack('GET /../../../etc/passwd HTTP/1.1'), 'Path Traversal')

    def test_etc_passwd(self):
        self.assertEqual(detect_attack('GET /?file=/etc/passwd HTTP/1.1'), 'Path Traversal')

    def test_normal_path_not_traversal(self):
        self.assertIsNone(detect_attack('GET /wp-admin/post.php?post=489&action=edit HTTP/1.1'))


class TestCommandInjectionDetection(unittest.TestCase):

    def test_semicolon_cat(self):
        self.assertEqual(detect_attack('GET /?q=;cat /tmp/scan HTTP/1.1'), 'Command Injection')

    def test_pipe_bash(self):
        self.assertEqual(detect_attack('GET /?q=|bash HTTP/1.1'), 'Command Injection')

    def test_normal_query_not_injection(self):
        self.assertIsNone(detect_attack('GET /wp-admin/admin-ajax.php HTTP/1.1'))


class TestScannerDetection(unittest.TestCase):

    def test_sqlmap(self):
        self.assertEqual(detect_attack('GET /?id=1 sqlmap HTTP/1.1'), 'Scanner')

    def test_nikto(self):
        self.assertEqual(detect_attack('GET / Nikto/2.1.5 HTTP/1.1'), 'Scanner')


class TestWebshellDetection(unittest.TestCase):

    def test_cmd_php(self):
        self.assertEqual(detect_attack('GET /cmd.php HTTP/1.1'), 'Webshell')

    def test_eval(self):
        self.assertEqual(detect_attack('GET /?q=eval($_POST[cmd]) HTTP/1.1'), 'Webshell')


class TestCleanLogLines(unittest.TestCase):

    def test_wordpress_admin_ajax(self):
        self.assertIsNone(detect_attack('180.123.123.123 - - [03/Jul/2026:11:27:23 +0800] "POST /wp-admin/admin-ajax.php HTTP/2.0" 200 101 "https://mysite.cn/wp-admin/post.php?post=489&action=edit" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"'))

    def test_wordpress_rest_api(self):
        self.assertIsNone(detect_attack('180.123.123.123 - - [03/Jul/2026:11:27:14 +0800] "GET /wp-json/wp/v2/taxonomies?context=edit&per_page=100&_locale=user HTTP/2.0" 200 1736 "https://mysite.cn/wp-admin/post.php?post=489&action=edit" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"'))

    def test_wordpress_post_save(self):
        self.assertIsNone(detect_attack('180.123.123.123 - - [03/Jul/2026:11:40:30 +0800] "POST /wp-admin/post.php?post=489&action=edit&meta-box-loader=1&meta-box-loader-nonce=041caf0b7f&_locale=user HTTP/2.0" 302 0 "https://mysite.cn/wp-admin/post.php?post=489&action=edit" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"'))

    def test_wordpress_load_styles(self):
        self.assertIsNone(detect_attack('180.123.123.123 - - [03/Jul/2026:11:27:11 +0800] "GET /wp-admin/load-styles.php?c=0&dir=ltr&load%5Bchunk_0%5D=dashicons,admin-bar,buttons,media-views,editor-buttons,wp-components,wp-preferences,wp-block-editor,wp-reusable-blocks,wp-patter&load%5Bchunk_1%5D=ns,wp-editor,wp-base-styles,common,forms,wp-reset-editor-styles,wp-block-library,wp-block-editor-content,wp-editor-classic-layou&load%5Bchunk_2%5D=t-styles,wp-edit-blocks,wp-commands,wp-edit-post,wp-block-directory,wp-format-library,admin-menu,dashboard,list-tables,edit,revi&load%5Bchunk_3%5D=sions,media,themes,about,nav-menus,wp-pointer,widgets,site-icon,l10n,wp-auth-check,classic-theme-styles&ver=7.0 HTTP/2.0" 200 204768 "https://mysite.cn/wp-admin/post.php?post=489&action=edit" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"'))


if __name__ == '__main__':
    unittest.main()
