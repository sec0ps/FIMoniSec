# Author: Keith Pachulski
# Company: Red Cell Security, LLC
# Email: keith@redcellsecurity.org
# Website: www.redcellsecurity.org
#
# Copyright (c) 2025 Keith Pachulski. All rights reserved.
#
# License: This software is licensed under the MIT License.
#          You are free to use, modify, and distribute this software
#          in accordance with the terms of the license.
#
# Purpose: This script is part of the DumpSec-Py tool, which is designed to
#          perform detailed security audits on Windows systems. It covers
#          user rights, services, registry permissions, file/share permissions,
#          group policy enumeration, risk assessments, and more.
#
# DISCLAIMER: This software is provided "as-is," without warranty of any kind,
#             express or implied, including but not limited to the warranties
#             of merchantability, fitness for a particular purpose, and non-infringement.
#             In no event shall the authors or copyright holders be liable for any claim,
#             damages, or other liability, whether in an action of contract, tort, or otherwise,
#             arising from, out of, or in connection with the software or the use or other dealings
#             in the software.
#
# =============================================================================
import re
import time
import hashlib
from collections import defaultdict, deque

FAILED_LOGIN_THRESHOLD = 5
SCORE_THRESHOLD = 10
EVENT_WINDOW = 60  # seconds
SESSION_WINDOW = 120  # seconds for tracking sequences

class LogDetectionEngine:
    def __init__(self, excluded_ips=None, excluded_users=None):
        self.failed_logins = defaultdict(lambda: deque())
        self.user_scores = defaultdict(int)
        self.last_activity = defaultdict(lambda: 0)
        self.session_log = defaultdict(lambda: deque())
        self.excluded_ips = set(excluded_ips) if excluded_ips is not None else set()
        self.excluded_users = set(excluded_users) if excluded_users is not None else set()

    def _extract_context(self, line):
        ip_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
        ip = ip_match.group(1) if ip_match else None

        # Enhanced username extraction
        user_patterns = [
            r'user\s+(\w+)',
            r'invalid user\s+(\w+)',
            r'Accepted password for\s+(\w+)',
            r'authentication failure for\s+(\w+)',
            r'Failed password for\s+(\w+)',
            r'sudo:\s+(\w+)',
            r'su:\s+(\w+)'
        ]

        user = None
        for pattern in user_patterns:
            match = re.search(pattern, line)
            if match:
                user = match.group(1)
                break

        return ip, user

    def _log_session_event(self, ip, user, tag):
        key = (ip, user)
        now = time.time()
        self.session_log[key].append((tag, now))

        # Cleanup old session entries
        while self.session_log[key] and now - self.session_log[key][0][1] > SESSION_WINDOW:
            self.session_log[key].popleft()

    def _score_event(self, ip, user, line):
        if ip in self.excluded_ips or user in self.excluded_users:
            return None

        # Allow sudo session closes, but don't score them
        benign = [
            "sudo: pam_unix(sudo:session): session closed"
        ]
        if any(b in line for b in benign):
            return None  # allow session to be tracked but not scored

        key = (ip, user)
        line_id = hashlib.sha256(f"{ip}-{user}-{line.strip()}".encode()).hexdigest()
        now = time.time()

        if not hasattr(self, "recent_alerts"):
            self.recent_alerts = {}
        if line_id in self.recent_alerts and now - self.recent_alerts[line_id] < 60:
            return None

        score = 0
        tags = []
        reasons = []

        if "Failed password" in line or "authentication failure" in line:
            score += 2
            tags.append("failed_login")
            reasons.append("Failed login attempt")
            self.failed_logins[ip].append(now)
            self._log_session_event(ip, user, "failed_login")

        if "Accepted password for" in line:
            score += 2
            tags.append("successful_login")
            reasons.append("Successful login")
            self._log_session_event(ip, user, "login_success")

        if "sudo:" in line or "su:" in line:
            score += 3
            tags.append("priv_escalation")
            reasons.append("Privilege escalation attempt")
            self._log_session_event(ip, user, "escalation")

        if "failed_login" in tags:
            attempts = self.failed_logins[ip]
            while attempts and now - attempts[0] > EVENT_WINDOW:
                attempts.popleft()
            if len(attempts) >= FAILED_LOGIN_THRESHOLD:
                score += 5
                tags.append("brute_force")
                reasons.append(f"{len(attempts)} failed logins within {EVENT_WINDOW} seconds")

        session_events = [tag for tag, ts in self.session_log[(ip, user)]]
        if "login_success" in session_events and "escalation" in session_events:
            score += 3
            tags.append("suspicious_sequence")
            reasons.append("Login followed by privilege escalation")

        if now - self.last_activity[(ip, user)] < 5:
            score += 1
            tags.append("high_frequency")
            reasons.append("High-frequency actions")

        if not ip and not user:
            tags.append("unknown_source")
            reasons.append("Activity with no identifiable user or IP")

        self.last_activity[(ip, user)] = now

        # Apply score only if meaningful
        if score >= 3:
            self.user_scores[(ip, user)] += score

        if self.user_scores[(ip, user)] >= SCORE_THRESHOLD:
            final_score = self.user_scores[(ip, user)]
            self.user_scores[(ip, user)] = 0
            self.recent_alerts[line_id] = now
            return {
                "ip": ip,
                "user": user,
                "score": final_score,
                "tags": tags,
                "reason": reasons,
                "line": line.strip()
            }

        return None

    def analyze_line(self, line):
        ip, user = self._extract_context(line)
        if not ip and not user:
            return None
        return self._score_event(ip, user, line)
