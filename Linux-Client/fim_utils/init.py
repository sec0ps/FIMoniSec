# =============================================================================
# FIMonsec Tool - File Integrity Monitoring Security Solution
# =============================================================================
#
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
# Purpose: This script is part of the FIMonsec Tool, which provides enterprise-grade
#          system integrity monitoring with real-time alerting capabilities. It monitors
#          critical system and application files for unauthorized modifications,
#          supports baseline comparisons, and integrates with SIEM solutions.
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
# FIM Utilities Package
__all__ = [
    'AdaptiveScanner',
    'ContextAwareDetection', 
    'EnhancedBehavioralBaselining',
    'AdvancedFileContentAnalysis',
    'EnhancedFIM',
    'FIMIntegration'
]

from fim_utils.fim_perf import AdaptiveScanner
from fim_utils.fim_context import ContextAwareDetection
from fim_utils.fim_behavioral import EnhancedBehavioralBaselining
from fim_utils.adv_analysis import AdvancedFileContentAnalysis
from fim_utils.fim_controller import EnhancedFIM
from fim_utils.fim_integration import FIMIntegration
