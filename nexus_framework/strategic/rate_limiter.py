"""
Adaptive Rate Limiter & Evasion Engine

Detects rate limiting, WAF blocking, and target unreachability.
Automatically adjusts request rates, rotates strategies, and
implements intelligent backoff to maintain operational continuity.

Features:
- HTTP 429/503 detection
- Response time anomaly detection
- Connection reset/timeout tracking
- Adaptive throttling with jitter
- Request pattern randomization
- User-Agent rotation
- Proxy/IP rotation support
- WAF fingerprint-based evasion
- Target health monitoring
"""

import asyncio
import logging
import random
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple


class TargetState(Enum):
    """Target availability states."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    RATE_LIMITED = "rate_limited"
    BLOCKED = "blocked"
    UNREACHABLE = "unreachable"
    WAF_DETECTED = "waf_detected"


class EvasionStrategy(Enum):
    """Evasion strategies ordered by aggressiveness."""
    NONE = "none"
    SLOW_DOWN = "slow_down"
    JITTER = "jitter"
    ROTATE_UA = "rotate_user_agent"
    ROTATE_PROXY = "rotate_proxy"
    FRAGMENT = "fragment_requests"
    PAUSE_AND_RESUME = "pause_and_resume"
    ABORT = "abort"


@dataclass
class RequestMetrics:
    """Tracks request/response metrics for rate limit detection."""
    response_times: deque = field(default_factory=lambda: deque(maxlen=100))
    status_codes: deque = field(default_factory=lambda: deque(maxlen=100))
    timestamps: deque = field(default_factory=lambda: deque(maxlen=100))
    errors: deque = field(default_factory=lambda: deque(maxlen=50))
    consecutive_failures: int = 0
    consecutive_429s: int = 0
    consecutive_timeouts: int = 0
    total_requests: int = 0
    total_blocked: int = 0
    total_rate_limited: int = 0
    baseline_response_time: float = 0.0
    last_successful_request: float = 0.0


@dataclass
class ThrottleConfig:
    """Throttling configuration."""
    base_delay: float = 0.5
    current_delay: float = 0.5
    max_delay: float = 30.0
    min_delay: float = 0.1
    jitter_range: float = 0.3
    backoff_factor: float = 1.5
    recovery_factor: float = 0.8
    max_concurrent: int = 10
    current_concurrent: int = 10


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
]

WAF_SIGNATURES = {
    "cloudflare": ["cf-ray", "cf-cache-status", "__cfduid", "cloudflare"],
    "akamai": ["akamai", "x-akamai", "ak_bmsc"],
    "aws_waf": ["x-amzn-requestid", "x-amz-cf-id", "aws"],
    "imperva": ["incap_ses", "visid_incap", "x-iinfo"],
    "f5_bigip": ["bigipserver", "x-cnection", "f5"],
    "sucuri": ["x-sucuri-id", "sucuri", "x-sucuri-cache"],
    "modsecurity": ["modsecurity", "mod_security"],
    "barracuda": ["barra_counter_session", "barracuda"],
    "fortiweb": ["fortiwafsid", "fortiweb"],
    "palo_alto": ["x-pan-", "palo alto"],
}


class AdaptiveRateLimiter:
    """
    Adaptive rate limiter that detects and responds to rate limiting,
    WAF blocking, and target unreachability in real-time.
    """

    def __init__(self):
        self.logger = logging.getLogger("rate_limiter")
        self.targets: Dict[str, RequestMetrics] = {}
        self.throttle_configs: Dict[str, ThrottleConfig] = {}
        self.target_states: Dict[str, TargetState] = {}
        self.active_strategies: Dict[str, List[EvasionStrategy]] = {}
        self.proxy_pool: List[str] = []
        self.current_proxy_index: int = 0
        self._ua_index: int = 0

    def get_target_metrics(self, target: str) -> RequestMetrics:
        """Get or create metrics for a target."""
        if target not in self.targets:
            self.targets[target] = RequestMetrics()
            self.throttle_configs[target] = ThrottleConfig()
            self.target_states[target] = TargetState.HEALTHY
            self.active_strategies[target] = [EvasionStrategy.NONE]
        return self.targets[target]

    def record_response(self, target: str, status_code: int, response_time: float,
                        headers: Optional[Dict[str, str]] = None, error: Optional[str] = None):
        """Record a response and analyze for rate limiting signals."""
        metrics = self.get_target_metrics(target)
        now = time.time()
        metrics.total_requests += 1
        metrics.timestamps.append(now)
        metrics.response_times.append(response_time)
        metrics.status_codes.append(status_code)

        if error:
            metrics.errors.append((now, error))
            metrics.consecutive_failures += 1
        else:
            metrics.consecutive_failures = 0
            metrics.last_successful_request = now

        # Detect rate limiting signals
        if status_code == 429:
            metrics.consecutive_429s += 1
            metrics.total_rate_limited += 1
            self._handle_rate_limit(target, headers)
        elif status_code in (403, 406, 418, 503):
            metrics.total_blocked += 1
            self._handle_block(target, status_code, headers)
        elif status_code == 0 or error:
            metrics.consecutive_timeouts += 1
            self._handle_unreachable(target, error)
        else:
            metrics.consecutive_429s = 0
            metrics.consecutive_timeouts = 0
            self._check_degradation(target, response_time)

        # Check for WAF
        if headers:
            self._detect_waf(target, headers)

        # Update baseline
        if metrics.total_requests <= 10 and status_code == 200:
            times = list(metrics.response_times)
            if times:
                metrics.baseline_response_time = sum(times) / len(times)

    def _handle_rate_limit(self, target: str, headers: Optional[Dict] = None):
        """React to HTTP 429 rate limiting."""
        config = self.throttle_configs[target]
        self.target_states[target] = TargetState.RATE_LIMITED

        # Check Retry-After header
        retry_after = None
        if headers:
            retry_after = headers.get("retry-after") or headers.get("Retry-After")

        if retry_after:
            try:
                config.current_delay = max(config.current_delay, float(retry_after))
            except ValueError:
                config.current_delay = min(config.current_delay * config.backoff_factor, config.max_delay)
        else:
            config.current_delay = min(config.current_delay * config.backoff_factor, config.max_delay)

        # Reduce concurrency
        config.current_concurrent = max(1, config.current_concurrent - 2)

        strategies = [EvasionStrategy.SLOW_DOWN, EvasionStrategy.JITTER]
        if self.targets[target].consecutive_429s > 3:
            strategies.append(EvasionStrategy.ROTATE_UA)
        if self.targets[target].consecutive_429s > 5:
            strategies.append(EvasionStrategy.ROTATE_PROXY)
        if self.targets[target].consecutive_429s > 10:
            strategies.append(EvasionStrategy.PAUSE_AND_RESUME)

        self.active_strategies[target] = strategies
        self.logger.warning(f"[{target}] Rate limited (429). Delay: {config.current_delay:.1f}s, Concurrent: {config.current_concurrent}, Strategies: {[s.value for s in strategies]}")

    def _handle_block(self, target: str, status_code: int, headers: Optional[Dict] = None):
        """React to blocking (403/503)."""
        config = self.throttle_configs[target]
        metrics = self.targets[target]

        if metrics.total_blocked > 5:
            self.target_states[target] = TargetState.BLOCKED
            config.current_delay = min(config.current_delay * 2, config.max_delay)
            self.active_strategies[target] = [
                EvasionStrategy.SLOW_DOWN, EvasionStrategy.ROTATE_UA,
                EvasionStrategy.ROTATE_PROXY, EvasionStrategy.JITTER
            ]
            self.logger.warning(f"[{target}] Persistent blocking detected (HTTP {status_code}). Engaging full evasion.")
        else:
            self.target_states[target] = TargetState.DEGRADED
            config.current_delay = min(config.current_delay * config.backoff_factor, config.max_delay)

    def _handle_unreachable(self, target: str, error: Optional[str] = None):
        """React to target becoming unreachable."""
        metrics = self.targets[target]
        config = self.throttle_configs[target]

        if metrics.consecutive_timeouts >= 3:
            self.target_states[target] = TargetState.UNREACHABLE
            config.current_delay = min(30.0, config.current_delay * 3)
            self.active_strategies[target] = [EvasionStrategy.PAUSE_AND_RESUME]
            self.logger.error(f"[{target}] UNREACHABLE after {metrics.consecutive_timeouts} timeouts. Error: {error}")
        elif metrics.consecutive_timeouts >= 1:
            self.target_states[target] = TargetState.DEGRADED
            config.current_delay = min(config.current_delay * config.backoff_factor, config.max_delay)

    def _check_degradation(self, target: str, response_time: float):
        """Check if response times indicate degradation."""
        metrics = self.targets[target]
        config = self.throttle_configs[target]

        if metrics.baseline_response_time > 0 and response_time > metrics.baseline_response_time * 3:
            self.target_states[target] = TargetState.DEGRADED
            config.current_delay = min(config.current_delay * 1.2, config.max_delay)
            self.logger.info(f"[{target}] Response degradation: {response_time:.2f}s vs baseline {metrics.baseline_response_time:.2f}s")
        elif self.target_states.get(target) in (TargetState.DEGRADED, TargetState.RATE_LIMITED):
            # Recovery
            config.current_delay = max(config.min_delay, config.current_delay * config.recovery_factor)
            config.current_concurrent = min(config.max_concurrent, config.current_concurrent + 1)
            if config.current_delay <= config.base_delay * 1.5:
                self.target_states[target] = TargetState.HEALTHY
                self.active_strategies[target] = [EvasionStrategy.NONE]
                self.logger.info(f"[{target}] Recovered to HEALTHY state")

    def _detect_waf(self, target: str, headers: Dict[str, str]):
        """Detect WAF from response headers."""
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        all_header_text = " ".join(headers_lower.keys()) + " " + " ".join(headers_lower.values())

        for waf_name, signatures in WAF_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in all_header_text:
                    if self.target_states.get(target) != TargetState.WAF_DETECTED:
                        self.target_states[target] = TargetState.WAF_DETECTED
                        self.logger.warning(f"[{target}] WAF detected: {waf_name}")
                    return waf_name
        return None

    async def get_delay(self, target: str) -> float:
        """Get the current recommended delay before next request."""
        config = self.throttle_configs.get(target, ThrottleConfig())
        delay = config.current_delay

        # Add jitter
        if EvasionStrategy.JITTER in self.active_strategies.get(target, []):
            jitter = random.uniform(-config.jitter_range, config.jitter_range) * delay
            delay = max(config.min_delay, delay + jitter)

        return delay

    async def wait_before_request(self, target: str):
        """Wait the appropriate amount of time before making a request."""
        delay = await self.get_delay(target)
        if delay > 0.1:
            await asyncio.sleep(delay)

    def get_user_agent(self, target: str) -> str:
        """Get a rotated User-Agent string."""
        if EvasionStrategy.ROTATE_UA in self.active_strategies.get(target, []):
            self._ua_index = (self._ua_index + 1) % len(USER_AGENTS)
            return USER_AGENTS[self._ua_index]
        return USER_AGENTS[0]

    def get_proxy(self, target: str) -> Optional[str]:
        """Get a rotated proxy."""
        if not self.proxy_pool:
            return None
        if EvasionStrategy.ROTATE_PROXY in self.active_strategies.get(target, []):
            self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxy_pool)
            return self.proxy_pool[self.current_proxy_index]
        return None

    def get_target_state(self, target: str) -> Dict[str, Any]:
        """Get comprehensive state report for a target."""
        metrics = self.get_target_metrics(target)
        config = self.throttle_configs.get(target, ThrottleConfig())
        state = self.target_states.get(target, TargetState.HEALTHY)

        avg_response_time = 0.0
        if metrics.response_times:
            avg_response_time = sum(metrics.response_times) / len(metrics.response_times)

        return {
            "target": target,
            "state": state.value,
            "total_requests": metrics.total_requests,
            "total_rate_limited": metrics.total_rate_limited,
            "total_blocked": metrics.total_blocked,
            "consecutive_failures": metrics.consecutive_failures,
            "avg_response_time": round(avg_response_time, 3),
            "baseline_response_time": round(metrics.baseline_response_time, 3),
            "current_delay": round(config.current_delay, 2),
            "current_concurrent": config.current_concurrent,
            "active_strategies": [s.value for s in self.active_strategies.get(target, [])],
            "recent_errors": [(t, e) for t, e in list(metrics.errors)[-5:]],
        }

    def should_abort(self, target: str) -> bool:
        """Determine if operations against target should be aborted."""
        metrics = self.get_target_metrics(target)
        state = self.target_states.get(target, TargetState.HEALTHY)

        if state == TargetState.UNREACHABLE and metrics.consecutive_timeouts > 10:
            return True
        if state == TargetState.BLOCKED and metrics.total_blocked > 20:
            return True
        if metrics.consecutive_429s > 20:
            return True
        return False

    def add_proxy(self, proxy_url: str):
        """Add a proxy to the rotation pool."""
        if proxy_url not in self.proxy_pool:
            self.proxy_pool.append(proxy_url)

    def reset_target(self, target: str):
        """Reset all state for a target."""
        self.targets.pop(target, None)
        self.throttle_configs.pop(target, None)
        self.target_states.pop(target, None)
        self.active_strategies.pop(target, None)


# Global singleton instance
adaptive_rate_limiter = AdaptiveRateLimiter()
