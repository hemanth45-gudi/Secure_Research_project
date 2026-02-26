import time
from flask import g, request
import logging

logger = logging.getLogger(__name__)

class MetricsTracker:
    def __init__(self):
        self.total_requests = 0
        self.success_count = 0
        self.failure_count = 0
        self.security_layers = ["JWT", "OTP", "RBAC"]
        self.total_response_time = 0.0

    def start_request(self):
        g.start_time = time.time()
        self.total_requests += 1

    def end_request(self, response):
        if hasattr(g, 'start_time'):
            duration = (time.time() - g.start_time) * 1000  # Convert to ms
            self.total_response_time += duration
            
            status_code = response.status_code
            if 200 <= status_code < 400:
                self.success_count += 1
                status = "SUCCESS"
            else:
                self.failure_count += 1
                status = "FAILURE"

            # Log the individual request metrics
            logger.info(
                f"Request: {request.method} {request.path} | "
                f"Status: {status} ({status_code}) | "
                f"Duration: {duration:.2f}ms | "
                f"Security Layers: {', '.join(self.security_layers)}"
            )
            
            # Print to console as requested: "Log all results clearly in output"
            print(f"\n[METRICS] {request.method} {request.path}")
            print(f" > Status: {status} ({status_code})")
            print(f" > Duration: {duration:.2f}ms")
            print(f" > Security Layers: {', '.join(self.security_layers)}")
            print("-" * 30)

    def get_summary(self):
        avg_response_time = (
            self.total_response_time / self.total_requests 
            if self.total_requests > 0 else 0
        )
        success_rate = (
            (self.success_count / self.total_requests) * 100 
            if self.total_requests > 0 else 0
        )
        
        return {
            "total_requests": self.total_requests,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "success_rate": f"{success_rate:.2f}%",
            "avg_response_time_ms": f"{avg_response_time:.2f}ms",
            "security_layers": self.security_layers
        }

metrics_tracker = MetricsTracker()
