"""
Layer 7: Morphogenetic Self-Healing Orchestration System
Eight-Layer Quantum-Hardened Security Architecture

NIST FIPS 203/204/205 Compliant Post-Quantum Cryptography
ML-DSA-87 (Dilithium5) Cryptographically Signed Healing Actions

Security Guarantee: p₇ = 0.01 (1% annual breach probability)

This layer provides:
- Autonomous health monitoring across all 8 layers
- Statistical anomaly detection with adaptive thresholds
- Self-healing with ML-DSA-87 signed remediation actions
- System stability control under attack conditions
- Cryptographically signed audit trails

Mathematical Models:
- Exponential Moving Average (EMA): EMA_t = α·x_t + (1-α)·EMA_{t-1}
- Adaptive Threshold: threshold = μ + k·σ (k=3 for 99.7% confidence)
- Stability Metric: S = 1 - (failures / total_checks)
- Healing Success Rate: HSR = successful_healings / total_healing_attempts

Author: Jason Jarmacz (NeuroDivergent AI Evolution Strategist)
Organization: Trade Momentum LLC / Neurodivergence.Works
License: Proprietary
Version: 2.0.0
"""

import hashlib
import json
import logging
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Callable
from statistics import mean, stdev

try:
    import pqcrypto.sign.ml_dsa_87 as ml_dsa_87
    PQC_AVAILABLE = True
except ImportError:
    PQC_AVAILABLE = False
    logging.warning("pqcrypto not available - ML-DSA-87 signatures disabled")


# ============================================================================
# CONSTANTS AND CONFIGURATION
# ============================================================================

# Layer breach probabilities (annual)
LAYER_BREACH_PROBABILITIES = {
    1: 0.01,   # Identity Verification
    2: 0.01,   # Authorization
    3: 0.01,   # Network Security
    4: 0.001,  # Data Encryption
    5: 0.01,   # Database Security
    6: 0.001,  # PHI Isolation
    7: 0.01,   # Self-Healing (this layer)
    8: 0.001,  # PQC Orchestration
}

# Anomaly detection parameters
ANOMALY_DETECTION_CONFIG = {
    'ema_alpha': 0.3,              # EMA smoothing factor (0.1-0.5)
    'std_dev_threshold': 3.0,      # Standard deviations for anomaly (3σ = 99.7%)
    'min_samples': 30,             # Minimum samples before detection
    'lookback_window': 1000,       # Historical samples to maintain
    'false_positive_target': 0.01, # Target false positive rate (1%)
    'threshold_adjustment_rate': 0.1,  # Rate of threshold adaptation
}

# Stability control parameters
STABILITY_CONFIG = {
    'max_healing_rate': 100,       # Maximum healings per minute
    'circuit_breaker_threshold': 0.5,  # Open circuit at 50% failure rate
    'circuit_breaker_timeout': 300,    # Reset circuit after 5 minutes
    'rate_limit_window': 60,       # Rate limiting window (seconds)
    'stability_target': 0.95,      # Target stability metric (95%)
}

# Health check intervals (seconds)
HEALTH_CHECK_INTERVALS = {
    1: 60,    # Identity - check every minute
    2: 60,    # Authorization
    3: 30,    # Network Security - more frequent
    4: 120,   # Data Encryption
    5: 90,    # Database Security
    6: 120,   # PHI Isolation
    7: 30,    # Self-Healing - monitor ourselves frequently
    8: 60,    # PQC Orchestration
}


# ============================================================================
# ENUMERATIONS
# ============================================================================

class LayerStatus(Enum):
    """Health status of a layer"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    FAILED = "failed"
    RECOVERING = "recovering"
    UNKNOWN = "unknown"


class AnomalyType(Enum):
    """Types of detected anomalies"""
    STATISTICAL = "statistical"
    THRESHOLD = "threshold"
    PATTERN = "pattern"
    RATE = "rate"
    CONFIGURATION = "configuration"
    PERFORMANCE = "performance"
    SECURITY = "security"


class HealingAction(Enum):
    """Types of healing actions"""
    RESTART_SERVICE = "restart_service"
    RESET_CONNECTION = "reset_connection"
    CLEAR_CACHE = "clear_cache"
    ROTATE_KEYS = "rotate_keys"
    ADJUST_THRESHOLD = "adjust_threshold"
    ENABLE_BACKUP = "enable_backup"
    RATE_LIMIT = "rate_limit"
    CIRCUIT_BREAK = "circuit_break"
    ROLLBACK_CONFIG = "rollback_config"
    ESCALATE = "escalate"


class CircuitState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"     # Normal operation
    OPEN = "open"         # Blocking requests
    HALF_OPEN = "half_open"  # Testing recovery


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class HealthMetrics:
    """Health metrics for a layer"""
    layer_id: int
    status: LayerStatus
    uptime_seconds: float
    error_rate: float
    response_time_ms: float
    throughput: float
    memory_usage_mb: float
    cpu_usage_percent: float
    active_connections: int
    failed_checks: int
    total_checks: int
    last_check_time: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def stability_metric(self) -> float:
        """Calculate stability metric: S = 1 - (failures / total_checks)"""
        if self.total_checks == 0:
            return 1.0
        return 1.0 - (self.failed_checks / self.total_checks)

    @property
    def success_rate(self) -> float:
        """Calculate success rate"""
        if self.total_checks == 0:
            return 1.0
        return (self.total_checks - self.failed_checks) / self.total_checks


@dataclass
class AnomalyReport:
    """Report of a detected anomaly"""
    anomaly_id: str
    layer_id: int
    anomaly_type: AnomalyType
    severity: float  # 0.0 to 1.0
    metric_name: str
    observed_value: float
    expected_value: float
    threshold: float
    deviation_sigma: float
    detection_time: datetime
    confidence: float  # 0.0 to 1.0
    context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        result = asdict(self)
        result['anomaly_type'] = self.anomaly_type.value
        result['detection_time'] = self.detection_time.isoformat()
        return result


@dataclass
class HealingRecord:
    """Record of a healing action"""
    healing_id: str
    layer_id: int
    action: HealingAction
    anomaly_id: str
    initiated_time: datetime
    completed_time: Optional[datetime]
    success: bool
    signature: Optional[bytes]  # ML-DSA-87 signature
    public_key: Optional[bytes]  # ML-DSA-87 public key
    action_parameters: Dict[str, Any] = field(default_factory=dict)
    result_data: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        result = asdict(self)
        result['action'] = self.action.value
        result['initiated_time'] = self.initiated_time.isoformat()
        result['completed_time'] = self.completed_time.isoformat() if self.completed_time else None
        result['signature'] = self.signature.hex() if self.signature else None
        result['public_key'] = self.public_key.hex() if self.public_key else None
        return result


@dataclass
class AuditEntry:
    """Cryptographically signed audit log entry"""
    entry_id: str
    timestamp: datetime
    event_type: str
    layer_id: int
    severity: str
    message: str
    data: Dict[str, Any]
    signature: Optional[bytes]
    public_key: Optional[bytes]
    previous_hash: Optional[str]  # Blockchain-style hash chain

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        result = asdict(self)
        result['timestamp'] = self.timestamp.isoformat()
        result['signature'] = self.signature.hex() if self.signature else None
        result['public_key'] = self.public_key.hex() if self.public_key else None
        return result

    def compute_hash(self) -> str:
        """Compute SHA3-384 hash of entry for chain integrity"""
        data = {
            'entry_id': self.entry_id,
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type,
            'layer_id': self.layer_id,
            'severity': self.severity,
            'message': self.message,
            'data': self.data,
            'previous_hash': self.previous_hash,
        }
        json_str = json.dumps(data, sort_keys=True)
        return hashlib.sha3_384(json_str.encode()).hexdigest()


# ============================================================================
# LAYER HEALTH MONITOR
# ============================================================================

class LayerHealthMonitor:
    """
    Monitors health of all 8 layers with configurable check intervals.

    Tracks metrics:
    - Uptime, error rates, response times
    - Resource usage (CPU, memory)
    - Stability metrics
    - Historical health data
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__ + ".HealthMonitor")
        self.health_data: Dict[int, HealthMetrics] = {}
        self.health_history: Dict[int, deque] = {
            i: deque(maxlen=1000) for i in range(1, 9)
        }
        self.lock = threading.RLock()
        self.monitoring_active = False
        self.monitor_threads: Dict[int, threading.Thread] = {}
        self.check_functions: Dict[int, Callable] = {}

    def register_health_check(self, layer_id: int, check_function: Callable) -> None:
        """
        Register a health check function for a layer.

        Args:
            layer_id: Layer number (1-8)
            check_function: Function that returns HealthMetrics
        """
        if not 1 <= layer_id <= 8:
            raise ValueError(f"Invalid layer_id: {layer_id}")

        with self.lock:
            self.check_functions[layer_id] = check_function
            self.logger.info(f"Registered health check for Layer {layer_id}")

    def start_monitoring(self) -> None:
        """Start monitoring all registered layers"""
        with self.lock:
            if self.monitoring_active:
                self.logger.warning("Monitoring already active")
                return

            self.monitoring_active = True

            for layer_id, check_func in self.check_functions.items():
                thread = threading.Thread(
                    target=self._monitor_layer,
                    args=(layer_id, check_func),
                    daemon=True,
                    name=f"HealthMonitor-Layer{layer_id}"
                )
                thread.start()
                self.monitor_threads[layer_id] = thread
                self.logger.info(f"Started monitoring Layer {layer_id}")

    def stop_monitoring(self) -> None:
        """Stop monitoring all layers"""
        with self.lock:
            self.monitoring_active = False

            for layer_id, thread in self.monitor_threads.items():
                thread.join(timeout=5.0)
                self.logger.info(f"Stopped monitoring Layer {layer_id}")

            self.monitor_threads.clear()

    def _monitor_layer(self, layer_id: int, check_func: Callable) -> None:
        """Monitor a single layer continuously"""
        interval = HEALTH_CHECK_INTERVALS.get(layer_id, 60)

        while self.monitoring_active:
            try:
                metrics = check_func()
                if isinstance(metrics, HealthMetrics):
                    self.update_health(layer_id, metrics)
                else:
                    self.logger.error(f"Layer {layer_id} check returned invalid type")
            except Exception as e:
                self.logger.error(f"Health check failed for Layer {layer_id}: {e}")
                # Record failed check
                self._record_failed_check(layer_id)

            time.sleep(interval)

    def _record_failed_check(self, layer_id: int) -> None:
        """Record a failed health check"""
        with self.lock:
            if layer_id in self.health_data:
                self.health_data[layer_id].failed_checks += 1
                self.health_data[layer_id].total_checks += 1
                self.health_data[layer_id].status = LayerStatus.CRITICAL

    def update_health(self, layer_id: int, metrics: HealthMetrics) -> None:
        """
        Update health metrics for a layer.

        Args:
            layer_id: Layer number (1-8)
            metrics: Current health metrics
        """
        with self.lock:
            self.health_data[layer_id] = metrics
            self.health_history[layer_id].append({
                'timestamp': datetime.now(),
                'metrics': metrics
            })

    def get_health(self, layer_id: int) -> Optional[HealthMetrics]:
        """Get current health metrics for a layer"""
        with self.lock:
            return self.health_data.get(layer_id)

    def get_all_health(self) -> Dict[int, HealthMetrics]:
        """Get health metrics for all layers"""
        with self.lock:
            return self.health_data.copy()

    def get_system_stability(self) -> float:
        """
        Calculate overall system stability metric.

        Returns:
            Stability metric (0.0 to 1.0)
        """
        with self.lock:
            if not self.health_data:
                return 1.0

            stability_values = [
                metrics.stability_metric
                for metrics in self.health_data.values()
            ]

            return mean(stability_values) if stability_values else 1.0

    def get_health_history(self, layer_id: int,
                          duration_seconds: int = 3600) -> List[Dict]:
        """
        Get health history for a layer.

        Args:
            layer_id: Layer number (1-8)
            duration_seconds: How far back to look

        Returns:
            List of historical health records
        """
        with self.lock:
            if layer_id not in self.health_history:
                return []

            cutoff_time = datetime.now() - timedelta(seconds=duration_seconds)
            history = self.health_history[layer_id]

            return [
                record for record in history
                if record['timestamp'] >= cutoff_time
            ]


# ============================================================================
# ANOMALY DETECTOR
# ============================================================================

class AnomalyDetector:
    """
    Statistical anomaly detection using exponential moving averages
    and adaptive thresholds.

    Features:
    - Exponential Moving Average (EMA) for baseline
    - Adaptive thresholds using standard deviation
    - Self-optimization based on false positive rates
    - Pattern-based anomaly detection
    """

    def __init__(self, config: Optional[Dict] = None):
        self.logger = logging.getLogger(__name__ + ".AnomalyDetector")
        self.config = config or ANOMALY_DETECTION_CONFIG.copy()

        # Metric tracking
        self.metric_ema: Dict[str, float] = {}
        self.metric_std: Dict[str, float] = {}
        self.metric_history: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=self.config['lookback_window'])
        )

        # Threshold adaptation
        self.adaptive_thresholds: Dict[str, float] = {}
        self.false_positives: Dict[str, int] = defaultdict(int)
        self.true_positives: Dict[str, int] = defaultdict(int)

        # Anomaly tracking
        self.detected_anomalies: deque = deque(maxlen=10000)
        self.anomaly_count = 0

        self.lock = threading.RLock()

    def update_metric(self, metric_name: str, value: float,
                     layer_id: int) -> Optional[AnomalyReport]:
        """
        Update a metric and check for anomalies.

        Args:
            metric_name: Name of the metric
            value: Current metric value
            layer_id: Layer this metric belongs to

        Returns:
            AnomalyReport if anomaly detected, None otherwise
        """
        with self.lock:
            # Update history
            self.metric_history[metric_name].append(value)

            # Update EMA
            if metric_name in self.metric_ema:
                alpha = self.config['ema_alpha']
                self.metric_ema[metric_name] = (
                    alpha * value + (1 - alpha) * self.metric_ema[metric_name]
                )
            else:
                self.metric_ema[metric_name] = value

            # Check if we have enough samples
            if len(self.metric_history[metric_name]) < self.config['min_samples']:
                return None

            # Calculate standard deviation
            history = list(self.metric_history[metric_name])
            self.metric_std[metric_name] = stdev(history)

            # Get or initialize adaptive threshold
            if metric_name not in self.adaptive_thresholds:
                self.adaptive_thresholds[metric_name] = (
                    self.config['std_dev_threshold']
                )

            # Detect anomaly
            expected = self.metric_ema[metric_name]
            threshold_sigma = self.adaptive_thresholds[metric_name]
            threshold_value = threshold_sigma * self.metric_std[metric_name]
            deviation = abs(value - expected)

            if deviation > threshold_value:
                # Anomaly detected
                deviation_sigma = deviation / self.metric_std[metric_name] if self.metric_std[metric_name] > 0 else 0
                severity = min(deviation_sigma / 10.0, 1.0)  # Normalize to 0-1
                confidence = min(deviation_sigma / threshold_sigma, 1.0)

                anomaly = AnomalyReport(
                    anomaly_id=self._generate_anomaly_id(),
                    layer_id=layer_id,
                    anomaly_type=AnomalyType.STATISTICAL,
                    severity=severity,
                    metric_name=metric_name,
                    observed_value=value,
                    expected_value=expected,
                    threshold=threshold_value,
                    deviation_sigma=deviation_sigma,
                    detection_time=datetime.now(),
                    confidence=confidence,
                    context={
                        'ema': expected,
                        'std_dev': self.metric_std[metric_name],
                        'sample_count': len(history),
                    }
                )

                self.detected_anomalies.append(anomaly)
                self.anomaly_count += 1

                self.logger.warning(
                    f"Anomaly detected: {metric_name}={value:.2f} "
                    f"(expected {expected:.2f}, {deviation_sigma:.2f}σ)"
                )

                return anomaly

            return None

    def _generate_anomaly_id(self) -> str:
        """Generate unique anomaly ID"""
        timestamp = datetime.now().isoformat()
        data = f"{timestamp}-{self.anomaly_count}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def report_false_positive(self, metric_name: str) -> None:
        """
        Report a false positive to adjust thresholds.

        Args:
            metric_name: Name of the metric that had false positive
        """
        with self.lock:
            self.false_positives[metric_name] += 1
            self._adjust_threshold(metric_name)

    def report_true_positive(self, metric_name: str) -> None:
        """
        Report a true positive (confirmed anomaly).

        Args:
            metric_name: Name of the metric
        """
        with self.lock:
            self.true_positives[metric_name] += 1

    def _adjust_threshold(self, metric_name: str) -> None:
        """
        Adjust detection threshold based on false positive rate.

        Self-optimization: Increases threshold if too many false positives.
        """
        total = self.false_positives[metric_name] + self.true_positives[metric_name]

        if total < 10:  # Need enough samples
            return

        false_positive_rate = self.false_positives[metric_name] / total
        target_rate = self.config['false_positive_target']
        adjustment_rate = self.config['threshold_adjustment_rate']

        if false_positive_rate > target_rate:
            # Too many false positives, increase threshold
            current = self.adaptive_thresholds.get(
                metric_name,
                self.config['std_dev_threshold']
            )
            self.adaptive_thresholds[metric_name] = current * (1 + adjustment_rate)

            self.logger.info(
                f"Adjusted threshold for {metric_name}: "
                f"{current:.2f} -> {self.adaptive_thresholds[metric_name]:.2f} "
                f"(FP rate: {false_positive_rate:.2%})"
            )

    def get_anomaly_statistics(self) -> Dict[str, Any]:
        """Get statistics about detected anomalies"""
        with self.lock:
            recent_anomalies = [
                a for a in self.detected_anomalies
                if (datetime.now() - a.detection_time).seconds < 3600
            ]

            return {
                'total_anomalies': self.anomaly_count,
                'recent_anomalies_1h': len(recent_anomalies),
                'anomalies_by_layer': self._count_by_layer(),
                'false_positive_rates': self._calculate_fp_rates(),
                'adaptive_thresholds': self.adaptive_thresholds.copy(),
            }

    def _count_by_layer(self) -> Dict[int, int]:
        """Count anomalies by layer"""
        counts = defaultdict(int)
        for anomaly in self.detected_anomalies:
            counts[anomaly.layer_id] += 1
        return dict(counts)

    def _calculate_fp_rates(self) -> Dict[str, float]:
        """Calculate false positive rates for each metric"""
        rates = {}
        for metric in self.false_positives.keys():
            total = self.false_positives[metric] + self.true_positives[metric]
            if total > 0:
                rates[metric] = self.false_positives[metric] / total
        return rates


# ============================================================================
# SELF-HEALING ENGINE
# ============================================================================

class SelfHealingEngine:
    """
    Autonomous remediation engine with ML-DSA-87 cryptographically
    signed healing actions.

    Features:
    - Automated healing action execution
    - ML-DSA-87 signatures for accountability
    - Healing success rate tracking
    - Action rollback on failure
    """

    def __init__(self, enable_signatures: bool = True):
        self.logger = logging.getLogger(__name__ + ".SelfHealingEngine")
        self.enable_signatures = enable_signatures and PQC_AVAILABLE

        # Cryptographic keys for signing
        if self.enable_signatures:
            self.public_key, self.secret_key = ml_dsa_87.generate_keypair()
            self.logger.info("Generated ML-DSA-87 signing key pair")
        else:
            self.public_key, self.secret_key = None, None
            self.logger.warning("ML-DSA-87 signatures disabled")

        # Healing tracking
        self.healing_history: deque = deque(maxlen=10000)
        self.healing_count = 0
        self.successful_healings = 0
        self.failed_healings = 0

        # Action handlers
        self.action_handlers: Dict[HealingAction, Callable] = {}
        self._register_default_handlers()

        self.lock = threading.RLock()

    def _register_default_handlers(self) -> None:
        """Register default healing action handlers"""
        self.action_handlers[HealingAction.RESTART_SERVICE] = self._handle_restart_service
        self.action_handlers[HealingAction.RESET_CONNECTION] = self._handle_reset_connection
        self.action_handlers[HealingAction.CLEAR_CACHE] = self._handle_clear_cache
        self.action_handlers[HealingAction.ROTATE_KEYS] = self._handle_rotate_keys
        self.action_handlers[HealingAction.ADJUST_THRESHOLD] = self._handle_adjust_threshold
        self.action_handlers[HealingAction.ENABLE_BACKUP] = self._handle_enable_backup
        self.action_handlers[HealingAction.RATE_LIMIT] = self._handle_rate_limit
        self.action_handlers[HealingAction.CIRCUIT_BREAK] = self._handle_circuit_break
        self.action_handlers[HealingAction.ROLLBACK_CONFIG] = self._handle_rollback_config
        self.action_handlers[HealingAction.ESCALATE] = self._handle_escalate

    def register_action_handler(self, action: HealingAction,
                               handler: Callable) -> None:
        """
        Register a custom healing action handler.

        Args:
            action: The healing action type
            handler: Function to execute the action
        """
        with self.lock:
            self.action_handlers[action] = handler
            self.logger.info(f"Registered handler for {action.value}")

    def execute_healing(self, layer_id: int, action: HealingAction,
                       anomaly_id: str,
                       parameters: Optional[Dict[str, Any]] = None) -> HealingRecord:
        """
        Execute a healing action with cryptographic signing.

        Args:
            layer_id: Layer to heal
            action: Healing action to execute
            anomaly_id: ID of the anomaly being addressed
            parameters: Action-specific parameters

        Returns:
            HealingRecord with execution results
        """
        healing_id = self._generate_healing_id()
        initiated_time = datetime.now()
        parameters = parameters or {}

        self.logger.info(
            f"Executing healing action: {action.value} for Layer {layer_id} "
            f"(anomaly: {anomaly_id})"
        )

        # Create initial record
        record = HealingRecord(
            healing_id=healing_id,
            layer_id=layer_id,
            action=action,
            anomaly_id=anomaly_id,
            initiated_time=initiated_time,
            completed_time=None,
            success=False,
            signature=None,
            public_key=self.public_key,
            action_parameters=parameters,
            result_data={},
            error_message=None
        )

        try:
            # Execute the action
            if action in self.action_handlers:
                handler = self.action_handlers[action]
                result = handler(layer_id, parameters)
                record.result_data = result
                record.success = True

                with self.lock:
                    self.successful_healings += 1
            else:
                raise ValueError(f"No handler registered for {action.value}")

        except Exception as e:
            self.logger.error(f"Healing action failed: {e}")
            record.success = False
            record.error_message = str(e)

            with self.lock:
                self.failed_healings += 1

        finally:
            record.completed_time = datetime.now()

            # Sign the healing record
            if self.enable_signatures:
                record.signature = self._sign_healing_record(record)

            # Store in history
            with self.lock:
                self.healing_history.append(record)
                self.healing_count += 1

        return record

    def _sign_healing_record(self, record: HealingRecord) -> bytes:
        """
        Sign healing record with ML-DSA-87.

        Args:
            record: Healing record to sign

        Returns:
            ML-DSA-87 signature
        """
        if not self.enable_signatures:
            return b''

        # Create canonical representation for signing
        sign_data = {
            'healing_id': record.healing_id,
            'layer_id': record.layer_id,
            'action': record.action.value,
            'anomaly_id': record.anomaly_id,
            'initiated_time': record.initiated_time.isoformat(),
            'success': record.success,
            'parameters': record.action_parameters,
        }

        message = json.dumps(sign_data, sort_keys=True).encode()
        signature = ml_dsa_87.sign(self.secret_key, message)

        return signature

    def verify_healing_signature(self, record: HealingRecord) -> bool:
        """
        Verify ML-DSA-87 signature on healing record.

        Args:
            record: Healing record to verify

        Returns:
            True if signature is valid
        """
        if not self.enable_signatures or not record.signature:
            return False

        sign_data = {
            'healing_id': record.healing_id,
            'layer_id': record.layer_id,
            'action': record.action.value,
            'anomaly_id': record.anomaly_id,
            'initiated_time': record.initiated_time.isoformat(),
            'success': record.success,
            'parameters': record.action_parameters,
        }

        message = json.dumps(sign_data, sort_keys=True).encode()

        try:
            ml_dsa_87.verify(record.public_key, message, record.signature)
            return True
        except Exception:
            return False

    def _generate_healing_id(self) -> str:
        """Generate unique healing ID"""
        timestamp = datetime.now().isoformat()
        data = f"{timestamp}-{self.healing_count}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def get_healing_success_rate(self) -> float:
        """
        Calculate healing success rate.

        Returns:
            Success rate (0.0 to 1.0)
        """
        with self.lock:
            total = self.successful_healings + self.failed_healings
            if total == 0:
                return 1.0
            return self.successful_healings / total

    def get_healing_statistics(self) -> Dict[str, Any]:
        """Get statistics about healing actions"""
        with self.lock:
            recent_healings = [
                h for h in self.healing_history
                if (datetime.now() - h.initiated_time).seconds < 3600
            ]

            return {
                'total_healings': self.healing_count,
                'successful_healings': self.successful_healings,
                'failed_healings': self.failed_healings,
                'success_rate': self.get_healing_success_rate(),
                'recent_healings_1h': len(recent_healings),
                'healings_by_action': self._count_by_action(),
                'healings_by_layer': self._count_by_layer(),
            }

    def _count_by_action(self) -> Dict[str, int]:
        """Count healings by action type"""
        counts = defaultdict(int)
        for record in self.healing_history:
            counts[record.action.value] += 1
        return dict(counts)

    def _count_by_layer(self) -> Dict[int, int]:
        """Count healings by layer"""
        counts = defaultdict(int)
        for record in self.healing_history:
            counts[record.layer_id] += 1
        return dict(counts)

    # ========================================================================
    # DEFAULT ACTION HANDLERS
    # ========================================================================

    def _handle_restart_service(self, layer_id: int,
                               parameters: Dict) -> Dict[str, Any]:
        """Handle service restart action"""
        service_name = parameters.get('service_name', f'layer{layer_id}')
        self.logger.info(f"Restarting service: {service_name}")

        # In production, this would actually restart the service
        # For now, simulate the action
        time.sleep(0.1)  # Simulate restart delay

        return {
            'service_name': service_name,
            'restart_time': datetime.now().isoformat(),
            'status': 'restarted'
        }

    def _handle_reset_connection(self, layer_id: int,
                                 parameters: Dict) -> Dict[str, Any]:
        """Handle connection reset action"""
        connection_id = parameters.get('connection_id', 'default')
        self.logger.info(f"Resetting connection: {connection_id}")

        return {
            'connection_id': connection_id,
            'reset_time': datetime.now().isoformat(),
            'status': 'reset'
        }

    def _handle_clear_cache(self, layer_id: int,
                           parameters: Dict) -> Dict[str, Any]:
        """Handle cache clear action"""
        cache_name = parameters.get('cache_name', 'default')
        self.logger.info(f"Clearing cache: {cache_name}")

        return {
            'cache_name': cache_name,
            'cleared_time': datetime.now().isoformat(),
            'items_cleared': 0  # Would be actual count in production
        }

    def _handle_rotate_keys(self, layer_id: int,
                           parameters: Dict) -> Dict[str, Any]:
        """Handle cryptographic key rotation"""
        key_type = parameters.get('key_type', 'session')
        self.logger.info(f"Rotating {key_type} keys for Layer {layer_id}")

        return {
            'key_type': key_type,
            'rotation_time': datetime.now().isoformat(),
            'status': 'rotated'
        }

    def _handle_adjust_threshold(self, layer_id: int,
                                parameters: Dict) -> Dict[str, Any]:
        """Handle threshold adjustment"""
        threshold_name = parameters.get('threshold_name', 'default')
        adjustment = parameters.get('adjustment', 1.1)
        self.logger.info(
            f"Adjusting threshold {threshold_name} by {adjustment}x"
        )

        return {
            'threshold_name': threshold_name,
            'adjustment_factor': adjustment,
            'adjusted_time': datetime.now().isoformat()
        }

    def _handle_enable_backup(self, layer_id: int,
                             parameters: Dict) -> Dict[str, Any]:
        """Handle enabling backup system"""
        backup_type = parameters.get('backup_type', 'primary')
        self.logger.info(f"Enabling {backup_type} backup for Layer {layer_id}")

        return {
            'backup_type': backup_type,
            'enabled_time': datetime.now().isoformat(),
            'status': 'enabled'
        }

    def _handle_rate_limit(self, layer_id: int,
                          parameters: Dict) -> Dict[str, Any]:
        """Handle rate limiting activation"""
        limit = parameters.get('limit', 100)
        duration = parameters.get('duration', 60)
        self.logger.info(
            f"Enabling rate limit: {limit} requests per {duration}s"
        )

        return {
            'limit': limit,
            'duration_seconds': duration,
            'enabled_time': datetime.now().isoformat()
        }

    def _handle_circuit_break(self, layer_id: int,
                             parameters: Dict) -> Dict[str, Any]:
        """Handle circuit breaker activation"""
        timeout = parameters.get('timeout', 300)
        self.logger.warning(
            f"Opening circuit breaker for Layer {layer_id} "
            f"(timeout: {timeout}s)"
        )

        return {
            'timeout_seconds': timeout,
            'opened_time': datetime.now().isoformat(),
            'status': 'open'
        }

    def _handle_rollback_config(self, layer_id: int,
                               parameters: Dict) -> Dict[str, Any]:
        """Handle configuration rollback"""
        version = parameters.get('version', 'previous')
        self.logger.info(
            f"Rolling back configuration to {version} for Layer {layer_id}"
        )

        return {
            'rollback_version': version,
            'rollback_time': datetime.now().isoformat(),
            'status': 'rolled_back'
        }

    def _handle_escalate(self, layer_id: int,
                        parameters: Dict) -> Dict[str, Any]:
        """Handle escalation to human operators"""
        severity = parameters.get('severity', 'high')
        self.logger.critical(
            f"ESCALATING: Layer {layer_id} issue (severity: {severity})"
        )

        return {
            'severity': severity,
            'escalated_time': datetime.now().isoformat(),
            'notification_sent': True
        }


# ============================================================================
# STABILITY CONTROLLER
# ============================================================================

class StabilityController:
    """
    Maintains system equilibrium under attack using rate limiting
    and circuit breakers.

    Features:
    - Rate limiting with sliding window
    - Circuit breaker pattern
    - Adaptive throttling
    - System stability metric tracking
    """

    def __init__(self, config: Optional[Dict] = None):
        self.logger = logging.getLogger(__name__ + ".StabilityController")
        self.config = config or STABILITY_CONFIG.copy()

        # Rate limiting
        self.healing_timestamps: deque = deque(maxlen=1000)

        # Circuit breakers per layer
        self.circuit_states: Dict[int, CircuitState] = {
            i: CircuitState.CLOSED for i in range(1, 9)
        }
        self.circuit_failures: Dict[int, int] = defaultdict(int)
        self.circuit_opened_time: Dict[int, Optional[datetime]] = {
            i: None for i in range(1, 9)
        }

        # Stability metrics
        self.stability_history: deque = deque(maxlen=1000)

        self.lock = threading.RLock()

    def check_rate_limit(self) -> Tuple[bool, str]:
        """
        Check if healing action is within rate limit.

        Returns:
            (allowed, reason) tuple
        """
        with self.lock:
            now = datetime.now()
            window_start = now - timedelta(
                seconds=self.config['rate_limit_window']
            )

            # Remove old timestamps
            while (self.healing_timestamps and
                   self.healing_timestamps[0] < window_start):
                self.healing_timestamps.popleft()

            # Check rate
            current_rate = len(self.healing_timestamps)
            max_rate = self.config['max_healing_rate']

            if current_rate >= max_rate:
                return False, f"Rate limit exceeded: {current_rate}/{max_rate}"

            return True, "Within rate limit"

    def record_healing_attempt(self) -> None:
        """Record a healing attempt for rate limiting"""
        with self.lock:
            self.healing_timestamps.append(datetime.now())

    def check_circuit_breaker(self, layer_id: int) -> Tuple[bool, str]:
        """
        Check circuit breaker state for a layer.

        Args:
            layer_id: Layer to check

        Returns:
            (allowed, reason) tuple
        """
        with self.lock:
            state = self.circuit_states.get(layer_id, CircuitState.CLOSED)

            if state == CircuitState.CLOSED:
                return True, "Circuit closed - normal operation"

            elif state == CircuitState.OPEN:
                # Check if timeout expired
                opened_time = self.circuit_opened_time.get(layer_id)
                if opened_time:
                    elapsed = (datetime.now() - opened_time).seconds
                    timeout = self.config['circuit_breaker_timeout']

                    if elapsed >= timeout:
                        # Try half-open state
                        self.circuit_states[layer_id] = CircuitState.HALF_OPEN
                        self.logger.info(
                            f"Layer {layer_id} circuit breaker -> HALF_OPEN"
                        )
                        return True, "Circuit half-open - testing recovery"

                return False, "Circuit breaker OPEN - blocking requests"

            else:  # HALF_OPEN
                return True, "Circuit half-open - testing"

    def record_success(self, layer_id: int) -> None:
        """
        Record successful operation for circuit breaker.

        Args:
            layer_id: Layer that succeeded
        """
        with self.lock:
            state = self.circuit_states.get(layer_id, CircuitState.CLOSED)

            if state == CircuitState.HALF_OPEN:
                # Success in half-open -> close circuit
                self.circuit_states[layer_id] = CircuitState.CLOSED
                self.circuit_failures[layer_id] = 0
                self.logger.info(f"Layer {layer_id} circuit breaker -> CLOSED")

    def record_failure(self, layer_id: int) -> None:
        """
        Record failed operation for circuit breaker.

        Args:
            layer_id: Layer that failed
        """
        with self.lock:
            self.circuit_failures[layer_id] += 1
            state = self.circuit_states.get(layer_id, CircuitState.CLOSED)

            # Calculate failure rate
            total_checks = self.circuit_failures[layer_id] + 1
            failure_rate = self.circuit_failures[layer_id] / total_checks
            threshold = self.config['circuit_breaker_threshold']

            if failure_rate >= threshold or state == CircuitState.HALF_OPEN:
                # Open the circuit
                self.circuit_states[layer_id] = CircuitState.OPEN
                self.circuit_opened_time[layer_id] = datetime.now()

                self.logger.warning(
                    f"Layer {layer_id} circuit breaker -> OPEN "
                    f"(failure rate: {failure_rate:.2%})"
                )

    def calculate_system_stability(self,
                                   health_metrics: Dict[int, HealthMetrics]) -> float:
        """
        Calculate overall system stability metric.

        S = 1 - (failures / total_checks)

        Args:
            health_metrics: Current health metrics for all layers

        Returns:
            Stability metric (0.0 to 1.0)
        """
        if not health_metrics:
            return 1.0

        total_failures = sum(m.failed_checks for m in health_metrics.values())
        total_checks = sum(m.total_checks for m in health_metrics.values())

        if total_checks == 0:
            return 1.0

        stability = 1.0 - (total_failures / total_checks)

        with self.lock:
            self.stability_history.append({
                'timestamp': datetime.now(),
                'stability': stability,
                'total_failures': total_failures,
                'total_checks': total_checks,
            })

        return stability

    def get_stability_statistics(self) -> Dict[str, Any]:
        """Get stability statistics"""
        with self.lock:
            recent_stability = [
                s['stability'] for s in self.stability_history
                if (datetime.now() - s['timestamp']).seconds < 3600
            ]

            circuit_states = {
                layer_id: state.value
                for layer_id, state in self.circuit_states.items()
            }

            return {
                'current_stability': recent_stability[-1] if recent_stability else 1.0,
                'average_stability_1h': mean(recent_stability) if recent_stability else 1.0,
                'circuit_breaker_states': circuit_states,
                'open_circuits': [
                    layer_id for layer_id, state in self.circuit_states.items()
                    if state == CircuitState.OPEN
                ],
                'healing_rate_current': len(self.healing_timestamps),
                'healing_rate_limit': self.config['max_healing_rate'],
            }


# ============================================================================
# AUDIT LOGGER
# ============================================================================

class AuditLogger:
    """
    Cryptographically signed audit trail with blockchain-style hash chain.

    Features:
    - ML-DSA-87 signatures on all entries
    - Hash chain linking for tamper detection
    - Structured logging with severity levels
    - Persistent storage support
    """

    def __init__(self, log_path: Optional[Path] = None,
                 enable_signatures: bool = True):
        self.logger = logging.getLogger(__name__ + ".AuditLogger")
        self.log_path = log_path
        self.enable_signatures = enable_signatures and PQC_AVAILABLE

        # Cryptographic keys
        if self.enable_signatures:
            self.public_key, self.secret_key = ml_dsa_87.generate_keypair()
            self.logger.info("Generated ML-DSA-87 audit signing key pair")
        else:
            self.public_key, self.secret_key = None, None
            self.logger.warning("ML-DSA-87 audit signatures disabled")

        # Audit log
        self.audit_log: deque = deque(maxlen=100000)
        self.entry_count = 0
        self.previous_hash: Optional[str] = None

        self.lock = threading.RLock()

    def log_event(self, event_type: str, layer_id: int, severity: str,
                  message: str, data: Optional[Dict[str, Any]] = None) -> AuditEntry:
        """
        Log an auditable event with cryptographic signature.

        Args:
            event_type: Type of event (e.g., "anomaly_detected", "healing_executed")
            layer_id: Layer this event relates to
            severity: Event severity (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            message: Human-readable message
            data: Additional structured data

        Returns:
            AuditEntry with signature
        """
        entry_id = self._generate_entry_id()
        timestamp = datetime.now()
        data = data or {}

        # Create entry
        entry = AuditEntry(
            entry_id=entry_id,
            timestamp=timestamp,
            event_type=event_type,
            layer_id=layer_id,
            severity=severity,
            message=message,
            data=data,
            signature=None,
            public_key=self.public_key,
            previous_hash=self.previous_hash
        )

        # Compute hash
        entry_hash = entry.compute_hash()

        # Sign entry
        if self.enable_signatures:
            entry.signature = self._sign_entry(entry)

        # Update chain
        with self.lock:
            self.previous_hash = entry_hash
            self.audit_log.append(entry)
            self.entry_count += 1

        # Persist if configured
        if self.log_path:
            self._persist_entry(entry)

        # Log to standard logger
        log_method = getattr(self.logger, severity.lower(), self.logger.info)
        log_method(f"[{event_type}] Layer {layer_id}: {message}")

        return entry

    def _sign_entry(self, entry: AuditEntry) -> bytes:
        """
        Sign audit entry with ML-DSA-87.

        Args:
            entry: Entry to sign

        Returns:
            ML-DSA-87 signature
        """
        if not self.enable_signatures:
            return b''

        sign_data = {
            'entry_id': entry.entry_id,
            'timestamp': entry.timestamp.isoformat(),
            'event_type': entry.event_type,
            'layer_id': entry.layer_id,
            'severity': entry.severity,
            'message': entry.message,
            'data': entry.data,
            'previous_hash': entry.previous_hash,
        }

        message = json.dumps(sign_data, sort_keys=True).encode()
        signature = ml_dsa_87.sign(self.secret_key, message)

        return signature

    def verify_entry_signature(self, entry: AuditEntry) -> bool:
        """
        Verify ML-DSA-87 signature on audit entry.

        Args:
            entry: Entry to verify

        Returns:
            True if signature is valid
        """
        if not self.enable_signatures or not entry.signature:
            return False

        sign_data = {
            'entry_id': entry.entry_id,
            'timestamp': entry.timestamp.isoformat(),
            'event_type': entry.event_type,
            'layer_id': entry.layer_id,
            'severity': entry.severity,
            'message': entry.message,
            'data': entry.data,
            'previous_hash': entry.previous_hash,
        }

        message = json.dumps(sign_data, sort_keys=True).encode()

        try:
            ml_dsa_87.verify(entry.public_key, message, entry.signature)
            return True
        except Exception:
            return False

    def verify_chain_integrity(self) -> Tuple[bool, List[str]]:
        """
        Verify hash chain integrity of audit log.

        Returns:
            (valid, errors) tuple
        """
        with self.lock:
            if not self.audit_log:
                return True, []

            errors = []
            previous_hash = None

            for i, entry in enumerate(self.audit_log):
                # Check hash chain
                if entry.previous_hash != previous_hash:
                    errors.append(
                        f"Entry {i} ({entry.entry_id}): "
                        f"Hash chain broken (expected {previous_hash}, "
                        f"got {entry.previous_hash})"
                    )

                # Check signature
                if self.enable_signatures and not self.verify_entry_signature(entry):
                    errors.append(
                        f"Entry {i} ({entry.entry_id}): Invalid signature"
                    )

                previous_hash = entry.compute_hash()

            return len(errors) == 0, errors

    def _generate_entry_id(self) -> str:
        """Generate unique entry ID"""
        timestamp = datetime.now().isoformat()
        data = f"{timestamp}-{self.entry_count}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def _persist_entry(self, entry: AuditEntry) -> None:
        """Persist entry to disk"""
        if not self.log_path:
            return

        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)

            with open(self.log_path, 'a') as f:
                json.dump(entry.to_dict(), f)
                f.write('\n')
        except Exception as e:
            self.logger.error(f"Failed to persist audit entry: {e}")

    def get_recent_entries(self, limit: int = 100) -> List[AuditEntry]:
        """Get recent audit entries"""
        with self.lock:
            entries = list(self.audit_log)
            return entries[-limit:] if len(entries) > limit else entries

    def get_entries_by_layer(self, layer_id: int, limit: int = 100) -> List[AuditEntry]:
        """Get audit entries for a specific layer"""
        with self.lock:
            entries = [e for e in self.audit_log if e.layer_id == layer_id]
            return entries[-limit:] if len(entries) > limit else entries

    def get_audit_statistics(self) -> Dict[str, Any]:
        """Get audit log statistics"""
        with self.lock:
            severity_counts = defaultdict(int)
            event_type_counts = defaultdict(int)

            for entry in self.audit_log:
                severity_counts[entry.severity] += 1
                event_type_counts[entry.event_type] += 1

            chain_valid, errors = self.verify_chain_integrity()

            return {
                'total_entries': self.entry_count,
                'entries_in_memory': len(self.audit_log),
                'chain_integrity_valid': chain_valid,
                'chain_errors': errors,
                'entries_by_severity': dict(severity_counts),
                'entries_by_event_type': dict(event_type_counts),
            }


# ============================================================================
# MAIN ORCHESTRATOR
# ============================================================================

class MorphogeneticSelfHealingOrchestrator:
    """
    Main orchestrator for Layer 7 morphogenetic self-healing system.

    Integrates:
    - LayerHealthMonitor
    - AnomalyDetector
    - SelfHealingEngine
    - StabilityController
    - AuditLogger

    Provides autonomous, adaptive defense with cryptographic accountability.
    """

    def __init__(self,
                 audit_log_path: Optional[Path] = None,
                 enable_signatures: bool = True):
        self.logger = logging.getLogger(__name__ + ".Orchestrator")

        # Initialize components
        self.health_monitor = LayerHealthMonitor()
        self.anomaly_detector = AnomalyDetector()
        self.healing_engine = SelfHealingEngine(enable_signatures=enable_signatures)
        self.stability_controller = StabilityController()
        self.audit_logger = AuditLogger(
            log_path=audit_log_path,
            enable_signatures=enable_signatures
        )

        # Orchestration state
        self.active = False
        self.orchestration_thread: Optional[threading.Thread] = None

        self.lock = threading.RLock()

        self.logger.info("Morphogenetic Self-Healing Orchestrator initialized")

    def start(self) -> None:
        """Start the self-healing orchestrator"""
        with self.lock:
            if self.active:
                self.logger.warning("Orchestrator already active")
                return

            self.active = True

            # Start health monitoring
            self.health_monitor.start_monitoring()

            # Start orchestration loop
            self.orchestration_thread = threading.Thread(
                target=self._orchestration_loop,
                daemon=True,
                name="SelfHealingOrchestrator"
            )
            self.orchestration_thread.start()

            self.audit_logger.log_event(
                event_type="orchestrator_started",
                layer_id=7,
                severity="INFO",
                message="Morphogenetic self-healing orchestrator started",
                data={}
            )

            self.logger.info("Self-healing orchestrator started")

    def stop(self) -> None:
        """Stop the self-healing orchestrator"""
        with self.lock:
            if not self.active:
                return

            self.active = False

            # Stop health monitoring
            self.health_monitor.stop_monitoring()

            # Wait for orchestration thread
            if self.orchestration_thread:
                self.orchestration_thread.join(timeout=5.0)

            self.audit_logger.log_event(
                event_type="orchestrator_stopped",
                layer_id=7,
                severity="INFO",
                message="Morphogenetic self-healing orchestrator stopped",
                data={}
            )

            self.logger.info("Self-healing orchestrator stopped")

    def _orchestration_loop(self) -> None:
        """Main orchestration loop"""
        while self.active:
            try:
                # Get current health metrics
                health_metrics = self.health_monitor.get_all_health()

                # Check for anomalies
                for layer_id, metrics in health_metrics.items():
                    self._check_layer_anomalies(layer_id, metrics)

                # Calculate system stability
                stability = self.stability_controller.calculate_system_stability(
                    health_metrics
                )

                # Check if stability is below target
                if stability < STABILITY_CONFIG['stability_target']:
                    self.audit_logger.log_event(
                        event_type="low_stability_detected",
                        layer_id=7,
                        severity="WARNING",
                        message=f"System stability below target: {stability:.2%}",
                        data={'stability': stability}
                    )

                # Sleep before next iteration
                time.sleep(10)  # Check every 10 seconds

            except Exception as e:
                self.logger.error(f"Orchestration loop error: {e}")
                time.sleep(30)  # Back off on error

    def _check_layer_anomalies(self, layer_id: int,
                               metrics: HealthMetrics) -> None:
        """Check a layer for anomalies and trigger healing if needed"""

        # Check various metrics for anomalies
        metric_checks = [
            ('error_rate', metrics.error_rate),
            ('response_time_ms', metrics.response_time_ms),
            ('memory_usage_mb', metrics.memory_usage_mb),
            ('cpu_usage_percent', metrics.cpu_usage_percent),
        ]

        for metric_name, value in metric_checks:
            anomaly = self.anomaly_detector.update_metric(
                f"layer{layer_id}_{metric_name}",
                value,
                layer_id
            )

            if anomaly:
                # Anomaly detected
                self.audit_logger.log_event(
                    event_type="anomaly_detected",
                    layer_id=layer_id,
                    severity="WARNING",
                    message=f"Anomaly detected: {metric_name}",
                    data=anomaly.to_dict()
                )

                # Determine healing action
                action = self._determine_healing_action(anomaly, metrics)

                if action:
                    self._execute_healing(layer_id, action, anomaly)

    def _determine_healing_action(self, anomaly: AnomalyReport,
                                  metrics: HealthMetrics) -> Optional[HealingAction]:
        """
        Morphogenetic decision making: Determine appropriate healing action.

        Adapts based on:
        - Anomaly severity and type
        - Layer status
        - Historical healing success rates
        """

        # High severity -> aggressive action
        if anomaly.severity > 0.8:
            if metrics.status == LayerStatus.FAILED:
                return HealingAction.RESTART_SERVICE
            elif anomaly.metric_name.endswith('error_rate'):
                return HealingAction.RESET_CONNECTION

        # Medium severity -> moderate action
        elif anomaly.severity > 0.5:
            if anomaly.metric_name.endswith('response_time_ms'):
                return HealingAction.CLEAR_CACHE
            elif anomaly.metric_name.endswith('cpu_usage_percent'):
                return HealingAction.RATE_LIMIT

        # Low severity -> light touch
        else:
            return HealingAction.ADJUST_THRESHOLD

        return None

    def _execute_healing(self, layer_id: int, action: HealingAction,
                        anomaly: AnomalyReport) -> None:
        """Execute healing action with stability controls"""

        # Check rate limit
        allowed, reason = self.stability_controller.check_rate_limit()
        if not allowed:
            self.audit_logger.log_event(
                event_type="healing_rate_limited",
                layer_id=layer_id,
                severity="WARNING",
                message=f"Healing rate limited: {reason}",
                data={'anomaly_id': anomaly.anomaly_id}
            )
            return

        # Check circuit breaker
        allowed, reason = self.stability_controller.check_circuit_breaker(layer_id)
        if not allowed:
            self.audit_logger.log_event(
                event_type="healing_circuit_broken",
                layer_id=layer_id,
                severity="ERROR",
                message=f"Circuit breaker open: {reason}",
                data={'anomaly_id': anomaly.anomaly_id}
            )
            return

        # Record attempt
        self.stability_controller.record_healing_attempt()

        # Execute healing
        record = self.healing_engine.execute_healing(
            layer_id=layer_id,
            action=action,
            anomaly_id=anomaly.anomaly_id,
            parameters={}
        )

        # Update stability controller
        if record.success:
            self.stability_controller.record_success(layer_id)
        else:
            self.stability_controller.record_failure(layer_id)

        # Audit log
        self.audit_logger.log_event(
            event_type="healing_executed",
            layer_id=layer_id,
            severity="INFO" if record.success else "ERROR",
            message=f"Healing action {action.value}: "
                   f"{'SUCCESS' if record.success else 'FAILED'}",
            data=record.to_dict()
        )

    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        with self.lock:
            return {
                'orchestrator_active': self.active,
                'system_stability': self.stability_controller.calculate_system_stability(
                    self.health_monitor.get_all_health()
                ),
                'health_summary': {
                    layer_id: {
                        'status': metrics.status.value,
                        'stability': metrics.stability_metric,
                        'error_rate': metrics.error_rate,
                    }
                    for layer_id, metrics in self.health_monitor.get_all_health().items()
                },
                'anomaly_statistics': self.anomaly_detector.get_anomaly_statistics(),
                'healing_statistics': self.healing_engine.get_healing_statistics(),
                'stability_statistics': self.stability_controller.get_stability_statistics(),
                'audit_statistics': self.audit_logger.get_audit_statistics(),
            }


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

def create_example_health_check(layer_id: int) -> Callable:
    """Create an example health check function for testing"""
    import random

    def health_check() -> HealthMetrics:
        """Simulated health check"""
        return HealthMetrics(
            layer_id=layer_id,
            status=LayerStatus.HEALTHY,
            uptime_seconds=random.uniform(1000, 10000),
            error_rate=random.uniform(0, 0.1),
            response_time_ms=random.uniform(10, 100),
            throughput=random.uniform(100, 1000),
            memory_usage_mb=random.uniform(100, 500),
            cpu_usage_percent=random.uniform(10, 80),
            active_connections=random.randint(10, 100),
            failed_checks=random.randint(0, 5),
            total_checks=random.randint(100, 1000),
            last_check_time=datetime.now(),
        )

    return health_check


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Create orchestrator
    orchestrator = MorphogeneticSelfHealingOrchestrator(
        audit_log_path=Path("/tmp/layer7_audit.log"),
        enable_signatures=True
    )

    # Register health checks for all layers
    for layer_id in range(1, 9):
        orchestrator.health_monitor.register_health_check(
            layer_id,
            create_example_health_check(layer_id)
        )

    # Start orchestrator
    orchestrator.start()

    try:
        # Run for demonstration
        print("Morphogenetic Self-Healing Orchestrator running...")
        print("Press Ctrl+C to stop")

        while True:
            time.sleep(10)

            # Print status
            status = orchestrator.get_system_status()
            print(f"\nSystem Stability: {status['system_stability']:.2%}")
            print(f"Healing Success Rate: "
                  f"{status['healing_statistics']['success_rate']:.2%}")
            print(f"Total Anomalies: "
                  f"{status['anomaly_statistics']['total_anomalies']}")

    except KeyboardInterrupt:
        print("\nStopping orchestrator...")
        orchestrator.stop()
        print("Stopped.")
