"""In-memory server-side state: the firmware registry, the vehicle fleet
registry, and the event log the dashboard reads from.
"""
import threading
import time
from collections import deque
from dataclasses import dataclass, field


@dataclass
class FirmwarePackage:
    version: str
    model_scope: str
    bytes_: bytes
    sha256: str
    signature_b64: str
    is_buggy: bool = False
    published_at: float = field(default_factory=time.time)


@dataclass
class Vehicle:
    vin: str
    model: str
    region: str
    current_version: str
    registered: bool = True


class OtaStore:
    def __init__(self):
        self._lock = threading.Lock()
        self.firmware: dict[str, FirmwarePackage] = {}
        self.campaigns: dict[str, dict] = {}  # model_scope -> {version, regions}
        self.vehicles: dict[str, Vehicle] = {}
        self.events: deque = deque(maxlen=500)

    def lock(self):
        return self._lock

    def add_vehicle(self, vin, model, region, current_version):
        # Idempotent: registration models a vehicle "checking in as
        # existing" as much as first enrollment, so it must never reset a
        # vehicle's real progress back to its initial factory version.
        if vin not in self.vehicles:
            self.vehicles[vin] = Vehicle(vin, model, region, current_version)

    def publish_firmware(self, pkg: FirmwarePackage, target_regions):
        self.firmware[pkg.version] = pkg
        self.campaigns[pkg.model_scope] = {
            "version": pkg.version,
            "regions": target_regions,
            "published_at": pkg.published_at,
        }

    def active_campaign_for(self, vehicle: Vehicle):
        campaign = self.campaigns.get(vehicle.model)
        if not campaign:
            return None
        if campaign["regions"] and vehicle.region not in campaign["regions"]:
            return None
        return campaign

    def log_event(self, vin: str, event_type: str, version: str, reason: str = ""):
        self.events.append({
            "ts": time.time(), "vin": vin, "event": event_type,
            "version": version, "reason": reason,
        })

    def recent_events(self, n=25):
        return list(self.events)[-n:][::-1]

    def totals(self):
        events = list(self.events)
        return {
            "total_vehicles": len(self.vehicles),
            "installs": sum(1 for e in events if e["event"] == "installed"),
            "rollbacks": sum(1 for e in events if e["event"] == "rolled_back"),
            "rejected": sum(1 for e in events if e["event"] == "rejected"),
            "firmware_versions": len(self.firmware),
        }

    def version_distribution(self):
        dist: dict[str, int] = {}
        for v in self.vehicles.values():
            dist[v.current_version] = dist.get(v.current_version, 0) + 1
        return dist

    def rejected_by_reason(self):
        counts: dict[str, int] = {}
        for e in self.events:
            if e["event"] == "rejected":
                counts[e["reason"]] = counts.get(e["reason"], 0) + 1
        return counts
