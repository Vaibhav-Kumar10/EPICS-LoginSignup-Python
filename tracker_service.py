"""
ESP32 AirTag Tracker Service

Background service that periodically polls Apple's Find My network
to get the latest location of all registered ESP32 trackers.

Uses Option B: A single server Apple ID session for all trackers.
"""

import os
import logging
from pathlib import Path
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from findmy import KeyPair
from findmy import AppleAccount, LocalAnisetteProvider

from database import SessionLocal
from models import Tracker

logger = logging.getLogger(__name__)

# Paths relative to this file's directory
BASE_DIR = Path(__file__).parent.resolve()
TRACKER_KEYS_DIR = BASE_DIR / "tracker_keys"
APPLE_SESSION_PATH = TRACKER_KEYS_DIR / "apple_account.json"
ANISETTE_LIBS_PATH = TRACKER_KEYS_DIR / "anisette_libs.bin"


def _load_apple_account():
    """Load the saved Apple ID session from disk."""
    if not APPLE_SESSION_PATH.exists():
        logger.error(f"Apple session not found at {APPLE_SESSION_PATH}")
        logger.error("Run fetch_location.py interactively first to create a session.")
        return None

    try:
        account = AppleAccount.from_json(
            str(APPLE_SESSION_PATH),
            anisette_libs_path=(
                str(ANISETTE_LIBS_PATH) if ANISETTE_LIBS_PATH.exists() else None
            ),
        )
        logger.info(f"Apple session loaded: {account.account_name}")
        return account
    except Exception as e:
        logger.error(f"Failed to load Apple session: {e}")
        return None


def _load_private_key(key_path: str) -> bytes:
    """Load and extract raw 28-byte private key from PEM file."""
    full_path = Path(key_path)
    if not full_path.is_absolute():
        full_path = TRACKER_KEYS_DIR / key_path

    if not full_path.exists():
        raise FileNotFoundError(f"Private key not found: {full_path}")

    pem_data = full_path.read_text()
    private_key = serialization.load_pem_private_key(
        pem_data.encode(), password=None, backend=default_backend()
    )
    return private_key.private_numbers().private_value.to_bytes(28, "big")


def poll_tracker_locations():
    """
    Main polling function — called periodically by APScheduler.

    For each active Tracker in the database:
    1. Loads its private key
    2. Queries Apple's Find My servers
    3. Updates the tracker's last known location in the DB
    """
    logger.info("=" * 50)
    logger.info("Tracker Poll: Starting location fetch cycle...")

    account = _load_apple_account()
    if account is None:
        logger.warning("Tracker Poll: Skipping — no Apple session available")
        return

    db = SessionLocal()
    try:
        trackers = db.query(Tracker).filter(Tracker.is_active == True).all()

        if not trackers:
            logger.info("Tracker Poll: No active trackers found in database")
            return

        logger.info(f"Tracker Poll: Fetching locations for {len(trackers)} tracker(s)")

        for tracker in trackers:
            try:
                raw_key = _load_private_key(tracker.private_key_path)
                key = KeyPair(raw_key)
                logger.info(
                    f"  Tracker '{tracker.device_name}' (user_id={tracker.user_id}): fetching..."
                )

                location = account.fetch_location(key)

                if location is not None:
                    tracker.last_latitude = str(location.latitude)
                    tracker.last_longitude = str(location.longitude)
                    tracker.last_seen = datetime.now(timezone.utc)
                    db.commit()
                    logger.info(
                        f"    ✓ Location: {location.latitude}, {location.longitude} "
                        f"(timestamp: {location.timestamp})"
                    )
                else:
                    logger.info(
                        f"    — No location reports yet (ESP32 may not be detected)"
                    )

            except FileNotFoundError as e:
                logger.error(f"    ✗ Key file missing for tracker {tracker.id}: {e}")
            except Exception as e:
                logger.error(
                    f"    ✗ Failed to fetch location for tracker {tracker.id}: {e}"
                )

        # Save the Apple session back (tokens may have been refreshed)
        try:
            account.to_json(str(APPLE_SESSION_PATH))
        except Exception as e:
            logger.warning(f"Failed to save Apple session: {e}")

    finally:
        db.close()

    logger.info("Tracker Poll: Cycle complete")
    logger.info("=" * 50)


def get_tracker_location(user_id: int):
    """
    Get the last known tracker location for a specific user.
    Returns dict with lat/lng/last_seen or None.
    """
    db = SessionLocal()
    try:
        tracker = (
            db.query(Tracker)
            .filter(Tracker.user_id == user_id, Tracker.is_active == True)
            .first()
        )
        if not tracker or not tracker.last_latitude:
            return None

        return {
            "device_name": tracker.device_name,
            "latitude": float(tracker.last_latitude),
            "longitude": float(tracker.last_longitude),
            "last_seen": tracker.last_seen.isoformat() if tracker.last_seen else None,
            "google_maps_link": f"https://www.google.com/maps?q={tracker.last_latitude},{tracker.last_longitude}",
        }
    finally:
        db.close()
