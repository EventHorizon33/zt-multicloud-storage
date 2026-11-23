"""Behaviour detection (ARCHITECTURE R4): bulk-download and credential-stuffing
signals. Detection never blocks by itself: it records a ``DownloadBlock`` and
sets ``RequestContext.download_blocked``; the PDP makes the decision."""
from app.detection.detector import (AUTH_ANOMALY_EVENT, BULK_DOWNLOAD_EVENT, AuthFailureDetector,
                                    DownloadDetector, DownloadSignals)

__all__ = ["AUTH_ANOMALY_EVENT", "BULK_DOWNLOAD_EVENT", "AuthFailureDetector", "DownloadDetector",
           "DownloadSignals"]
