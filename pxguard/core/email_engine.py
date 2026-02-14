"""
PXGuard - Email alert system on anomaly.

Sends email with subject [PXGuard ALERT] Critical File Activity Detected,
attaches PNG graph and report .txt, inline summary. Uses smtplib + EmailMessage, TLS.
Config via environment variables. Handles failures gracefully.
"""

import logging
import os
import smtplib
from email.message import EmailMessage
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)

# Environment variable names (no secrets in code)
ENV_SMTP_HOST = "PXGUARD_SMTP_HOST"
ENV_SMTP_PORT = "PXGUARD_SMTP_PORT"
ENV_SMTP_USER = "PXGUARD_SMTP_USER"
ENV_SMTP_PASSWORD = "PXGUARD_SMTP_PASSWORD"
ENV_ALERT_TO = "PXGUARD_ALERT_TO"
ENV_ALERT_FROM = "PXGUARD_ALERT_FROM"

DEFAULT_PORT = 587


def send_alert_email(
    *,
    subject: str = "[PXGuard ALERT] Critical File Activity Detected",
    body_text: str,
    attachment_paths: Optional[List[Path]] = None,
) -> bool:
    """
    Send email via SMTP (TLS). Uses env: PXGUARD_SMTP_HOST, PXGUARD_SMTP_PORT,
    PXGUARD_SMTP_USER, PXGUARD_SMTP_PASSWORD, PXGUARD_ALERT_TO, PXGUARD_ALERT_FROM.
    Attaches given files (e.g. PNG graph, report .txt). Returns True on success.
    """
    host = os.environ.get(ENV_SMTP_HOST)
    to_addr = os.environ.get(ENV_ALERT_TO)
    if not host or not to_addr:
        logger.debug("Email not sent: missing %s or %s", ENV_SMTP_HOST, ENV_ALERT_TO)
        return False
    port = int(os.environ.get(ENV_SMTP_PORT, str(DEFAULT_PORT)))
    user = os.environ.get(ENV_SMTP_USER)
    password = os.environ.get(ENV_SMTP_PASSWORD)
    from_addr = os.environ.get(ENV_ALERT_FROM) or user or to_addr

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg.set_content(body_text)

    attachment_paths = attachment_paths or []
    for path in attachment_paths:
        path = Path(path)
        if not path.is_file():
            logger.warning("Attachment not found: %s", path)
            continue
        try:
            data = path.read_bytes()
            msg.add_attachment(data, filename=path.name)
        except OSError as e:
            logger.warning("Could not read attachment %s: %s", path, e)

    try:
        with smtplib.SMTP(host, port) as server:
            server.starttls()
            if user and password:
                server.login(user, password)
            server.send_message(msg)
        logger.info("Alert email sent to %s", to_addr)
        return True
    except smtplib.SMTPException as e:
        logger.warning("SMTP error sending alert: %s", e)
        return False
    except Exception as e:
        logger.warning("Failed to send alert email: %s", e, exc_info=True)
        return False
