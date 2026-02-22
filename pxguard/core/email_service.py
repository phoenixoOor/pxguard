"""
PXGuard - SMTP email transport service.

Handles SMTP connection, health check, and sending of pre-built MIME messages.
No template rendering, no report logic — pure transport layer.
Credentials from config dict (loaded from env vars by config_loader).
"""

import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class SMTPConfig:
    """Validated SMTP connection parameters."""

    __slots__ = ("host", "port", "user", "password", "email_to")

    def __init__(
        self,
        *,
        host: str,
        port: int,
        user: str,
        password: str,
        email_to: str,
    ) -> None:
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.email_to = email_to

    @property
    def is_complete(self) -> bool:
        return bool(self.host and self.user and self.password and self.email_to)


class EmailService:
    """
    SMTP transport layer.
    - verify(): health check (connect + TLS + login)
    - send(): transmit a pre-assembled MIMEMultipart message
    - build_message(): assemble MIME structure from parts
    """

    def __init__(self, smtp_config: SMTPConfig) -> None:
        self._cfg = smtp_config

    @property
    def is_configured(self) -> bool:
        return self._cfg.is_complete

    def verify(self) -> None:
        """
        SMTP health check: connect → STARTTLS → login.
        Raises RuntimeError on any failure.
        """
        if not self.is_configured:
            raise RuntimeError(
                "SMTP not fully configured. Required env vars: "
                "PXGUARD_SMTP_HOST, PXGUARD_SMTP_PORT, PXGUARD_SMTP_USER, PXGUARD_SMTP_PASSWORD"
            )
        try:
            with smtplib.SMTP(self._cfg.host, self._cfg.port, timeout=15) as server:
                server.starttls()
                logger.info("[SMTP] Connected to %s:%d", self._cfg.host, self._cfg.port)
                server.login(self._cfg.user, self._cfg.password)
                logger.info("[SMTP] Authenticated as %s", self._cfg.user)
        except smtplib.SMTPAuthenticationError as e:
            raise RuntimeError(f"SMTP authentication failed: {e}") from e
        except smtplib.SMTPException as e:
            raise RuntimeError(f"SMTP connection error: {e}") from e
        except Exception as e:
            raise RuntimeError(f"SMTP health check failed: {e}") from e

    def build_message(
        self,
        *,
        subject: str,
        plain_text: str,
        html_body: str,
        graph_path: Optional[Path] = None,
        graph_cid: str = "pxguard_graph",
        report_path: Optional[Path] = None,
    ) -> MIMEMultipart:
        """
        Assemble a multipart/mixed message:
          mixed
            ├── alternative
            │     ├── text/plain
            │     └── related
            │           ├── text/html
            │           └── image/png (inline, Content-ID)
            └── text/plain attachment (report .txt)
        """
        root = MIMEMultipart("mixed")
        root["Subject"] = subject
        root["From"] = self._cfg.user
        root["To"] = self._cfg.email_to

        alt = MIMEMultipart("alternative")
        alt.attach(MIMEText(plain_text, "plain", "utf-8"))

        related = MIMEMultipart("related")
        related.attach(MIMEText(html_body, "html", "utf-8"))

        if graph_path and Path(graph_path).is_file():
            try:
                img_data = Path(graph_path).read_bytes()
                img = MIMEImage(img_data, _subtype="png")
                img.add_header("Content-ID", f"<{graph_cid}>")
                img.add_header("Content-Disposition", "inline", filename=Path(graph_path).name)
                related.attach(img)
            except OSError as e:
                logger.warning("[EMAIL] Could not embed graph %s: %s", graph_path, e)

        alt.attach(related)
        root.attach(alt)

        if report_path and Path(report_path).is_file():
            try:
                data = Path(report_path).read_bytes()
                part = MIMEBase("text", "plain")
                part.set_payload(data)
                encoders.encode_base64(part)
                part.add_header("Content-Disposition", "attachment", filename=Path(report_path).name)
                root.attach(part)
            except OSError as e:
                logger.warning("[EMAIL] Could not attach report %s: %s", report_path, e)

        logger.debug("[EMAIL] Message built: subject=%r, to=%s", subject, self._cfg.email_to)
        return root

    def send(self, message: MIMEMultipart) -> bool:
        """
        Send a pre-built MIME message via SMTP/TLS.
        Returns True on success, False on failure (logged, never crashes).
        """
        try:
            with smtplib.SMTP(self._cfg.host, self._cfg.port, timeout=30) as server:
                server.starttls()
                server.login(self._cfg.user, self._cfg.password)
                server.sendmail(self._cfg.user, self._cfg.email_to, message.as_string())
            logger.info("[EMAIL] Alert email sent successfully to %s", self._cfg.email_to)
            return True
        except smtplib.SMTPException as e:
            logger.warning("[EMAIL] SMTP error: %s", e)
            return False
        except Exception as e:
            logger.warning("[EMAIL] Failed to send: %s", e, exc_info=True)
            return False
