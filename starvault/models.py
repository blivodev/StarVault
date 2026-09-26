"""Domain models for StarVault entries (Server, Service, Keypair)."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
import uuid

from starvault.crypto import decrypt_field, encrypt_field


def utc_now_iso() -> str:
    """Returns current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


@dataclass
class VaultEntry:
    """Base class for all vault entries."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    entry_type: str = "server"  # 'server', 'service', 'keypair'
    title: str = ""
    category: str = "General"
    groups: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    is_favorite: bool = False
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)

    # Relational Parent/Child hierarchy
    parent_server_id: Optional[str] = None
    parent_domain_id: Optional[str] = None

    # Arbitrary Custom Key-Value fields [{"key": "License", "value": "XYZ"}]
    custom_fields: List[Dict[str, str]] = field(default_factory=list)

    # Infrastructure / Server fields
    hostname: str = ""
    port: int = 22
    username: str = ""
    password: str = ""  # encrypted
    ssh_key_id: Optional[str] = None
    ssh_private_key: str = ""  # encrypted
    ssh_public_key: str = ""
    sudo_password: str = ""  # encrypted
    os_distro: str = ""

    # Service / App fields
    app_name: str = ""
    url: str = ""
    api_token: str = ""  # encrypted
    db_name: str = ""
    service_type: str = "generic"  # 'database', 'web', 'docker', 'api', etc.

    # Keypair fields
    key_name: str = ""
    key_type: str = "ed25519"  # 'ed25519', 'rsa4096', 'gpg'
    fingerprint: str = ""
    public_key: str = ""
    private_key: str = ""  # encrypted
    passphrase: str = ""  # encrypted

    # API Key fields
    provider: str = ""
    api_key_format: str = "bearer"
    api_key_secret: str = ""  # encrypted
    environment: str = "Production"  # 'Production', 'Staging', 'Development', 'Test'
    expires_at: str = ""  # 'YYYY-MM-DD'
    scopes: str = ""

    # TOTP / MFA secret (encrypted, RFC 6238 Base32)
    totp_secret: str = ""  # encrypted

    # Domain / DNS fields
    domain_name: str = ""
    registrar: str = ""
    auto_renew: bool = False
    registered_at: str = ""  # purchase / registration date (YYYY-MM-DD)
    renewal_cost: str = ""  # e.g. '$12.99 / yr'
    dns_provider: str = ""
    nameservers: str = ""
    auth_code: str = ""  # encrypted transfer/EPP code

    # Common rich content
    notes: str = ""  # encrypted

    def __post_init__(self):
        # Guarantee groups has at least category
        if not self.groups and self.category:
            self.groups = [self.category]
        elif self.groups and not self.category:
            self.category = self.groups[0]
        # Guarantee services has at least app_name if entry is a service
        if not self.services and self.app_name:
            self.services = [self.app_name]
        elif self.services and not self.app_name:
            self.app_name = self.services[0]
        # Guarantee services has domain_name if entry is a domain
        if self.entry_type == "domain":
            d_name = self.domain_name or self.title
            if d_name and not self.services:
                self.services = [d_name]

    def duplicate(self) -> "VaultEntry":
        """Creates an independent clone of this entry with '- Copy' title."""
        return VaultEntry(
            id=str(uuid.uuid4()),
            entry_type=self.entry_type,
            title=f"{self.title} - Copy" if self.title else "Untitled - Copy",
            category=self.category,
            groups=list(self.groups),
            services=list(self.services),
            tags=list(self.tags),
            is_favorite=False,
            created_at=utc_now_iso(),
            updated_at=utc_now_iso(),
            parent_server_id=self.parent_server_id,
            parent_domain_id=self.parent_domain_id,
            custom_fields=[dict(cf) for cf in self.custom_fields],
            hostname=self.hostname,
            port=self.port,
            username=self.username,
            password=self.password,
            ssh_key_id=self.ssh_key_id,
            ssh_private_key=self.ssh_private_key,
            ssh_public_key=self.ssh_public_key,
            sudo_password=self.sudo_password,
            os_distro=self.os_distro,
            app_name=self.app_name,
            url=self.url,
            api_token=self.api_token,
            db_name=self.db_name,
            service_type=self.service_type,
            key_name=self.key_name,
            key_type=self.key_type,
            fingerprint=self.fingerprint,
            public_key=self.public_key,
            private_key=self.private_key,
            passphrase=self.passphrase,
            provider=self.provider,
            api_key_format=self.api_key_format,
            api_key_secret=self.api_key_secret,
            environment=self.environment,
            expires_at=self.expires_at,
            scopes=self.scopes,
            totp_secret=self.totp_secret,
            domain_name=self.domain_name,
            registrar=self.registrar,
            auto_renew=self.auto_renew,
            registered_at=self.registered_at,
            renewal_cost=self.renewal_cost,
            dns_provider=self.dns_provider,
            nameservers=self.nameservers,
            auth_code=self.auth_code,
            notes=self.notes,
        )

    def get_groups_display(self) -> str:
        """Returns comma-separated groups string."""
        if self.groups:
            return ", ".join(self.groups)
        return self.category or "General"

    def set_groups_from_str(self, groups_str: str) -> None:
        """Parses comma-separated groups string into clean list."""
        if not groups_str:
            self.groups = []
        else:
            self.groups = [g.strip() for g in groups_str.split(",") if g.strip()]
        if self.groups:
            self.category = self.groups[0]

    def get_services_display(self) -> str:
        """Returns comma-separated services string."""
        if self.services:
            return ", ".join(self.services)
        return self.app_name or ""

    def set_services_from_str(self, services_str: str) -> None:
        """Parses comma-separated services string into clean list."""
        if not services_str:
            self.services = []
        else:
            self.services = [s.strip() for s in services_str.split(",") if s.strip()]
        if self.services and not self.app_name:
            self.app_name = self.services[0]

    def get_tags_display(self) -> str:
        """Returns comma-separated tags string."""
        return ", ".join(self.tags)

    def set_tags_from_str(self, tags_str: str) -> None:
        """Parses comma-separated string into clean tags list."""
        if not tags_str:
            self.tags = []
        else:
            self.tags = [t.strip().lower() for t in tags_str.split(",") if t.strip()]

    def to_encrypted_payload(self, key: bytes) -> str:
        """Serializes sensitive and custom fields into an encrypted JSON blob."""
        sensitive_data = {
            "password": self.password,
            "ssh_private_key": self.ssh_private_key,
            "sudo_password": self.sudo_password,
            "api_token": self.api_token,
            "private_key": self.private_key,
            "passphrase": self.passphrase,
            "notes": self.notes,
            "custom_fields": self.custom_fields,
            "parent_server_id": self.parent_server_id,
            "parent_domain_id": self.parent_domain_id,
            "groups": self.groups,
            "services": self.services,
            # Extra fields bundled inside payload
            "hostname": self.hostname,
            "port": self.port,
            "username": self.username,
            "ssh_key_id": self.ssh_key_id,
            "ssh_public_key": self.ssh_public_key,
            "os_distro": self.os_distro,
            "app_name": self.app_name,
            "url": self.url,
            "db_name": self.db_name,
            "service_type": self.service_type,
            "key_name": self.key_name,
            "key_type": self.key_type,
            "fingerprint": self.fingerprint,
            "public_key": self.public_key,
            # API Key & TOTP fields
            "provider": self.provider,
            "api_key_format": self.api_key_format,
            "api_key_secret": self.api_key_secret,
            "environment": self.environment,
            "expires_at": self.expires_at,
            "scopes": self.scopes,
            "totp_secret": self.totp_secret,
            # Domain fields
            "domain_name": self.domain_name,
            "registrar": self.registrar,
            "auto_renew": self.auto_renew,
            "registered_at": self.registered_at,
            "renewal_cost": self.renewal_cost,
            "dns_provider": self.dns_provider,
            "nameservers": self.nameservers,
            "auth_code": self.auth_code,
        }
        json_str = json.dumps(sensitive_data)
        return encrypt_field(json_str, key)

    def load_encrypted_payload(self, payload: str, key: bytes) -> None:
        """Decrypts and unpacks sensitive and detail fields."""
        if not payload:
            return
        json_str = decrypt_field(payload, key)
        data = json.loads(json_str)

        self.password = data.get("password", "")
        self.ssh_private_key = data.get("ssh_private_key", "")
        self.sudo_password = data.get("sudo_password", "")
        self.api_token = data.get("api_token", "")
        self.private_key = data.get("private_key", "")
        self.passphrase = data.get("passphrase", "")
        self.notes = data.get("notes", "")
        self.custom_fields = data.get("custom_fields", [])
        self.parent_server_id = data.get("parent_server_id", self.parent_server_id)
        self.parent_domain_id = data.get("parent_domain_id", self.parent_domain_id)

        self.hostname = data.get("hostname", self.hostname)
        self.port = data.get("port", self.port)
        self.username = data.get("username", self.username)
        self.ssh_key_id = data.get("ssh_key_id", self.ssh_key_id)
        self.ssh_public_key = data.get("ssh_public_key", self.ssh_public_key)
        self.os_distro = data.get("os_distro", self.os_distro)
        self.app_name = data.get("app_name", self.app_name)
        self.url = data.get("url", self.url)
        self.db_name = data.get("db_name", self.db_name)
        self.service_type = data.get("service_type", self.service_type)
        self.key_name = data.get("key_name", self.key_name)
        self.key_type = data.get("key_type", self.key_type)
        self.fingerprint = data.get("fingerprint", self.fingerprint)
        self.public_key = data.get("public_key", self.public_key)
        self.provider = data.get("provider", self.provider)
        self.api_key_format = data.get("api_key_format", self.api_key_format)
        self.api_key_secret = data.get("api_key_secret", self.api_key_secret)
        self.environment = data.get("environment", self.environment)
        self.expires_at = data.get("expires_at", self.expires_at)
        self.scopes = data.get("scopes", self.scopes)
        self.totp_secret = data.get("totp_secret", self.totp_secret)
        self.domain_name = data.get("domain_name", self.domain_name)
        self.registrar = data.get("registrar", self.registrar)
        self.auto_renew = bool(data.get("auto_renew", self.auto_renew))
        self.registered_at = data.get("registered_at", self.registered_at)
        self.renewal_cost = data.get("renewal_cost", self.renewal_cost)
        self.dns_provider = data.get("dns_provider", self.dns_provider)
        self.nameservers = data.get("nameservers", self.nameservers)
        self.auth_code = data.get("auth_code", self.auth_code)

        loaded_groups = data.get("groups", None)
        if loaded_groups is not None and isinstance(loaded_groups, list):
            self.groups = [g for g in loaded_groups if g]
        if not self.groups and self.category:
            self.groups = [self.category]

        loaded_services = data.get("services", None)
        if loaded_services is not None and isinstance(loaded_services, list):
            self.services = [s for s in loaded_services if s]
        if not self.services and self.app_name:
            self.services = [self.app_name]

    @classmethod
    def create_server(
        cls,
        title: str,
        hostname: str,
        username: str = "root",
        password: str = "",
        port: int = 22,
        ssh_private_key: str = "",
        ssh_public_key: str = "",
        tags: Optional[List[str]] = None,
        notes: str = "",
        os_distro: str = "",
        category: str = "Infrastructure",
        groups: Optional[List[str]] = None,
        services: Optional[List[str]] = None,
    ) -> "VaultEntry":
        return cls(
            entry_type="server",
            title=title or hostname,
            category=category,
            groups=groups or ([category] if category else []),
            services=services or [],
            tags=tags or [],
            hostname=hostname,
            port=port,
            username=username,
            password=password,
            ssh_private_key=ssh_private_key,
            ssh_public_key=ssh_public_key,
            os_distro=os_distro,
            notes=notes,
        )

    @classmethod
    def create_service(
        cls,
        title: str,
        app_name: str,
        url: str = "",
        port: int = 80,
        username: str = "",
        password: str = "",
        api_token: str = "",
        db_name: str = "",
        service_type: str = "generic",
        tags: Optional[List[str]] = None,
        notes: str = "",
        category: str = "Services",
        groups: Optional[List[str]] = None,
        services: Optional[List[str]] = None,
    ) -> "VaultEntry":
        return cls(
            entry_type="service",
            title=title or app_name,
            category=category,
            groups=groups or ([category] if category else []),
            services=services or ([app_name] if app_name else []),
            tags=tags or [],
            app_name=app_name,
            url=url,
            port=port,
            username=username,
            password=password,
            api_token=api_token,
            db_name=db_name,
            service_type=service_type,
            notes=notes,
        )

    @classmethod
    def create_keypair(
        cls,
        title: str,
        key_name: str,
        key_type: str,
        public_key: str,
        private_key: str,
        fingerprint: str = "",
        passphrase: str = "",
        tags: Optional[List[str]] = None,
        notes: str = "",
        category: str = "Keys",
        groups: Optional[List[str]] = None,
        services: Optional[List[str]] = None,
    ) -> "VaultEntry":
        return cls(
            entry_type="keypair",
            title=title or key_name,
            category=category,
            groups=groups or ([category] if category else []),
            services=services or [],
            tags=tags or [],
            key_name=key_name,
            key_type=key_type,
            public_key=public_key,
            private_key=private_key,
            fingerprint=fingerprint,
            passphrase=passphrase,
            notes=notes,
        )

    @classmethod
    def create_api_key(
        cls,
        title: str,
        api_token: str,
        provider: str = "",
        api_key_format: str = "bearer",
        api_key_secret: str = "",
        environment: str = "Production",
        expires_at: str = "",
        scopes: str = "",
        tags: Optional[List[str]] = None,
        notes: str = "",
        category: str = "API Keys",
        parent_server_id: Optional[str] = None,
        groups: Optional[List[str]] = None,
        services: Optional[List[str]] = None,
    ) -> "VaultEntry":
        return cls(
            entry_type="apikey",
            title=title or f"{provider} API Key" if provider else "API Key",
            category=category,
            groups=groups or ([category] if category else []),
            services=services or ([provider] if provider else []),
            tags=tags or [],
            api_token=api_token,
            provider=provider,
            api_key_format=api_key_format,
            api_key_secret=api_key_secret,
            environment=environment,
            expires_at=expires_at,
            scopes=scopes,
            parent_server_id=parent_server_id,
            notes=notes,
        )

    @classmethod
    def create_domain(
        cls,
        title: str,
        domain_name: str,
        url: Optional[str] = None,
        registrar: str = "",
        expires_at: str = "",
        auto_renew: bool = False,
        registered_at: str = "",
        renewal_cost: str = "",
        dns_provider: str = "",
        nameservers: str = "",
        auth_code: str = "",
        parent_server_id: Optional[str] = None,
        parent_domain_id: Optional[str] = None,
        tags: Optional[List[str]] = None,
        notes: str = "",
        category: str = "Domains",
        groups: Optional[List[str]] = None,
        services: Optional[List[str]] = None,
    ) -> "VaultEntry":
        clean_url = url or domain_name
        if clean_url and not (clean_url.startswith("http://") or clean_url.startswith("https://")):
            clean_url = f"https://{clean_url}"
        return cls(
            entry_type="domain",
            title=title or domain_name or "Untitled Domain",
            category=category,
            groups=groups or ([category] if category else []),
            services=services or ([domain_name] if domain_name else []),
            tags=tags or [],
            domain_name=domain_name,
            url=clean_url,
            registrar=registrar,
            expires_at=expires_at,
            auto_renew=auto_renew,
            registered_at=registered_at,
            renewal_cost=renewal_cost,
            dns_provider=dns_provider,
            nameservers=nameservers,
            auth_code=auth_code,
            parent_server_id=parent_server_id,
            parent_domain_id=parent_domain_id,
            notes=notes,
        )


@dataclass
class VaultFile:
    """Represents an encrypted file stored in the vault."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    filename: str = ""
    file_size: int = 0
    mime_type: str = "application/octet-stream"
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)

    def get_tags_display(self) -> str:
        """Returns comma-separated tags string."""
        return ", ".join(self.tags)

    def set_tags_from_str(self, tags_str: str) -> None:
        """Parses comma-separated string into clean tags list."""
        if not tags_str:
            self.tags = []
        else:
            self.tags = [t.strip().lower() for t in tags_str.split(",") if t.strip()]

