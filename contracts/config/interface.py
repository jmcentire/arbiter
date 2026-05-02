# === Configuration Loader (config) v1 ===
# Loads and validates arbiter.yaml via a Pydantic Settings model. Exposes all configurable values for the Arbiter trust enforcement system including registry, trust scoring, soak testing, OTLP telemetry, API, classification registry, human gate, and ledger settings. Provides a global get_config() accessor for immutable configuration and handles default config generation for `arbiter init`. Source priority: defaults → YAML file → environment variables (prefix=ARBITER_, nested delimiter=__). All config is frozen/immutable after load. YAML source uses yaml.safe_load() exclusively.

# Module invariants:
#   - ArbiterConfig is frozen/immutable after construction — no field mutation allowed
#   - The module-level _config singleton is either None or a fully validated ArbiterConfig instance
#   - get_config() always returns the same ArbiterConfig instance until reset_config() is called
#   - Source priority is always: defaults → YAML file → environment variables (ARBITER_ prefix, __ nested delimiter)
#   - All Path fields use pathlib.Path; all timestamps use UTC
#   - trust.floor <= trust.authority_override_floor (cross-field invariant)
#   - trust.floor >= 0.0 and trust.floor <= 1.0
#   - trust.authority_override_floor >= 0.0 and trust.authority_override_floor <= 1.0
#   - trust.decay_lambda >= 0.0
#   - trust.conflict_trust_delta_threshold >= 0.0 and trust.conflict_trust_delta_threshold <= 1.0
#   - soak.target_requests >= 1
#   - otlp.listen_port is a valid port number (1..65535)
#   - otlp.http_port is a valid port number (1..65535)
#   - api.port is a valid port number (1..65535)
#   - ledger.checksum_interval >= 1
#   - config_version == 1 for this contract version
#   - Trust ledger is append-only — config cannot enable update or delete semantics
#   - All soak.base_durations keys must be valid DataClassificationTier variants
#   - All trust.taint_lock_tiers entries must be valid DataClassificationTier variants
#   - YAML file is read via yaml.safe_load() exclusively — never yaml.load()

class DataClassificationTier(Enum):
    """Data classification tiers used across the Arbiter system. StrEnum for YAML/JSON serialization compatibility."""
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"
    CRITICAL = "CRITICAL"

class RegistryConfig:
    """Configuration for the component/service registry."""
    path: str = ./registry                   # optional, Filesystem path to the registry directory. Resolved as pathlib.Path at runtime.
    append_only: bool = true                 # optional, Whether the registry operates in append-only mode (no overwrites).

class TrustConfig:
    """Configuration for trust score computation, decay, and conflict thresholds. All policy calculations use raw trust score, never display tiers."""
    floor: float = 0.10                      # optional, range(0.0 <= value <= 1.0), Minimum trust score floor. Trust scores cannot decay below this value.
    authority_override_floor: float = 0.40   # optional, range(0.0 <= value <= 1.0), Minimum trust score required for authority override operations. Must be >= trust.floor.
    decay_lambda: float = 0.05               # optional, range(value >= 0.0), Exponential decay rate lambda for trust score time-based decay.
    conflict_trust_delta_threshold: float = 0.20 # optional, range(0.0 <= value <= 1.0), Minimum trust score delta between conflicting nodes to trigger a conflict finding.
    taint_lock_tiers: TaintLockTiersList = ['RESTRICTED', 'CRITICAL'] # optional, List of DataClassificationTier values for which taint-lock is enforced. Nodes handling data at these tiers have stricter trust requirements.

TaintLockTiersList = list[DataClassificationTier]
# List of DataClassificationTier values for taint lock enforcement.

class SoakDurationsMap:
    """Mapping from DataClassificationTier to base soak duration in seconds. Keys must be valid DataClassificationTier variants."""
    PUBLIC: int = 3600                       # optional, Soak duration in seconds for PUBLIC tier.
    INTERNAL: int = 7200                     # optional, Soak duration in seconds for INTERNAL tier.
    CONFIDENTIAL: int = 14400                # optional, Soak duration in seconds for CONFIDENTIAL tier.
    RESTRICTED: int = 28800                  # optional, Soak duration in seconds for RESTRICTED tier.
    CRITICAL: int = 86400                    # optional, Soak duration in seconds for CRITICAL tier.

class SoakConfig:
    """Configuration for soak testing parameters — duration and request volume gates per classification tier."""
    base_durations: SoakDurationsMap = SoakDurationsMap() # optional, Mapping of DataClassificationTier to base soak duration in seconds.
    target_requests: int = 1000              # optional, range(value >= 1), Target number of requests to observe during soak period before promotion.

class OtlpConfig:
    """Configuration for OpenTelemetry Protocol (OTLP) listener ports."""
    listen_port: int = 4317                  # optional, range(1 <= value <= 65535), gRPC port for OTLP telemetry ingestion.
    http_port: int = 4318                    # optional, range(1 <= value <= 65535), HTTP port for OTLP telemetry ingestion.

class ApiConfig:
    """Configuration for the Arbiter HTTP API server."""
    port: int = 7700                         # optional, range(1 <= value <= 65535), HTTP port for the Arbiter API server.

class ClassificationRegistryConfig:
    """Configuration for the field classification registry."""
    path: str = ./classification_registry.yaml # optional, Filesystem path to the classification registry file or directory. Resolved as pathlib.Path at runtime.

class HumanGateConfig:
    """Configuration for the human-in-the-loop approval gate."""
    webhook_url: str = None                  # optional, URL for the webhook to notify when a human gate is triggered. Empty string means no webhook configured.
    block_on_gate: bool = true               # optional, Whether to block (halt processing) when a human gate is triggered, waiting for approval. If false, gate is advisory only.

class LedgerConfig:
    """Configuration for the trust ledger (append-only JSONL with periodic SHA256 checksums)."""
    checksum_interval: int = 100             # optional, range(value >= 1), Number of ledger entries between SHA256 checksum lines.

class ArbiterConfig:
    """Root configuration model for the Arbiter system. Composes all section configs. Extends Pydantic BaseSettings with frozen immutability and custom YAML settings source. Source priority: defaults → YAML → env vars (prefix=ARBITER_, nested delimiter=__)."""
    config_version: int = 1                  # optional, range(value == 1), Configuration schema version for future migration support. Must be 1 for this version.
    registry: RegistryConfig = RegistryConfig() # optional, Component/service registry configuration section.
    trust: TrustConfig = TrustConfig()       # optional, Trust score computation and policy configuration section.
    soak: SoakConfig = SoakConfig()          # optional, Soak testing parameters configuration section.
    otlp: OtlpConfig = OtlpConfig()          # optional, OTLP telemetry listener configuration section.
    api: ApiConfig = ApiConfig()             # optional, HTTP API server configuration section.
    classification_registry: ClassificationRegistryConfig = ClassificationRegistryConfig() # optional, Field classification registry configuration section.
    human_gate: HumanGateConfig = HumanGateConfig() # optional, Human-in-the-loop approval gate configuration section.
    ledger: LedgerConfig = LedgerConfig()    # optional, Trust ledger configuration section.

class ConfigurationError:
    """Exception wrapping Pydantic ValidationError with file path context. Raised when config file is present but contains invalid values. Includes the file path, the original validation errors, and a human-readable message suitable for CLI display via click."""
    config_path: str                         # required, Filesystem path of the config file that failed validation.
    message: str                             # required, Human-readable error message including file path and specific field/value details.
    validation_errors: ValidationErrorList   # required, List of individual field-level validation error detail dicts from Pydantic.

class ValidationErrorDetail:
    """A single field-level validation error extracted from Pydantic ValidationError."""
    field: str                               # required, Dot-separated field path (e.g. 'trust.floor').
    message: str                             # required, Human-readable validation error message.
    value: str                               # required, String representation of the invalid value.

ValidationErrorList = list[ValidationErrorDetail]
# List of individual validation error details.

class ConfigNotLoadedError:
    """Exception raised when get_config() is called before load_config(). Indicates the module-level singleton has not been initialized."""
    message: str                             # required, Error message indicating config was not loaded.

OptionalPath = str | None

def load_config(
    path: OptionalPath = None,
) -> ArbiterConfig:
    """
    Loads, validates, and caches the Arbiter configuration from a YAML file. If path is None, looks for 'arbiter.yaml' in the current working directory. If the file does not exist at the resolved path, falls back to defaults (with env var overrides). Stores the resulting ArbiterConfig in the module-level singleton. Subsequent calls overwrite the cached config. Source priority: defaults → YAML file contents → environment variables.

    Preconditions:
      - If path is provided, it must be a string representing a valid filesystem path or a pathlib.Path
      - If the YAML file exists, it must be readable by the current process

    Postconditions:
      - The returned ArbiterConfig is fully validated against all field constraints and cross-field invariants
      - The module-level _config singleton is set to the returned ArbiterConfig instance
      - get_config() will return this same instance until load_config() or reset_config() is called again
      - The returned ArbiterConfig is frozen/immutable
      - trust.floor <= trust.authority_override_floor in the returned config

    Errors:
      - validation_error (ConfigurationError): YAML file or env vars contain values that fail Pydantic validation (type mismatch, out-of-range, cross-field constraint violation)
          config_path: Path to the invalid config file
          message: Includes specific field and value details
      - yaml_parse_error (ConfigurationError): YAML file exists but contains malformed YAML syntax that yaml.safe_load() cannot parse
          config_path: Path to the malformed file
          message: YAML parse error details
      - permission_error (ConfigurationError): YAML file exists but the process lacks read permissions
          config_path: Path to the unreadable file
          message: Permission denied details
      - cross_field_validation_error (ConfigurationError): trust.floor > trust.authority_override_floor or other cross-field constraint violations
          config_path: Path to the config file
          message: Cross-field constraint violation details

    Side effects: none
    Idempotent: yes
    """
    ...

def get_config() -> ArbiterConfig:
    """
    Returns the cached ArbiterConfig singleton. Must be called after load_config(). This is the primary accessor for all Arbiter components to retrieve configuration values. Returns the same immutable instance on every call until reset_config() or another load_config() call.

    Preconditions:
      - load_config() must have been called successfully at least once prior to this call

    Postconditions:
      - Returns the same ArbiterConfig instance that was set by the most recent load_config() call
      - The returned ArbiterConfig is frozen/immutable

    Errors:
      - config_not_loaded (ConfigNotLoadedError): load_config() has not been called, or reset_config() was called without a subsequent load_config()
          message: Configuration not loaded. Call load_config() before get_config().

    Side effects: none
    Idempotent: yes
    """
    ...

def reset_config() -> None:
    """
    Resets the module-level _config singleton to None. Primarily used in testing to ensure clean state between test cases. After calling this, get_config() will raise ConfigNotLoadedError until load_config() is called again.

    Postconditions:
      - The module-level _config singleton is set to None
      - Subsequent get_config() calls will raise ConfigNotLoadedError until load_config() is called

    Side effects: none
    Idempotent: yes
    """
    ...

def generate_default_config(
    path: str,
    overwrite: bool = false,
) -> None:
    """
    Generates an arbiter.yaml file with all default configuration values. Used by `arbiter init` CLI command. Instantiates ArbiterConfig() with all defaults, serializes via model_dump(mode='json'), and writes to the target path using yaml.dump(sort_keys=False). Includes a YAML header comment identifying the file as auto-generated. Will not overwrite an existing file unless overwrite=True.

    Preconditions:
      - The parent directory of path must exist and be writable by the current process
      - path must be a valid filesystem path string

    Postconditions:
      - A valid YAML file exists at the specified path containing all ArbiterConfig defaults
      - The generated YAML file can be loaded by load_config() without errors
      - The file begins with a YAML header comment identifying it as auto-generated
      - YAML keys are in definition order (sort_keys=False)
      - The generated file includes config_version: 1

    Errors:
      - file_exists_no_overwrite (ConfigurationError): A file already exists at the target path and overwrite is False
          config_path: Target file path
          message: File already exists at <path>. Use --force to overwrite.
      - parent_directory_not_found (ConfigurationError): The parent directory of the target path does not exist
          config_path: Target file path
          message: Parent directory does not exist: <parent_path>
      - permission_error (ConfigurationError): The process lacks write permissions to the target path or its parent directory
          config_path: Target file path
          message: Permission denied writing to <path>

    Side effects: none
    Idempotent: yes
    """
    ...

def validate_config_file(
    path: str,
) -> ArbiterConfig:
    """
    Validates an existing arbiter.yaml file without loading it into the module singleton. Parses and validates the file, returning the validated ArbiterConfig or raising ConfigurationError. Useful for CLI `arbiter config validate` command and CI checks.

    Preconditions:
      - path must point to an existing, readable file
      - The file must contain YAML content

    Postconditions:
      - If no error is raised, the returned ArbiterConfig is fully valid
      - The module-level _config singleton is NOT modified
      - The returned ArbiterConfig is frozen/immutable

    Errors:
      - file_not_found (ConfigurationError): No file exists at the specified path
          config_path: Specified file path
          message: Config file not found: <path>
      - yaml_parse_error (ConfigurationError): File contains malformed YAML syntax
          config_path: Specified file path
          message: YAML parse error details
      - validation_error (ConfigurationError): YAML content fails Pydantic validation
          config_path: Specified file path
          message: Includes specific field and value details
      - permission_error (ConfigurationError): File exists but process lacks read permission
          config_path: Specified file path
          message: Permission denied reading <path>

    Side effects: none
    Idempotent: yes
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['DataClassificationTier', 'RegistryConfig', 'TrustConfig', 'TaintLockTiersList', 'SoakDurationsMap', 'SoakConfig', 'OtlpConfig', 'ApiConfig', 'ClassificationRegistryConfig', 'HumanGateConfig', 'LedgerConfig', 'ArbiterConfig', 'ConfigurationError', 'ValidationErrorDetail', 'ValidationErrorList', 'ConfigNotLoadedError', 'OptionalPath', 'load_config', 'get_config', 'reset_config', 'generate_default_config', 'validate_config_file']
