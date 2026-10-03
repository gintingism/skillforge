"""Public exception types for SkillForge."""


class SkillForgeError(Exception):
    """Base class for expected SkillForge errors."""


class SkillParseError(SkillForgeError):
    """Raised when a skill document cannot be parsed."""


class SkillValidationError(SkillForgeError):
    """Raised when a skill contains invalid metadata or paths."""


class RegistryError(SkillForgeError):
    """Raised when a registry operation fails."""


class AdapterError(SkillForgeError):
    """Raised when an adapter cannot install a skill."""
