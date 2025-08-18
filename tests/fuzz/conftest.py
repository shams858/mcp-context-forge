# -*- coding: utf-8 -*-
"""Fuzzing test configuration."""
import pytest
from hypothesis import settings, Verbosity, HealthCheck

# Mark all tests in this directory as fuzz tests
pytestmark = pytest.mark.fuzz

# Configure Hypothesis profiles for different environments
settings.register_profile(
    "dev",
    max_examples=100,
    verbosity=Verbosity.normal,
    suppress_health_check=[HealthCheck.too_slow]
)

settings.register_profile(
    "ci",
    max_examples=50,
    verbosity=Verbosity.quiet,
    suppress_health_check=[HealthCheck.too_slow]
)

settings.register_profile(
    "thorough",
    max_examples=1000,
    verbosity=Verbosity.verbose,
    suppress_health_check=[HealthCheck.too_slow]
)

@pytest.fixture(scope="session")
def fuzz_settings():
    """Configure fuzzing settings based on environment."""
    import os
    profile = os.getenv("HYPOTHESIS_PROFILE", "dev")
    settings.load_profile(profile)
    return profile
