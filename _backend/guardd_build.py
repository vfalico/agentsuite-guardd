from setuptools.build_meta import *  # noqa: F403
from setuptools.build_meta import build_sdist as _setuptools_build_sdist
from setuptools.build_meta import build_wheel as _setuptools_build_wheel

from reproducible_sdist import normalize_sdist, normalize_wheel, source_date_epoch


def build_sdist(sdist_directory, config_settings=None):
    filename = _setuptools_build_sdist(sdist_directory, config_settings)
    normalize_sdist(sdist_directory, filename, source_date_epoch())
    return filename


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    filename = _setuptools_build_wheel(
        wheel_directory,
        config_settings,
        metadata_directory,
    )
    normalize_wheel(wheel_directory, filename, source_date_epoch())
    return filename
