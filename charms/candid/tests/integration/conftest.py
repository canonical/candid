import logging
from asyncio.log import logger
from pathlib import Path
from typing import Tuple

import pytest
from pytest_operator.plugin import OpsTest

from integration.utils import build_snap_and_charm

LOGGER = logging.getLogger(__name__)


# Fixtures to handle the deployment per each test suite.
# ops_test is a module fixture, which kind of limits us in what we
# can do regarding building artifacts required for the tests.
# As such, we run a subproc validating the snap version
# such that we don't have to try build it over and over.
#
# As for the charm, we should probably do the same. But for
# now we use the built in ops_test.build_charm

# TODO: Move this into setupTest funcs and turns the bundlepath & snap/charm build fixture
# into session fixtures. Then pull bundle path into each setupTest lifecycle func and
# deploy per each test suite.

# TODO: Figure out why snap sometimes builds, sometimes doesn't ...
@pytest.fixture(name="snap_and_charm_paths", scope="module")
async def build_snap_and_charm_fixture(ops_test: OpsTest):
    LOGGER.info("Building snap and charm.")
    charm_directory = Path.cwd()
    root_directory = charm_directory.parent.parent.absolute()
    snap_path, charm_path = await build_snap_and_charm(
        root_directory, charm_directory, ops_test
    )
    yield snap_path, charm_path


@pytest.fixture(
    name="bundle_path", scope="module"
)  # snap_and_charm_paths: Tuple[str, str])
def render_bundle_fixture(
    ops_test: OpsTest, snap_and_charm_paths: Tuple[str, str]
):
    LOGGER.info("Rendering bundle with snap and charm paths.")
    charm_directory = Path.cwd()
    tests_directory = charm_directory.joinpath("tests")
    tests_data_directory = tests_directory.joinpath("data")
    bundle_path = tests_data_directory.joinpath("bundle-01.yaml")

    rendered_bundle_path = ops_test.render_bundle(
        bundle_path,
        charm_path=snap_and_charm_paths[1],
        snap_path=snap_and_charm_paths[0],
    )
    LOGGER.info("Bundle path is: %s", str(rendered_bundle_path.absolute()))
    yield rendered_bundle_path


# TODO: Move this into setupTest funcs and turns the bundlepath & snap/charm build fixture
# into session fixtures. Then pull bundle path into each setupTest lifecycle func and
# deploy per each test suite.
@pytest.fixture(name="deploy_built_bundle", scope="module")
async def deploy_bundle_function(ops_test: OpsTest, bundle_path: Path):
    juju_cmd = [
        "deploy",
        "-m",
        ops_test.model_full_name,
        str(bundle_path.absolute()),
    ]
    rc, stdout, stderr = await ops_test.juju(*juju_cmd)
    if rc != 0:
        raise FailedToDeployBundleError(stderr, stdout)


class FailedToDeployBundleError(Exception):
    """Exception raised when bundle fails to deploy.
    Attributes:
        stderr -- todo
        stdout -- todo
    """

    def __init__(self, stderr, stdout):
        self.message = f"Bundle deploy failed: {(stderr or stdout).strip()}"
        super().__init__(self.message)
