import logging
import os
from pathlib import Path
from subprocess import PIPE, Popen, check_output
from typing import Dict, Tuple

from juju.application import Application
from juju.unit import Unit
from pytest_operator.plugin import OpsTest

LOGGER = logging.getLogger(__name__)


async def get_unit_by_name(
    unit_name: str, unit_index: str, unit_list: Dict[str, Unit]
) -> Unit:
    return unit_list.get(
        "{unitname}/{unitindex}".format(
            unitname=unit_name, unitindex=unit_index
        )
    )


async def get_application_by_name(
    app_name: str, app_list: Dict[str, Application]
) -> Application:
    return app_list.get(app_name)


async def build_snap_and_charm(
    root_directory: str, charm_directory: str, ops_test: OpsTest
) -> Tuple[str, str]:
    """
    Builds the snap and charm, returning a tuple of [snappath,charmpath]
    """
    LOGGER.info("Building snap...")
    LOGGER.info("Root directory is {}".format(root_directory))
    snap_exists, path = await check_if_snap_exists(
        root_directory, root_directory
    )
    if snap_exists:
        LOGGER.info("Snap already exists, skipping build.")
        snap_path = path
    else:
        snap_path = await build_snap_lxd(root_directory)
    LOGGER.info("Snap path is: %s", str(snap_path))

    LOGGER.info("Building charm...")
    charm_path = await ops_test.build_charm(charm_directory)
    LOGGER.info("Charm path is: %s", str(charm_path.absolute()))
    return snap_path, charm_path


async def build_snap_lxd(working_directory: Path) -> Path:
    snap_path = Path(str(working_directory.absolute()))
    """
    Will build (& print sub proc output) a snap in LXD and return the Path to it
    """
    # Instead of this (resources = {rsc.stem: rsc for rsc in resources}),
    # we run commands ourselves and move to tmp_path
    # additionally cleaning up ourselves.
    # resources = await ops_test.build_resources(build_snap_script, False)
    #
    # I wanted to see the build output for the snap and additionally the charm
    # in verbose mode too, hence, opted for this approach.
    p = Popen(
        # Having multipass issues, so lxd will have to do for now...
        # TODO: Figure out why multipass is trying to export /usr/sbin as a variable
        args="snapcraft --use-lxd",
        stdout=PIPE,
        stderr=PIPE,
        universal_newlines=True,
        shell=True,
        cwd=str(snap_path),
        bufsize=1,  # We want immediate output for the snap building.
    )
    # Create iter() with sentinel set to b'', such that
    # we can detect an effective EOF for the completed snapcraft process.
    for line in iter(p.stdout.readline, b""):
        LOGGER.info(line)
        # If the line contains "Snapped", we know the file name is
        # immediately after, as for whether this is reliable - probably not
        # and we could walk() the dir. But it works for now.
        if "Snapped" in line:
            snap_path = snap_path.joinpath(line.split(" ")[1])
        # If it polls to none, we're certain it's finished.
        # We check both in case the process does output b'' and we accidentally
        # break the read too early.
        if line == "" and p.poll() is not None:
            break
    p.stdout.close()
    p.wait()

    if p.returncode != 0:
        raise FailedToBuildSnapError(p.returncode)

    return snap_path


async def check_if_snap_exists(
    git_dir: Path, snap_build_dir: Path
) -> Tuple[bool, str]:
    """
    Finds if the snap exists already by version.
    If true, snap exists, else no no
    """
    _command = [
        "git",
        "describe",
        "--tags",
        # We use dirty such that we are aware we're making changes.
        # and that this build of the snap is not feasible.
        # Perhaps though, we should add a check to see if the working
        # tree is actually dirty and abort the entire test suite?
        #
        # Up for discussion.
        "--dirty",
        "--abbrev=0",
    ]

    git_version = check_output(_command, universal_newlines=True, cwd=git_dir)
    for fname in os.listdir(str(snap_build_dir)):
        if fname.endswith(".snap"):
            if git_version.strip() in fname.strip():
                path = os.path.abspath(
                    "{path}/{file}".format(
                        path=str(snap_build_dir), file=fname.strip()
                    )
                )
                return True, path
            break
    return False, None


class FailedToBuildSnapError(Exception):
    """Exception raised when snap fails to build.
    Attributes:
        respcode-- todo
    """

    def __init__(self, respcode):
        self.message = (
            "Snap failed to build with response code: {respcode} ".format(
                respcode=respcode
            )
        )
        super().__init__(self.message)
