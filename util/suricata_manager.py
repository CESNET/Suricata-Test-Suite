"""
Author(s):  Eliška Červinková <eliska.cervinkova@cesnet.cz>
            Adam Kiripolský <adam.kiripolsky@cesnet.cz>
            Matyáš Sedmidubský <matyas.sedmidubsky@cesnet.cz>

Copyright: (C) 2023 - 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause
"""

import os
import time
import os.path

from lbr_testsuite.executable import executable, remote_executor, ExecutableProcessError
from util.suri_util import is_running
from typing import List


SURI_PID = "/var/run/suricata.pid"
DEFALUT_CONF_FILE = "/etc/suricata/suricata.yaml"
DEFAULT_RULES_FILE = "/var/lib/suricata/rules/suricata.rules"
REMOTE_SURICATA_DIR = f"/tmp/suricata-{int(time.time())}/"


class SuriDown(Exception):
    """Exception raised for custom error, if Suricata is down."""

    pass


class Suricata_manager:
    def __init__(
        self,
        request,
        suricata_tmp_stats_path: str,
        interface: str,
        capture_mode: str,
        workers: List[int] = [],
        asynch: bool = False,
        log_dir: str = "/var/log/suricata",
        conf_file: str = DEFALUT_CONF_FILE,
        rules_file: str = DEFAULT_RULES_FILE,
    ):
        """Class Suricata_manager for controlling Suricata instance on remote machine

        Parameters
        ----------
        request : fixture
            Special pytest fixture used for retrieving command
            line parameters in this case.
        suricata_tmp_stats_path: str
            Path to temporary eve.json file on local machine
            that is overwritten with every run of Suricata.
        interface: str
            Interface for Suricata
        capture_mode: str
            Suricata's capture mode for run
        workers: List[int]
            List of Suricata threads
        asynch: bool
            Flag whether to wait for the start of Suricata
            automatically or run other commands meanwhile.

            If true, method Suricata_manager.wait_on_start()
            needs to be used in the pytest file.
        log_file: str
            Path to directory where Suricata statistics and log are stored
        conf_file: str
            Path to Suricata configuration file
        rule_file: str
            Path to Suricata rules file
        """

        self.log_dir: str
        self.conf_file: str
        self.rules_file: str

        self.host_server = request.config.getoption("--remote-host")
        self.pcie_adress = interface
        self.capture_mode = capture_mode
        self.user: str = os.environ["USER"]

        self.local_tmp_stats: str = suricata_tmp_stats_path
        self.asynch: bool = asynch
        self.workers: List[int] = workers
        self._pid_file = SURI_PID

        self.host_executor: remote_executor.Executor = remote_executor.RemoteExecutor(
            host=self.host_server, user=self.user
        )

        self.addfinalizer(request)
        self._set_log(log_dir)
        self._set_conf(request, conf_file)
        self._set_rules(rules_file)
        self._change_remote_dir_permissions()

        self.last_start_delay: int = 0

    def addfinalizer(self, request):
        request.addfinalizer(self.kill)

    def _set_log(self, log_dir: str):
        self.log_dir = log_dir

    def _set_conf(self, request, conf_file: str):
        """Set configuration file for Suricata.
            Hierarchy of precedence which configration file to use:
            1. File set in command line when running pytest
            2. File set in Suricata_manager constructor
            3. DEFALUT_CONF_FILE

            All configuration files except DEFALUT_CONF_FILE need to be
            stored on the machine that runs pytests as they are automatically copied
            to the remote machine that runs Suricata.

        Parameters
        ----------
        request : fixture
            Special pytest fixture used for retrieving command
            line parameters in this case.
        conf_file : str
            Path to Suricata configuration file.
        """
        if conf_file != DEFALUT_CONF_FILE:
            file_name: str = conf_file.split("/")[-1]
            remote_conf_file = f"{REMOTE_SURICATA_DIR}{file_name}"

            process_copy_conf_to_remote = executable.Tool(
                f"rsync -a {conf_file} {self.user}@{self.host_server}:{REMOTE_SURICATA_DIR}"
            )
            process_copy_conf_to_remote.run()
            self.conf_file = remote_conf_file
        else:
            self.conf_file = conf_file

    def _set_rules(self, rules_file: str):
        """Set Suricata rules file and copy the file onto remote machine running suricata.

        Parameters
        ----------
        rules_file: str
            Path to local Suricata rules file
        """
        if rules_file != DEFAULT_RULES_FILE and "/dev/null" not in rules_file:
            file_name: str = rules_file.split("/")[-1]
            rules_file = f"{REMOTE_SURICATA_DIR}{file_name}"

            process_copy_rules_to_remote = executable.Tool(
                f"rsync -a {rules_file} {self.user}@{self.host_server}:{REMOTE_SURICATA_DIR}"
            )
            process_copy_rules_to_remote.run()

        self.rules_file = rules_file

    def get_path_to_binary(self) -> str:
        process_copy_conf_to_remote = executable.Tool(
            "which suricata",
            sudo=True,
            executor=self.host_executor,
            failure_verbosity="no-error",
        )
        stdout, stderr = process_copy_conf_to_remote.run()

        assert stderr == "", "Could not find Suricata in PATH"
        return stdout.strip()

    def _change_remote_dir_permissions(self):
        process_set_permissions = executable.Tool(
            f"""if [ -d {REMOTE_SURICATA_DIR} ];
                                                then chmod -R 766 {REMOTE_SURICATA_DIR};
                                                else exit 0;
                                                fi""",
            sudo=True,
            executor=self.host_executor,
        )
        process_set_permissions.run()

    def kill(self):
        proccess_kill = executable.Tool(
            "pkill Suricata-Main || true", sudo=True, executor=self.host_executor
        )
        proccess_kill.run()

    def is_alive(self):
        process_find_suri_process = executable.Tool(
            "ps aux | grep suricata | grep -v grep || true",
            sudo=True,
            executor=self.host_executor,
        )
        suri = process_find_suri_process.run()[0]
        if not suri:
            raise SuriDown

    def wait_on_start(self) -> None:
        """Wait until Suricata is started, then continue"""
        can_continue = False
        self.last_start_delay = 0
        while not can_continue:
            time.sleep(1)
            self.last_start_delay += 1
            process_wait_on_start = executable.Tool(
                "suricatasc -c uptime",
                sudo=True,
                executor=self.host_executor,
                failure_verbosity="no-error",
            )

            try:
                stdout, _ = process_wait_on_start.run()
                can_continue = is_running(stdout)

            except ExecutableProcessError:
                can_continue = False
                print("Suricata is not started yet")
                self.is_alive()

    def _wait_for_clean_start(self) -> None:
        """Wait until previous instance of Suricata is fully shut down, then continue."""
        can_continue = False
        while not can_continue:
            time.sleep(3)
            process_wait_on_end = executable.Tool(
                "suricatasc -c uptime",
                sudo=True,
                executor=self.host_executor,
                failure_verbosity="no-error",
            )

            try:
                stdout, _ = process_wait_on_end.run()
                can_continue = not is_running(stdout)
                print("Other Suricata instance is running, waiting for finish")
                self.kill()

            except ExecutableProcessError:
                can_continue = True

    def start(self) -> None:
        """Remove Suricata PID file and local and remote
        eve.json/eve-stats.json statistic files and start Suricata as a daemon
        on remote machine.
        """

        self._wait_for_clean_start()

        process_destroy_pid = executable.Tool(
            f"rm -f {self._pid_file}", sudo=True, executor=self.host_executor
        )
        process_destroy_pid.run()
        time.sleep(2)

        process_destroy_eve = executable.Tool(
            f"rm -f {os.path.join(self.log_dir, 'eve.json')}",
            sudo=True,
            executor=self.host_executor,
        )
        process_destroy_eve.run()
        time.sleep(2)

        process_destroy_eve_stats = executable.Tool(
            f"rm -f {os.path.join(self.log_dir, 'eve-stats.json')}",
            sudo=True,
            executor=self.host_executor,
        )
        process_destroy_eve_stats.run()
        time.sleep(2)

        proces_destroy_suricata_log = executable.Tool(
            f"rm -f {os.path.join(self.log_dir, 'suricata.log')} || true",
            sudo=True,
            executor=self.host_executor,
        )
        proces_destroy_suricata_log.run()
        time.sleep(2)

        process_destroy_tmp_files = executable.Tool(
            f"rm -rf {self.local_tmp_stats}/suricata-{self.user}",
            sudo=True,
        )
        process_destroy_tmp_files.run()
        time.sleep(2)

        suri_cmd = f"suricata -c {self.conf_file} -l {self.log_dir} -S {self.rules_file} -D --{self.capture_mode} --pidfile {self._pid_file}"
        print(f"Running command: {suri_cmd}")
        process_suri = executable.Tool(suri_cmd, sudo=True, executor=self.host_executor)
        process_suri.run()

        if not self.asynch:
            self.wait_on_start()

    def stop(self) -> None:
        """Get PID of running Suricata and kill it with SIGTERM.
        Fetch remote files onto local machine.
        """
        proccess_get_pid = executable.Tool(
            "pidof suricata",
            sudo=True,
            executor=self.host_executor,
            failure_verbosity="no-error",
        )

        not_killed = True
        while not_killed:
            try:
                suri_pid, _ = proccess_get_pid.run()

                proccess_kill = executable.Tool(
                    f"kill -15 {suri_pid}",
                    sudo=True,
                    executor=self.host_executor,
                    failure_verbosity="no-error",
                )
                proccess_kill.run()
                time.sleep(2)

            except ExecutableProcessError:
                try:
                    check_successful_end_process = executable.Tool(
                        f'cd {self.log_dir} && cat suricata.log | grep "Notice: suricata: Signal Received.  Stopping engine."',
                        sudo=True,
                        executor=self.host_executor,
                    )
                    check_successful_end_process.run()
                except ExecutableProcessError:
                    raise SuriDown

                not_killed = False

        process_copy_result_to_local = executable.Tool(
            f"rsync -r {self.user}@{self.host_server}:{self.log_dir}/ {self.local_tmp_stats}/suricata-{self.user}/"
        )
        process_copy_result_to_local.run()
