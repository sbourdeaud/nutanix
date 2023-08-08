"""
Blueprint Name: ubuntu_fio
Description: Ubuntu based virtual machine with data disk and fio pre-installed. 
             Ability to specify fio workload configuration file. 
             Ability to specify quantity of VMs as well as VM anti-affinity rule.
Author: Stéphane Bourdeaud (Nutanix Professional Services)
Version: 2023-08-07
"""

import json
import os

from calm.dsl.builtins import *


# Secret Variables
BP_CRED_linux_KEY = read_local_file("BP_CRED_linux_KEY")
BP_CRED_root_PASSWORD = read_local_file("BP_CRED_root_PASSWORD")
BP_CRED_prism_central_PASSWORD = read_local_file("BP_CRED_prism_central_PASSWORD")

# Credentials
BP_CRED_linux = basic_cred(
    "linux",
    BP_CRED_linux_KEY,
    name="linux",
    type="KEY",
    default=True,
    editables={"username": True, "secret": True},
)
BP_CRED_root = basic_cred(
    "root",
    BP_CRED_root_PASSWORD,
    name="root",
    type="PASSWORD",
)
BP_CRED_prism_central = basic_cred(
    "stephane.bourdeaud@emeagso.lab",
    BP_CRED_prism_central_PASSWORD,
    name="prism_central",
    type="PASSWORD",
)


class UbuntuFio(Service):
    @action
    def __create__():
        """System action for creating an application"""

        CalmTask.Exec.ssh(
            name="CreateGitHubRunner",
            filename=os.path.join(
                "scripts",
                "Service_LinuxGitHubRunner_Action___create___Task_CreateGitHubRunner.sh",
            ),
            cred=ref(BP_CRED_runner),
            target=ref(LinuxGitHubRunner),
        )

    @action
    def __delete__():
        """System action for deleting an application. Deletes created VMs as well"""

        CalmTask.Exec.ssh(
            name="DeleteGitHubRunner",
            filename=os.path.join(
                "scripts",
                "Service_LinuxGitHubRunner_Action___delete___Task_DeleteGitHubRunner.sh",
            ),
            cred=ref(BP_CRED_runner),
            target=ref(LinuxGitHubRunner),
        )

    @action
    def __start__():
        """System action for starting an application"""

        CalmTask.Exec.ssh(
            name="StartGitHubRunner",
            filename=os.path.join(
                "scripts",
                "Service_LinuxGitHubRunner_Action___start___Task_StartGitHubRunner.sh",
            ),
            cred=ref(BP_CRED_runner),
            target=ref(LinuxGitHubRunner),
        )

    @action
    def __stop__():
        """System action for stopping an application"""

        CalmTask.Exec.ssh(
            name="StopGitHubRunner",
            filename=os.path.join(
                "scripts",
                "Service_LinuxGitHubRunner_Action___stop___Task_StopGitHubRunner.sh",
            ),
            cred=ref(BP_CRED_runner),
            target=ref(LinuxGitHubRunner),
        )

    @action
    def __restart__():
        """System action for restarting an application"""

        CalmTask.Exec.ssh(
            name="RestartGitHubRunner",
            filename=os.path.join(
                "scripts",
                "Service_LinuxGitHubRunner_Action___restart___Task_RestartGitHubRunner.sh",
            ),
            cred=ref(BP_CRED_runner),
            target=ref(LinuxGitHubRunner),
        )


class fio_array_indexcalm_timeResources(AhvVmResources):

    memory = 8
    vCPUs = 8
    cores_per_vCPU = 1
    disks = [AhvVmDisk.Disk.Scsi.cloneFromImageService("CentOS_8_Cloud", bootable=True)]
    nics = [AhvVmNic.NormalNic.ingress("VLAN99-DHCP-01", cluster="Lancelot")]

    guest_customization = AhvVmGC.CloudInit(
        filename=os.path.join(
            "specs", "capghrcalm_array_indexcalm_time_cloud_init_data.yaml"
        )
    )


class capghrcalm_array_indexcalm_time(AhvVm):

    name = "cap-ghr-@@{calm_array_index}@@-@@{calm_time}@@"
    resources = capghrcalm_array_indexcalm_timeResources

    categories = {"cap-pracdev": "github-runner"}


class LinuxVm(Substrate):

    os_type = "Linux"
    provider_type = "AHV_VM"
    provider_spec = capghrcalm_array_indexcalm_time
    provider_spec_editables = read_spec(
        os.path.join("specs", "LinuxVm_create_spec_editables.yaml")
    )
    readiness_probe = readiness_probe(
        connection_type="SSH",
        disabled=False,
        retries="5",
        connection_port=22,
        address="@@{platform.status.resources.nic_list[0].ip_endpoint_list[0].ip}@@",
        delay_secs="120",
        credential=ref(BP_CRED_runner),
    )


class capghrcalm_array_indexcalm_timeResources(AhvVmResources):

    memory = 2
    vCPUs = 1
    cores_per_vCPU = 1
    disks = [AhvVmDisk.Disk.Scsi.cloneFromImageService("", bootable=True)]
    nics = [AhvVmNic.NormalNic.ingress("VLAN99-DHCP-01", cluster="Lancelot")]

    guest_customization = AhvVmGC.CloudInit(
        filename=os.path.join(
            "specs", "capghrcalm_array_indexcalm_time_cloud_init_data.yaml"
        )
    )


class capghrcalm_array_indexcalm_time(AhvVm):

    name = "cap-ghr-@@{calm_array_index}@@-@@{calm_time}@@"
    resources = capghrcalm_array_indexcalm_timeResources

    categories = {"cap-pracdev": "github-runner"}


class UbuntuVm(Substrate):

    os_type = "Linux"
    provider_type = "AHV_VM"
    provider_spec = capghrcalm_array_indexcalm_time
    provider_spec_editables = read_spec(
        os.path.join("specs", "UbuntuVm_create_spec_editables.yaml")
    )
    readiness_probe = readiness_probe(
        connection_type="SSH",
        disabled=False,
        retries="5",
        connection_port=22,
        address="@@{platform.status.resources.nic_list[0].ip_endpoint_list[0].ip}@@",
        delay_secs="120",
        credential=ref(BP_CRED_runner),
    )


class Package_Centos(Package):

    services = [ref(LinuxGitHubRunner)]

    @action
    def __install__():

        CalmTask.Exec.ssh(
            name="DownloadGitHubRunner",
            filename=os.path.join(
                "scripts",
                "Package_Package_Centos_Action___install___Task_DownloadGitHubRunner.sh",
            ),
            cred=ref(BP_CRED_runner),
            target=ref(LinuxGitHubRunner),
        )
        CalmTask.Exec.ssh(
            name="ConfigureGitHubRunner",
            filename=os.path.join(
                "scripts",
                "Package_Package_Centos_Action___install___Task_ConfigureGitHubRunner.sh",
            ),
            cred=ref(BP_CRED_runner),
            target=ref(LinuxGitHubRunner),
        )
        CalmTask.Exec.ssh(
            name="InstallGit",
            filename=os.path.join(
                "scripts",
                "Package_Package_Centos_Action___install___Task_InstallGit.sh",
            ),
            cred=ref(BP_CRED_runner),
            target=ref(LinuxGitHubRunner),
        )
        CalmTask.Exec.ssh(
            name="InstallCalmDSL",
            filename=os.path.join(
                "scripts",
                "Package_Package_Centos_Action___install___Task_InstallCalmDSL.sh",
            ),
            cred=ref(BP_CRED_runner),
            target=ref(LinuxGitHubRunner),
        )
        with parallel():
            CalmTask.Exec.ssh(
                name="InstallDocker",
                filename=os.path.join(
                    "scripts",
                    "Package_Package_Centos_Action___install___Task_InstallDocker.sh",
                ),
                cred=ref(BP_CRED_runner),
                target=ref(LinuxGitHubRunner),
            )
            CalmTask.Exec.ssh(
                name="InstallCookiecutter",
                filename=os.path.join(
                    "scripts",
                    "Package_Package_Centos_Action___install___Task_InstallCookiecutter.sh",
                ),
                cred=ref(BP_CRED_runner),
                target=ref(LinuxGitHubRunner),
            )
        CalmTask.Exec.ssh(
            name="UpdateCentOS",
            filename=os.path.join(
                "scripts",
                "Package_Package_Centos_Action___install___Task_UpdateCentOS.sh",
            ),
            cred=ref(BP_CRED_runner),
            target=ref(LinuxGitHubRunner),
        )

    @action
    def __uninstall__():

        CalmTask.Exec.ssh(
            name="RemoveGitHubRunner",
            filename=os.path.join(
                "scripts",
                "Package_Package_Centos_Action___uninstall___Task_RemoveGitHubRunner.sh",
            ),
            cred=ref(BP_CRED_runner),
            target=ref(LinuxGitHubRunner),
        )


class Package_Ubuntu(Package):

    services = [ref(LinuxGitHubRunner)]

    @action
    def __install__():

        CalmTask.Exec.ssh(
            name="DownloadGitHubRunnerUbuntu",
            filename=os.path.join(
                "scripts",
                "Package_Package_Ubuntu_Action___install___Task_DownloadGitHubRunnerUbuntu.sh",
            ),
            cred=ref(BP_CRED_runner),
            target=ref(LinuxGitHubRunner),
        )
        CalmTask.Exec.ssh(
            name="ConfigureGitHubRunnerUbuntu",
            filename=os.path.join(
                "scripts",
                "Package_Package_Ubuntu_Action___install___Task_ConfigureGitHubRunnerUbuntu.sh",
            ),
            cred=ref(BP_CRED_runner),
            target=ref(LinuxGitHubRunner),
        )
        CalmTask.Exec.ssh(
            name="InstallDockerUbuntu",
            filename=os.path.join(
                "scripts",
                "Package_Package_Ubuntu_Action___install___Task_InstallDockerUbuntu.sh",
            ),
            cred=ref(BP_CRED_runner),
            target=ref(LinuxGitHubRunner),
        )

    @action
    def __uninstall__():

        CalmTask.Exec.ssh(
            name="RemoveGitHubRunnerUbuntu",
            filename=os.path.join(
                "scripts",
                "Package_Package_Ubuntu_Action___uninstall___Task_RemoveGitHubRunnerUbuntu.sh",
            ),
            cred=ref(BP_CRED_runner),
            target=ref(LinuxGitHubRunner),
        )


class _4e8cd0f3_deployment(Deployment):

    name = "4e8cd0f3_deployment"
    min_replicas = "1"
    max_replicas = "15"
    default_replicas = "1"

    packages = [ref(Package_Centos)]
    substrate = ref(LinuxVm)
    editables = {"min_replicas": False, "default_replicas": True, "max_replicas": False}


class be90a1d9_deployment(Deployment):

    min_replicas = "1"
    max_replicas = "1"
    default_replicas = "1"

    packages = [ref(Package_Ubuntu)]
    substrate = ref(UbuntuVm)


class CentOS(Profile):

    deployments = [_4e8cd0f3_deployment]

    github_repo_token = CalmVariable.Simple.Secret(
        Profile_CentOS_variable_github_repo_token,
        label="GitHub Repository Token",
        is_mandatory=True,
        is_hidden=False,
        runtime=True,
        description="Paste here the token for your GitHub repository.",
    )

    github_repo = CalmVariable.Simple(
        "",
        label="GitHub Repository URL",
        is_mandatory=True,
        is_hidden=False,
        runtime=True,
        description="Paste here the GitHub repository URL",
    )

    public_key = CalmVariable.Simple(
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC9GE/gov8gOPsSkKVeejG5NYTJTQGNFCsJOXFcszhd1s1ixS1ClVZs3MduB1fWSvY8Vjzs+jD5VkW7SdwxEQQmOvyF8sHGNM1s4FGNgnRIvKXlPaXQSe9TUEl52xJa7G0JwggiG4kNgCtJmunK9cXZMj+iTQqSwdGvidOFdMxTbmSjlTNEE4kMIP4jiyZEKztVbz4i9+bI/Sq8cQVX+pNF6XTjxqUgDH15KIejnXw6QDH26yv6KWbSjtRl+8HvE1yNtJh9yXDEJ1pt4jcvE2SHNfFYlY8HM9qyymeVkL7SzL3u6dmkN7ospqiNgJVEW/iOATUHICLZpSXj1kr73xFB",
        label="SSH Public Key",
        is_mandatory=True,
        is_hidden=False,
        runtime=True,
        description="Paste here your .ssh/id_rsa.pub key",
    )

    @action
    def ScaleOut():

        runner_add_count = CalmVariable.Simple(
            "1",
            label="how many runners do you want to add?",
            is_mandatory=True,
            is_hidden=False,
            runtime=True,
            description="",
        )
        github_repo_token = CalmVariable.Simple.Secret(
            Profile_CentOS_Action_ScaleOut_variable_github_repo_token,
            label="GitHub Token",
            is_mandatory=True,
            is_hidden=False,
            runtime=True,
            description="Enter the token obtained from your GitHub repository (settings: actions: runners: add runner)",
        )
        CalmTask.Scaling.scale_out(
            "@@{runner_add_count}@@", name="ScaleOut", target=ref(_4e8cd0f3_deployment)
        )

    @action
    def ScaleIn():

        runner_del_count = CalmVariable.Simple(
            "1",
            label="how many runners do you want to remove?",
            is_mandatory=True,
            is_hidden=False,
            runtime=True,
            description="",
        )
        github_repo_token = CalmVariable.Simple.Secret(
            Profile_CentOS_Action_ScaleIn_variable_github_repo_token,
            label="GitHub Token",
            is_mandatory=True,
            is_hidden=False,
            runtime=True,
            description="Enter the token obtained from your GitHub repository (settings: actions: runners: add runner)",
        )
        CalmTask.Scaling.scale_in(
            "@@{runner_del_count}@@", name="ScaleIn", target=ref(_4e8cd0f3_deployment)
        )


class Ubuntu(Profile):

    deployments = [be90a1d9_deployment]

    github_repo_token = CalmVariable.Simple.Secret(
        Profile_Ubuntu_variable_github_repo_token,
        label="GitHub Repository Token",
        is_mandatory=True,
        is_hidden=False,
        runtime=True,
        description="Paste here the token for your GitHub repository.",
    )

    github_repo = CalmVariable.Simple(
        "",
        label="GitHub Repository URL",
        is_mandatory=True,
        is_hidden=False,
        runtime=True,
        description="Paste here the GitHub repository URL",
    )

    public_key = CalmVariable.Simple(
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC9GE/gov8gOPsSkKVeejG5NYTJTQGNFCsJOXFcszhd1s1ixS1ClVZs3MduB1fWSvY8Vjzs+jD5VkW7SdwxEQQmOvyF8sHGNM1s4FGNgnRIvKXlPaXQSe9TUEl52xJa7G0JwggiG4kNgCtJmunK9cXZMj+iTQqSwdGvidOFdMxTbmSjlTNEE4kMIP4jiyZEKztVbz4i9+bI/Sq8cQVX+pNF6XTjxqUgDH15KIejnXw6QDH26yv6KWbSjtRl+8HvE1yNtJh9yXDEJ1pt4jcvE2SHNfFYlY8HM9qyymeVkL7SzL3u6dmkN7ospqiNgJVEW/iOATUHICLZpSXj1kr73xFB",
        label="SSH Public Key",
        is_mandatory=True,
        is_hidden=False,
        runtime=True,
        description="Paste here your .ssh/id_rsa.pub key",
    )


class capgithubrunner(Blueprint):
    """Creates a GitHub self-hosted runner for the provided GitHub repo."""

    services = [LinuxGitHubRunner]
    packages = [Package_Centos, Package_Ubuntu]
    substrates = [LinuxVm, UbuntuVm]
    profiles = [CentOS, Ubuntu]
    credentials = [BP_CRED_runner]
