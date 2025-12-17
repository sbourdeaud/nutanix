# generate_init_script

This Python script can be used to generate guest customization init scripts (unattend.xml for Windwos and cloud-init.yaml for Linux) to be used when creating AHV VMs from templates or disk images.

> [!IMPORTANT]
> This script assumes that your disk images or templates are ready for customization. This means your Windows image/template has been sysprep'ed and is ready to accept an unattend.xml and your Linux image/template has cloud-init installed and enabled.
> The unattend.xml and cloud-init.yaml have been tested with: Windows Server 2025 and RHEL 9.

## Installation

1. Clone this repo
2. Install the required python modules in your venv using `pip install -r requirements.txt`
3. Customize the template files (windows.xml and linux.yaml) in the config directory as required
4. If you add or change macros in those files, make sure to edit the windows_schema.json or linux_schema.json files. This is what is used by click to capture user input and then used by jinja2 to render the template files.  Note that macros use the {{ macro_name }} convention.
5. Run the script with the `--os` argument which can be either `windows` or `linux`
6. Use the generated file in the .local/output directory