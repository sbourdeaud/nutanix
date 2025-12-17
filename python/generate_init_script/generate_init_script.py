"""_summary_
    Captures user input for generating an OS init script to be used when generating an AHV VM.
"""

#region #* IMPORT
import datetime
import json
import argparse
import os
import pathlib

import click
from jsonschema import validate, ValidationError
from jinja2 import Environment, FileSystemLoader
#endregion #* IMPORT


#region #* CLASS
class PrintColors:
    """Used for colored output formatting.
    """
    OK = '\033[92m' #GREEN
    SUCCESS = '\033[96m' #CYAN
    DATA = '\033[097m' #WHITE
    WARNING = '\033[93m' #YELLOW
    FAIL = '\033[91m' #RED
    STEP = '\033[95m' #PURPLE
    RESET = '\033[0m' #RESET COLOR
#endregion #* CLASS


#region #* FUNCTIONS
def main(operating_system):
    """Main function to capture user input and generate the init file.
    """

    #* read schema
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Reading schema...{PrintColors.RESET}")
    with open(f'./config/{operating_system}_schema.json', encoding='utf-8') as f:
        schema = json.load(f)

    #* capture user input
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Prompting user for necessary input...{PrintColors.RESET}")
    macros = {"init_variables": {}}
    for macro in schema['init_variables']['schema']:
        if macro.endswith('password'): # capture password input securely
            macro_value = click.prompt(
                click.style(schema['init_variables']['schema'][macro]['meta']['description'],"cyan"),
                prompt_suffix=click.style(" >> ", fg="green"),
                hide_input=True,
                confirmation_prompt=True
            )
        else:
            default_value = schema['init_variables']['schema'][macro].get('default','')
            macro_value = click.prompt(click.style(schema['init_variables']['schema'][macro]['meta']['description'],"cyan"), default=default_value, prompt_suffix=click.style(" >> ", fg="green"))
        if macro == "public_key": # read public key from file
            with open(os.path.expanduser(macro_value), 'r', encoding='utf-8') as pk_file:
                macro_value = pk_file.read().strip()
        macros[macro] = macro_value

    #* load template, render and write to file
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Rendring templates using user input...{PrintColors.RESET}")
    env = Environment(loader=FileSystemLoader('./config'))
    output_path = './.local/output'
    path_obj = pathlib.Path(output_path)
    path_obj.mkdir(parents=True, exist_ok=True)
    if operating_system == 'linux':
        template = env.get_template('linux.yaml')
        output = template.render(macros)
        file_path = path_obj / f'{macros["hostname"]}.yaml'
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(output)
    elif operating_system == 'windows':
        template = env.get_template('windows.xml')
        output = template.render(macros)
        file_path = path_obj / f'{macros["computer_name"]}.xml'
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(output)
    print(f"{PrintColors.OK}{(datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Init file has been saved in the .local/output directory{PrintColors.RESET}")

#endregion #* FUNCTIONS



if __name__ == '__main__':

    # * parsing script arguments
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--os",
        "-o",  
        choices=["windows", "linux"],
        required=True,
         help="Operating system type for init script generation."
    )
    args = parser.parse_args()

    main(operating_system=args.os)
