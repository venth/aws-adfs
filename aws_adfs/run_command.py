import json
import logging
import subprocess

def run_command(command):
    try:
        logging.debug("Executing `{}`".format(command))
        proc = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=True,
            shell=True,
        )
        data = json.loads(proc.stdout)
    except subprocess.CalledProcessError as e:
        logging.error(
            "Failed to execute the `{}` command: \n\n{}".format(
                command, e.output
            )
        )
        data = None
    except json.JSONDecodeError as e:
        logging.error(
            "Failed to decode the output of the `{}` command as JSON: \n\n{}".format(
                command, e
            )
        )
        data = None

    return data
