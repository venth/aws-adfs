import collections
import logging

import click


def choose_role_to_assume(config, principal_roles):
    chosen_principal_arn = None
    chosen_role_arn = None

    principal_roles_emptied = not bool(principal_roles)
    if principal_roles_emptied:
        return chosen_principal_arn, chosen_role_arn

    role_collection = []
    principal_roles = collections.OrderedDict(sorted(principal_roles.items(), key=lambda t: t[0]))
    for account_name in principal_roles.keys():
        roles = principal_roles[account_name]
        for role_arn in roles.keys():
            role_collection.append([roles[role_arn]['principal_arn'], role_arn])

    logging.debug(u'Role arn from config: {}'.format(config.role_arn))

    chosen_principal_role = [role for role in role_collection if config.role_arn == role[1]]

    logging.debug(u'Calculated role collection: {}'.format(role_collection))
    if len(chosen_principal_role) == 1:
        logging.debug(u'Chosen principal role based on previously used role_arn stored in config: {}'
                      .format(chosen_principal_role))
        chosen_principal_arn = chosen_principal_role[0][0]
        chosen_role_arn = chosen_principal_role[0][1]
        return chosen_principal_arn, chosen_role_arn

    if len(role_collection) == 1:
        logging.debug(u'There is only one role to choose')
        chosen_principal_arn = role_collection[0][0]
        chosen_role_arn = role_collection[0][1]
    elif len(role_collection) > 1:
        logging.debug(u'Manual choice')
        click.echo(u'Please choose the role you would like to assume:')
        i = 0
        for account_name in principal_roles.keys():
            roles = principal_roles[account_name]
            for role_arn in roles.keys():
                role_entry = roles[role_arn]
                click.echo(' [{}] : {} / {} '.format(i, account_name, role_entry['name']))
                i += 1

        selected_index = click.prompt(text='Selection', type=click.IntRange(0, len(role_collection)))

        chosen_principal_arn = role_collection[selected_index][0]
        chosen_role_arn = role_collection[selected_index][1]
        custom_profile = 'default'
        if(role_arn is not None):
            for key, value in principal_roles.items():
                for accountKey in value.keys():
                    if(accountKey.find(chosen_role_arn) != -1):
                        custom_profile = key
                        custom_profile = custom_profile + "-" + chosen_role_arn.split("/")[1]
                        break
    click.echo(' Profile {} '.format(custom_profile))
    return chosen_principal_arn, chosen_role_arn, custom_profile
