from aws_adfs import role_chooser
from aws_adfs.role_chooser import click


class TestRoleChooser:

    def test_returns_no_roles_for_empty_list(self):
        # given user without roles
        empty_roles_collection = [{}, None, []]

        for empty_principal_roles in empty_roles_collection:
            # when an user is asked to choose a role
            chosen_principal_arn, chosen_role_arn = role_chooser.choose_role_to_assume(
                config=self.irrelevant_config,
                principal_roles=empty_principal_roles
            )

            # then there are not roles
            assert chosen_principal_arn is None
            assert chosen_role_arn is None

    def test_returns_already_chosen_roles_when_it_is_named_for_an_user(self):
        # given role already chosen by an user
        already_chosen_role_arn = 'already_chosen_role_arn'

        config_with_already_chosen_role = type('', (), {})()
        config_with_already_chosen_role.role_arn = already_chosen_role_arn

        # and roles collection for the user still contains already chosen role
        already_chosen_principal_arn = 'already_chosen_principal_arn'
        roles_collection_with_already_chosen_one = {
            'awesome_account': {
                'irrelevant_arn': {'name': 'irrelevant', 'principal_arn': 'irrelevant'},
                already_chosen_role_arn: {'name': 'irrelevant', 'principal_arn': already_chosen_principal_arn},
            }
        }

        # when an user is asked to choose a role
        chosen_principal_arn, chosen_role_arn = role_chooser.choose_role_to_assume(
            config=config_with_already_chosen_role,
            principal_roles=roles_collection_with_already_chosen_one
        )

        # then returns already chosen role
        assert chosen_principal_arn == already_chosen_principal_arn
        assert chosen_role_arn == already_chosen_role_arn

    def test_returns_one_role_when_only_one_is_available(self):
        # given roles collection for the user contains one available role
        one_available_principal_arn = 'one_available_principal_arn'
        one_available_role_arn = 'one_available_role_arn'
        roles_collection_with_one_available_role = {
            'awesome_account': {
                one_available_role_arn: {'name': 'irrelevant', 'principal_arn': one_available_principal_arn}
            }
        }

        # when an user is asked to choose a role from two available
        chosen_principal_arn, chosen_role_arn = role_chooser.choose_role_to_assume(
            config=self.irrelevant_config,
            principal_roles=roles_collection_with_one_available_role
        )
        # then returns the one role that was assigned to the user
        assert chosen_principal_arn == one_available_principal_arn
        assert chosen_role_arn == one_available_role_arn

    def test_returns_second_role_chosen_by_the_user(self):
        # given roles collection for the user contains two roles
        first_principal_arn = 'first_principal_arn'
        first_role_arn = 'first_role_arn'
        chosen_by_the_user_principal_arn = 'chosen_by_the_user_principal_arn'
        chosen_by_the_user_role_arn = 'chosen_by_the_user_role_arn'
        roles_collection_with_one_available_role = {
            'awesome_account': {
                first_role_arn: {'name': first_role_arn, 'principal_arn': first_principal_arn}
            },
            'second_account': {
                chosen_by_the_user_role_arn: {'name': chosen_by_the_user_role_arn, 'principal_arn': chosen_by_the_user_principal_arn}
            }
        }

        # and the user chosen second role
        click.prompt = lambda **kwargs: 1

        # when an user is asked to choose a role from only one available
        chosen_principal_arn, chosen_role_arn = role_chooser.choose_role_to_assume(
            config=self.irrelevant_config,
            principal_roles=roles_collection_with_one_available_role
        )
        # then returns the role that was chosen by the user
        assert chosen_principal_arn == chosen_by_the_user_principal_arn
        assert chosen_role_arn == chosen_by_the_user_role_arn

    def test_goes_for_roles_choice_when_there_wasnt_any_previously_used_role_in_config(self):
        # given roles collection for the user contains two roles
        first_principal_arn = 'first_principal_arn'
        first_role_arn = 'first_role_arn'
        chosen_by_the_user_principal_arn = 'chosen_by_the_user_principal_arn'
        chosen_by_the_user_role_arn = 'chosen_by_the_user_role_arn'
        roles_collection_with_one_available_role = {
            'awesome_account': {
                first_role_arn: {'name': first_role_arn, 'principal_arn': first_principal_arn}
            },
            'second_account': {
                chosen_by_the_user_role_arn: {'name': chosen_by_the_user_role_arn, 'principal_arn': chosen_by_the_user_principal_arn}
            }
        }

        # and there wasn't any previously used role
        config_without_previously_used_role = type('', (), {})()
        config_without_previously_used_role.role_arn = None

        # and the user chosen second role
        click.prompt = lambda **kwargs: 1

        # when an user is asked to choose a role from only one available
        chosen_principal_arn, chosen_role_arn = role_chooser.choose_role_to_assume(
            config=config_without_previously_used_role,
            principal_roles=roles_collection_with_one_available_role
        )
        # then returns the role that was chosen by the user
        assert chosen_principal_arn == chosen_by_the_user_principal_arn
        assert chosen_role_arn == chosen_by_the_user_role_arn

    def test_lets_user_choose_in_case_of_missing_already_chosen_role_in_current_list(self):
        # given role already chosen by an user
        already_chosen_role_arn = 'already_chosen_role_arn'

        config_with_already_chosen_role = type('', (), {})()
        config_with_already_chosen_role.role_arn = already_chosen_role_arn

        # and roles collection for the user contains two roles without already chosen by the user
        first_principal_arn = 'first_principal_arn'
        first_role_arn = 'first_role_arn'
        chosen_by_the_user_principal_arn = 'chosen_by_the_user_principal_arn'
        chosen_by_the_user_role_arn = 'chosen_by_the_user_role_arn'
        roles_collection_with_one_available_role = {
            'awesome_account': {
                first_role_arn: {'name': first_role_arn, 'principal_arn': first_principal_arn}
            },
            'second_account': {
                chosen_by_the_user_role_arn: {'name': chosen_by_the_user_role_arn, 'principal_arn': chosen_by_the_user_principal_arn}
            }
        }

        # and the user chosen second role
        click.prompt = lambda **kwargs: 1

        # when an user is asked to choose a role from two available
        chosen_principal_arn, chosen_role_arn = role_chooser.choose_role_to_assume(
            config=self.irrelevant_config,
            principal_roles=roles_collection_with_one_available_role
        )
        # then returns the role that was chosen by the user
        assert chosen_principal_arn == chosen_by_the_user_principal_arn
        assert chosen_role_arn == chosen_by_the_user_role_arn

    def test_asks_user_to_choose_a_role(self):
        # given the role is assumed for the first time
        config = type('', (), {})()
        config.role_arn = None

        # and the user chosen second role
        click.prompt = lambda **kwargs: 1

        # when an user is asked to choose a role from two available
        chosen_principal_arn, chosen_role_arn = role_chooser.choose_role_to_assume(
            config=config,
            principal_roles=self._two_roles_grouped_in_one_account()
        )

        # then returns the role that was chosen by the user
        assert chosen_principal_arn is not None
        assert chosen_role_arn is not None

    def _two_roles_grouped_in_one_account(self):
        return {'COMPANY': {'arn:aws:iam::AWSACCOUNT:role/CORP-SuperAdmin': {'principal_arn': 'arn:aws:iam::AWSACCOUNT:saml-provider/ADFS', 'name': 'CORP-SuperAdmin'}, 'arn:aws:iam::AWSACCOUNT:role/CORP-DataScience': {'principal_arn': 'arn:aws:iam::AWSACCOUNT:saml-provider/ADFS', 'name': 'CORP-DataScience'}}}

    def setup_method(self, method):
        self.irrelevant_config = type('', (), {})()
        self.irrelevant_config.role_arn = 'irrelevant_role'
