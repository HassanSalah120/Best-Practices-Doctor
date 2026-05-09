from core.ruleset import RuleConfig
from rules.laravel.contract_suggestion import ContractSuggestionRule


def test_contract_param_parser_private_readonly_fqcn():
    rule = ContractSuggestionRule(RuleConfig())
    parsed = rule._parse_typed_param("private readonly App\\Services\\UserService $svc")
    assert parsed == ("App\\Services\\UserService", "$svc")


def test_contract_param_parser_nullable_type():
    rule = ContractSuggestionRule(RuleConfig())
    parsed = rule._parse_typed_param("?UserService $svc")
    assert parsed == ("UserService", "$svc")


def test_contract_param_parser_union_picks_first_non_null():
    rule = ContractSuggestionRule(RuleConfig())
    parsed = rule._parse_typed_param("UserService|Foo $svc")
    assert parsed == ("UserService", "$svc")

