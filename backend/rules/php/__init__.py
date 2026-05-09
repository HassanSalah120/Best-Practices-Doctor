"""PHP rules init."""
from .array_unpacking_in_loop import ArrayUnpackingInLoopRule
from .bulk_insert_missing import BulkInsertMissingRule
from .catch_too_broad import CatchTooBroadRule
from .circular_dependency import CircularDependencyRule
from .command_injection_risk import CommandInjectionRiskRule
from .complexity import HighComplexityRule
from .config_in_loop import ConfigInLoopRule
from .dry_violation import DryViolationRule
from .exception_swallowing import ExceptionSwallowingRule
from .god_class import GodClassRule
from .high_coupling_class import HighCouplingClassRule
from .long_method import LongMethodRule
from .low_coverage_files import LowCoverageFilesRule
from .missing_return_type_nullable import MissingReturnTypeNullableRule
from .missing_strict_types import MissingStrictTypesRule
from .missing_type_declarations import MissingTypeDeclarationsRule
from .mutable_global_state import MutableGlobalStateRule
from .pcre_redos_risk import PcreRedosRiskRule
from .prefer_imports import PreferImportsRule
from .raw_sql import RawSqlRule
from .sql_injection_risk import SqlInjectionRiskRule
from .static_helper_abuse import StaticHelperAbuseRule
from .string_concat_in_loop import StringConcatInLoopRule
from .tests_missing import TestsMissingRule
from .too_many_dependencies import TooManyDependenciesRule
from .unsafe_eval import UnsafeEvalRule
from .unsafe_file_include_variable import UnsafeFileIncludeVariableRule
from .unsafe_unserialize import UnsafeUnserializeRule
from .unused_private_method import UnusedPrivateMethodRule

__all__ = [
    "DryViolationRule",
    "HighComplexityRule",
    "LongMethodRule",
    "GodClassRule",
    "TooManyDependenciesRule",
    "RawSqlRule",
    "ConfigInLoopRule",
    "StaticHelperAbuseRule",
    "UnusedPrivateMethodRule",
    "CircularDependencyRule",
    "HighCouplingClassRule",
    "UnsafeEvalRule",
    "UnsafeUnserializeRule",
    "CommandInjectionRiskRule",
    "SqlInjectionRiskRule",
    "TestsMissingRule",
    "LowCoverageFilesRule",
    "PreferImportsRule",
    "PcreRedosRiskRule",
    "UnsafeFileIncludeVariableRule",
    "MissingStrictTypesRule",
    "MissingTypeDeclarationsRule",
    "ExceptionSwallowingRule",
    "MutableGlobalStateRule",
    "ArrayUnpackingInLoopRule",
    "StringConcatInLoopRule",
    "BulkInsertMissingRule",
    "MissingReturnTypeNullableRule",
    "CatchTooBroadRule",
]
