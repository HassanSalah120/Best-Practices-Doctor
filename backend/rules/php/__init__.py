"""PHP rules init."""
from .dry_violation import DryViolationRule
from .complexity import HighComplexityRule
from .long_method import LongMethodRule
from .god_class import GodClassRule
from .too_many_dependencies import TooManyDependenciesRule
from .raw_sql import RawSqlRule
from .config_in_loop import ConfigInLoopRule
from .static_helper_abuse import StaticHelperAbuseRule
from .unused_private_method import UnusedPrivateMethodRule
from .circular_dependency import CircularDependencyRule
from .high_coupling_class import HighCouplingClassRule
from .unsafe_eval import UnsafeEvalRule
from .unsafe_unserialize import UnsafeUnserializeRule
from .command_injection_risk import CommandInjectionRiskRule
from .sql_injection_risk import SqlInjectionRiskRule
from .tests_missing import TestsMissingRule
from .low_coverage_files import LowCoverageFilesRule
from .prefer_imports import PreferImportsRule
from .pcre_redos_risk import PcreRedosRiskRule
from .unsafe_file_include_variable import UnsafeFileIncludeVariableRule
from .missing_strict_types import MissingStrictTypesRule
from .missing_type_declarations import MissingTypeDeclarationsRule
from .exception_swallowing import ExceptionSwallowingRule
from .mutable_global_state import MutableGlobalStateRule
from .array_unpacking_in_loop import ArrayUnpackingInLoopRule
from .string_concat_in_loop import StringConcatInLoopRule
from .bulk_insert_missing import BulkInsertMissingRule
from .missing_return_type_nullable import MissingReturnTypeNullableRule
from .catch_too_broad import CatchTooBroadRule

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
