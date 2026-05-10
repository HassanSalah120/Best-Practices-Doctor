from __future__ import annotations

from rules.php.array_unpacking_in_loop import ArrayUnpackingInLoopRule
from rules.php.bulk_insert_missing import BulkInsertMissingRule
from rules.php.exception_swallowing import ExceptionSwallowingRule
from rules.php.missing_strict_types import MissingStrictTypesRule
from rules.php.missing_type_declarations import MissingTypeDeclarationsRule
from rules.php.mutable_global_state import MutableGlobalStateRule
from rules.php.string_concat_in_loop import StringConcatInLoopRule
from schemas.facts import Facts


def _facts() -> Facts:
    return Facts(project_path=".")


def test_missing_strict_types_valid_invalid_fp_guard():
    rule = MissingStrictTypesRule()
    valid = "<?php\ndeclare(strict_types=1);\nclass UserService {}"
    invalid = "<?php\nclass UserService {}"
    fp_guard = "<?php\nreturn ['debug' => true];"

    assert rule.analyze_regex("app/Services/UserService.php", valid, _facts()) == []
    assert len(rule.analyze_regex("app/Services/UserService.php", invalid, _facts())) == 1
    assert rule.analyze_regex("config/app.php", fp_guard, _facts()) == []


def test_missing_type_declarations_valid_invalid_fp_guard():
    rule = MissingTypeDeclarationsRule()
    valid = "<?php\nclass Processor { public function process(array $data): array { return $data; } }"
    invalid = "<?php\nclass Processor { public function process($data) { return $data; } }"
    fp_guard = "<?php\nclass UserTest extends TestCase { public function test_it_works() { $this->assertTrue(true); } }"

    assert rule.analyze_regex("app/Services/Processor.php", valid, _facts()) == []
    assert len(rule.analyze_regex("app/Services/Processor.php", invalid, _facts())) == 1
    assert rule.analyze_regex("tests/Feature/UserTest.php", fp_guard, _facts()) == []


def test_exception_swallowing_valid_invalid_fp_guard():
    rule = ExceptionSwallowingRule()
    valid = "<?php\ntry { sync(); } catch (Exception $e) { Log::error($e->getMessage()); throw $e; }"
    invalid = "<?php\ntry { sync(); } catch (Exception $e) { }"
    fp_guard = "<?php\ntry { sync(); } catch (Exception $e) { return false; }"

    assert rule.analyze_regex("app/Services/SyncService.php", valid, _facts()) == []
    assert len(rule.analyze_regex("app/Services/SyncService.php", invalid, _facts())) == 1
    assert rule.analyze_regex("app/Services/SyncService.php", fp_guard, _facts()) == []


def test_mutable_global_state_valid_invalid_fp_guard():
    rule = MutableGlobalStateRule()
    valid = "<?php\nfunction process(Config $config): void { $config->set('key', 'val'); }"
    invalid = "<?php\nfunction process(): void { global $config; $config['key'] = 'val'; }"
    fp_guard = "<?php\nfunction app() { global $app; return $app; }"

    assert rule.analyze_regex("app/Support/helpers2.php", valid, _facts()) == []
    assert len(rule.analyze_regex("app/Support/Processor.php", invalid, _facts())) == 1
    assert rule.analyze_regex("bootstrap.php", fp_guard, _facts()) == []


def test_array_unpacking_in_loop_valid_invalid_fp_guard():
    rule = ArrayUnpackingInLoopRule()
    valid = "<?php\n$rows = array_merge(...$items);"
    invalid = "<?php\nforeach ($items as $item) { $rows = array_merge($rows, $item); }"
    fp_guard = "<?php\nforeach ($items as $item) { $rows[] = $item; }"

    assert rule.analyze_regex("app/Services/ImportService.php", valid, _facts()) == []
    assert len(rule.analyze_regex("app/Services/ImportService.php", invalid, _facts())) == 1
    assert rule.analyze_regex("app/Services/ImportService.php", fp_guard, _facts()) == []


def test_string_concat_in_loop_valid_invalid_fp_guard():
    rule = StringConcatInLoopRule()
    valid = "<?php\n$parts = []; foreach ($rows as $row) { $parts[] = $row['name']; } $out = implode(PHP_EOL, $parts);"
    invalid = "<?php\nforeach ($rows as $row) { $output .= $row['name'] . PHP_EOL; }"
    fp_guard = "<?php\nforeach ($parts as $part) { $sql .= ' AND '; }"

    assert rule.analyze_regex("app/Services/ExportService.php", valid, _facts()) == []
    assert len(rule.analyze_regex("app/Services/ExportService.php", invalid, _facts())) == 1
    assert rule.analyze_regex("app/Services/QueryBuilder.php", fp_guard, _facts()) == []


def test_bulk_insert_missing_valid_invalid_fp_guard():
    rule = BulkInsertMissingRule()
    valid = "<?php\nDB::table('items')->insert($items);"
    invalid = "<?php\nforeach ($items as $item) { DB::insert('insert into items values (?)', $item); }"
    fp_guard = "<?php\nforeach ($items as $item) { if ($item->ready()) { $item->save(); } }"

    assert rule.analyze_regex("app/Services/ImportService.php", valid, _facts()) == []
    assert len(rule.analyze_regex("app/Services/ImportService.php", invalid, _facts())) == 1
    assert rule.analyze_regex("app/Services/ImportService.php", fp_guard, _facts()) == []
