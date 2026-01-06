"""Test SAST functionality."""
import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import tempfile
import json

from ghidrecomp.sast import check_tools, run_semgrep_scan, run_codeql_scan, merge_sarif_files, generate_sast_summary, preprocess_c_files


def test_check_tools_semgrep_missing():
    """Test check_tools raises error when semgrep is missing."""
    with patch('ghidrecomp.sast.shutil.which', return_value=None):
        with pytest.raises(RuntimeError, match="semgrep not installed"):
            check_tools()


def test_check_tools_semgrep_present():
    """Test check_tools passes when semgrep is present."""
    with patch('ghidrecomp.sast.shutil.which', return_value='/usr/bin/semgrep'):
        check_tools()  # Should not raise


@patch('ghidrecomp.sast.run')
@patch('ghidrecomp.sast.shutil.which')
def test_run_semgrep_scan(mock_which, mock_run):
    """Test semgrep scan execution."""
    mock_which.return_value = '/usr/bin/semgrep'
    mock_run.return_value = (0, '{"runs": []}', '')

    with tempfile.TemporaryDirectory() as tmp:
        decomp_dir = Path(tmp) / 'decomps'
        decomp_dir.mkdir()
        (decomp_dir / 'test.c').write_text('int main() { return 0; }')

        out_sarif = Path(tmp) / 'output.sarif'
        result = run_semgrep_scan(decomp_dir, [], out_sarif)

        assert result == str(out_sarif)
        assert out_sarif.exists()
        # Verify SARIF content
        with open(out_sarif) as f:
            data = json.load(f)
            assert 'runs' in data


def test_run_codeql_scan():
    """Test CodeQL placeholder."""
    with tempfile.TemporaryDirectory() as tmp:
        out_sarif = Path(tmp) / 'codeql.sarif'
        result = run_codeql_scan(Path(tmp), [], out_sarif)
        assert result == str(out_sarif)
        assert out_sarif.exists()


def test_merge_sarif_files():
    """Test SARIF merging."""
    sarif1 = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "tool1"}}, "results": []}]}
    sarif2 = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "tool2"}}, "results": []}]}

    with tempfile.TemporaryDirectory() as tmp:
        input1 = Path(tmp) / '1.sarif'
        input2 = Path(tmp) / '2.sarif'
        output = Path(tmp) / 'merged.sarif'

        with open(input1, 'w') as f:
            json.dump(sarif1, f)
        with open(input2, 'w') as f:
            json.dump(sarif2, f)

        merge_sarif_files(str(output), [str(input1), str(input2)])

        assert output.exists()
        with open(output) as f:
            merged = json.load(f)
            assert len(merged['runs']) == 2


def test_generate_sast_summary():
    """Test SAST summary generation."""
    # Create test SARIF with findings
    test_sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "semgrep",
                        "rules": [
                            {"id": "rule1", "name": "Test Rule 1"},
                            {"id": "rule2", "name": "Test Rule 2"}
                        ]
                    }
                },
                "artifacts": [
                    {"uri": "test1.c"},
                    {"uri": "test2.c"}
                ],
                "results": [
                    {
                        "ruleId": "rule1",
                        "level": "error",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "test1.c"
                                    }
                                }
                            }
                        ]
                    },
                    {
                        "ruleId": "rule2", 
                        "level": "warning",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "test2.c"
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        ]
    }

    with tempfile.TemporaryDirectory() as tmp:
        # Create actual C files to test file counting
        (Path(tmp) / 'test1.c').write_text('int main() { return 0; }')
        (Path(tmp) / 'test2.c').write_text('void func() { }')
        
        sarif_file = Path(tmp) / 'test.sarif'
        with open(sarif_file, 'w') as f:
            json.dump(test_sarif, f)

        summary = generate_sast_summary([str(sarif_file)], tmp)

        # Verify summary structure
        assert summary["total_findings"] == 2
        assert summary["total_sarif_files"] == 1
        assert summary["files_scanned"] == 2
        assert summary["tools_used"] == ["semgrep"]
        assert summary["findings_by_severity"]["error"] == 1
        assert summary["findings_by_severity"]["warning"] == 1
        assert summary["findings_by_rule"]["rule1"] == 1
        assert summary["findings_by_rule"]["rule2"] == 1
        assert len(summary["top_findings"]) == 2
        # Both files should have 1 finding each
        top_files = {item["file"]: item["count"] for item in summary["top_findings"]}
        assert top_files["test1.c"] == 1
        assert top_files["test2.c"] == 1
        assert summary["rules_executed"] == 2
        assert summary["files_with_findings"] == 2
        assert summary["base_directory"] == tmp
        assert "scan_timestamp" in summary

        # Test without base directory
        summary_no_base = generate_sast_summary([str(sarif_file)])
        assert summary_no_base["base_directory"] is None


def test_preprocess_c_files():
    """Test simple C file preprocessing."""
    with tempfile.TemporaryDirectory() as tmp:
        # Create test C file with calling conventions
        test_content = '''
int __stdcall function1(void) { return 1; }
int __cdecl function2(void) { return 2; }
int __thiscall function3(void) { return 3; }
int __fastcall function4(void) { return 4; }
int __vectorcall function5(void) { return 5; }
'''
        c_file = Path(tmp) / 'test.c'
        c_file.write_text(test_content)
        
        # Count original lines
        original_lines = len(test_content.strip().split('\n'))
        
        # Preprocess
        preprocess_c_files(Path(tmp))
        
        # Read back and verify
        processed_content = c_file.read_text()
        processed_lines = len(processed_content.strip().split('\n'))
        
        # Verify line count is preserved
        assert processed_lines == original_lines
        
        # Verify calling conventions are removed
        assert '__stdcall' not in processed_content
        assert '__cdecl' not in processed_content
        assert '__thiscall' not in processed_content
        assert '__fastcall' not in processed_content
        assert '__vectorcall' not in processed_content
        
        # Verify function bodies remain
        assert 'return 1;' in processed_content
        assert 'return 2;' in processed_content