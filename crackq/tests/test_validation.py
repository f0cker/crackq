from crackq.validator import FileValidation as val
from pathlib import Path


def test_valid_filepath():
    valid_file = '/var/crackq/logs/val_test.txt'
    res = val.val_filepath(fullfile_string=valid_file)
    assert res

def test_invalid_filepath():
    invalid_file_sanitize = '/var/../../*!)(*&^^$$@!/crackq/logs/val_test.txt'
    res = val.val_filepath(fullfile_string=invalid_file_sanitize)
    assert res == '/var/crackq/logs/val_test.txt'
