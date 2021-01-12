from crackq.validator import FileValidation as val
from pathlib import Path


def test_valid_filepath():
    valid_file = '/var/crackq/logs/val_test.txt'
    res = val.val_filepath(fullfile_string=valid_file)
    assert res

def test_invalid_filepath():
    invalid_path = '/var/crackq/logs/'
    invalid_file = '../../val_test.txt'
    res = str(val.val_filepath(path_string=invalid_path, file_string=invalid_file))
    assert res

