"""Validation module"""
from pathlib import Path
from crackq.logger import logger
import pathvalidate as pv


class FileValidation(object):
    """File and path validation"""

    @classmethod
    def val_path(cls, path_string):
        """
        Get and parse a path string

        Arguments
        ---------
        path_string: Path
            string representation of path name

        Returns
        -------

        Validated path string
        """
        try:
            pv.validate_filepath(path_string, platform='auto')
            str_path = pv.sanitize_filepath(path_string, platform='auto')
            return str_path
        except ValueError as err:
            logger.error('Invalid filepath provided: {}'.format(err))
            return False

    @classmethod
    def get_home(cls):
        """
         Get and validate home directory from env variable

         Returns
         -------
         home: Path obj
            validated user home path string
        """
        try:
            if Path.home().startswith('/home/'):
                str_path = Path.home()
                return str_path
            else:
                raise Exception('Invalid $HOME env variable detected')
        except ValueError as err:
            logger.error('Invalid $HOME env variable detected {}'.format(err))
            return False

    @classmethod
    def val_filepath(cls,
                     fullfile_string=None,
                     path_string=None,
                     file_string=None):
        """
        Get and parse a full file path string

        Arguments
        ---------
        fullfile_string: str
            string representation of full file path and name
        path_string: str
            string representation of file path
        file_string: str
            string representation of file name

        Returns
        --------
        path: Path object | boolean
            validated file string Path
        """
        if fullfile_string:
            file_string = Path(fullfile_string).name
            path_string = Path(fullfile_string).parents[0]
        if not all([path_string, file_string]):
            return False
        logger.debug('Validating filename')
        file_string = FileValidation.val_file(file_string)
        logger.debug('Validating filepath')
        path_string = FileValidation.val_path(path_string)
        return Path.joinpath(Path(path_string), file_string)

    @classmethod
    def val_file(cls, file_string):
        """
        Get and parse a file string

        Arguments
        ---------
        file_string: string
            string representation of file name

        Returns
        --------
        file: Path object | boolean
            validated file string
        """
        try:
            pv.validate_filename(file_string, platform='auto')
            str_file = pv.sanitize_filename(file_string, platform='auto')
            return str_file
        except ValueError as err:
            logger.error('Invalid file name: {} \n{} '.format(file_string, err))
            return False
