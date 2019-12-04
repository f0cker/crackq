import json

class HModes(object):
    @classmethod
    def modes_dict(cls):
        """
        Dictionary containing supported hashcat hash algorithms and
        corresponding hash mode value, type and speed

        Returns
        -------
        hash_modes: dict
            dictionary containing hash modes, their corresponding hash type,
            category and speed
        """
        with open('/var/crackq/files/hashm_dict.json', 'r') as fh_hashm:
            hash_modes = json.loads(fh_hashm.read())

        return hash_modes
