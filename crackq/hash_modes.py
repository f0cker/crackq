import json
from pyhashcat import Hashcat

class HModes(object):
    """
    Class to update/create reference dictionary containing all hashcat hash modes
    """
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

    @classmethod
    def update_modes(cls):
        """
        This method updates the dictionary containing the
        hashcat supported hash algorithms. Run this with every
        hashcat update if you want the latest hash types.
        """
        hc = Hashcat()
        hc.hwmon_disable = True
        hc.usage = True
        hc.left = False
        hc.logfile_disable = True
        hc.spin_damp = 0
        hc.potfile_disable = True
        hc.show = False
        hc.session = 'usage'
        hc.backend_info = True
        hc.quiet = True
        print("[+] Running hashcat")
        if hc.hashcat_session_execute() >= 0:
            hashm_dict = hc.hashcat_list_hashmodes()
            if isinstance(hashm_dict, dict):
                print('[+] Hashmodes list gathered')
        print('[+] Updating Hash Modes dictionary')
        hashm_file = '/var/crackq/files/hashm_dict.json'
        print('[+] Writing dicitonary to file: {}'.format(hashm_file))
        with open(hashm_file, 'w') as fh_hashm:
            fh_hashm.write(json.dumps(hashm_dict))
        print('[+] Done')
